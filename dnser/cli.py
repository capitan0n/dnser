"""dnser command-line interface.

Phase 1: status, backends, list
Phase 2: set, restore
"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.table import Table

from dnser import __version__, backup
from dnser.backends.base import BackendError, Scope
from dnser.backends.detect import active_backend, all_backends
from dnser.conflicts import scan_conflicts
from dnser.providers import ProviderError, get_config_path, load_providers


console = Console()
err_console = Console(stderr=True, style="bold red")


# ----------------------------------------------------------------------
# Command handlers
# ----------------------------------------------------------------------

def cmd_status(_args: argparse.Namespace) -> int:
    """Show which backend is active and the current DNS configuration."""
    backend = active_backend()
    if backend is None:
        err_console.print("No supported DNS backend detected on this system.")
        err_console.print("Run `dnser backends` to see what dnser looked for.")
        return 1

    console.print(f"[bold]Active backend:[/bold] {backend.display_name}")

    try:
        state = backend.get_current()
    except BackendError as e:
        err_console.print(f"Failed to read current DNS state: {e}")
        return 1

    if not state.per_interface:
        console.print("[yellow]No active interfaces with DNS configuration.[/yellow]")
    else:
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Interface")
        table.add_column("DNS Servers")
        for iface, servers in state.per_interface.items():
            servers_str = ", ".join(servers) if servers else "[dim](none / DHCP-managed)[/dim]"
            table.add_row(iface, servers_str)
        console.print(table)

    for note in state.notes:
        console.print(f"[dim]note:[/dim] {note}")

    # Conflict scan — warn about other configs that might affect DNS.
    # This is the differentiator vs other DNS switchers: we help the user
    # understand *why* their config might not be doing what they expect.
    warnings = scan_conflicts()
    if warnings:
        console.print("\n[bold yellow]⚠ potential conflicts detected:[/bold yellow]")
        for w in warnings:
            console.print(f"  [yellow]•[/yellow] {w}")
        console.print(
            "[dim]  these files may influence DNS resolution independently of dnser.[/dim]"
        )

    # Show the most recent backup so the user knows restore is possible.
    latest = backup.list_backups()
    if latest:
        console.print(f"\n[dim]latest backup: {latest[0].name}[/dim]")

    return 0


def cmd_backends(_args: argparse.Namespace) -> int:
    """List all known backends and their availability on this system."""
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Backend")
    table.add_column("Available")
    table.add_column("Notes")

    for backend in all_backends():
        available = backend.is_available()
        marker = "[green]yes[/green]" if available else "[red]no[/red]"
        note = "" if available else "not installed or service not running"
        table.add_row(backend.display_name, marker, note)

    console.print(table)
    return 0


def cmd_list(_args: argparse.Namespace) -> int:
    """List all configured DNS providers."""
    try:
        providers = load_providers()
    except ProviderError as e:
        err_console.print(str(e))
        return 1

    console.print(f"[dim]config: {get_config_path()}[/dim]\n")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Key")
    table.add_column("Name")
    table.add_column("IPv4")
    table.add_column("Description", overflow="fold")

    for key, p in providers.items():
        table.add_row(key, p.name, ", ".join(p.ipv4), p.description)

    console.print(table)
    return 0


def cmd_set(args: argparse.Namespace) -> int:
    """Apply a provider's DNS servers with the requested scope."""
    # 1. Resolve provider
    try:
        providers = load_providers()
    except ProviderError as e:
        err_console.print(str(e))
        return 1

    provider = providers.get(args.provider)
    if provider is None:
        err_console.print(f"Unknown provider: '{args.provider}'")
        err_console.print("Run `dnser list` to see available providers.")
        return 1

    # 2. Resolve backend
    backend = active_backend()
    if backend is None:
        err_console.print("No supported DNS backend detected.")
        return 1

    # 3. Determine scope. --global wins over --all if both are given.
    if args.global_:
        scope = Scope.GLOBAL
    elif args.all:
        scope = Scope.ALL
    else:
        scope = Scope.CURRENT

    # 4. Snapshot first — never mutate without a way back.
    try:
        snap = backend.snapshot()
    except BackendError as e:
        err_console.print(f"Failed to take backup snapshot: {e}")
        return 1
    backup_path = backup.save(snap)

    # 5. Apply.
    if args.dot:
        if not provider.dot_hostname:
            err_console.print(
                f"Provider '{provider.key}' has no DoT hostname configured. "
                "Cannot use --dot."
            )
            return 1
        servers = provider.all_servers_dot(include_ipv6=not args.no_ipv6)
    else:
        servers = provider.all_servers(include_ipv6=not args.no_ipv6)
    try:
        backend.set_dns(servers, scope=scope, interface=args.iface)
    except BackendError as e:
        err_console.print(f"Failed to apply DNS: {e}")
        err_console.print(f"[dim]backup saved at: {backup_path}[/dim]")
        err_console.print("[dim]run `dnser restore` to revert if the system is in a bad state.[/dim]")
        return 1

    scope_desc = {
        Scope.CURRENT: "current connection",
        Scope.ALL: "all saved connections",
        Scope.GLOBAL: "system-wide global override",
    }[scope]
    console.print(
        f"[green]OK[/green] applied [bold]{provider.name}[/bold] "
        f"({', '.join(servers)}) to [bold]{scope_desc}[/bold]"
    )
    console.print(f"[dim]backup: {backup_path.name}[/dim]")
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    """Restore DNS state from the most recent (or specified) backup."""
    backups = backup.list_backups()

    if args.list:
        if not backups:
            console.print("[dim]no backups found[/dim]")
            return 0
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("#", justify="right")
        table.add_column("Timestamp")
        table.add_column("Backend")
        for i, path in enumerate(backups):
            payload = backup.load(path)
            table.add_row(str(i), path.stem, payload.backend_name)
        console.print(table)
        return 0

    if not backups:
        err_console.print("No backups to restore from.")
        return 1

    # Default: latest (index 0). --index N picks an older one.
    index = args.index if args.index is not None else 0
    if index < 0 or index >= len(backups):
        err_console.print(f"Invalid index: {index}. Valid range: 0..{len(backups)-1}")
        return 1

    payload = backup.load(backups[index])

    backend = active_backend()
    if backend is None:
        err_console.print("No supported DNS backend detected.")
        return 1

    if payload.backend_name != backend.name:
        err_console.print(
            f"Backup was taken with backend '{payload.backend_name}', "
            f"but active backend is '{backend.name}'."
        )
        return 1

    try:
        backend.restore_from(payload)
    except BackendError as e:
        err_console.print(f"Restore failed: {e}")
        return 1

    console.print(f"[green]OK[/green] restored from {backups[index].name}")
    return 0


# ----------------------------------------------------------------------
# Argument parser
# ----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dnser",
        description="Terminal-first DNS switcher for Linux.",
    )
    parser.add_argument("--version", action="version", version=f"dnser {__version__}")

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # --- status ---
    p_status = subparsers.add_parser("status", help="Show current DNS configuration")
    p_status.set_defaults(func=cmd_status)

    # --- backends ---
    p_backends = subparsers.add_parser("backends", help="List known DNS backends and availability")
    p_backends.set_defaults(func=cmd_backends)

    # --- list ---
    p_list = subparsers.add_parser("list", help="List configured DNS providers")
    p_list.set_defaults(func=cmd_list)

    # --- set ---
    p_set = subparsers.add_parser(
        "set",
        help="Set DNS to a provider preset",
        description=(
            "Set DNS servers from a provider preset.\n"
            "By default, changes only the currently active connection.\n"
            "Use --all to change every saved connection, or --global for a\n"
            "system-wide override that also applies to future connections."
        ),
    )
    p_set.add_argument("provider", help="Provider key (see `dnser list`)")
    p_set.add_argument(
        "--all", action="store_true",
        help="Apply to every saved connection profile",
    )
    # We spell the attribute global_ because `global` is a Python keyword.
    p_set.add_argument(
        "--global", dest="global_", action="store_true",
        help="System-wide override (also affects future connections). Requires sudo.",
    )
    p_set.add_argument(
        "--iface", metavar="IFACE",
        help="Target a specific interface (only with default per-current-connection scope)",
    )
    p_set.add_argument(
        "--no-ipv6", action="store_true",
        help="Skip IPv6 servers even if the provider defines them",
    )
    p_set.add_argument(
        "--dot", action="store_true",
        help="Use DNS-over-TLS with hostname verification (resolved backend only)",
    )
    p_set.set_defaults(func=cmd_set)

    # --- restore ---
    p_restore = subparsers.add_parser(
        "restore",
        help="Restore DNS from a previous backup",
    )
    p_restore.add_argument(
        "--list", action="store_true",
        help="List available backups instead of restoring",
    )
    p_restore.add_argument(
        "--index", type=int,
        help="Backup index to restore (0 = latest). Default: 0.",
    )
    p_restore.set_defaults(func=cmd_restore)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
