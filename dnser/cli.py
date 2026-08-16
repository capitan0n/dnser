"""dnser command-line interface.

Commands: status, backends, list, check, set, unset, restore.

Privilege model: commands that change system state require the process to
already be root. There is no sudo re-exec and no `sudo tee` fallback — the
tool either has the privileges it needs or tells you exactly how to re-run.
"""

from __future__ import annotations

import argparse
import os
import sys

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from dnser import __version__, backup, check
from dnser.backends.base import BackendError, ProtocolSettings, Scope, sudo_hint
from dnser.backends.detect import active_backend, all_backends
from dnser.backup import BackupError
from dnser.conflicts import scan_conflicts
from dnser.providers import ProviderError, get_config_path, load_providers

console = Console()
err_console = Console(stderr=True, style="bold red")


# ----------------------------------------------------------------------
# Output helpers
# ----------------------------------------------------------------------
# Provider metadata and backend error text are untrusted as far as rich is
# concerned: a description containing '[red]' would otherwise be parsed as
# markup. Everything dynamic goes through escape().

def _fail(message: str) -> None:
    """Print an error message, escaping any markup it may contain."""
    err_console.print(escape(message))


# Each tag gets a distinct color so the list is scannable. Unknown tags
# fall back to plain text — the JSON schema does not restrict tag names.
_TAG_STYLES = {
    "malware": "red",
    "ads": "yellow",
    "family": "magenta",
    "no-log": "green",
    "dnssec": "cyan",
    "ecs": "blue",
}


def _render_tags(tags: list[str]) -> str:
    """Format tags as small colored labels for the list table."""
    parts = []
    for tag in tags:
        safe = escape(tag)
        style = _TAG_STYLES.get(tag)
        parts.append(f"[{style}]{safe}[/{style}]" if style else safe)
    return " ".join(parts)


def _split_backup_name(stem: str) -> tuple[str, str]:
    """Split a backup filename stem into (label, timestamp).

    Filenames are '<timestamp>_<label>', timestamp first, so that sorting
    by name sorts by age.
    """
    timestamp, sep, label = stem.partition("_")
    if not sep or len(timestamp) < 8 or not timestamp[:8].isdigit():
        return (stem, "-")
    return (label or "-", timestamp)


def _protocol_status_marker(value: str) -> str:
    """Colorize a protocol state value for the status table."""
    safe = escape(value)
    lowered = value.lower()
    if lowered in ("no", "yes-strict"):
        return f"[green]{safe}[/green]"
    if lowered == "yes":
        return safe
    if lowered in ("opportunistic", "allow-downgrade", "resolve"):
        return f"[yellow]{safe}[/yellow]"
    if lowered in ("unsupported", "unknown", ""):
        return f"[dim]{safe or '-'}[/dim]"
    return safe


def _render_protocols(protocols: dict[str, str]) -> Table | None:
    """Return a small table with the protocol state, or None if empty."""
    if not protocols:
        return None

    canonical_order = ("LLMNR", "mDNS", "DNSSEC", "DNSOverTLS")
    rows = [(p, protocols[p]) for p in canonical_order if p in protocols]
    rows += [(k, v) for k, v in protocols.items() if k not in canonical_order]

    table = Table(show_header=True, header_style="bold cyan", title="Protocols")
    table.add_column("Protocol")
    table.add_column("State")
    for name, value in rows:
        safe = escape(value)
        lowered = value.lower()
        # Multicast name resolution leaks hostnames on the local segment,
        # so 'no' is the good state. DNSSEC and DoT are the opposite.
        if name in ("LLMNR", "mDNS"):
            good, bad = "no", "yes"
        elif name in ("DNSSEC", "DNSOverTLS"):
            good, bad = "yes", "no"
        else:
            table.add_row(escape(name), _protocol_status_marker(value))
            continue

        if lowered == good:
            marker = f"[green]{safe}[/green]"
        elif lowered == bad:
            marker = f"[red]{safe}[/red]"
        else:
            marker = _protocol_status_marker(value)
        table.add_row(escape(name), marker)
    return table


def _format_ms(value: float | None) -> str:
    """Right-aligned latency cell — dim dash when absent."""
    return "[dim]—[/dim]" if value is None else f"{value:.0f} ms"


def _require_root() -> bool:
    """Return True if we are root; otherwise explain how to re-run."""
    if os.geteuid() == 0:
        return True
    err_console.print("This command changes system state and needs root.")
    console.print(f"[dim]  {escape(sudo_hint())}[/dim]")
    return False


def _print_plan(actions: list[str]) -> None:
    """Print a dry-run plan without touching anything."""
    console.print("[bold yellow]dry run[/bold yellow] — nothing was changed\n")
    for action in actions:
        console.print(f"  {escape(action)}")


# ----------------------------------------------------------------------
# Command handlers
# ----------------------------------------------------------------------

def cmd_status(_args: argparse.Namespace) -> int:
    """Show which backend is active and the current DNS configuration."""
    backend = active_backend()
    if backend is None:
        err_console.print("No supported DNS backend detected on this system.")
        console.print(
            "[dim]dnser needs one of: NetworkManager (nmcli) or systemd-resolved.[/dim]"
        )
        console.print("[dim]run `dnser backends` to see which are installed.[/dim]")
        return 1

    console.print(f"[bold]Active backend:[/bold] {escape(backend.display_name)}")

    try:
        state = backend.get_current()
    except BackendError as exc:
        _fail(f"Failed to read current DNS state: {exc}")
        return 1

    if not state.per_interface:
        console.print("[yellow]No active interfaces with DNS configuration.[/yellow]")
    else:
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Interface")
        table.add_column("DNS Servers")
        for iface, servers in state.per_interface.items():
            cell = escape(", ".join(servers)) if servers else "[dim](none / DHCP)[/dim]"
            table.add_row(escape(iface), cell)
        console.print(table)

    proto_table = _render_protocols(state.protocols)
    if proto_table is not None:
        console.print()
        console.print(proto_table)

    for note in state.notes:
        console.print(f"[dim]note:[/dim] {escape(note)}")

    warnings = scan_conflicts()
    if warnings:
        console.print("\n[bold yellow]⚠ potential conflicts detected:[/bold yellow]")
        for warning in warnings:
            console.print(f"  [yellow]•[/yellow] {escape(warning)}")
        console.print(
            "[dim]  these files may influence DNS resolution independently of dnser.[/dim]"
        )

    backups = backup.list_backups()
    if backups:
        console.print(f"\n[dim]latest backup: {escape(backups[0].name)}[/dim]")

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
        table.add_row(escape(backend.display_name), marker, note)

    console.print(table)
    return 0


def cmd_list(_args: argparse.Namespace) -> int:
    """List all configured DNS providers."""
    try:
        providers = load_providers()
        config_path = get_config_path()
    except ProviderError as exc:
        _fail(str(exc))
        return 1

    console.print(f"[dim]config: {escape(str(config_path))}[/dim]\n")

    # show_lines draws a rule between rows so long descriptions don't
    # visually collide with the next entry; padding keeps text off the
    # borders, which the (0, 0) default does not.
    table = Table(show_header=True, header_style="bold cyan", show_lines=True, padding=(0, 1))
    table.add_column("Key", no_wrap=True, style="bold")
    table.add_column("Name", no_wrap=True)
    table.add_column("IPv4", no_wrap=True)
    table.add_column("Tags", min_width=14)
    table.add_column("Description", overflow="fold", min_width=32)

    # Group by family (the key before the first '-') with a separator, so
    # "Quad9 has three variants" is visible at a glance.
    previous_family: str | None = None
    for key, provider in providers.items():
        family = key.split("-", 1)[0]
        if previous_family is not None and family != previous_family:
            table.add_section()
        previous_family = family

        table.add_row(
            escape(key),
            escape(provider.name),
            escape(", ".join(provider.ipv4)),
            _render_tags(provider.tags),
            escape(provider.description),
        )

    console.print(table)
    return 0


def cmd_check(_args: argparse.Namespace) -> int:
    """Probe each provider's reachability and latency."""
    try:
        providers = load_providers()
    except ProviderError as exc:
        _fail(str(exc))
        return 1

    console.print("[dim]Probing providers over UDP/53 (cached + 2 uncached each)…[/dim]\n")
    results = check.check_all(providers)

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Provider")
    table.add_column("Status")
    table.add_column("Cached", justify="right")
    table.add_column("Uncached", justify="right")
    table.add_column("Notes", overflow="fold")

    for result in results:
        # Three visual states: working, skipped (DoT-only, not a failure),
        # and failed.
        if not result.ok:
            status = "[red]✗ fail[/red]"
        elif result.cached_ms is None and result.uncached_ms is None:
            status = "[yellow]○ skip[/yellow]"
        else:
            status = "[green]✓ ok[/green]"
        table.add_row(
            escape(result.provider_key),
            status,
            _format_ms(result.cached_ms),
            _format_ms(result.uncached_ms),
            escape(result.error or ""),
        )

    console.print(table)

    # Rank by uncached latency: real usage hits uncached lookups constantly,
    # so a cached-only responder is noteworthy but not "best".
    ranked = [r for r in results if r.ok and r.uncached_ms is not None]
    if ranked:
        fastest = min(ranked, key=lambda r: r.uncached_ms or float("inf"))
        console.print(
            f"\nFastest (by uncached lookup): [bold]{escape(fastest.provider_key)}[/bold] "
            f"({_format_ms(fastest.uncached_ms)} uncached, {_format_ms(fastest.cached_ms)} cached)"
        )
        console.print(f"[dim]apply with: sudo dnser set {escape(fastest.provider_key)}[/dim]")
    elif any(r.ok for r in results):
        console.print(
            "\n[yellow]Some providers answered cached lookups but failed uncached "
            "queries — check the network path to authoritative servers.[/yellow]"
        )
    else:
        err_console.print("\nNo provider responded. Check your network connection.")
        return 1

    return 0


def cmd_set(args: argparse.Namespace) -> int:
    """Apply a provider's DNS servers with the requested scope."""
    try:
        providers = load_providers()
    except ProviderError as exc:
        _fail(str(exc))
        return 1

    provider = providers.get(args.provider)
    if provider is None:
        _fail(f"Unknown provider: '{args.provider}'")
        console.print("[dim]run `dnser list` to see available providers.[/dim]")
        return 1

    # Resolve the server list up front. Everything that can be rejected is
    # rejected before we take a snapshot, so a failed command never burns a
    # slot in the backup ring and evicts a good one.
    if args.dot:
        if not provider.dot_hostname:
            _fail(f"Provider '{provider.key}' has no DoT hostname configured.")
            return 1
        servers = provider.all_servers_dot(include_ipv6=not args.no_ipv6)
    else:
        # Providers we know answer only over DoT would silently break
        # resolution if configured as plain DNS.
        if provider.requires_dot:
            _fail(f"Provider '{provider.key}' only answers over DoT.")
            console.print(
                f"[dim]  re-run with --dot: sudo dnser set {escape(provider.key)} --dot[/dim]"
            )
            return 1
        servers = provider.all_servers(include_ipv6=not args.no_ipv6)

    if not servers:
        _fail(f"Provider '{provider.key}' has no servers left after filtering.")
        return 1

    if args.global_:
        scope = Scope.GLOBAL
    elif args.all:
        scope = Scope.ALL
    else:
        scope = Scope.CURRENT

    if args.iface and scope is not Scope.CURRENT:
        _fail("--iface only applies to the default (current connection) scope.")
        return 1

    protocols = ProtocolSettings(
        no_llmnr=args.no_llmnr,
        no_mdns=args.no_mdns,
        dnssec=args.dnssec,
    )

    backend = active_backend()
    if backend is None:
        err_console.print("No supported DNS backend detected.")
        return 1

    if args.dry_run:
        try:
            _, actions = backend.set_dns(
                servers, scope=scope, interface=args.iface,
                protocols=protocols, dry_run=True,
            )
        except BackendError as exc:
            _fail(str(exc))
            return 1
        _print_plan(actions)
        return 0

    if not _require_root():
        return 1

    try:
        snapshot = backend.snapshot()
        label = backend.describe_current_state()
    except BackendError as exc:
        _fail(f"Failed to take backup snapshot: {exc}")
        return 1

    try:
        backup_path = backup.save(snapshot, label=label)
    except BackupError as exc:
        _fail(str(exc))
        return 1

    try:
        effective_scope, _ = backend.set_dns(
            servers, scope=scope, interface=args.iface, protocols=protocols
        )
    except BackendError as exc:
        _fail(f"Failed to apply DNS: {exc}")
        console.print(f"[dim]backup saved at: {escape(str(backup_path))}[/dim]")
        console.print("[dim]run `dnser restore` to revert.[/dim]")
        return 1

    scope_desc = {
        Scope.CURRENT: "current connection",
        Scope.ALL: "all saved connections",
        Scope.GLOBAL: "system-wide global override",
    }[effective_scope]
    console.print(
        f"[green]OK[/green] applied [bold]{escape(provider.name)}[/bold] "
        f"({escape(', '.join(servers))}) to [bold]{scope_desc}[/bold]"
    )
    if effective_scope is not scope:
        console.print(
            f"[dim]note: {escape(backend.name)} has no per-connection scope; "
            f"'{scope.value}' was applied as '{effective_scope.value}'.[/dim]"
        )

    applied = []
    if args.dot:
        applied.append("DoT=on")
    if protocols.dnssec:
        applied.append("DNSSEC=on")
    if protocols.no_llmnr:
        applied.append("LLMNR=off")
    if protocols.no_mdns:
        applied.append("mDNS=off")
    if applied:
        console.print(f"[dim]hardening: {', '.join(applied)}[/dim]")

    console.print(f"[dim]backup: {escape(backup_path.name)}[/dim]")
    return 0


def cmd_unset(args: argparse.Namespace) -> int:
    """Remove dnser's configuration and return DNS to system defaults."""
    backend = active_backend()
    if backend is None:
        err_console.print("No supported DNS backend detected.")
        return 1

    if args.dry_run:
        try:
            actions = backend.unset(dry_run=True)
        except BackendError as exc:
            _fail(str(exc))
            return 1
        _print_plan(actions)
        return 0

    if not _require_root():
        return 1

    # Snapshot first: unset is as destructive as set, so it must be just
    # as undoable.
    try:
        snapshot = backend.snapshot()
        label = backend.describe_current_state()
    except BackendError as exc:
        _fail(f"Failed to take backup snapshot: {exc}")
        return 1

    try:
        backup_path = backup.save(snapshot, label=label)
    except BackupError as exc:
        _fail(str(exc))
        return 1

    try:
        backend.unset()
    except BackendError as exc:
        _fail(f"Failed to remove dnser configuration: {exc}")
        console.print(f"[dim]backup saved at: {escape(str(backup_path))}[/dim]")
        return 1

    console.print("[green]OK[/green] removed dnser configuration; DNS is back to defaults")
    console.print(f"[dim]backup: {escape(backup_path.name)}[/dim]")
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
        table.add_column("Label")
        table.add_column("Timestamp")
        table.add_column("Backend")
        for index, path in enumerate(backups):
            label, timestamp = _split_backup_name(path.stem)
            try:
                backend_name = backup.load(path).backend_name
            except BackupError:
                backend_name = "[red]corrupt[/red]"
            table.add_row(str(index), escape(label), escape(timestamp), backend_name)
        console.print(table)
        return 0

    if not backups:
        err_console.print("No backups to restore from.")
        console.print(
            "[dim]backups are created automatically by `dnser set` and `dnser unset`.[/dim]"
        )
        console.print("[dim]to clear dnser's config without one, run `dnser unset`.[/dim]")
        return 1

    index = args.index if args.index is not None else 0
    if index < 0 or index >= len(backups):
        _fail(f"Invalid backup index: {index}. Valid range: 0..{len(backups) - 1}")
        console.print("[dim]run `dnser restore --list` to see available backups.[/dim]")
        return 1

    try:
        payload = backup.load(backups[index])
    except BackupError as exc:
        _fail(str(exc))
        return 1

    backend = active_backend()
    if backend is None:
        err_console.print("No supported DNS backend detected.")
        return 1

    if payload.backend_name != backend.name:
        _fail(
            f"Cannot restore: backup was taken with backend '{payload.backend_name}', "
            f"but the active backend is '{backend.name}'."
        )
        console.print(
            "[dim]run `dnser restore --list` to find a matching backup, "
            "or revert manually via nmcli / resolvectl.[/dim]"
        )
        return 1

    if not _require_root():
        return 1

    try:
        backend.restore_from(payload)
    except BackendError as exc:
        _fail(f"Restore failed: {exc}")
        return 1

    console.print(f"[green]OK[/green] restored from {escape(backups[index].name)}")
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

    p_status = subparsers.add_parser("status", help="Show current DNS configuration")
    p_status.set_defaults(func=cmd_status)

    p_backends = subparsers.add_parser(
        "backends", help="List known DNS backends and availability"
    )
    p_backends.set_defaults(func=cmd_backends)

    p_list = subparsers.add_parser("list", help="List configured DNS providers")
    p_list.set_defaults(func=cmd_list)

    p_check = subparsers.add_parser(
        "check", help="Probe reachability and latency of all providers"
    )
    p_check.set_defaults(func=cmd_check)

    p_set = subparsers.add_parser(
        "set",
        help="Set DNS to a provider preset",
        description=(
            "Set DNS servers from a provider preset. By default this changes "
            "only the currently active connection. Use --all for every saved "
            "connection, or --global for a system-wide override that also "
            "applies to future connections."
        ),
    )
    p_set.add_argument("provider", help="Provider key (see `dnser list`)")
    p_set.add_argument(
        "--all", action="store_true", help="Apply to every saved connection profile"
    )
    p_set.add_argument(
        "--global",
        dest="global_",
        action="store_true",
        help="System-wide override, including future connections",
    )
    p_set.add_argument(
        "--iface",
        metavar="IFACE",
        help="Target a specific interface (default scope only)",
    )
    p_set.add_argument(
        "--no-ipv6", action="store_true", help="Skip IPv6 servers even if defined"
    )
    p_set.add_argument(
        "--dot",
        action="store_true",
        help="DNS-over-TLS, fail-closed, certificate-verified (systemd-resolved only)",
    )
    p_set.add_argument(
        "--dnssec",
        action="store_true",
        help="Require DNSSEC validation (systemd-resolved only)",
    )
    p_set.add_argument(
        "--no-llmnr",
        action="store_true",
        help="Disable Link-Local Multicast Name Resolution (spoofable legacy protocol)",
    )
    p_set.add_argument(
        "--no-mdns", action="store_true", help="Disable Multicast DNS (.local resolution)"
    )
    p_set.add_argument(
        "--dry-run",
        action="store_true",
        help="Print exactly what would be written and run, then exit",
    )
    p_set.set_defaults(func=cmd_set)

    p_unset = subparsers.add_parser(
        "unset",
        help="Remove dnser's configuration and revert to system defaults",
        description=(
            "Delete the files dnser manages and reset the settings it touches, "
            "without needing a backup. A snapshot is taken first, so this is "
            "itself undoable with `dnser restore`."
        ),
    )
    p_unset.add_argument(
        "--dry-run",
        action="store_true",
        help="Print exactly what would be removed and run, then exit",
    )
    p_unset.set_defaults(func=cmd_unset)

    p_restore = subparsers.add_parser("restore", help="Restore DNS from a previous backup")
    p_restore.add_argument(
        "--list", action="store_true", help="List available backups instead of restoring"
    )
    p_restore.add_argument(
        "--index", type=int, help="Backup index to restore (0 = latest). Default: 0."
    )
    p_restore.set_defaults(func=cmd_restore)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
