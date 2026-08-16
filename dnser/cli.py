"""dnser command-line interface.

Commands: status, backends, list, set, restore, check

Conflict detection lives at the bottom of this file (used only by `status`).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from dnser import __version__, backup, check
from dnser.backends.base import BackendError, ProtocolSettings, Scope
from dnser.backends.detect import active_backend, all_backends
from dnser.providers import ProviderError, get_config_path, load_providers


console = Console()
err_console = Console(stderr=True, style="bold red")


# ----------------------------------------------------------------------
# Tag rendering
# ----------------------------------------------------------------------
# Each tag gets a distinct color so users can scan the list visually.
# Unknown tags fall back to plain text — the JSON schema doesn't restrict
# what tags can appear, but we style the common ones consistently.

_TAG_STYLES = {
    "malware": "red",
    "ads":     "yellow",
    "family":  "magenta",
    "no-log":  "green",
    "dnssec":  "cyan",
    "ecs":     "blue",
}


def _render_tags(tags: list[str]) -> str:
    """Format tags as small colored labels for the list table."""
    if not tags:
        return ""
    parts = []
    for tag in tags:
        style = _TAG_STYLES.get(tag)
        if style:
            parts.append(f"[{style}]{tag}[/{style}]")
        else:
            parts.append(tag)
    return " ".join(parts)


def _split_backup_name(stem: str) -> tuple[str, str]:
    """Split a backup filename stem into (label, timestamp)."""
    if "_" not in stem:
        return ("-", stem)
    label, _, timestamp = stem.rpartition("_")
    if len(timestamp) < 8 or not timestamp[:8].isdigit():
        return (stem, "-")
    return (label, timestamp)


def _protocol_status_marker(value: str) -> str:
    """Colorize a protocol state value for display in the status table."""
    v = value.lower()
    if v in ("no", "yes-strict"):
        return f"[green]{value}[/green]"
    if v in ("yes",):
        return value
    if v in ("opportunistic", "allow-downgrade", "resolve"):
        return f"[yellow]{value}[/yellow]"
    if v in ("unsupported", "unknown", ""):
        return f"[dim]{value or '-'}[/dim]"
    return value


def _render_protocols(protocols: dict[str, str]) -> Table | None:
    """Return a small rich Table with the protocol state, or None if empty."""
    if not protocols:
        return None

    canonical_order = ("LLMNR", "mDNS", "DNSSEC", "DNSOverTLS")
    rows = [(p, protocols[p]) for p in canonical_order if p in protocols]
    for k, v in protocols.items():
        if k not in canonical_order:
            rows.append((k, v))

    table = Table(show_header=True, header_style="bold cyan", title="Protocols")
    table.add_column("Protocol")
    table.add_column("State")
    for name, value in rows:
        vl = value.lower()
        if name in ("LLMNR", "mDNS"):
            marker = f"[green]{value}[/green]" if vl == "no" else (
                f"[red]{value}[/red]" if vl == "yes" else _protocol_status_marker(value)
            )
        elif name in ("DNSSEC", "DNSOverTLS"):
            marker = f"[green]{value}[/green]" if vl == "yes" else (
                f"[red]{value}[/red]" if vl == "no" else _protocol_status_marker(value)
            )
        else:
            marker = _protocol_status_marker(value)
        table.add_row(name, marker)
    return table


def _format_ms(value: float | None) -> str:
    """Right-aligned latency cell — dim dash on absence."""
    if value is None:
        return "[dim]—[/dim]"
    return f"{value:.0f} ms"


# ----------------------------------------------------------------------
# Command handlers
# ----------------------------------------------------------------------

def cmd_status(_args: argparse.Namespace) -> int:
    """Show which backend is active and the current DNS configuration."""
    backend = active_backend()
    if backend is None:
        err_console.print("No supported DNS backend detected on this system.")
        err_console.print(
            "[dim]dnser needs one of: NetworkManager (nmcli) or systemd-resolved.[/dim]"
        )
        err_console.print(
            "[dim]run `dnser backends` to see which are installed but inactive.[/dim]"
        )
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

    proto_table = _render_protocols(state.protocols)
    if proto_table is not None:
        console.print()
        console.print(proto_table)

    for note in state.notes:
        console.print(f"[dim]note:[/dim] {note}")

    warnings = _scan_conflicts()
    if warnings:
        console.print("\n[bold yellow]⚠ potential conflicts detected:[/bold yellow]")
        for w in warnings:
            console.print(f"  [yellow]•[/yellow] {w}")
        console.print(
            "[dim]  these files may influence DNS resolution independently of dnser.[/dim]"
        )

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

    # show_lines=True draws a rule between every row so long descriptions
    # and multi-value cells don't visually collide with the next entry.
    # padding=(0, 1) gives one column of horizontal breathing room on
    # each side of every cell — the default (0, 0) glues text to borders.
    table = Table(
        show_header=True,
        header_style="bold cyan",
        show_lines=True,
        padding=(0, 1),
    )
    table.add_column("Key", no_wrap=True, style="bold")
    table.add_column("Name", no_wrap=True)
    table.add_column("IPv4", no_wrap=True)
    table.add_column("Tags", min_width=14)
    table.add_column("Description", overflow="fold", min_width=32)

    # Group by family (the part of the key before the first '-') and draw
    # a blank separator row between families. Makes it easy to scan for
    # 'Quad9 has three variants' without following underlines.
    previous_family: str | None = None
    for key, p in providers.items():
        family = key.split("-", 1)[0]
        if previous_family is not None and family != previous_family:
            table.add_section()
        previous_family = family

        table.add_row(
            key,
            p.name,
            ", ".join(p.ipv4),
            _render_tags(p.tags),
            p.description,
        )

    console.print(table)
    return 0


def cmd_check(_args: argparse.Namespace) -> int:
    """Probe each provider's reachability + latency (cached and uncached)."""
    try:
        providers = load_providers()
    except ProviderError as e:
        err_console.print(str(e))
        return 1

    console.print(
        "[dim]Probing providers over UDP/53 (cached + 2 uncached queries each)…[/dim]\n"
    )
    results = check.check_all(providers)

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Provider")
    table.add_column("Status")
    table.add_column("Cached", justify="right")
    table.add_column("Uncached", justify="right")
    table.add_column("Notes", overflow="fold")

    for r in results:
        # Three visual states:
        #   - fully working: green ✓ ok
        #   - skipped (DoT-only): yellow ○ skip — not a failure, just untestable here
        #   - failed: red ✗ fail
        if not r.ok:
            status = "[red]✗ fail[/red]"
        elif r.cached_ms is None and r.uncached_ms is None:
            status = "[yellow]○ skip[/yellow]"
        else:
            status = "[green]✓ ok[/green]"
        table.add_row(
            r.provider_key,
            status,
            _format_ms(r.cached_ms),
            _format_ms(r.uncached_ms),
            r.error or "",
        )

    console.print(table)

    # Rank by uncached (real-world) latency for providers that fully succeeded.
    # Cached-only responders are noteworthy but not "best" — real usage will
    # hit uncached lookups constantly.
    fully_working = [r for r in results if r.ok and r.uncached_ms is not None]
    if fully_working:
        fastest = min(fully_working, key=lambda r: r.uncached_ms)  # type: ignore[arg-type]
        console.print(
            f"\nFastest (by uncached lookup): [bold]{fastest.provider_key}[/bold] "
            f"({fastest.uncached_ms:.0f} ms uncached, {fastest.cached_ms:.0f} ms cached)"
        )
        console.print(f"[dim]apply with: sudo dnser set {fastest.provider_key}[/dim]")
    elif any(r.ok for r in results):
        console.print(
            "\n[yellow]Some providers responded to cached lookups but failed on "
            "uncached queries — check network / firewall for authoritative traffic.[/yellow]"
        )
    else:
        err_console.print("\nNo provider responded. Check your network connection.")
        return 1

    return 0


def cmd_set(args: argparse.Namespace) -> int:
    """Apply a provider's DNS servers with the requested scope."""
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

    backend = active_backend()
    if backend is None:
        err_console.print("No supported DNS backend detected.")
        return 1

    if args.global_:
        scope = Scope.GLOBAL
    elif args.all:
        scope = Scope.ALL
    else:
        scope = Scope.CURRENT

    if args.dot_strict and not args.dot:
        err_console.print(
            "--dot-strict requires --dot (strict mode only makes sense with DoT enabled)."
        )
        return 1

    protocols = ProtocolSettings(
        no_llmnr=args.no_llmnr,
        no_mdns=args.no_mdns,
        dnssec=args.dnssec,
        dot_strict=args.dot_strict,
    )

    try:
        snap = backend.snapshot()
        label = backend.describe_current_state()
    except BackendError as e:
        err_console.print(f"Failed to take backup snapshot: {e}")
        return 1
    backup_path = backup.save(snap, label=label)

    if args.dot:
        if not provider.dot_hostname:
            err_console.print(
                f"Provider '{provider.key}' has no DoT hostname configured. "
                "Cannot use --dot."
            )
            return 1
        servers = provider.all_servers_dot(include_ipv6=not args.no_ipv6)
    else:
        # Refuse plain-DNS usage of providers that we know only answer
        # over DoT — otherwise the user's system will be silently broken.
        if provider.requires_dot:
            err_console.print(
                f"Provider '{provider.key}' only answers over DoT.\n"
                f"  Re-run with --dot: sudo dnser set {provider.key} --dot"
            )
            return 1
        servers = provider.all_servers(include_ipv6=not args.no_ipv6)

    try:
        backend.set_dns(servers, scope=scope, interface=args.iface, protocols=protocols)
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

    applied = []
    if protocols.no_llmnr:
        applied.append("LLMNR=off")
    if protocols.no_mdns:
        applied.append("mDNS=off")
    if protocols.dnssec:
        applied.append("DNSSEC=on")
    if protocols.dot_strict:
        applied.append("DoT=strict")
    if applied:
        console.print(f"[dim]hardening: {', '.join(applied)}[/dim]")

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
        table.add_column("Label")
        table.add_column("Timestamp")
        table.add_column("Backend")
        for i, path in enumerate(backups):
            payload = backup.load(path)
            label, timestamp = _split_backup_name(path.stem)
            table.add_row(str(i), label, timestamp, payload.backend_name)
        console.print(table)
        return 0

    if not backups:
        err_console.print("No backups to restore from.")
        err_console.print(
            "[dim]backups are created automatically when you run `dnser set`.[/dim]"
        )
        return 1

    index = args.index if args.index is not None else 0
    if index < 0 or index >= len(backups):
        err_console.print(
            f"Invalid backup index: {index}. Valid range: 0..{len(backups) - 1}"
        )
        err_console.print("[dim]run `dnser restore --list` to see available backups.[/dim]")
        return 1

    payload = backup.load(backups[index])

    backend = active_backend()
    if backend is None:
        err_console.print("No supported DNS backend detected.")
        return 1

    if payload.backend_name != backend.name:
        err_console.print(
            f"Cannot restore: backup was taken with backend '{payload.backend_name}', "
            f"but active backend is '{backend.name}'."
        )
        err_console.print(
            "[dim]this happens when the system's DNS management changed since the backup.[/dim]"
        )
        err_console.print(
            "[dim]run `dnser restore --list` to find a backup matching the current backend,[/dim]"
        )
        err_console.print(
            "[dim]or restore manually via nmcli / resolvectl.[/dim]"
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

    p_status = subparsers.add_parser("status", help="Show current DNS configuration")
    p_status.set_defaults(func=cmd_status)

    p_backends = subparsers.add_parser("backends", help="List known DNS backends and availability")
    p_backends.set_defaults(func=cmd_backends)

    p_list = subparsers.add_parser("list", help="List configured DNS providers")
    p_list.set_defaults(func=cmd_list)

    p_check = subparsers.add_parser(
        "check",
        help="Probe reachability + latency (cached and uncached) of all providers",
    )
    p_check.set_defaults(func=cmd_check)

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
    p_set.add_argument(
        "--dot-strict", action="store_true",
        help="Fail-closed if DoT can't be established (requires --dot, resolved only)",
    )

    p_set.add_argument(
        "--no-llmnr", action="store_true",
        help="Disable Link-Local Multicast Name Resolution (Windows legacy, spoofable)",
    )
    p_set.add_argument(
        "--no-mdns", action="store_true",
        help="Disable Multicast DNS (.local resolution)",
    )
    p_set.add_argument(
        "--dnssec", action="store_true",
        help="Require DNSSEC validation (resolved backend only)",
    )
    p_set.set_defaults(func=cmd_set)

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


# ----------------------------------------------------------------------
# Conflict detection
# ----------------------------------------------------------------------

_OUR_FILES = {
    "00-dnser-global.conf",   # NM global override
    "00-dnser.conf",          # resolved drop-in
}

_NM_CONFLICT_KEYS = (
    "servers=",
    "ignore-auto-dns",
)

_RESOLVED_CONFLICT_KEYS = (
    "DNS=",
    "FallbackDNS=",
    "Domains=",
)

_NM_INTEGRATION_ONLY_KEYS = (
    "dns=",
    "systemd-resolved=",
    "rc-manager=",
)


def _scan_conflicts() -> list[str]:
    """Return human-readable warnings about potentially conflicting configs."""
    warnings: list[str] = []

    nm_dir = Path("/etc/NetworkManager/conf.d")
    if nm_dir.is_dir():
        for path in sorted(nm_dir.glob("*.conf")):
            if path.name in _OUR_FILES:
                continue
            if _classify_nm_file(path) == "conflict":
                warnings.append(f"NetworkManager drop-in overrides DNS: {path}")

    resolved_dir = Path("/etc/systemd/resolved.conf.d")
    if resolved_dir.is_dir():
        for path in sorted(resolved_dir.glob("*.conf")):
            if path.name in _OUR_FILES:
                continue
            if _file_has_any_keys(path, _RESOLVED_CONFLICT_KEYS):
                warnings.append(f"systemd-resolved drop-in overrides DNS: {path}")

    resolved_conf = Path("/etc/systemd/resolved.conf")
    if resolved_conf.is_file() and _file_has_any_keys(
        resolved_conf, _RESOLVED_CONFLICT_KEYS
    ):
        warnings.append(f"resolved.conf has active DNS settings: {resolved_conf}")

    return warnings


def _classify_nm_file(path: Path) -> str:
    """Return 'conflict', 'integration', or 'empty'."""
    active_keys = _active_config_keys(path)
    if not active_keys:
        return "empty"
    if any(_line_starts_with_any(line, _NM_CONFLICT_KEYS) for line in active_keys):
        return "conflict"
    if any(_line_starts_with_any(line, _NM_INTEGRATION_ONLY_KEYS) for line in active_keys):
        return "integration"
    return "empty"


def _active_config_keys(path: Path) -> list[str]:
    """Return non-comment, non-blank lines from a config file."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    result: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("["):
            continue
        result.append(stripped)
    return result


def _line_starts_with_any(line: str, keys: tuple[str, ...]) -> bool:
    """Return True if the line's config key matches any of `keys`."""
    for key in keys:
        if line.startswith(key):
            return True
        if "." in line:
            _, _, after_dot = line.rpartition(".")
            if after_dot.startswith(key):
                return True
    return False


def _file_has_any_keys(path: Path, keys: tuple[str, ...]) -> bool:
    """Return True if the file has any active line whose key matches one of `keys`."""
    for line in _active_config_keys(path):
        if _line_starts_with_any(line, keys):
            return True
    return False


if __name__ == "__main__":
    sys.exit(main())
