"""Detect other DNS configurations on the system that may conflict with dnser.

The point isn't to fix them — the user might want them. The point is to
warn: 'you have other configs at these paths that could affect DNS'.
This is the killer feature that no existing DNS switcher offers.

We distinguish two kinds of "other configs":
  1. INTEGRATION configs — expected/healthy plumbing between layers.
     Example: NM's `dns=systemd-resolved` handoff. Not a conflict.
  2. CONFLICT configs — actually set DNS servers, ignore_auto_dns, or
     force specific resolvers in ways that compete with what dnser sets.

Only category 2 gets warned about.
"""

from __future__ import annotations

from pathlib import Path


# Files dnser itself manages — skip these when scanning.
_OUR_FILES = {
    "00-dnser-global.conf",   # NM global override
    "00-dnser.conf",          # resolved drop-in
}

# Keys that mean "this file actually sets or overrides DNS".
# We split by backend to phrase warnings accurately.
_NM_CONFLICT_KEYS = (
    "servers=",          # [global-dns] or [global-dns-domain-*] servers list
    "ignore-auto-dns",   # forces disable of DHCP-provided DNS
)

_RESOLVED_CONFLICT_KEYS = (
    "DNS=",
    "FallbackDNS=",
    "Domains=",
)

# Keys that mean "this file is plumbing / integration" — not a conflict.
# Example: `dns=systemd-resolved` in an NM conf tells NM to hand off DNS
# management to resolved. That's an integration setup we WANT.
_NM_INTEGRATION_ONLY_KEYS = (
    "dns=",              # dns=systemd-resolved, dns=default, dns=none, etc.
    "systemd-resolved=", # systemd-resolved=true toggle
    "rc-manager=",       # which program owns /etc/resolv.conf
)


def scan_conflicts() -> list[str]:
    """Return a list of human-readable warnings about potentially conflicting configs.

    Empty list = clean system.
    """
    warnings: list[str] = []

    # 1. Scan NetworkManager drop-ins
    nm_dir = Path("/etc/NetworkManager/conf.d")
    if nm_dir.is_dir():
        for path in sorted(nm_dir.glob("*.conf")):
            if path.name in _OUR_FILES:
                continue
            kind = _classify_nm_file(path)
            if kind == "conflict":
                warnings.append(f"NetworkManager drop-in overrides DNS: {path}")
            # "integration" and "empty" → no warning

    # 2. Scan systemd-resolved drop-ins
    resolved_dir = Path("/etc/systemd/resolved.conf.d")
    if resolved_dir.is_dir():
        for path in sorted(resolved_dir.glob("*.conf")):
            if path.name in _OUR_FILES:
                continue
            if _file_has_any_keys(path, _RESOLVED_CONFLICT_KEYS):
                warnings.append(f"systemd-resolved drop-in overrides DNS: {path}")

    # 3. Check main resolved.conf
    resolved_conf = Path("/etc/systemd/resolved.conf")
    if resolved_conf.is_file() and _file_has_any_keys(
        resolved_conf, _RESOLVED_CONFLICT_KEYS
    ):
        warnings.append(f"resolved.conf has active DNS settings: {resolved_conf}")

    return warnings


# ----------------------------------------------------------------------
# Internals
# ----------------------------------------------------------------------

def _classify_nm_file(path: Path) -> str:
    """Return 'conflict', 'integration', or 'empty'.

    - 'conflict': file sets specific DNS servers or forces ignore-auto-dns
    - 'integration': file only routes DNS between backends (e.g. dns=systemd-resolved)
    - 'empty': no relevant DNS-affecting keys at all
    """
    active_keys = _active_config_keys(path)
    if not active_keys:
        return "empty"

    has_conflict = any(_line_starts_with_any(line, _NM_CONFLICT_KEYS) for line in active_keys)
    if has_conflict:
        return "conflict"

    has_integration = any(
        _line_starts_with_any(line, _NM_INTEGRATION_ONLY_KEYS) for line in active_keys
    )
    if has_integration:
        return "integration"

    return "empty"


def _active_config_keys(path: Path) -> list[str]:
    """Return the list of non-comment, non-blank lines from a config file."""
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
    """Return True if `line` starts with any of the given keys.

    We match against the line START (not `in`) because ini keys always
    appear at the beginning of a line. Substring matching produces false
    positives like `MulticastDNS=no` matching `DNS=`.
    """
    return any(line.startswith(key) for key in keys)


def _file_has_any_keys(path: Path, keys: tuple[str, ...]) -> bool:
    """Return True if the file has any active line whose key matches one of `keys`."""
    for line in _active_config_keys(path):
        if _line_starts_with_any(line, keys):
            return True
    return False
