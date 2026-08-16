"""Detection of DNS configuration that competes with dnser.

`dnser status` warns about other files on the system that can influence
resolution, so a change that "didn't work" has a visible explanation.

The matching is key-aware rather than substring-based: a naive `"DNS=" in
line` check fires on 'MulticastDNS=no', 'DNSOverTLS=' and 'DNSSEC=', which
are ordinary settings, not conflicts.
"""

from __future__ import annotations

from pathlib import Path

NM_CONF_DIR = Path("/etc/NetworkManager/conf.d")
RESOLVED_CONF_DIR = Path("/etc/systemd/resolved.conf.d")
RESOLVED_CONF = Path("/etc/systemd/resolved.conf")

# Files dnser writes itself — never report our own work as a conflict.
_OUR_FILES = frozenset(
    {
        "00-dnser-global.conf",  # NetworkManager global override
        "00-dnser.conf",  # systemd-resolved drop-in
    }
)

# NetworkManager keys that actually take DNS decisions away from us.
# Integration keys like 'dns=systemd-resolved' are deliberately absent:
# they describe *who* resolves, not *what* the servers are.
_NM_CONFLICT_KEYS = (
    "servers=",
    "ignore-auto-dns",
)

_RESOLVED_CONFLICT_KEYS = (
    "DNS=",
    "FallbackDNS=",
    "Domains=",
)


def scan_conflicts() -> list[str]:
    """Return human-readable warnings about potentially conflicting configs."""
    warnings: list[str] = []

    if NM_CONF_DIR.is_dir():
        for path in sorted(NM_CONF_DIR.glob("*.conf")):
            if path.name in _OUR_FILES:
                continue
            if nm_file_conflicts(path):
                warnings.append(f"NetworkManager drop-in overrides DNS: {path}")

    if RESOLVED_CONF_DIR.is_dir():
        for path in sorted(RESOLVED_CONF_DIR.glob("*.conf")):
            if path.name in _OUR_FILES:
                continue
            if file_has_any_keys(path, _RESOLVED_CONFLICT_KEYS):
                warnings.append(f"systemd-resolved drop-in overrides DNS: {path}")

    if RESOLVED_CONF.is_file() and file_has_any_keys(RESOLVED_CONF, _RESOLVED_CONFLICT_KEYS):
        warnings.append(f"resolved.conf has active DNS settings: {RESOLVED_CONF}")

    return warnings


def nm_file_conflicts(path: Path) -> bool:
    """Return True if a NetworkManager drop-in sets DNS servers itself."""
    return file_has_any_keys(path, _NM_CONFLICT_KEYS)


def file_has_any_keys(path: Path, keys: tuple[str, ...]) -> bool:
    """Return True if any active line in the file has one of these keys."""
    return any(line_starts_with_any(line, keys) for line in active_config_keys(path))


def active_config_keys(path: Path) -> list[str]:
    """Return non-comment, non-blank, non-section lines from a config file."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    result: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        result.append(line)
    return result


def line_starts_with_any(line: str, keys: tuple[str, ...]) -> bool:
    """Return True if the line's config key matches any of `keys`.

    Handles NetworkManager's dotted notation (ipv4.ignore-auto-dns=true)
    by also testing the segment after the final dot.
    """
    for key in keys:
        if line.startswith(key):
            return True
        if "." in line:
            _, _, after_dot = line.rpartition(".")
            if after_dot.startswith(key):
                return True
    return False
