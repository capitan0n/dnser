"""Backend detection and dispatch.

We check each backend and return the one that owns DNS on the current
system. On mixed setups (NetworkManager + systemd-resolved, which is the
default on Manjaro, Ubuntu, Fedora, ...) we prefer the resolved backend
because it's where DNS actually gets resolved — writing to NM alone would
be shadowed by resolved's config.

Detection logic:
  1. If systemd-resolved is running AND is what actually resolves DNS
     (i.e. /etc/resolv.conf points at 127.0.0.53), use ResolvedBackend.
  2. Otherwise, if NetworkManager is running, use NetworkManagerBackend.
  3. Otherwise, no backend (future: plain resolv.conf backend).
"""

from __future__ import annotations

from pathlib import Path

from dnser.backends.base import Backend
from dnser.backends.networkmanager import NetworkManagerBackend
from dnser.backends.resolved import ResolvedBackend


def _resolved_owns_resolv_conf() -> bool:
    """Return True if /etc/resolv.conf points at systemd-resolved's stub.

    If it does, resolved is the effective DNS layer, regardless of whether
    NetworkManager is also running.
    """
    resolv = Path("/etc/resolv.conf")
    if not resolv.exists():
        return False
    try:
        # Check via symlink target OR by reading the first non-comment line.
        # Both cases catch the "resolved stub is active" state.
        if resolv.is_symlink():
            target = str(resolv.resolve())
            if "systemd/resolve" in target or "systemd-resolved" in target:
                return True
        # Also handle non-symlink case (e.g. a static file copy of stub-resolv.conf)
        for line in resolv.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("nameserver") and "127.0.0.53" in line:
                return True
    except OSError:
        return False
    return False


def all_backends() -> list[Backend]:
    """Instantiate every known backend (available or not).

    Order here is display-only (used by `dnser backends` command).
    Actual selection is done by active_backend() below.
    """
    return [ResolvedBackend(), NetworkManagerBackend()]


def active_backend() -> Backend | None:
    """Return the backend that actually controls DNS on this system.

    See module docstring for the priority rules.
    """
    resolved = ResolvedBackend()
    nm = NetworkManagerBackend()

    resolved_available = resolved.is_available()
    nm_available = nm.is_available()

    # Case 1: resolved owns /etc/resolv.conf → it's the source of truth.
    if resolved_available and _resolved_owns_resolv_conf():
        return resolved

    # Case 2: NM is running but resolved is not (or doesn't own resolv.conf).
    if nm_available:
        return nm

    # Case 3: resolved running but not owning resolv.conf (unusual, but
    # still better than nothing — its dropins will take effect after restart).
    if resolved_available:
        return resolved

    return None
