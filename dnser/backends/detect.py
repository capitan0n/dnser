"""Backend detection and dispatch.

On mixed setups (NetworkManager + systemd-resolved, the default on
Manjaro, Ubuntu, Fedora, ...) we prefer the resolved backend, because
that is where DNS actually gets resolved — writing to NM alone would be
shadowed by resolved's own configuration.

Detection logic:
  1. systemd-resolved is running AND queries actually go through it
     (/etc/resolv.conf points at the 127.0.0.53 stub) -> ResolvedBackend.
  2. Otherwise, NetworkManager is running -> NetworkManagerBackend.
  3. Otherwise, resolved is running but not in the resolution path ->
     ResolvedBackend anyway; its drop-in takes effect once resolv.conf
     is pointed back at the stub.
  4. Otherwise, no backend.
"""

from __future__ import annotations

from pathlib import Path

from dnser.backends.base import Backend
from dnser.backends.networkmanager import NetworkManagerBackend
from dnser.backends.resolved import ResolvedBackend

RESOLV_CONF = Path("/etc/resolv.conf")


def _resolved_owns_resolv_conf() -> bool:
    """Return True if /etc/resolv.conf routes queries to the resolved stub.

    Reading the file covers every layout at once — symlink to
    stub-resolv.conf, symlink to the static /usr/lib copy, or a plain
    file someone wrote by hand. All of them route through resolved only
    if 127.0.0.53 is the nameserver, so that is the single thing we test.
    Resolved's "uplink" mode lists the real upstream servers instead, and
    correctly fails this check.
    """
    try:
        text = RESOLV_CONF.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("nameserver") and "127.0.0.53" in line:
            return True
    return False


def all_backends() -> list[Backend]:
    """Instantiate every known backend (available or not), for display."""
    return [ResolvedBackend(), NetworkManagerBackend()]


def active_backend() -> Backend | None:
    """Return the backend that actually controls DNS on this system."""
    resolved = ResolvedBackend()
    nm = NetworkManagerBackend()

    resolved_available = resolved.is_available()

    if resolved_available and _resolved_owns_resolv_conf():
        return resolved
    if nm.is_available():
        return nm
    if resolved_available:
        return resolved
    return None
