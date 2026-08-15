"""Abstract base class for DNS backends.

Every backend (NetworkManager, systemd-resolved, plain resolv.conf, ...)
implements this interface. The CLI never calls a backend directly — it
goes through the dispatcher in `detect.py`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


class Scope(Enum):
    """Where to apply a DNS change.

    - CURRENT: only the currently-active connection profile
    - ALL:     every saved connection profile on this system
    - GLOBAL:  system-wide default that overrides per-connection settings
               and applies to future connections too (privacy use case)
    """
    CURRENT = "current"
    ALL = "all"
    GLOBAL = "global"


@dataclass
class DNSState:
    """Snapshot of DNS configuration at a point in time.

    A backend returns this from get_current(). It's also what we serialize
    for backup/restore.
    """
    backend_name: str
    # Per-interface DNS servers currently in use, keyed by device name.
    per_interface: dict[str, list[str]] = field(default_factory=dict)
    # Human-readable notes: e.g. "DoT enabled", "search domains: example.com"
    notes: list[str] = field(default_factory=list)


@dataclass
class BackupPayload:
    """Everything needed to restore a backend to a previous state.

    The shape is backend-specific (each backend serializes what it needs),
    stored as a plain dict so we can JSON-encode it without custom logic.
    """
    backend_name: str
    data: dict


class BackendError(Exception):
    """Raised when a backend operation fails (command failure, permission, etc)."""


class Backend(ABC):
    """The contract every DNS backend must implement.

    Design principle: backends are stateless wrappers around system tools.
    They don't cache; they always query the live system state.
    """

    #: short identifier used in logs and status output, e.g. "networkmanager"
    name: str = ""

    #: human-readable name, e.g. "NetworkManager (nmcli)"
    display_name: str = ""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this backend can run on the current system.

        Must never raise — return False on any error.
        """

    @abstractmethod
    def get_current(self) -> DNSState:
        """Return the current DNS configuration as seen by this backend.

        Raises BackendError if the query fails.
        """

    @abstractmethod
    def snapshot(self) -> BackupPayload:
        """Capture enough state to fully undo any change we're about to make.

        Called by the CLI right before set_dns(). The returned payload is
        opaque to the CLI — only the same backend knows how to restore from it.
        """

    @abstractmethod
    def set_dns(
        self,
        servers: list[str],
        scope: Scope,
        interface: str | None = None,
    ) -> None:
        """Apply the given DNS servers according to scope.

        - Scope.CURRENT: modify the currently-active connection (or `interface`
                         if given). Only one profile changes.
        - Scope.ALL:     modify every saved connection profile.
        - Scope.GLOBAL:  set a system-wide override that applies to all
                         connections, present and future.

        Raises BackendError on failure. Should be idempotent: calling twice
        with the same args must not produce different results.
        """

    @abstractmethod
    def restore_from(self, payload: BackupPayload) -> None:
        """Reverse a previous set_dns using the snapshot taken beforehand.

        Raises BackendError if the payload is for a different backend or
        the restore fails.
        """

    def describe_current_state(self) -> str:
        """Return a short label describing the current DNS state.

        Used by the CLI to name backup files after the state they contain
        (not the state that's about to replace them). Common return values:
          - "baseline" — no dnser drop-in / override is active
          - "<provider>" — a known provider's servers are currently set
          - "external" — a non-dnser drop-in / override is present
          - "managed" — a dnser drop-in exists but its IPs match no known provider

        Default returns "snapshot" — backends override for smarter labels.
        """
        return "snapshot"
