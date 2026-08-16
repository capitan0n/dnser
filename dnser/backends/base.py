"""Abstract base class for DNS backends.

Every backend (NetworkManager, systemd-resolved, plain resolv.conf, ...)
implements this interface. The CLI never calls a backend directly — it
goes through the dispatcher in `detect.py`.
"""

from __future__ import annotations

import sys
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
class ProtocolSettings:
    """Optional protocol-level hardening flags applied alongside a DNS change.

    All defaults mean "leave alone" — a set_dns call with an empty
    ProtocolSettings changes only the DNS servers, nothing else.

    Not every backend supports every flag. Backends that can't honor a
    requested flag raise BackendError with a clear message.
    """
    no_llmnr: bool = False       # disable Link-Local Multicast Name Resolution
    no_mdns: bool = False        # disable Multicast DNS (.local resolution)
    dnssec: bool = False         # require DNSSEC validation (resolved only)
    dot_strict: bool = False     # DoT strict mode: fail-closed on TLS failure


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
    # Per-protocol state, keyed by protocol name (LLMNR/mDNS/DNSSEC/DNSOverTLS).
    # Values are backend-reported strings ('yes','no','opportunistic','unknown').
    # Empty dict means the backend didn't report protocol state.
    protocols: dict[str, str] = field(default_factory=dict)


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


def sudo_hint() -> str:
    """Build a copy-pasteable sudo command to re-run the current invocation.

    We echo the argv verbatim (with the resolved script path) so the user
    doesn't have to figure out venv paths themselves.
    """
    executable = sys.argv[0] if sys.argv else "dnser"
    args = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else ""
    return f"sudo {executable} {args}".rstrip()


class Backend(ABC):
    """The contract every DNS backend must implement.

    Design principle: backends are stateless wrappers around system tools.
    They don't cache; they always query the live system state.
    """

    name: str = ""
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
        protocols: ProtocolSettings | None = None,
    ) -> None:
        """Apply the given DNS servers according to scope.

        `protocols` optionally enables hardening flags. Backends that can't
        honor a requested flag raise BackendError with a clear message so
        the user knows why the request failed instead of silently getting
        less than they asked for.

        Raises BackendError on failure. Should be idempotent.
        """

    @abstractmethod
    def restore_from(self, payload: BackupPayload) -> None:
        """Reverse a previous set_dns using the snapshot taken beforehand.

        Raises BackendError if the payload is for a different backend or
        the restore fails.
        """

    def describe_current_state(self) -> str:
        """Return a short label describing the current DNS state.

        Used by the CLI to name backup files. Common return values:
          - "baseline" — no dnser drop-in / override is active
          - "<provider>" — a known provider's servers are currently set
          - "external" — a non-dnser drop-in / override is present
          - "managed" — a dnser drop-in exists but IPs don't match a known provider
        """
        return "snapshot"
