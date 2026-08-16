"""Shared types and helpers for DNS backends.

Every backend (NetworkManager, systemd-resolved, ...) implements the
`Backend` interface. The CLI never picks a backend directly — it goes
through the dispatcher in `detect.py`.

Privilege model: every mutating operation requires the process to already
be running as root. There is no sudo-escalation fallback; the CLI checks
euid up front and tells the user how to re-run. One model, no half-applied
states.
"""

from __future__ import annotations

import os
import sys
from abc import ABC, abstractmethod
from contextlib import suppress
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Scope(Enum):
    """Where to apply a DNS change.

    - CURRENT: only the currently-active connection profile
    - ALL:     every saved connection profile on this system
    - GLOBAL:  system-wide default that overrides per-connection settings
               and applies to future connections too (privacy use case)

    Not every backend can honor every scope. `set_dns` returns the scope
    that was *actually* applied so the CLI never reports a lie.
    """

    CURRENT = "current"
    ALL = "all"
    GLOBAL = "global"


@dataclass
class ProtocolSettings:
    """Optional protocol-level hardening applied alongside a DNS change.

    All defaults mean "leave alone" — a set_dns call with an empty
    ProtocolSettings changes only the DNS servers, nothing else.

    Note there is no `dot_strict`: in systemd-resolved, `DNSOverTLS=yes`
    is already fail-closed, so DoT strictness is implied by `--dot`.
    """

    no_llmnr: bool = False  # disable Link-Local Multicast Name Resolution
    no_mdns: bool = False  # disable Multicast DNS (.local resolution)
    dnssec: bool = False  # require DNSSEC validation (resolved only)


@dataclass
class DNSState:
    """Snapshot of DNS configuration at a point in time, for display."""

    # Per-interface DNS servers currently in use, keyed by device name.
    per_interface: dict[str, list[str]] = field(default_factory=dict)
    # Human-readable notes, e.g. "dnser drop-in active: /etc/...".
    notes: list[str] = field(default_factory=list)
    # Per-protocol state keyed by protocol name (LLMNR/mDNS/DNSSEC/DNSOverTLS).
    # Values are backend-reported strings ('yes', 'no', 'opportunistic', ...).
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
    """Raised when a backend operation fails (command failure, bad state, ...)."""


def sudo_hint() -> str:
    """Build a copy-pasteable sudo command to re-run the current invocation."""
    executable = sys.argv[0] if sys.argv else "dnser"
    args = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else ""
    return f"sudo {executable} {args}".rstrip()


def write_system_file(path: Path, content: str, mode: int = 0o644) -> None:
    """Atomically write a config file under /etc.

    Written to a temporary file in the same directory, fsynced, then
    renamed into place — an interrupted run can never leave a truncated
    DNS config behind. O_NOFOLLOW refuses to follow a symlink planted at
    the target path.
    """
    tmp = path.with_name(path.name + ".dnser-tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
        fd = os.open(tmp, flags, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except OSError as exc:
        with suppress(OSError):
            tmp.unlink()
        raise BackendError(f"Failed to write {path}: {exc}") from exc


def remove_system_file(path: Path) -> None:
    """Delete a config file we manage. A missing file is not an error."""
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise BackendError(f"Failed to remove {path}: {exc}") from exc


class Backend(ABC):
    """The contract every DNS backend must implement.

    Design principle: backends are stateless wrappers around system tools.
    They never cache; they always query the live system state.
    """

    name: str = ""
    display_name: str = ""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this backend can run here. Must never raise."""

    @abstractmethod
    def get_current(self) -> DNSState:
        """Return the current DNS configuration as seen by this backend."""

    @abstractmethod
    def snapshot(self) -> BackupPayload:
        """Capture enough state to fully undo the change we're about to make."""

    @abstractmethod
    def set_dns(
        self,
        servers: list[str],
        scope: Scope,
        interface: str | None = None,
        protocols: ProtocolSettings | None = None,
        dry_run: bool = False,
    ) -> tuple[Scope, list[str]]:
        """Apply the given DNS servers according to scope.

        Returns (effective_scope, actions) where `actions` is a
        human-readable list of everything that was done — or, when
        `dry_run` is True, everything that *would* be done while the
        system is left untouched.

        Backends that cannot honor a requested protocol flag raise
        BackendError with a clear message rather than silently doing less.
        """

    @abstractmethod
    def unset(self, dry_run: bool = False) -> list[str]:
        """Remove dnser's configuration and revert to backend defaults.

        Unlike `restore_from`, this needs no backup: it deletes what dnser
        writes and resets the fields dnser touches. Returns the list of
        actions performed (or planned, under `dry_run`).
        """

    @abstractmethod
    def restore_from(self, payload: BackupPayload) -> None:
        """Reverse a previous change using the snapshot taken beforehand."""

    def describe_current_state(self) -> str:
        """Return a short label describing the current DNS state.

        Used by the CLI to name backup files. Common return values:
          - "baseline" — no dnser drop-in / override is active
          - "<provider>" — a known provider's servers are currently set
          - "external" — a non-dnser drop-in / override is present
          - "managed" — a dnser drop-in exists but IPs match no known provider
        """
        return "snapshot"
