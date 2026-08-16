"""systemd-resolved backend.

Manages DNS by writing a drop-in under /etc/systemd/resolved.conf.d/ and
using `resolvectl` for live queries. Persistent across reboots.

Why a drop-in instead of editing /etc/systemd/resolved.conf directly:
  - The main file usually holds distro or user comments we shouldn't clobber.
  - systemd merges every *.conf in resolved.conf.d/ alphabetically, later
    values winning. Our "00-" prefix means we load first and stay
    overridable by anything the user adds later.
  - Deleting our drop-in cleanly reverts to the pre-dnser state.

Scopes: resolved has no per-connection concept, so every scope resolves to
GLOBAL. set_dns reports that back so the CLI can tell the user.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from dnser.backends.base import (
    Backend,
    BackendError,
    BackupPayload,
    DNSState,
    ProtocolSettings,
    Scope,
    remove_system_file,
    write_system_file,
)
from dnser.providers import identify_provider

# Drop-in path. "00-" so we load first among any user drop-ins.
DROPIN_PATH = Path("/etc/systemd/resolved.conf.d/00-dnser.conf")

DNSER_HEADER = "# Managed by dnser — do not edit by hand."

# Keys we are willing to write back when restoring a backup. Backups live
# in a user-writable directory but are applied as root, so restoring
# unvalidated content would let an unprivileged process dictate a
# root-owned config file. Anything outside this set is refused.
_ALLOWED_RESOLVE_KEYS = frozenset(
    {
        "DNS",
        "FallbackDNS",
        "Domains",
        "DNSOverTLS",
        "DNSSEC",
        "LLMNR",
        "MulticastDNS",
        "Cache",
        "DNSStubListener",
        "ReadEtcHosts",
    }
)


class ResolvedBackend(Backend):
    name = "resolved"
    display_name = "systemd-resolved (resolvectl)"

    # ------------------------------------------------------------------
    # is_available
    # ------------------------------------------------------------------
    def is_available(self) -> bool:
        """True if resolvectl exists AND systemd-resolved is running."""
        if shutil.which("resolvectl") is None:
            return False
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "--quiet", "systemd-resolved"],
                timeout=5,
            )
        except (subprocess.TimeoutExpired, OSError):
            return False
        return result.returncode == 0

    # ------------------------------------------------------------------
    # get_current
    # ------------------------------------------------------------------
    def get_current(self) -> DNSState:
        """Return DNS state as seen by resolved (per-link, plus global)."""
        state = DNSState()

        try:
            output = self._run(["resolvectl", "dns"])
        except BackendError as exc:
            state.notes.append(f"Could not query resolved: {exc}")
            return state

        for raw in output.strip().splitlines():
            line = raw.strip()
            if not line or ":" not in line:
                continue
            label, _, servers_raw = line.partition(":")
            label = label.strip()
            servers = servers_raw.strip().split()

            if label.lower().startswith("link"):
                if "(" in label and ")" in label:
                    iface = label[label.index("(") + 1 : label.index(")")]
                else:
                    iface = label
                if iface == "lo":
                    continue
                state.per_interface[iface] = servers
            elif label.lower() == "global" and servers:
                state.per_interface["(global)"] = servers

        if DROPIN_PATH.exists():
            state.notes.append(f"dnser drop-in active: {DROPIN_PATH}")

        state.protocols = self._read_protocol_state()
        return state

    # ------------------------------------------------------------------
    # describe_current_state
    # ------------------------------------------------------------------
    def describe_current_state(self) -> str:
        """Label for the backup filename — describes what's being snapshotted."""
        if not DROPIN_PATH.exists():
            return "baseline"
        try:
            content = DROPIN_PATH.read_text(encoding="utf-8")
        except OSError:
            return "managed"

        if "Managed by dnser" not in content:
            return "external"

        for raw in content.splitlines():
            line = raw.strip()
            if line.startswith("DNS="):
                provider_key = identify_provider(line[len("DNS=") :].split())
                if provider_key:
                    return provider_key
                break
        return "managed"

    # ------------------------------------------------------------------
    # snapshot
    # ------------------------------------------------------------------
    def snapshot(self) -> BackupPayload:
        """Capture the existing drop-in content (or None if absent).

        The drop-in holds the entire state we manage (DNS plus protocol
        settings), so one file is enough to restore everything.
        """
        dropin_content: str | None = None
        if DROPIN_PATH.exists():
            try:
                dropin_content = DROPIN_PATH.read_text(encoding="utf-8")
            except OSError:
                dropin_content = ""
        return BackupPayload(
            backend_name=self.name,
            data={"dropin_content": dropin_content},
        )

    # ------------------------------------------------------------------
    # set_dns
    # ------------------------------------------------------------------
    def set_dns(
        self,
        servers: list[str],
        scope: Scope,
        interface: str | None = None,
        protocols: ProtocolSettings | None = None,
        dry_run: bool = False,
    ) -> tuple[Scope, list[str]]:
        """Write the drop-in and restart resolved. Always global in effect."""
        if not servers:
            raise BackendError("set_dns called with empty server list")
        del interface, scope  # resolved is inherently global

        content = self._build_dropin(servers, protocols or ProtocolSettings())
        actions = [f"write {DROPIN_PATH}"]
        actions += [f"  | {line}" for line in content.splitlines()]
        actions.append("run: systemctl restart systemd-resolved")

        if not dry_run:
            write_system_file(DROPIN_PATH, content)
            self._restart_resolved()

        return Scope.GLOBAL, actions

    # ------------------------------------------------------------------
    # unset
    # ------------------------------------------------------------------
    def unset(self, dry_run: bool = False) -> list[str]:
        """Delete the drop-in so resolved falls back to its own defaults."""
        if not DROPIN_PATH.exists():
            return [f"nothing to do: {DROPIN_PATH} does not exist"]

        actions = [
            f"remove {DROPIN_PATH}",
            "run: systemctl restart systemd-resolved",
        ]
        if not dry_run:
            remove_system_file(DROPIN_PATH)
            self._restart_resolved()
        return actions

    # ------------------------------------------------------------------
    # restore_from
    # ------------------------------------------------------------------
    def restore_from(self, payload: BackupPayload) -> None:
        """Restore the drop-in to its snapshot state (or remove it)."""
        if payload.backend_name != self.name:
            raise BackendError(
                f"Backup was taken with backend '{payload.backend_name}', "
                f"cannot restore with '{self.name}'"
            )
        original = payload.data.get("dropin_content")
        if original is None:
            remove_system_file(DROPIN_PATH)
        else:
            if not isinstance(original, str):
                raise BackendError("Corrupt backup: dropin_content is not text")
            validate_dropin(original)
            write_system_file(DROPIN_PATH, original)
        self._restart_resolved()

    # ==================================================================
    # Internal: subprocess helper
    # ==================================================================
    def _run(self, args: list[str]) -> str:
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired as exc:
            raise BackendError(f"Command timed out: {' '.join(args)}") from exc
        except OSError as exc:
            raise BackendError(f"Failed to run {args[0]}: {exc}") from exc
        if result.returncode != 0:
            stderr = result.stderr.strip() or "no error message"
            raise BackendError(
                f"Command failed ({result.returncode}): {' '.join(args)}\n{stderr}"
            )
        return result.stdout

    # ==================================================================
    # Internal: drop-in construction
    # ==================================================================
    def _build_dropin(self, servers: list[str], settings: ProtocolSettings) -> str:
        """Build the [Resolve] drop-in contents.

        DoT: servers carrying '#hostname' mean the caller asked for
        DNS-over-TLS, so we write DNSOverTLS=yes, which systemd treats as
        fail-closed (an unencrypted fallback is never attempted). Plain
        IPs get 'opportunistic'.

        Protocol lines are written only when explicitly requested, so we
        never silently override resolved's defaults for unset flags.
        """
        dot_value = "yes" if any("#" in s for s in servers) else "opportunistic"

        lines = [
            DNSER_HEADER,
            "# Remove with: dnser unset  (or: dnser restore)",
            "[Resolve]",
            f"DNS={' '.join(servers)}",
            "Domains=~.",
            f"DNSOverTLS={dot_value}",
        ]
        if settings.dnssec:
            lines.append("DNSSEC=yes")
        if settings.no_llmnr:
            lines.append("LLMNR=no")
        if settings.no_mdns:
            lines.append("MulticastDNS=no")

        return "\n".join(lines) + "\n"

    def _restart_resolved(self) -> None:
        """Restart systemd-resolved so drop-in changes take effect."""
        self._run(["systemctl", "restart", "systemd-resolved"])

    # ==================================================================
    # Internal: protocol status extraction
    # ==================================================================
    def _read_protocol_state(self) -> dict[str, str]:
        """Parse `resolvectl status` for LLMNR/mDNS/DNSSEC/DoT global state.

        The 'Protocols:' line (systemd 250+) looks like:
          Protocols: -LLMNR -mDNS DNSOverTLS=opportunistic DNSSEC=no/unsupported

        A leading '-' means disabled, no prefix means enabled, key=value
        pairs are explicit. We normalize all three into a flat dict and
        take only the first (global) line — per-link ones come later.
        """
        protocols: dict[str, str] = {}
        try:
            output = self._run(["resolvectl", "status"])
        except BackendError:
            return protocols

        for raw in output.splitlines():
            stripped = raw.strip()
            if not stripped.startswith("Protocols:"):
                continue
            payload = stripped[len("Protocols:") :].strip()
            for token in payload.split():
                if "=" in token:
                    key, _, value = token.partition("=")
                    protocols[key] = value
                elif token.startswith("-"):
                    protocols[token[1:]] = "no"
                else:
                    protocols[token] = "yes"
            break
        return protocols


def validate_dropin(content: str) -> None:
    """Raise BackendError unless `content` is a plain [Resolve] drop-in.

    Applied to anything read back from a backup file before it is written
    into /etc as root.
    """
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            if line != "[Resolve]":
                raise BackendError(f"Refusing to restore unknown section: {line}")
            continue
        key = line.split("=", 1)[0].strip()
        if key not in _ALLOWED_RESOLVE_KEYS:
            raise BackendError(f"Refusing to restore unknown resolved key: {key}")
