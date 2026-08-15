"""systemd-resolved backend.

Manages DNS by writing drop-in files under /etc/systemd/resolved.conf.d/
and using `resolvectl` for live queries. Persistent across reboots.

Why drop-ins instead of editing /etc/systemd/resolved.conf directly:
  - The main file often contains user or distro comments/settings we
    shouldn't clobber.
  - systemd merges all *.conf files in resolved.conf.d/ alphabetically,
    with later values winning. Our "00-" prefix ensures we're read first
    but overridable by any later file the user might add.
  - Removing our drop-in cleanly reverts to the pre-dnser state.

Scopes for this backend:
  - GLOBAL: write /etc/systemd/resolved.conf.d/00-dnser.conf (default,
            because resolved doesn't have "per-connection" the way NM does)
  - CURRENT / ALL: same as GLOBAL for now — resolved is inherently global.
                   We treat these scopes as aliases and warn.
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
    Scope,
)


# Drop-in path. "00-" so we load first among any user drop-ins.
DROPIN_PATH = Path("/etc/systemd/resolved.conf.d/00-dnser.conf")


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
            # `systemctl is-active` returns 0 if the service is running.
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
        state = DNSState(backend_name=self.display_name)

        # `resolvectl dns` produces one line per link:
        #   "Global: 9.9.9.9 149.112.112.112"
        #   "Link 3 (wlp2s0): 192.168.0.1"
        try:
            output = self._run(["resolvectl", "dns"])
        except BackendError as e:
            state.notes.append(f"Could not query resolved: {e}")
            return state

        for line in output.strip().splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            label, _, servers_raw = line.partition(":")
            label = label.strip()
            servers = servers_raw.strip().split()

            # Normalize labels: "Link 3 (wlp2s0)" -> "wlp2s0"; "Global" -> "global"
            if label.lower().startswith("link"):
                # Extract text inside parentheses
                if "(" in label and ")" in label:
                    iface = label[label.index("(") + 1 : label.index(")")]
                else:
                    iface = label
                if iface == "lo":
                    continue
                state.per_interface[iface] = servers
            elif label.lower() == "global":
                # Only show a "global" row if it actually has servers set.
                # An empty Global entry is the normal default state.
                if servers:
                    state.per_interface["(global)"] = servers

        # Note if our drop-in is active — user should know.
        if DROPIN_PATH.exists():
            state.notes.append(f"dnser drop-in active: {DROPIN_PATH}")

        # Also note DoT / DNSSEC status from the top of `resolvectl status`.
        state.notes.extend(self._protocol_notes())

        return state

    # ------------------------------------------------------------------
    # snapshot
    # ------------------------------------------------------------------
    def snapshot(self) -> BackupPayload:
        """Capture existing drop-in content (or None if absent)."""
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
    ) -> None:
        """Write drop-in and restart resolved.

        All scopes are treated as global for this backend (resolved has no
        per-connection notion). We accept the flags for CLI compatibility
        but the effect is the same. `interface` is currently ignored.
        """
        if not servers:
            raise BackendError("set_dns called with empty server list")
        # interface is intentionally ignored for the resolved backend —
        # accepted for CLI compatibility across backends.
        del interface

        # We don't error on non-GLOBAL scopes to keep the CLI backend-agnostic,
        # but callers should be aware they behave the same here.
        _ = scope

        content = self._build_dropin(servers)
        self._write_dropin(content)
        self._restart_resolved()

    # ------------------------------------------------------------------
    # restore_from
    # ------------------------------------------------------------------
    def restore_from(self, payload: BackupPayload) -> None:
        """Restore drop-in to its snapshot state (or remove it)."""
        if payload.backend_name != self.name:
            raise BackendError(
                f"Backup was taken with backend '{payload.backend_name}', "
                f"cannot restore with '{self.name}'"
            )
        original = payload.data.get("dropin_content")
        if original is None:
            self._remove_dropin()
        else:
            self._write_dropin(original)
        self._restart_resolved()

    # ==================================================================
    # Internal: subprocess helper
    # ==================================================================
    def _run(self, args: list[str], sudo: bool = False) -> str:
        cmd = (["sudo", "--non-interactive"] + args) if sudo else args
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
            )
        except subprocess.TimeoutExpired as e:
            raise BackendError(f"Command timed out: {' '.join(cmd)}") from e
        except OSError as e:
            raise BackendError(f"Failed to run {cmd[0]}: {e}") from e
        if result.returncode != 0:
            stderr = result.stderr.strip() or "no error message"
            if sudo and "password is required" in stderr.lower():
                raise BackendError(
                    "This operation requires root. Re-run with sudo."
                )
            raise BackendError(
                f"Command failed ({result.returncode}): {' '.join(cmd)}\n{stderr}"
            )
        return result.stdout

    # ==================================================================
    # Internal: drop-in file management
    # ==================================================================
    def _build_dropin(self, servers: list[str]) -> str:
        """Build the [Resolve] section contents for a drop-in file.

        We enable DoT (opportunistic → yes) when the server list contains
        entries with #hostname syntax, since providers that support DoT
        should always be used with TLS. Otherwise leave opportunistic.
        """
        has_dot = any("#" in s for s in servers)
        dot_line = "DNSOverTLS=yes" if has_dot else "DNSOverTLS=opportunistic"

        return (
            "# Managed by dnser — do not edit by hand.\n"
            "# Remove with: dnser restore\n"
            "[Resolve]\n"
            f"DNS={' '.join(servers)}\n"
            "Domains=~.\n"
            f"{dot_line}\n"
        )

    def _write_dropin(self, content: str) -> None:
        """Write the drop-in file. Uses sudo/tee if not writable directly."""
        try:
            DROPIN_PATH.parent.mkdir(parents=True, exist_ok=True)
            DROPIN_PATH.write_text(content, encoding="utf-8")
            return
        except (PermissionError, OSError):
            pass
        # Fallback: sudo tee
        proc = subprocess.run(
            ["sudo", "--non-interactive", "tee", str(DROPIN_PATH)],
            input=content, capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            stderr = proc.stderr.strip() or "no error message"
            if "password is required" in stderr.lower():
                raise BackendError(
                    f"Writing {DROPIN_PATH} requires root. Re-run with sudo."
                )
            raise BackendError(f"Failed to write drop-in: {stderr}")

    def _remove_dropin(self) -> None:
        if not DROPIN_PATH.exists():
            return
        try:
            DROPIN_PATH.unlink()
            return
        except PermissionError:
            pass
        proc = subprocess.run(
            ["sudo", "--non-interactive", "rm", "-f", str(DROPIN_PATH)],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            raise BackendError(
                f"Failed to remove {DROPIN_PATH}: {proc.stderr.strip()}"
            )

    def _restart_resolved(self) -> None:
        """Restart systemd-resolved so drop-in changes take effect.

        We need a full restart (not just reload) because drop-ins are only
        re-read on start-up. Reload only reloads runtime state, not config.
        """
        try:
            self._run(["systemctl", "restart", "systemd-resolved"])
        except BackendError:
            self._run(["systemctl", "restart", "systemd-resolved"], sudo=True)

    # ==================================================================
    # Internal: protocol status extraction
    # ==================================================================
    def _protocol_notes(self) -> list[str]:
        """Return short notes about DoT/DNSSEC status from resolvectl status."""
        notes: list[str] = []
        try:
            output = self._run(["resolvectl", "status"])
        except BackendError:
            return notes

        # Look for the Global "Protocols:" line, which lists the enabled
        # protocols in a compact form:
        #   Protocols: -LLMNR -mDNS DNSOverTLS=yes DNSSEC=no
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Protocols:") and "DNSOverTLS" in line:
                # Only take the first (global) match to keep notes short.
                notes.append(line)
                break
        return notes
