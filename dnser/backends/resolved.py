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
    sudo_hint,
)
from dnser.providers import identify_provider


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

            if label.lower().startswith("link"):
                if "(" in label and ")" in label:
                    iface = label[label.index("(") + 1 : label.index(")")]
                else:
                    iface = label
                if iface == "lo":
                    continue
                state.per_interface[iface] = servers
            elif label.lower() == "global":
                if servers:
                    state.per_interface["(global)"] = servers

        if DROPIN_PATH.exists():
            state.notes.append(f"dnser drop-in active: {DROPIN_PATH}")

        state.protocols = self._read_protocol_state()
        return state

    # ------------------------------------------------------------------
    # describe_current_state
    # ------------------------------------------------------------------
    def describe_current_state(self) -> str:
        """Label for backup filename — describes what's in the snapshot."""
        if not DROPIN_PATH.exists():
            return "baseline"
        try:
            content = DROPIN_PATH.read_text(encoding="utf-8")
        except OSError:
            return "managed"

        if "Managed by dnser" not in content:
            return "external"

        for line in content.splitlines():
            line = line.strip()
            if line.startswith("DNS="):
                servers = line[4:].split()
                provider_key = identify_provider(servers)
                if provider_key:
                    return provider_key
                break
        return "managed"

    # ------------------------------------------------------------------
    # snapshot
    # ------------------------------------------------------------------
    def snapshot(self) -> BackupPayload:
        """Capture existing drop-in content (or None if absent).

        The drop-in file contains the entire state we manage (DNS +
        protocol settings), so a single file is enough to restore everything.
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
    ) -> None:
        """Write drop-in and restart resolved.

        All scopes are treated as global for this backend. `interface` is
        accepted for CLI parity but ignored. `protocols` fully supported.
        """
        if not servers:
            raise BackendError("set_dns called with empty server list")
        del interface  # resolved is inherently global; accept for CLI parity
        _ = scope

        settings = protocols or ProtocolSettings()
        content = self._build_dropin(servers, settings)
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
                    "This operation requires root privileges.\n"
                    f"  Re-run: {sudo_hint()}"
                )
            raise BackendError(
                f"Command failed ({result.returncode}): {' '.join(cmd)}\n{stderr}"
            )
        return result.stdout

    # ==================================================================
    # Internal: drop-in file management
    # ==================================================================
    def _build_dropin(self, servers: list[str], settings: ProtocolSettings) -> str:
        """Build the [Resolve] section contents for a drop-in file.

        DoT behavior:
          - If any server has '#hostname' syntax, DoT is required → 'yes'
            (or 'yes' + explicit strict if dot_strict).
          - dot_strict without any DoT servers is a config error caught upstream.
          - Otherwise 'opportunistic' (default resolved behavior).

        Protocol lines are only written when the user explicitly requested them,
        so we don't silently override resolved's defaults for flags left unset.
        """
        has_dot_servers = any("#" in s for s in servers)

        if settings.dot_strict:
            dot_value = "yes"  # strict = fail closed
        elif has_dot_servers:
            dot_value = "yes"  # DoT servers imply required DoT
        else:
            dot_value = "opportunistic"

        lines = [
            "# Managed by dnser — do not edit by hand.",
            "# Remove with: dnser restore",
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

    def _write_dropin(self, content: str) -> None:
        """Write the drop-in file. Uses sudo/tee if not writable directly."""
        try:
            DROPIN_PATH.parent.mkdir(parents=True, exist_ok=True)
            DROPIN_PATH.write_text(content, encoding="utf-8")
            return
        except (PermissionError, OSError):
            pass
        proc = subprocess.run(
            ["sudo", "--non-interactive", "tee", str(DROPIN_PATH)],
            input=content, capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            stderr = proc.stderr.strip() or "no error message"
            if "password is required" in stderr.lower():
                raise BackendError(
                    f"Writing {DROPIN_PATH} requires root.\n"
                    f"  Re-run: {sudo_hint()}"
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
        """Restart systemd-resolved so drop-in changes take effect."""
        try:
            self._run(["systemctl", "restart", "systemd-resolved"])
        except BackendError:
            self._run(["systemctl", "restart", "systemd-resolved"], sudo=True)

    # ==================================================================
    # Internal: protocol status extraction
    # ==================================================================
    def _read_protocol_state(self) -> dict[str, str]:
        """Parse `resolvectl status` for LLMNR/mDNS/DNSSEC/DoT global state.

        The 'Protocols:' line format (as of systemd 250+):
          Protocols: -LLMNR -mDNS DNSOverTLS=opportunistic DNSSEC=no/unsupported

        Leading '-' means disabled; no prefix means enabled. Key=value pairs
        are explicit. We normalize everything into a flat dict.
        """
        protocols: dict[str, str] = {}
        try:
            output = self._run(["resolvectl", "status"])
        except BackendError:
            return protocols

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped.startswith("Protocols:"):
                continue
            # Only take the first (global) match — per-link Protocols lines
            # come later and would overwrite.
            payload = stripped[len("Protocols:"):].strip()
            for token in payload.split():
                if "=" in token:
                    # e.g. 'DNSOverTLS=opportunistic'
                    key, _, value = token.partition("=")
                    protocols[key] = value
                elif token.startswith("-"):
                    # e.g. '-LLMNR' -> disabled
                    protocols[token[1:]] = "no"
                else:
                    # e.g. 'LLMNR' (no prefix) -> enabled
                    protocols[token] = "yes"
            break
        return protocols
