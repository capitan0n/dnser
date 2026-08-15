"""NetworkManager backend — uses `nmcli` under the hood.

We call nmcli as a subprocess (not the D-Bus API) because:
  - Zero extra Python deps
  - Portable across distros
  - Easier to debug (you can copy-paste the command and run it manually)

Trade-off: slightly slower (fork+exec per call). Fine for a CLI tool.

Scopes:
  - CURRENT: modify only the currently active connection profile
  - ALL:     modify every saved connection profile
  - GLOBAL:  write /etc/NetworkManager/conf.d/00-dnser-global.conf which
             overrides all per-connection DNS via NM global-dns-domain-*
             (present and future connections included)
"""

from __future__ import annotations

import os
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


# Path where we write the global DNS override for NetworkManager.
# The "00-" prefix ensures it loads before other conf.d files.
GLOBAL_CONF_PATH = Path("/etc/NetworkManager/conf.d/00-dnser-global.conf")


class NetworkManagerBackend(Backend):
    name = "networkmanager"
    display_name = "NetworkManager (nmcli)"

    # ------------------------------------------------------------------
    # is_available
    # ------------------------------------------------------------------
    def is_available(self) -> bool:
        """Check that nmcli is installed AND NetworkManager is running."""
        if shutil.which("nmcli") is None:
            return False
        try:
            result = subprocess.run(
                ["nmcli", "general", "status"],
                capture_output=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, OSError):
            return False
        return result.returncode == 0

    # ------------------------------------------------------------------
    # get_current
    # ------------------------------------------------------------------
    def get_current(self) -> DNSState:
        """Return current DNS state per active device."""
        state = DNSState(backend_name=self.display_name)

        devices = self._active_devices()
        if not devices:
            state.notes.append("No active network devices found.")
        else:
            for device in devices:
                state.per_interface[device] = self._dns_for_device(device)

        # Report if a global override is in effect — the user should know
        # because it explains why per-connection changes may not take effect.
        if GLOBAL_CONF_PATH.exists():
            state.notes.append(
                f"Global DNS override active: {GLOBAL_CONF_PATH}"
            )

        return state

    # ------------------------------------------------------------------
    # snapshot
    # ------------------------------------------------------------------
    def snapshot(self) -> BackupPayload:
        """Capture per-connection DNS settings and any existing global override.

        We save the 4 fields NM uses for DNS on each connection:
          - ipv4.dns, ipv4.ignore-auto-dns
          - ipv6.dns, ipv6.ignore-auto-dns
        This is enough to fully restore original behavior (DHCP or manual).
        """
        per_connection: dict[str, dict[str, str]] = {}
        for name in self._all_connection_names():
            per_connection[name] = self._connection_dns_fields(name)

        global_conf_content: str | None = None
        if GLOBAL_CONF_PATH.exists():
            try:
                global_conf_content = GLOBAL_CONF_PATH.read_text(encoding="utf-8")
            except OSError:
                # Unreadable (perms) — record that it existed but content lost
                global_conf_content = ""

        return BackupPayload(
            backend_name=self.name,
            data={
                "per_connection": per_connection,
                "global_conf_content": global_conf_content,
            },
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
        """Apply DNS according to scope. See base class for semantics."""
        if not servers:
            raise BackendError("set_dns called with empty server list")

        if scope is Scope.GLOBAL:
            self._set_global(servers)
        elif scope is Scope.ALL:
            for conn in self._all_connection_names():
                self._set_connection(conn, servers)
            self._reactivate_current()
        elif scope is Scope.CURRENT:
            conn = self._connection_for_interface(interface) if interface else self._active_connection_name()
            if conn is None:
                raise BackendError(
                    "No active connection found. Use --all or --global, "
                    "or connect to a network first."
                )
            self._set_connection(conn, servers)
            self._reactivate_connection(conn)
        else:
            raise BackendError(f"Unknown scope: {scope}")

    # ------------------------------------------------------------------
    # restore_from
    # ------------------------------------------------------------------
    def restore_from(self, payload: BackupPayload) -> None:
        """Reverse a set_dns using the given snapshot."""
        if payload.backend_name != self.name:
            raise BackendError(
                f"Backup was taken with backend '{payload.backend_name}', "
                f"cannot restore with '{self.name}'"
            )

        # 1. Restore per-connection settings for every connection still present.
        existing = set(self._all_connection_names())
        for conn, fields in payload.data.get("per_connection", {}).items():
            if conn not in existing:
                # Connection was deleted since backup — skip silently.
                continue
            self._restore_connection_fields(conn, fields)

        # 2. Restore or remove the global override.
        original_global = payload.data.get("global_conf_content")
        if original_global is None:
            # There was no global override at backup time — remove ours.
            self._remove_global_conf()
        else:
            # There was one — write it back verbatim.
            self._write_global_conf(original_global)

        # 3. Reload NM to pick up global config changes, and reactivate
        # the current connection so per-conn DNS changes take effect.
        self._reload_nm()
        self._reactivate_current()

    # ==================================================================
    # Internal: subprocess wrapper
    # ==================================================================
    def _run(self, args: list[str], sudo: bool = False) -> str:
        """Run a command and return stdout. Raise BackendError on failure."""
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
                    "This operation requires root privileges. "
                    "Re-run with sudo, or configure passwordless sudo for nmcli."
                )
            raise BackendError(
                f"Command failed ({result.returncode}): {' '.join(cmd)}\n{stderr}"
            )
        return result.stdout

    # ==================================================================
    # Internal: device/connection queries
    # ==================================================================
    def _active_devices(self) -> list[str]:
        """Return names of currently connected devices (excl. loopback)."""
        output = self._run(["nmcli", "-t", "-f", "DEVICE,STATE", "device"])
        devices: list[str] = []
        for line in output.strip().splitlines():
            parts = line.split(":", 1)
            if len(parts) != 2:
                continue
            device, state = parts
            if device == "lo":
                continue
            if state == "connected":
                devices.append(device)
        return devices

    def _dns_for_device(self, device: str) -> list[str]:
        """Return DNS servers currently in use on <device>."""
        try:
            output = self._run([
                "nmcli", "-t", "-f", "IP4.DNS,IP6.DNS",
                "device", "show", device,
            ])
        except BackendError:
            return []
        servers: list[str] = []
        for line in output.strip().splitlines():
            if ":" not in line:
                continue
            _, _, value = line.partition(":")
            value = value.strip()
            if value:
                servers.append(value)
        return servers

    def _all_connection_names(self) -> list[str]:
        """Return names of all saved connection profiles.

        We only touch real network connections — skip loopback and
        anything that isn't a normal profile.
        """
        output = self._run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"])
        names: list[str] = []
        for line in output.strip().splitlines():
            # A connection name can contain colons, so split from the right (rsplit)
            # to correctly extract just the TYPE field.
            parts = line.rsplit(":", 1)
            if len(parts) != 2:
                continue
            name, conn_type = parts
            if conn_type == "loopback":
                continue
            names.append(name)
        return names

    def _active_connection_name(self) -> str | None:
        """Return the name of the currently active (non-loopback) connection."""
        output = self._run([
            "nmcli", "-t", "-f", "NAME,TYPE,DEVICE",
            "connection", "show", "--active",
        ])
        for line in output.strip().splitlines():
            parts = line.rsplit(":", 2)
            if len(parts) != 3:
                continue
            name, conn_type, device = parts
            if conn_type == "loopback" or device == "lo":
                continue
            return name
        return None

    def _connection_for_interface(self, interface: str) -> str | None:
        """Return the active connection name bound to <interface>."""
        output = self._run([
            "nmcli", "-t", "-f", "NAME,DEVICE",
            "connection", "show", "--active",
        ])
        for line in output.strip().splitlines():
            parts = line.rsplit(":", 1)
            if len(parts) != 2:
                continue
            name, device = parts
            if device == interface:
                return name
        return None

    def _connection_dns_fields(self, connection: str) -> dict[str, str]:
        """Read the 4 DNS-relevant fields from a connection profile."""
        fields = ["ipv4.dns", "ipv4.ignore-auto-dns",
                  "ipv6.dns", "ipv6.ignore-auto-dns"]
        output = self._run([
            "nmcli", "-t", "-f", ",".join(fields),
            "connection", "show", connection,
        ])
        result: dict[str, str] = {}
        for line in output.strip().splitlines():
            # Format: "ipv4.dns:1.1.1.1 9.9.9.9" (space-separated values)
            key, _, value = line.partition(":")
            result[key.strip()] = value.strip()
        return result

    # ==================================================================
    # Internal: mutation
    # ==================================================================
    def _set_connection(self, connection: str, servers: list[str]) -> None:
        """Set DNS on a single saved connection profile.

        We set both ipv4.dns and ignore-auto-dns=yes so DHCP-provided
        servers don't sneak back in. IPv6 servers are handled by NM
        automatically if the user's providers.json lists them.
        """
        # Separate v4 and v6 by presence of ':'
        v4 = [s for s in servers if ":" not in s]
        v6 = [s for s in servers if ":" in s]

        args = ["nmcli", "connection", "modify", connection]
        if v4:
            args += ["ipv4.dns", " ".join(v4), "ipv4.ignore-auto-dns", "yes"]
        if v6:
            args += ["ipv6.dns", " ".join(v6), "ipv6.ignore-auto-dns", "yes"]
        self._run(args)

    def _restore_connection_fields(self, connection: str, fields: dict[str, str]) -> None:
        """Restore the 4 DNS fields on a connection to their backed-up values.

        Empty string means "not set" for nmcli — use empty quotes.
        """
        for key in ("ipv4.dns", "ipv4.ignore-auto-dns",
                    "ipv6.dns", "ipv6.ignore-auto-dns"):
            value = fields.get(key, "")
            # nmcli accepts "" to clear a field
            self._run(["nmcli", "connection", "modify", connection, key, value])

    def _reactivate_connection(self, connection: str) -> None:
        """Bring a connection down and up so new DNS takes immediate effect."""
        try:
            self._run(["nmcli", "connection", "up", connection])
        except BackendError:
            # Reactivation is a nice-to-have; if it fails (e.g. wifi not in
            # range), the config is still saved and will apply next connect.
            pass

    def _reactivate_current(self) -> None:
        """Reactivate the currently active connection, if any."""
        current = self._active_connection_name()
        if current:
            self._reactivate_connection(current)

    def _set_global(self, servers: list[str]) -> None:
        """Write /etc/NetworkManager/conf.d/00-dnser-global.conf.

        Requires root. The wildcard [global-dns-domain-*] section makes
        NM use these servers for every DNS query, overriding whatever
        each connection has configured.
        """
        content = (
            "# Managed by dnser — do not edit by hand.\n"
            "# Remove with: dnser restore\n"
            "[global-dns-domain-*]\n"
            f"servers={','.join(servers)}\n"
        )
        self._write_global_conf(content)
        self._reload_nm()

    def _write_global_conf(self, content: str) -> None:
        """Write to the global conf path. Uses sudo if not writable directly."""
        try:
            # Fast path: running as root, or the file is world-writable (unlikely).
            GLOBAL_CONF_PATH.parent.mkdir(parents=True, exist_ok=True)
            GLOBAL_CONF_PATH.write_text(content, encoding="utf-8")
            return
        except (PermissionError, OSError):
            pass
        # Slow path: write to a temp file we own, then sudo-move it into place.
        # tee is the simplest way to write a root-owned file via sudo.
        proc = subprocess.run(
            ["sudo", "--non-interactive", "tee", str(GLOBAL_CONF_PATH)],
            input=content, capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            stderr = proc.stderr.strip() or "no error message"
            if "password is required" in stderr.lower():
                raise BackendError(
                    f"Writing {GLOBAL_CONF_PATH} requires root. "
                    "Re-run with sudo."
                )
            raise BackendError(f"Failed to write global config: {stderr}")

    def _remove_global_conf(self) -> None:
        """Delete the global override file if it exists."""
        if not GLOBAL_CONF_PATH.exists():
            return
        try:
            GLOBAL_CONF_PATH.unlink()
            return
        except PermissionError:
            pass
        proc = subprocess.run(
            ["sudo", "--non-interactive", "rm", "-f", str(GLOBAL_CONF_PATH)],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            stderr = proc.stderr.strip() or "no error message"
            if "password is required" in stderr.lower():
                raise BackendError(
                    f"Removing {GLOBAL_CONF_PATH} requires root. "
                    "Re-run with sudo."
                )
            raise BackendError(f"Failed to remove global config: {stderr}")

    def _reload_nm(self) -> None:
        """Ask NM to re-read its config files (needed after touching conf.d)."""
        # `nmcli general reload` picks up conf.d changes without a full restart.
        # Doesn't require sudo on most systems if user is authenticated to NM.
        try:
            self._run(["nmcli", "general", "reload"])
        except BackendError:
            # Fall back to sudo — some systems (locked-down polkit) need it.
            self._run(["nmcli", "general", "reload"], sudo=True)
