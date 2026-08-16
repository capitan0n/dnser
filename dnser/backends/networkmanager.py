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

Protocol hardening:
  - LLMNR / mDNS: supported via nmcli's per-connection settings
    (connection.llmnr, connection.mdns) with values 'no' / 'default'
  - DNSSEC / DoT-strict: NOT supported by NM (needs a resolver). We
    raise BackendError with a clear message pointing at systemd-resolved.
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


# Path where we write the global DNS override for NetworkManager.
# The "00-" prefix ensures it loads before other conf.d files.
GLOBAL_CONF_PATH = Path("/etc/NetworkManager/conf.d/00-dnser-global.conf")

# The four DNS fields plus the two protocol fields we snapshot per connection.
# We keep DNS and protocol fields together so a single restore covers both.
_NM_DNS_FIELDS = (
    "ipv4.dns", "ipv4.ignore-auto-dns",
    "ipv6.dns", "ipv6.ignore-auto-dns",
)
_NM_PROTOCOL_FIELDS = (
    "connection.llmnr",
    "connection.mdns",
)


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

        if GLOBAL_CONF_PATH.exists():
            state.notes.append(f"Global DNS override active: {GLOBAL_CONF_PATH}")

        state.protocols = self._read_protocol_state()
        return state

    # ------------------------------------------------------------------
    # describe_current_state
    # ------------------------------------------------------------------
    def describe_current_state(self) -> str:
        """Label for backup filename — describes what's in the snapshot.

        For NM we check the global override file first (highest impact),
        then fall back to inspecting the active connection's DNS.
        """
        if GLOBAL_CONF_PATH.exists():
            try:
                content = GLOBAL_CONF_PATH.read_text(encoding="utf-8")
            except OSError:
                return "managed"
            if "Managed by dnser" not in content:
                return "external"
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("servers="):
                    servers = line[8:].split(",")
                    provider_key = identify_provider([s.strip() for s in servers if s.strip()])
                    if provider_key:
                        return provider_key
                    break
            return "managed"

        try:
            active = self._active_connection_name()
            if active is None:
                return "baseline"
            fields = self._connection_fields(active, _NM_DNS_FIELDS)
            servers_str = fields.get("ipv4.dns", "").strip()
            if not servers_str:
                return "baseline"
            servers = servers_str.split()
            provider_key = identify_provider(servers)
            return provider_key or "managed"
        except BackendError:
            return "snapshot"

    # ------------------------------------------------------------------
    # snapshot
    # ------------------------------------------------------------------
    def snapshot(self) -> BackupPayload:
        """Capture per-connection DNS + protocol settings and global override.

        We save DNS fields and protocol fields together so restore reverts
        everything in one shot without needing to know which was changed.
        """
        per_connection: dict[str, dict[str, str]] = {}
        for name in self._all_connection_names():
            per_connection[name] = self._connection_fields(
                name, _NM_DNS_FIELDS + _NM_PROTOCOL_FIELDS
            )

        global_conf_content: str | None = None
        if GLOBAL_CONF_PATH.exists():
            try:
                global_conf_content = GLOBAL_CONF_PATH.read_text(encoding="utf-8")
            except OSError:
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
        protocols: ProtocolSettings | None = None,
    ) -> None:
        """Apply DNS according to scope. See base class for semantics."""
        if not servers:
            raise BackendError("set_dns called with empty server list")

        settings = protocols or ProtocolSettings()
        self._validate_supported(settings)

        if scope is Scope.GLOBAL:
            self._set_global(servers, settings)
        elif scope is Scope.ALL:
            for conn in self._all_connection_names():
                self._set_connection(conn, servers, settings)
            self._reactivate_current()
        elif scope is Scope.CURRENT:
            conn = self._connection_for_interface(interface) if interface else self._active_connection_name()
            if conn is None:
                raise BackendError(
                    "No active connection found. Use --all or --global, "
                    "or connect to a network first."
                )
            self._set_connection(conn, servers, settings)
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

        existing = set(self._all_connection_names())
        for conn, fields in payload.data.get("per_connection", {}).items():
            if conn not in existing:
                continue
            self._restore_connection_fields(conn, fields)

        original_global = payload.data.get("global_conf_content")
        if original_global is None:
            self._remove_global_conf()
        else:
            self._write_global_conf(original_global)

        self._reload_nm()
        self._reactivate_current()

    # ==================================================================
    # Internal: capability checks
    # ==================================================================
    def _validate_supported(self, settings: ProtocolSettings) -> None:
        """Reject protocol flags NM cannot honor, with a clear message."""
        unsupported = []
        if settings.dnssec:
            unsupported.append("--dnssec")
        if settings.dot_strict:
            unsupported.append("--dot-strict")
        if unsupported:
            raise BackendError(
                f"NetworkManager backend cannot apply: {', '.join(unsupported)}.\n"
                "  These require a resolver. Install/enable systemd-resolved\n"
                "  and configure NM to hand off DNS (dns=systemd-resolved),\n"
                "  then re-run the command."
            )

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
                    "This operation requires root privileges.\n"
                    f"  Re-run: {sudo_hint()}"
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
        """Return names of all saved connection profiles."""
        output = self._run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"])
        names: list[str] = []
        for line in output.strip().splitlines():
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

    def _connection_fields(self, connection: str, fields: tuple[str, ...]) -> dict[str, str]:
        """Read a set of fields from a connection profile."""
        output = self._run([
            "nmcli", "-t", "-f", ",".join(fields),
            "connection", "show", connection,
        ])
        result: dict[str, str] = {}
        for line in output.strip().splitlines():
            key, _, value = line.partition(":")
            result[key.strip()] = value.strip()
        return result

    # ==================================================================
    # Internal: protocol state read
    # ==================================================================
    def _read_protocol_state(self) -> dict[str, str]:
        """Report LLMNR/mDNS state as seen on the currently active connection.

        NM stores these per-connection. We report the active connection's
        values as the effective global state — matches user expectation
        that `dnser status` shows what's actually in force *right now*.

        NM cannot report DNSSEC / DoT (no resolver in NM itself), so
        those keys are omitted rather than reported as 'unknown'.
        """
        result: dict[str, str] = {}
        try:
            active = self._active_connection_name()
        except BackendError:
            return result
        if active is None:
            return result
        try:
            fields = self._connection_fields(active, _NM_PROTOCOL_FIELDS)
        except BackendError:
            return result

        # nmcli returns values as strings; 'no' / '--' means disabled/default.
        # We normalize: '--' → 'default', anything else stays verbatim.
        llmnr = fields.get("connection.llmnr", "").strip()
        mdns = fields.get("connection.mdns", "").strip()
        if llmnr and llmnr != "--":
            result["LLMNR"] = llmnr
        if mdns and mdns != "--":
            result["mDNS"] = mdns
        return result

    # ==================================================================
    # Internal: mutation
    # ==================================================================
    def _set_connection(
        self, connection: str, servers: list[str], settings: ProtocolSettings
    ) -> None:
        """Set DNS + protocol settings on a single saved connection profile.

        We set both ipv4.dns and ignore-auto-dns=yes so DHCP-provided
        servers don't sneak back in. IPv6 handled the same way.
        LLMNR/mDNS are toggled to 'no' only when the user asked; otherwise
        left untouched (NM will use its default).
        """
        v4 = [s for s in servers if ":" not in s]
        v6 = [s for s in servers if ":" in s]

        args = ["nmcli", "connection", "modify", connection]
        if v4:
            args += ["ipv4.dns", " ".join(v4), "ipv4.ignore-auto-dns", "yes"]
        if v6:
            args += ["ipv6.dns", " ".join(v6), "ipv6.ignore-auto-dns", "yes"]
        if settings.no_llmnr:
            args += ["connection.llmnr", "no"]
        if settings.no_mdns:
            args += ["connection.mdns", "no"]
        self._run(args)

    def _restore_connection_fields(self, connection: str, fields: dict[str, str]) -> None:
        """Restore DNS + protocol fields on a connection to backed-up values."""
        for key in _NM_DNS_FIELDS + _NM_PROTOCOL_FIELDS:
            value = fields.get(key, "")
            # nmcli accepts "" to clear a field
            self._run(["nmcli", "connection", "modify", connection, key, value])

    def _reactivate_connection(self, connection: str) -> None:
        """Bring a connection down and up so new DNS takes immediate effect."""
        try:
            self._run(["nmcli", "connection", "up", connection])
        except BackendError:
            pass

    def _reactivate_current(self) -> None:
        """Reactivate the currently active connection, if any."""
        current = self._active_connection_name()
        if current:
            self._reactivate_connection(current)

    def _set_global(self, servers: list[str], settings: ProtocolSettings) -> None:
        """Write /etc/NetworkManager/conf.d/00-dnser-global.conf.

        The [global-dns-domain-*] section forces DNS servers globally.
        LLMNR/mDNS get applied to all saved connections (NM has no
        global toggle for them) as a best-effort for --global scope.
        """
        content = (
            "# Managed by dnser — do not edit by hand.\n"
            "# Remove with: dnser restore\n"
            "[global-dns-domain-*]\n"
            f"servers={','.join(servers)}\n"
        )
        self._write_global_conf(content)

        # LLMNR/mDNS have no global equivalent in NM — apply per-connection
        # as best-effort so --global with --no-llmnr does what the user
        # expects even though the mechanism is different.
        if settings.no_llmnr or settings.no_mdns:
            for conn in self._all_connection_names():
                args = ["nmcli", "connection", "modify", conn]
                if settings.no_llmnr:
                    args += ["connection.llmnr", "no"]
                if settings.no_mdns:
                    args += ["connection.mdns", "no"]
                self._run(args)

        self._reload_nm()

    def _write_global_conf(self, content: str) -> None:
        """Write to the global conf path. Uses sudo if not writable directly."""
        try:
            GLOBAL_CONF_PATH.parent.mkdir(parents=True, exist_ok=True)
            GLOBAL_CONF_PATH.write_text(content, encoding="utf-8")
            return
        except (PermissionError, OSError):
            pass
        proc = subprocess.run(
            ["sudo", "--non-interactive", "tee", str(GLOBAL_CONF_PATH)],
            input=content, capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            stderr = proc.stderr.strip() or "no error message"
            if "password is required" in stderr.lower():
                raise BackendError(
                    f"Writing {GLOBAL_CONF_PATH} requires root.\n"
                    f"  Re-run: {sudo_hint()}"
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
                    f"Removing {GLOBAL_CONF_PATH} requires root.\n"
                    f"  Re-run: {sudo_hint()}"
                )
            raise BackendError(f"Failed to remove global config: {stderr}")

    def _reload_nm(self) -> None:
        """Ask NM to re-read its config files (needed after touching conf.d)."""
        try:
            self._run(["nmcli", "general", "reload"])
        except BackendError:
            self._run(["nmcli", "general", "reload"], sudo=True)
