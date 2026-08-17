"""NetworkManager backend — uses `nmcli` under the hood.

We call nmcli as a subprocess rather than the D-Bus API because it needs
zero extra Python dependencies, is portable across distros, and every
command we run can be copy-pasted into a shell to debug it. The cost is a
fork+exec per call, which is irrelevant for a CLI.

Connections are addressed by **UUID**, never by name: names are not
unique in NetworkManager, and nmcli's terse output escapes colons inside
them, which makes name-based parsing ambiguous. UUIDs have neither problem.

Scopes:
  - CURRENT: modify only the currently active connection profile
  - ALL:     modify every saved connection profile
  - GLOBAL:  write /etc/NetworkManager/conf.d/00-dnser-global.conf, whose
             [global-dns-domain-*] section overrides per-connection DNS
             for present and future connections alike

Protocol hardening:
  - LLMNR / mDNS: supported per connection (connection.llmnr, connection.mdns)
  - DNSSEC and DNS-over-TLS: NOT supported — NetworkManager has no resolver
    of its own. We raise BackendError pointing at systemd-resolved.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
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

# Where we write the global DNS override. "00-" loads before other conf.d files.
GLOBAL_CONF_PATH = Path("/etc/NetworkManager/conf.d/00-dnser-global.conf")

DNSER_HEADER = "# Managed by dnser — do not edit by hand."

# The DNS fields plus the protocol fields we snapshot per connection. Kept
# together so a single restore reverts both in one nmcli call.
_NM_DNS_FIELDS = (
    "ipv4.dns",
    "ipv4.ignore-auto-dns",
    "ipv6.dns",
    "ipv6.ignore-auto-dns",
)
_NM_PROTOCOL_FIELDS = (
    "connection.llmnr",
    "connection.mdns",
)
_NM_ALL_FIELDS = _NM_DNS_FIELDS + _NM_PROTOCOL_FIELDS

# Sections and keys we accept when restoring a backed-up global conf file.
# Backups live in a user-writable directory but are applied as root, so
# unvalidated content would let an unprivileged process dictate a
# root-owned NetworkManager config.
_ALLOWED_CONF_SECTIONS = ("main", "global-dns", "global-dns-domain-")
_ALLOWED_CONF_KEYS = frozenset({"servers", "options", "dns", "systemd-resolved", "rc-manager"})


@dataclass(frozen=True)
class _Connection:
    """A saved NetworkManager profile. `uuid` is the stable handle."""

    uuid: str
    name: str


def _unescape(value: str) -> str:
    """Undo nmcli terse-mode escaping of ':' and '\\'."""
    return value.replace("\\:", ":").replace("\\\\", "\\")


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
        state = DNSState()

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
        """Label for the backup filename — describes what's being snapshotted.

        We check the global override first (highest impact), then fall
        back to the active connection's DNS.
        """
        if GLOBAL_CONF_PATH.exists():
            try:
                content = GLOBAL_CONF_PATH.read_text(encoding="utf-8")
            except OSError:
                return "managed"
            if "Managed by dnser" not in content:
                return "external"
            for raw in content.splitlines():
                line = raw.strip()
                if line.startswith("servers="):
                    servers = [s.strip() for s in line[len("servers=") :].split(",")]
                    provider_key = identify_provider([s for s in servers if s])
                    if provider_key:
                        return provider_key
                    break
            return "managed"

        try:
            active = self._active_connection()
            if active is None:
                return "baseline"
            fields = self._connection_fields(active, _NM_DNS_FIELDS)
            servers_str = fields.get("ipv4.dns", "").strip()
            if not servers_str:
                return "baseline"
            servers = [s.strip() for s in servers_str.replace(",", " ").split()]
            return identify_provider(servers) or "managed"
        except BackendError:
            return "snapshot"

    # ------------------------------------------------------------------
    # snapshot
    # ------------------------------------------------------------------
    def snapshot(self) -> BackupPayload:
        """Capture per-connection DNS + protocol fields and the global override.

        Keyed by connection UUID so restore can never hit the wrong profile
        when two of them share a display name.
        """
        per_connection: dict[str, dict[str, str]] = {}
        names: dict[str, str] = {}
        for conn in self._connections():
            per_connection[conn.uuid] = self._connection_fields(conn, _NM_ALL_FIELDS)
            names[conn.uuid] = conn.name

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
                "connection_names": names,  # for human-readable diagnostics only
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
        fallback: list[str] | None = None,
        dry_run: bool = False,
    ) -> tuple[Scope, list[str]]:
        """Apply DNS according to scope. See the base class for semantics.

        NetworkManager has no separate FallbackDNS concept: it hands the
        resolver an ordered server list and later entries are already tried
        only when earlier ones fail. So fallback servers are appended after
        the primaries, preserving primary-first order within each family.
        """
        if not servers:
            raise BackendError("set_dns called with empty server list")

        settings = protocols or ProtocolSettings()
        # Fallback IPs go through the same capability gate as primaries.
        combined = servers + list(fallback or [])
        self._validate_supported(combined, settings)

        conf_content: str | None = None
        commands: list[list[str]] = []
        reactivate: _Connection | None = None

        if scope is Scope.GLOBAL:
            conf_content = self._global_conf_content(combined)
            # NM has no global LLMNR/mDNS switch, so --global applies those
            # per connection as a best-effort equivalent.
            if settings.no_llmnr or settings.no_mdns:
                for conn in self._connections():
                    commands.append(self._protocol_args(conn, settings))
            commands.append(["nmcli", "general", "reload"])
            reactivate = self._active_connection()

        elif scope is Scope.ALL:
            conns = self._connections()
            if not conns:
                raise BackendError("No saved connection profiles to modify.")
            commands = [self._modify_args(c, combined, settings) for c in conns]
            reactivate = self._active_connection()

        elif scope is Scope.CURRENT:
            conn = (
                self._connection_for_interface(interface)
                if interface
                else self._active_connection()
            )
            if conn is None:
                where = f"interface '{interface}'" if interface else "any interface"
                raise BackendError(
                    f"No active connection found on {where}.\n"
                    "  Use --all or --global, or connect to a network first."
                )
            commands = [self._modify_args(conn, combined, settings)]
            reactivate = conn

        else:  # pragma: no cover - Scope is exhaustive
            raise BackendError(f"Unknown scope: {scope}")

        actions: list[str] = []
        if conf_content is not None:
            actions.append(f"write {GLOBAL_CONF_PATH}")
            actions += [f"  | {line}" for line in conf_content.splitlines()]
        actions += [f"run: {' '.join(cmd)}" for cmd in commands]
        if reactivate is not None:
            actions.append(f"run: nmcli connection up {reactivate.uuid}  # {reactivate.name}")

        if dry_run:
            return scope, actions

        if conf_content is not None:
            write_system_file(GLOBAL_CONF_PATH, conf_content)
        self._run_all(commands)
        if reactivate is not None:
            self._reactivate(reactivate)

        return scope, actions

    # ------------------------------------------------------------------
    # unset
    # ------------------------------------------------------------------
    def unset(self, dry_run: bool = False) -> list[str]:
        """Remove the global override and reset the fields dnser manages.

        Every field dnser can touch is set back to the empty value, which
        nmcli interprets as "revert to the NetworkManager default" — DNS
        goes back to whatever DHCP hands out.
        """
        conns = self._connections()
        commands = [
            ["nmcli", "connection", "modify", c.uuid]
            + [item for field in _NM_ALL_FIELDS for item in (field, "")]
            for c in conns
        ]
        commands.append(["nmcli", "general", "reload"])
        reactivate = self._active_connection()

        actions: list[str] = []
        if GLOBAL_CONF_PATH.exists():
            actions.append(f"remove {GLOBAL_CONF_PATH}")
        actions += [f"run: {' '.join(cmd)}" for cmd in commands]
        if reactivate is not None:
            actions.append(f"run: nmcli connection up {reactivate.uuid}  # {reactivate.name}")

        if not dry_run:
            remove_system_file(GLOBAL_CONF_PATH)
            self._run_all(commands)
            if reactivate is not None:
                self._reactivate(reactivate)

        return actions

    # ------------------------------------------------------------------
    # restore_from
    # ------------------------------------------------------------------
    def restore_from(self, payload: BackupPayload) -> None:
        """Reverse a previous change using the given snapshot."""
        if payload.backend_name != self.name:
            raise BackendError(
                f"Backup was taken with backend '{payload.backend_name}', "
                f"cannot restore with '{self.name}'"
            )

        per_connection = payload.data.get("per_connection") or {}
        if not isinstance(per_connection, dict):
            raise BackendError("Corrupt backup: per_connection is not an object")

        existing = {c.uuid: c for c in self._connections()}
        commands = [
            self._restore_args(existing[uuid], fields)
            for uuid, fields in per_connection.items()
            if uuid in existing
        ]

        original_global = payload.data.get("global_conf_content")
        if original_global is not None:
            if not isinstance(original_global, str):
                raise BackendError("Corrupt backup: global_conf_content is not text")
            validate_global_conf(original_global)

        if original_global is None:
            remove_system_file(GLOBAL_CONF_PATH)
        else:
            write_system_file(GLOBAL_CONF_PATH, original_global)

        commands.append(["nmcli", "general", "reload"])
        self._run_all(commands)

        current = self._active_connection()
        if current is not None:
            self._reactivate(current)

    # ==================================================================
    # Internal: capability checks
    # ==================================================================
    def _validate_supported(self, servers: list[str], settings: ProtocolSettings) -> None:
        """Reject anything NetworkManager cannot honor, with a clear message."""
        if any("#" in s for s in servers):
            raise BackendError(
                "NetworkManager cannot do DNS-over-TLS — it has no resolver.\n"
                "  Enable systemd-resolved, point NetworkManager at it\n"
                "  (dns=systemd-resolved in NetworkManager.conf), then re-run."
            )
        if settings.dnssec:
            raise BackendError(
                "NetworkManager cannot apply --dnssec — it has no resolver.\n"
                "  Enable systemd-resolved, point NetworkManager at it\n"
                "  (dns=systemd-resolved in NetworkManager.conf), then re-run."
            )
        if settings.no_cache:
            raise BackendError(
                "NetworkManager cannot apply --no-cache — it has no resolver.\n"
                "  Enable systemd-resolved, point NetworkManager at it\n"
                "  (dns=systemd-resolved in NetworkManager.conf), then re-run."
            )

    # ==================================================================
    # Internal: subprocess wrapper
    # ==================================================================
    def _run(self, args: list[str]) -> str:
        """Run a command and return stdout. Raise BackendError on failure."""
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

    def _run_all(self, commands: list[list[str]]) -> None:
        """Run every command, then report all failures together.

        Stopping at the first error would leave the remaining profiles
        untouched *and* hide how many others also failed. We attempt them
        all so the reported state matches reality; the caller still has
        the pre-change snapshot to fall back on.
        """
        failures: list[str] = []
        for cmd in commands:
            try:
                self._run(cmd)
            except BackendError as exc:
                failures.append(str(exc))
        if failures:
            raise BackendError(
                f"{len(failures)} of {len(commands)} nmcli commands failed:\n"
                + "\n".join(f"  - {f}" for f in failures)
                + "\n  Some profiles may be partially modified — "
                "run `dnser restore` to revert."
            )

    # ==================================================================
    # Internal: device / connection queries
    # ==================================================================
    def _active_devices(self) -> list[str]:
        """Return names of currently connected devices (excluding loopback)."""
        output = self._run(["nmcli", "-t", "-f", "DEVICE,STATE", "device"])
        devices: list[str] = []
        for line in output.strip().splitlines():
            device, sep, state = line.partition(":")
            if not sep or device == "lo":
                continue
            if state == "connected":
                devices.append(device)
        return devices

    def _dns_for_device(self, device: str) -> list[str]:
        """Return DNS servers currently in use on <device>."""
        try:
            output = self._run(
                ["nmcli", "-t", "-f", "IP4.DNS,IP6.DNS", "device", "show", device]
            )
        except BackendError:
            return []
        servers: list[str] = []
        for line in output.strip().splitlines():
            _, sep, value = line.partition(":")
            if not sep:
                continue
            value = value.strip()
            if value:
                servers.append(value)
        return servers

    def _connections(self) -> list[_Connection]:
        """Return every saved, non-loopback profile as (uuid, name)."""
        output = self._run(["nmcli", "-t", "-f", "UUID,NAME,TYPE", "connection", "show"])
        return self._parse_connections(output, skip_types={"loopback"})

    def _active_connections(self) -> list[tuple[_Connection, str]]:
        """Return active (uuid, name) profiles paired with their device."""
        output = self._run(
            ["nmcli", "-t", "-f", "UUID,NAME,DEVICE", "connection", "show", "--active"]
        )
        result: list[tuple[_Connection, str]] = []
        for line in output.strip().splitlines():
            uuid, sep, rest = line.partition(":")
            if not sep:
                continue
            name, sep2, device = rest.rpartition(":")
            if not sep2:
                continue
            if device in ("lo", ""):
                continue
            result.append((_Connection(uuid=uuid, name=_unescape(name)), device))
        return result

    def _active_connection(self) -> _Connection | None:
        """Return the currently active non-loopback connection, if any."""
        active = self._active_connections()
        return active[0][0] if active else None

    def _connection_for_interface(self, interface: str) -> _Connection | None:
        """Return the active connection bound to <interface>."""
        for conn, device in self._active_connections():
            if device == interface:
                return conn
        return None

    @staticmethod
    def _parse_connections(output: str, skip_types: set[str]) -> list[_Connection]:
        """Parse `nmcli -t -f UUID,NAME,TYPE connection show` output.

        The UUID never contains ':' and neither does the type, so the
        first and last colons are unambiguous delimiters even when the
        name in between holds escaped colons.
        """
        connections: list[_Connection] = []
        for line in output.strip().splitlines():
            uuid, sep, rest = line.partition(":")
            if not sep:
                continue
            name, sep2, conn_type = rest.rpartition(":")
            if not sep2 or conn_type in skip_types:
                continue
            connections.append(_Connection(uuid=uuid, name=_unescape(name)))
        return connections

    def _connection_fields(self, conn: _Connection, fields: tuple[str, ...]) -> dict[str, str]:
        """Read a set of fields from a connection profile."""
        output = self._run(
            ["nmcli", "-t", "-f", ",".join(fields), "connection", "show", conn.uuid]
        )
        result: dict[str, str] = {}
        for line in output.strip().splitlines():
            key, sep, value = line.partition(":")
            if not sep:
                continue
            result[key.strip()] = value.strip()
        return result

    # ==================================================================
    # Internal: protocol state read
    # ==================================================================
    def _read_protocol_state(self) -> dict[str, str]:
        """Report LLMNR/mDNS as configured on the active connection.

        NetworkManager stores these per connection; the active one is what
        is actually in force right now, which is what `dnser status` claims
        to show. NM cannot report DNSSEC or DoT (it has no resolver), so
        those keys are omitted rather than reported as 'unknown'.
        """
        result: dict[str, str] = {}
        try:
            active = self._active_connection()
            if active is None:
                return result
            fields = self._connection_fields(active, _NM_PROTOCOL_FIELDS)
        except BackendError:
            return result

        llmnr = fields.get("connection.llmnr", "").strip()
        mdns = fields.get("connection.mdns", "").strip()
        if llmnr and llmnr != "--":
            result["LLMNR"] = llmnr
        if mdns and mdns != "--":
            result["mDNS"] = mdns
        return result

    # ==================================================================
    # Internal: command construction
    # ==================================================================
    def _modify_args(
        self, conn: _Connection, servers: list[str], settings: ProtocolSettings
    ) -> list[str]:
        """Build one nmcli call setting DNS + protocol fields on a profile.

        ignore-auto-dns is set alongside each family we configure, so
        DHCP-provided servers can't sneak back in. Values are
        comma-separated to match what nmcli reads back, keeping set and
        restore symmetric.
        """
        v4 = [s for s in servers if ":" not in s]
        v6 = [s for s in servers if ":" in s]

        args = ["nmcli", "connection", "modify", conn.uuid]
        if v4:
            args += ["ipv4.dns", ",".join(v4), "ipv4.ignore-auto-dns", "yes"]
        if v6:
            args += ["ipv6.dns", ",".join(v6), "ipv6.ignore-auto-dns", "yes"]
        if settings.no_llmnr:
            args += ["connection.llmnr", "no"]
        if settings.no_mdns:
            args += ["connection.mdns", "no"]
        return args

    def _protocol_args(self, conn: _Connection, settings: ProtocolSettings) -> list[str]:
        """Build an nmcli call setting only the protocol fields."""
        args = ["nmcli", "connection", "modify", conn.uuid]
        if settings.no_llmnr:
            args += ["connection.llmnr", "no"]
        if settings.no_mdns:
            args += ["connection.mdns", "no"]
        return args

    def _restore_args(self, conn: _Connection, fields: dict[str, str]) -> list[str]:
        """Build one nmcli call restoring every managed field at once."""
        args = ["nmcli", "connection", "modify", conn.uuid]
        for key in _NM_ALL_FIELDS:
            # nmcli treats "" as "reset this property to its default".
            args += [key, str(fields.get(key, ""))]
        return args

    def _global_conf_content(self, servers: list[str]) -> str:
        """Build the [global-dns-domain-*] override file."""
        return (
            f"{DNSER_HEADER}\n"
            "# Remove with: dnser unset  (or: dnser restore)\n"
            "[global-dns-domain-*]\n"
            f"servers={','.join(servers)}\n"
        )

    def _reactivate(self, conn: _Connection) -> None:
        """Bring a connection up so new DNS takes effect immediately.

        Best-effort: a profile can legitimately fail to come up (out of
        range, cable unplugged) and that must not fail the whole command,
        since the configuration itself was already applied.
        """
        try:
            self._run(["nmcli", "connection", "up", conn.uuid])
        except BackendError:
            pass


def validate_global_conf(content: str) -> None:
    """Raise BackendError unless `content` is a plain NM DNS override file.

    Applied to anything read back from a backup before it is written into
    /etc as root.
    """
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line.strip("[]")
            if not any(section.startswith(allowed) for allowed in _ALLOWED_CONF_SECTIONS):
                raise BackendError(f"Refusing to restore unknown section: {line}")
            continue
        key = line.split("=", 1)[0].strip()
        if key not in _ALLOWED_CONF_KEYS:
            raise BackendError(
                f"Refusing to restore unknown NetworkManager key: {key}\n"
                "  Inspect the backup file and apply it by hand if it is genuine."
            )
