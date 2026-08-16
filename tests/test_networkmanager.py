"""Unit tests for NetworkManagerBackend.

subprocess.run is mocked throughout, so no test touches the real system.
Each test queues the exact nmcli outputs the code should ask for; an
unexpected extra call fails the test rather than silently passing.
"""

from __future__ import annotations

import subprocess

import pytest

from dnser.backends.base import BackendError, BackupPayload, ProtocolSettings, Scope
from dnser.backends.networkmanager import NetworkManagerBackend, validate_global_conf
from tests.conftest import completed

# `nmcli -t -f UUID,NAME,TYPE connection show`
CONNECTIONS = "u-home:Home WiFi:802-11-wireless\nu-lo:lo:loopback\n"
# `nmcli -t -f UUID,NAME,DEVICE connection show --active`
ACTIVE = "u-home:Home WiFi:wlp2s0\nu-lo:lo:lo\n"
NO_ACTIVE = "u-lo:lo:lo\n"
FIELDS = (
    "ipv4.dns:9.9.9.9\n"
    "ipv4.ignore-auto-dns:yes\n"
    "ipv6.dns:\n"
    "ipv6.ignore-auto-dns:no\n"
    "connection.llmnr:--\n"
    "connection.mdns:--\n"
)


@pytest.fixture
def global_conf(tmp_path, monkeypatch):
    """Point GLOBAL_CONF_PATH at a temp file and return it (not created)."""
    path = tmp_path / "00-dnser-global.conf"
    monkeypatch.setattr("dnser.backends.networkmanager.GLOBAL_CONF_PATH", path)
    return path


# ----------------------------------------------------------------------
# is_available
# ----------------------------------------------------------------------

class TestIsAvailable:
    def test_false_if_nmcli_missing(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: None)
        assert NetworkManagerBackend().is_available() is False

    def test_true_when_nmcli_present_and_service_up(self, monkeypatch, any_run):
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmcli")
        assert NetworkManagerBackend().is_available() is True

    def test_false_when_service_down(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmcli")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed(returncode=1))
        assert NetworkManagerBackend().is_available() is False

    def test_false_on_timeout(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmcli")

        def raise_timeout(*a, **kw):
            raise subprocess.TimeoutExpired(cmd="nmcli", timeout=5)

        monkeypatch.setattr(subprocess, "run", raise_timeout)
        assert NetworkManagerBackend().is_available() is False


# ----------------------------------------------------------------------
# Connection parsing
# ----------------------------------------------------------------------

class TestConnectionParsing:
    def test_uuid_and_name_are_split_correctly(self):
        conns = NetworkManagerBackend._parse_connections(CONNECTIONS, skip_types={"loopback"})
        assert [(c.uuid, c.name) for c in conns] == [("u-home", "Home WiFi")]

    def test_escaped_colons_in_names_are_unescaped(self):
        """nmcli terse mode escapes ':' inside names as '\\:'."""
        output = "u-1:Cafe\\: Free WiFi:802-11-wireless\n"
        conns = NetworkManagerBackend._parse_connections(output, skip_types=set())
        assert conns[0].name == "Cafe: Free WiFi"
        assert conns[0].uuid == "u-1"

    def test_duplicate_names_stay_distinct(self):
        """NetworkManager allows two profiles with the same name."""
        output = "u-1:Home:802-11-wireless\nu-2:Home:802-11-wireless\n"
        conns = NetworkManagerBackend._parse_connections(output, skip_types=set())
        assert [c.uuid for c in conns] == ["u-1", "u-2"]


# ----------------------------------------------------------------------
# get_current
# ----------------------------------------------------------------------

class TestGetCurrent:
    def test_parses_single_connected_device(self, global_conf, sequencer):
        sequencer(
            [
                "wlp2s0:connected\nlo:unmanaged\nenp3s0:disconnected\n",
                "IP4.DNS[1]:9.9.9.9\nIP4.DNS[2]:149.112.112.112\nIP6.DNS:\n",
                ACTIVE,
                "connection.llmnr:--\nconnection.mdns:--\n",
            ]
        )
        state = NetworkManagerBackend().get_current()
        assert state.per_interface == {"wlp2s0": ["9.9.9.9", "149.112.112.112"]}
        assert not any("Global DNS override" in n for n in state.notes)

    def test_skips_loopback_and_disconnected(self, global_conf, sequencer):
        sequencer(["lo:unmanaged\nenp3s0:disconnected\n", NO_ACTIVE])
        state = NetworkManagerBackend().get_current()
        assert state.per_interface == {}
        assert any("No active network devices" in n for n in state.notes)

    def test_device_with_no_dns_is_an_empty_list(self, global_conf, sequencer):
        sequencer(["wlp2s0:connected\n", "IP4.DNS:\nIP6.DNS:\n", ACTIVE, "\n"])
        state = NetworkManagerBackend().get_current()
        assert state.per_interface == {"wlp2s0": []}

    def test_reports_global_override_note(self, global_conf, sequencer):
        global_conf.write_text("dummy")
        sequencer(["wlp2s0:connected\n", "IP4.DNS[1]:1.1.1.1\n", ACTIVE, "\n"])
        state = NetworkManagerBackend().get_current()
        assert any("Global DNS override" in n for n in state.notes)

    def test_protocol_state_comes_from_the_active_connection(self, global_conf, sequencer):
        sequencer(
            [
                "wlp2s0:connected\n",
                "IP4.DNS[1]:1.1.1.1\n",
                ACTIVE,
                "connection.llmnr:no\nconnection.mdns:--\n",
            ]
        )
        state = NetworkManagerBackend().get_current()
        # '--' means "unset", which is not a state worth reporting.
        assert state.protocols == {"LLMNR": "no"}


# ----------------------------------------------------------------------
# snapshot
# ----------------------------------------------------------------------

class TestSnapshot:
    def test_captures_per_connection_fields_keyed_by_uuid(self, global_conf, sequencer):
        sequencer([CONNECTIONS, FIELDS])
        payload = NetworkManagerBackend().snapshot()

        assert payload.backend_name == "networkmanager"
        assert list(payload.data["per_connection"]) == ["u-home"]
        home = payload.data["per_connection"]["u-home"]
        assert home["ipv4.dns"] == "9.9.9.9"
        assert home["ipv4.ignore-auto-dns"] == "yes"
        assert payload.data["connection_names"]["u-home"] == "Home WiFi"
        assert payload.data["global_conf_content"] is None

    def test_captures_global_conf_when_present(self, global_conf, sequencer):
        global_conf.write_text("[global-dns-domain-*]\nservers=1.1.1.1\n")
        sequencer(["u-lo:lo:loopback\n"])
        payload = NetworkManagerBackend().snapshot()
        assert "servers=1.1.1.1" in payload.data["global_conf_content"]


# ----------------------------------------------------------------------
# set_dns
# ----------------------------------------------------------------------

class TestSetDns:
    def test_rejects_empty_server_list(self):
        with pytest.raises(BackendError, match="empty server list"):
            NetworkManagerBackend().set_dns([], Scope.CURRENT)

    def test_rejects_dot_servers(self):
        """NetworkManager has no resolver, so 'IP#hostname' is meaningless."""
        with pytest.raises(BackendError, match="cannot do DNS-over-TLS"):
            NetworkManagerBackend().set_dns(["9.9.9.9#dns.quad9.net"], Scope.CURRENT)

    def test_rejects_dnssec(self):
        with pytest.raises(BackendError, match="cannot apply --dnssec"):
            NetworkManagerBackend().set_dns(
                ["9.9.9.9"], Scope.CURRENT, protocols=ProtocolSettings(dnssec=True)
            )

    def test_current_scope_modifies_the_active_connection_by_uuid(self, global_conf, sequencer):
        seq = sequencer([ACTIVE, "", ""])
        NetworkManagerBackend().set_dns(["9.9.9.9"], Scope.CURRENT)

        modify = seq.calls[1]
        assert modify[:4] == ["nmcli", "connection", "modify", "u-home"]
        assert "ipv4.dns" in modify
        assert "9.9.9.9" in modify
        assert "ipv4.ignore-auto-dns" in modify
        assert seq.calls[2][:3] == ["nmcli", "connection", "up"]

    def test_current_scope_errors_when_no_active_connection(self, global_conf, sequencer):
        sequencer([NO_ACTIVE])
        with pytest.raises(BackendError, match="No active connection"):
            NetworkManagerBackend().set_dns(["9.9.9.9"], Scope.CURRENT)

    def test_separates_ipv4_and_ipv6(self, global_conf, sequencer):
        seq = sequencer([ACTIVE, "", ""])
        NetworkManagerBackend().set_dns(
            ["1.1.1.1", "2606:4700:4700::1111"], Scope.CURRENT
        )
        modify = seq.calls[1]
        assert modify[modify.index("ipv4.dns") + 1] == "1.1.1.1"
        assert modify[modify.index("ipv6.dns") + 1] == "2606:4700:4700::1111"

    def test_iface_selects_the_matching_connection(self, global_conf, sequencer):
        active = "u-home:Home:wlp2s0\nu-eth:Wired:enp3s0\n"
        seq = sequencer([active, "", ""])
        NetworkManagerBackend().set_dns(["1.1.1.1"], Scope.CURRENT, interface="enp3s0")
        assert seq.calls[1][3] == "u-eth"

    def test_global_scope_writes_the_conf_file(self, global_conf, sequencer):
        seq = sequencer([ACTIVE, "", ""])
        NetworkManagerBackend().set_dns(["1.1.1.1", "1.0.0.1"], Scope.GLOBAL)

        content = global_conf.read_text()
        assert "[global-dns-domain-*]" in content
        assert "servers=1.1.1.1,1.0.0.1" in content
        assert ["nmcli", "general", "reload"] in seq.calls

    def test_all_scope_touches_every_profile(self, global_conf, sequencer):
        conns = "u-a:A:802-11-wireless\nu-b:B:802-3-ethernet\nu-lo:lo:loopback\n"
        seq = sequencer([conns, ACTIVE, "", "", ""])
        NetworkManagerBackend().set_dns(["1.1.1.1"], Scope.ALL)

        modified = [c[3] for c in seq.calls if c[:3] == ["nmcli", "connection", "modify"]]
        assert modified == ["u-a", "u-b"]

    def test_reports_the_requested_scope_back(self, global_conf, sequencer):
        sequencer([ACTIVE, "", ""])
        effective, _ = NetworkManagerBackend().set_dns(["1.1.1.1"], Scope.CURRENT)
        assert effective is Scope.CURRENT

    def test_dry_run_only_reads(self, global_conf, sequencer):
        seq = sequencer([ACTIVE])
        _, actions = NetworkManagerBackend().set_dns(
            ["1.1.1.1"], Scope.CURRENT, dry_run=True
        )
        # One read to find the active connection, and nothing else.
        assert len(seq.calls) == 1
        assert not global_conf.exists()
        assert any("connection modify u-home" in a for a in actions)

    def test_partial_failure_is_reported_in_full(self, global_conf, monkeypatch):
        """One bad profile must not hide how many others also failed."""
        conns = "u-a:A:802-11-wireless\nu-b:B:802-3-ethernet\n"
        outputs = iter([completed(stdout=conns), completed(stdout=ACTIVE)])

        def fake_run(args, **kwargs):
            if args[:3] == ["nmcli", "connection", "modify"]:
                return completed(returncode=1, stderr="unknown property")
            return next(outputs)

        monkeypatch.setattr(subprocess, "run", fake_run)

        with pytest.raises(BackendError, match="2 of 2 nmcli commands failed"):
            NetworkManagerBackend().set_dns(["1.1.1.1"], Scope.ALL)


# ----------------------------------------------------------------------
# unset
# ----------------------------------------------------------------------

class TestUnset:
    def test_clears_managed_fields_and_removes_the_conf(self, global_conf, sequencer):
        global_conf.write_text("[global-dns-domain-*]\nservers=1.1.1.1\n")
        seq = sequencer([CONNECTIONS, ACTIVE, "", "", ""])

        NetworkManagerBackend().unset()

        assert not global_conf.exists()
        modify = next(c for c in seq.calls if c[:3] == ["nmcli", "connection", "modify"])
        assert modify[3] == "u-home"
        # Every managed field reset to nmcli's "restore default" empty value.
        assert modify[modify.index("ipv4.dns") + 1] == ""
        assert modify[modify.index("connection.mdns") + 1] == ""

    def test_dry_run_keeps_everything(self, global_conf, sequencer):
        global_conf.write_text("[global-dns-domain-*]\nservers=1.1.1.1\n")
        seq = sequencer([CONNECTIONS, ACTIVE])

        actions = NetworkManagerBackend().unset(dry_run=True)

        assert global_conf.exists()
        assert len(seq.calls) == 2  # two reads, no writes
        assert any("remove" in a for a in actions)


# ----------------------------------------------------------------------
# restore
# ----------------------------------------------------------------------

class TestRestore:
    def test_rejects_wrong_backend(self):
        payload = BackupPayload(backend_name="resolved", data={})
        with pytest.raises(BackendError, match="cannot restore"):
            NetworkManagerBackend().restore_from(payload)

    def test_restores_fields_in_a_single_call(self, global_conf, sequencer):
        seq = sequencer([CONNECTIONS, "", "", ACTIVE, ""])
        payload = BackupPayload(
            backend_name="networkmanager",
            data={
                "per_connection": {"u-home": {"ipv4.dns": "192.168.1.1"}},
                "global_conf_content": None,
            },
        )
        NetworkManagerBackend().restore_from(payload)

        modify = [c for c in seq.calls if c[:3] == ["nmcli", "connection", "modify"]]
        assert len(modify) == 1
        assert modify[0][modify[0].index("ipv4.dns") + 1] == "192.168.1.1"
        # Fields absent from the backup are reset, not left as-is.
        assert modify[0][modify[0].index("ipv6.dns") + 1] == ""

    def test_skips_connections_that_no_longer_exist(self, global_conf, sequencer):
        seq = sequencer([CONNECTIONS, "", ACTIVE, ""])
        payload = BackupPayload(
            backend_name="networkmanager",
            data={
                "per_connection": {"u-deleted": {"ipv4.dns": "1.1.1.1"}},
                "global_conf_content": None,
            },
        )
        NetworkManagerBackend().restore_from(payload)
        assert not any(c[:3] == ["nmcli", "connection", "modify"] for c in seq.calls)

    def test_rejects_tampered_global_conf(self, global_conf, sequencer):
        sequencer([CONNECTIONS])
        payload = BackupPayload(
            backend_name="networkmanager",
            data={
                "per_connection": {},
                "global_conf_content": "[main]\nplugins=evil\n",
            },
        )
        with pytest.raises(BackendError, match="Refusing to restore"):
            NetworkManagerBackend().restore_from(payload)


class TestValidateGlobalConf:
    def test_accepts_our_own_output(self):
        validate_global_conf("# comment\n[global-dns-domain-*]\nservers=1.1.1.1\n")

    def test_accepts_a_plain_main_section(self):
        validate_global_conf("[main]\ndns=systemd-resolved\n")

    @pytest.mark.parametrize(
        "content",
        ["[keyfile]\npath=/tmp\n", "[main]\nplugins=whatever\n"],
    )
    def test_rejects_anything_else(self, content):
        with pytest.raises(BackendError, match="Refusing to restore"):
            validate_global_conf(content)


# ----------------------------------------------------------------------
# describe_current_state
# ----------------------------------------------------------------------

class TestDescribeCurrentState:
    def test_identifies_provider_from_the_global_conf(self, global_conf):
        global_conf.write_text(
            "# Managed by dnser — do not edit by hand.\n"
            "[global-dns-domain-*]\nservers=9.9.9.9,149.112.112.112\n"
        )
        assert NetworkManagerBackend().describe_current_state() == "quad9"

    def test_external_for_a_foreign_file(self, global_conf):
        global_conf.write_text("[global-dns-domain-*]\nservers=8.8.8.8\n")
        assert NetworkManagerBackend().describe_current_state() == "external"

    def test_baseline_when_active_connection_has_no_dns(self, global_conf, sequencer):
        sequencer([ACTIVE, "ipv4.dns:\nipv4.ignore-auto-dns:no\n"])
        assert NetworkManagerBackend().describe_current_state() == "baseline"

    def test_identifies_provider_from_the_active_connection(self, global_conf, sequencer):
        sequencer([ACTIVE, "ipv4.dns:1.1.1.1,1.0.0.1\n"])
        assert NetworkManagerBackend().describe_current_state() == "cloudflare"
