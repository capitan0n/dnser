"""Unit tests for ResolvedBackend."""

from __future__ import annotations

import subprocess

import pytest

from dnser.backends.base import BackendError, BackupPayload, ProtocolSettings, Scope
from dnser.backends.resolved import ResolvedBackend, validate_dropin
from tests.conftest import completed


@pytest.fixture
def dropin(tmp_path, monkeypatch):
    """Point DROPIN_PATH at a temp file and return it (not created)."""
    path = tmp_path / "00-dnser.conf"
    monkeypatch.setattr("dnser.backends.resolved.DROPIN_PATH", path)
    return path


# ----------------------------------------------------------------------
# is_available
# ----------------------------------------------------------------------

class TestIsAvailable:
    def test_false_when_resolvectl_missing(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: None)
        assert ResolvedBackend().is_available() is False

    def test_true_when_service_active(self, monkeypatch, any_run):
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/resolvectl")
        assert ResolvedBackend().is_available() is True

    def test_false_when_service_inactive(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/resolvectl")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed(returncode=3))
        assert ResolvedBackend().is_available() is False

    def test_false_on_timeout(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/resolvectl")

        def raise_timeout(*a, **kw):
            raise subprocess.TimeoutExpired(cmd="systemctl", timeout=5)

        monkeypatch.setattr(subprocess, "run", raise_timeout)
        assert ResolvedBackend().is_available() is False


# ----------------------------------------------------------------------
# get_current
# ----------------------------------------------------------------------

DNS_OUTPUT = (
    "Global: 9.9.9.9 149.112.112.112\n"
    "Link 2 (enp3s0):\n"
    "Link 3 (wlp2s0): 192.168.0.1\n"
    "Link 4 (lo):\n"
)

STATUS_OUTPUT = (
    "Global\n"
    "           Protocols: -LLMNR -mDNS DNSOverTLS=opportunistic DNSSEC=no\n"
    "    resolv.conf mode: stub\n"
    "Link 3 (wlp2s0)\n"
    "           Protocols: LLMNR mDNS\n"
)


class TestGetCurrent:
    def test_parses_global_and_link_entries(self, dropin, sequencer):
        sequencer([DNS_OUTPUT, STATUS_OUTPUT])

        state = ResolvedBackend().get_current()

        assert state.per_interface["(global)"] == ["9.9.9.9", "149.112.112.112"]
        assert state.per_interface["wlp2s0"] == ["192.168.0.1"]
        assert state.per_interface["enp3s0"] == []
        assert "lo" not in state.per_interface

    def test_protocols_land_in_the_protocols_dict(self, dropin, sequencer):
        sequencer([DNS_OUTPUT, STATUS_OUTPUT])

        protocols = ResolvedBackend().get_current().protocols

        # Only the first (global) Protocols line counts; the per-link one
        # that follows must not overwrite it.
        assert protocols == {
            "LLMNR": "no",
            "mDNS": "no",
            "DNSOverTLS": "opportunistic",
            "DNSSEC": "no",
        }

    def test_omits_global_row_when_no_global_servers(self, dropin, sequencer):
        sequencer(["Global:\nLink 3 (wlp2s0): 192.168.0.1\n", ""])
        state = ResolvedBackend().get_current()
        assert "(global)" not in state.per_interface
        assert state.per_interface["wlp2s0"] == ["192.168.0.1"]

    def test_reports_dropin_note_when_file_exists(self, dropin, sequencer):
        dropin.write_text("[Resolve]\nDNS=9.9.9.9\n")
        sequencer(["Global: 9.9.9.9\n", ""])
        state = ResolvedBackend().get_current()
        assert any("dnser drop-in active" in n for n in state.notes)


# ----------------------------------------------------------------------
# snapshot / restore
# ----------------------------------------------------------------------

class TestSnapshotAndRestore:
    def test_snapshot_captures_existing_dropin(self, dropin):
        dropin.write_text("[Resolve]\nDNS=1.1.1.1\n")
        payload = ResolvedBackend().snapshot()
        assert payload.backend_name == "resolved"
        assert "DNS=1.1.1.1" in payload.data["dropin_content"]

    def test_snapshot_records_none_when_absent(self, dropin):
        assert ResolvedBackend().snapshot().data["dropin_content"] is None

    def test_restore_removes_dropin_when_backup_had_none(self, dropin, any_run):
        dropin.write_text("current content")
        payload = BackupPayload(backend_name="resolved", data={"dropin_content": None})
        ResolvedBackend().restore_from(payload)
        assert not dropin.exists()

    def test_restore_writes_back_original_content(self, dropin, any_run):
        dropin.write_text("new bad content")
        payload = BackupPayload(
            backend_name="resolved",
            data={"dropin_content": "[Resolve]\nDNS=8.8.8.8\n"},
        )
        ResolvedBackend().restore_from(payload)
        assert "DNS=8.8.8.8" in dropin.read_text()

    def test_restore_rejects_wrong_backend(self):
        payload = BackupPayload(backend_name="networkmanager", data={})
        with pytest.raises(BackendError, match="cannot restore"):
            ResolvedBackend().restore_from(payload)

    def test_restore_rejects_tampered_content(self, dropin, any_run):
        """Backups live in a user-writable dir but are applied as root."""
        payload = BackupPayload(
            backend_name="resolved",
            data={"dropin_content": "[Service]\nExecStart=/bin/sh\n"},
        )
        with pytest.raises(BackendError, match="Refusing to restore"):
            ResolvedBackend().restore_from(payload)


class TestValidateDropin:
    def test_accepts_a_normal_dropin(self):
        validate_dropin("# comment\n[Resolve]\nDNS=1.1.1.1\nDNSOverTLS=yes\n")

    @pytest.mark.parametrize(
        "content",
        [
            "[Service]\nExecStart=/bin/sh\n",
            "[Resolve]\nExecStart=/bin/sh\n",
            "[Install]\nWantedBy=multi-user.target\n",
        ],
    )
    def test_rejects_anything_else(self, content):
        with pytest.raises(BackendError, match="Refusing to restore"):
            validate_dropin(content)


# ----------------------------------------------------------------------
# set_dns
# ----------------------------------------------------------------------

class TestSetDns:
    def test_writes_dropin_with_dot_when_hostname_present(self, dropin, any_run):
        ResolvedBackend().set_dns(
            ["9.9.9.9#dns.quad9.net", "149.112.112.112#dns.quad9.net"], Scope.GLOBAL
        )
        content = dropin.read_text()
        assert "DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net" in content
        # 'yes' is systemd's fail-closed mode — no separate strict flag needed.
        assert "DNSOverTLS=yes" in content
        assert "Domains=~." in content

    def test_writes_opportunistic_for_plain_ips(self, dropin, any_run):
        ResolvedBackend().set_dns(["1.1.1.1", "1.0.0.1"], Scope.GLOBAL)
        content = dropin.read_text()
        assert "DNSOverTLS=opportunistic" in content
        assert "DNSOverTLS=yes" not in content

    def test_protocol_flags_are_written_only_when_asked(self, dropin, any_run):
        ResolvedBackend().set_dns(
            ["1.1.1.1"],
            Scope.GLOBAL,
            protocols=ProtocolSettings(no_llmnr=True, dnssec=True),
        )
        content = dropin.read_text()
        assert "LLMNR=no" in content
        assert "DNSSEC=yes" in content
        assert "MulticastDNS" not in content

    def test_rejects_empty_server_list(self):
        with pytest.raises(BackendError, match="empty server list"):
            ResolvedBackend().set_dns([], Scope.GLOBAL)

    def test_is_idempotent(self, dropin, any_run):
        ResolvedBackend().set_dns(["1.1.1.1"], Scope.GLOBAL)
        first = dropin.read_text()
        ResolvedBackend().set_dns(["1.1.1.1"], Scope.GLOBAL)
        assert dropin.read_text() == first

    def test_reports_global_as_the_effective_scope(self, dropin, any_run):
        """resolved has no per-connection scope, and must say so."""
        effective, _ = ResolvedBackend().set_dns(["1.1.1.1"], Scope.CURRENT)
        assert effective is Scope.GLOBAL

    def test_dry_run_changes_nothing(self, dropin, sequencer):
        seq = sequencer([])
        effective, actions = ResolvedBackend().set_dns(
            ["1.1.1.1"], Scope.CURRENT, dry_run=True
        )
        assert effective is Scope.GLOBAL
        assert not dropin.exists()
        assert seq.calls == []
        assert any("DNS=1.1.1.1" in a for a in actions)
        assert any("systemctl restart" in a for a in actions)


# ----------------------------------------------------------------------
# unset
# ----------------------------------------------------------------------

class TestUnset:
    def test_removes_the_dropin(self, dropin, any_run):
        dropin.write_text("[Resolve]\nDNS=1.1.1.1\n")
        ResolvedBackend().unset()
        assert not dropin.exists()

    def test_is_a_noop_when_nothing_is_configured(self, dropin, sequencer):
        seq = sequencer([])
        actions = ResolvedBackend().unset()
        assert seq.calls == []
        assert any("nothing to do" in a for a in actions)

    def test_dry_run_keeps_the_file(self, dropin, sequencer):
        dropin.write_text("[Resolve]\nDNS=1.1.1.1\n")
        seq = sequencer([])
        actions = ResolvedBackend().unset(dry_run=True)
        assert dropin.exists()
        assert seq.calls == []
        assert any("remove" in a for a in actions)


# ----------------------------------------------------------------------
# describe_current_state
# ----------------------------------------------------------------------

class TestDescribeCurrentState:
    def test_baseline_when_no_dropin(self, dropin):
        assert ResolvedBackend().describe_current_state() == "baseline"

    def test_external_for_foreign_dropin(self, dropin):
        dropin.write_text("[Resolve]\nDNS=8.8.8.8\n")
        assert ResolvedBackend().describe_current_state() == "external"

    def test_identifies_known_provider(self, dropin):
        dropin.write_text(
            "# Managed by dnser — do not edit by hand.\n"
            "[Resolve]\nDNS=9.9.9.9 149.112.112.112\n"
        )
        assert ResolvedBackend().describe_current_state() == "quad9"

    def test_identifies_provider_with_dot_suffix(self, dropin):
        dropin.write_text(
            "# Managed by dnser — do not edit by hand.\n"
            "[Resolve]\nDNS=1.1.1.1#one.one.one.one 1.0.0.1#one.one.one.one\n"
        )
        assert ResolvedBackend().describe_current_state() == "cloudflare"

    def test_managed_for_unknown_ips(self, dropin):
        dropin.write_text(
            "# Managed by dnser — do not edit by hand.\n"
            "[Resolve]\nDNS=203.0.113.1 203.0.113.2\n"  # RFC 5737 test range
        )
        assert ResolvedBackend().describe_current_state() == "managed"
