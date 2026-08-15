"""Unit tests for ResolvedBackend.

Same approach as test_networkmanager: mock subprocess.run for command
interactions, use tmp_path for drop-in file operations.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock

import pytest

from dnser.backends.base import BackendError, BackupPayload, Scope
from dnser.backends.resolved import ResolvedBackend


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    m = MagicMock()
    m.stdout = stdout
    m.stderr = stderr
    m.returncode = returncode
    return m


class _RunSequencer:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[list[str]] = []

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        if not self.responses:
            raise AssertionError(f"Unexpected extra subprocess call: {args}")
        return self.responses.pop(0)


# ----------------------------------------------------------------------
# is_available
# ----------------------------------------------------------------------

class TestIsAvailable:
    def test_false_when_resolvectl_missing(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: None)
        assert ResolvedBackend().is_available() is False

    def test_true_when_service_active(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/resolvectl")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _completed(returncode=0))
        assert ResolvedBackend().is_available() is True

    def test_false_when_service_inactive(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/resolvectl")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _completed(returncode=3))
        assert ResolvedBackend().is_available() is False


# ----------------------------------------------------------------------
# get_current — parsing of `resolvectl dns` output
# ----------------------------------------------------------------------

class TestGetCurrent:
    def test_parses_global_and_link_entries(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "dnser.backends.resolved.DROPIN_PATH", tmp_path / "missing.conf"
        )
        seq = _RunSequencer([
            # `resolvectl dns` output
            _completed(stdout=(
                "Global: 9.9.9.9 149.112.112.112\n"
                "Link 2 (enp3s0):\n"
                "Link 3 (wlp2s0): 192.168.0.1\n"
                "Link 4 (lo):\n"
            )),
            # `resolvectl status` for protocol notes
            _completed(stdout=(
                "Global\n"
                "           Protocols: -LLMNR -mDNS DNSOverTLS=opportunistic\n"
                "    resolv.conf mode: stub\n"
            )),
        ])
        monkeypatch.setattr(subprocess, "run", seq)

        state = ResolvedBackend().get_current()

        assert state.per_interface["(global)"] == ["9.9.9.9", "149.112.112.112"]
        assert state.per_interface["wlp2s0"] == ["192.168.0.1"]
        assert state.per_interface["enp3s0"] == []
        assert "lo" not in state.per_interface  # loopback filtered
        assert any("Protocols:" in n for n in state.notes)

    def test_omits_global_row_when_no_global_servers(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "dnser.backends.resolved.DROPIN_PATH", tmp_path / "missing.conf"
        )
        seq = _RunSequencer([
            _completed(stdout="Global:\nLink 3 (wlp2s0): 192.168.0.1\n"),
            _completed(stdout=""),
        ])
        monkeypatch.setattr(subprocess, "run", seq)

        state = ResolvedBackend().get_current()
        # Empty Global is normal default — don't clutter output with it.
        assert "(global)" not in state.per_interface
        assert state.per_interface["wlp2s0"] == ["192.168.0.1"]

    def test_reports_dropin_note_when_file_exists(self, monkeypatch, tmp_path):
        dropin = tmp_path / "00-dnser.conf"
        dropin.write_text("[Resolve]\nDNS=9.9.9.9\n")
        monkeypatch.setattr("dnser.backends.resolved.DROPIN_PATH", dropin)
        seq = _RunSequencer([
            _completed(stdout="Global: 9.9.9.9\n"),
            _completed(stdout=""),
        ])
        monkeypatch.setattr(subprocess, "run", seq)

        state = ResolvedBackend().get_current()
        assert any("dnser drop-in active" in n for n in state.notes)


# ----------------------------------------------------------------------
# snapshot + restore
# ----------------------------------------------------------------------

class TestSnapshotAndRestore:
    def test_snapshot_captures_existing_dropin(self, monkeypatch, tmp_path):
        dropin = tmp_path / "00-dnser.conf"
        dropin.write_text("[Resolve]\nDNS=1.1.1.1\n")
        monkeypatch.setattr("dnser.backends.resolved.DROPIN_PATH", dropin)

        payload = ResolvedBackend().snapshot()
        assert payload.backend_name == "resolved"
        assert "DNS=1.1.1.1" in payload.data["dropin_content"]

    def test_snapshot_records_none_when_absent(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "dnser.backends.resolved.DROPIN_PATH", tmp_path / "missing.conf"
        )
        payload = ResolvedBackend().snapshot()
        assert payload.data["dropin_content"] is None

    def test_restore_removes_dropin_when_backup_had_none(self, monkeypatch, tmp_path):
        # There's a drop-in now that we want restored to "absent"
        dropin = tmp_path / "00-dnser.conf"
        dropin.write_text("current content")
        monkeypatch.setattr("dnser.backends.resolved.DROPIN_PATH", dropin)
        # Stub the restart so we don't need a real systemctl
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _completed(returncode=0))

        payload = BackupPayload(
            backend_name="resolved",
            data={"dropin_content": None},
        )
        ResolvedBackend().restore_from(payload)
        assert not dropin.exists()

    def test_restore_writes_back_original_content(self, monkeypatch, tmp_path):
        dropin = tmp_path / "00-dnser.conf"
        dropin.write_text("new bad content")
        monkeypatch.setattr("dnser.backends.resolved.DROPIN_PATH", dropin)
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _completed(returncode=0))

        payload = BackupPayload(
            backend_name="resolved",
            data={"dropin_content": "[Resolve]\nDNS=8.8.8.8\n"},
        )
        ResolvedBackend().restore_from(payload)
        assert "DNS=8.8.8.8" in dropin.read_text()

    def test_restore_rejects_wrong_backend(self, monkeypatch):
        payload = BackupPayload(
            backend_name="networkmanager",
            data={},
        )
        with pytest.raises(BackendError, match="cannot restore"):
            ResolvedBackend().restore_from(payload)


# ----------------------------------------------------------------------
# set_dns — verify drop-in content and DoT auto-detection
# ----------------------------------------------------------------------

class TestSetDns:
    def test_writes_dropin_with_dot_when_hostname_present(self, monkeypatch, tmp_path):
        dropin = tmp_path / "00-dnser.conf"
        monkeypatch.setattr("dnser.backends.resolved.DROPIN_PATH", dropin)
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _completed(returncode=0))

        ResolvedBackend().set_dns(
            ["9.9.9.9#dns.quad9.net", "149.112.112.112#dns.quad9.net"],
            Scope.GLOBAL,
        )
        content = dropin.read_text()
        assert "DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net" in content
        assert "DNSOverTLS=yes" in content
        assert "Domains=~." in content

    def test_writes_dropin_with_opportunistic_when_plain_ips(self, monkeypatch, tmp_path):
        dropin = tmp_path / "00-dnser.conf"
        monkeypatch.setattr("dnser.backends.resolved.DROPIN_PATH", dropin)
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _completed(returncode=0))

        ResolvedBackend().set_dns(["1.1.1.1", "1.0.0.1"], Scope.GLOBAL)
        content = dropin.read_text()
        assert "DNSOverTLS=opportunistic" in content
        assert "DNSOverTLS=yes" not in content

    def test_rejects_empty_server_list(self):
        with pytest.raises(BackendError, match="empty server list"):
            ResolvedBackend().set_dns([], Scope.GLOBAL)

    def test_dropin_is_idempotent(self, monkeypatch, tmp_path):
        """Applying the same DNS twice should leave identical content."""
        dropin = tmp_path / "00-dnser.conf"
        monkeypatch.setattr("dnser.backends.resolved.DROPIN_PATH", dropin)
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _completed(returncode=0))

        ResolvedBackend().set_dns(["1.1.1.1"], Scope.GLOBAL)
        first = dropin.read_text()

        ResolvedBackend().set_dns(["1.1.1.1"], Scope.GLOBAL)
        second = dropin.read_text()

        assert first == second


# ----------------------------------------------------------------------
# describe_current_state — used for backup labeling
# ----------------------------------------------------------------------

class TestDescribeCurrentState:
    def test_returns_baseline_when_no_dropin(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "dnser.backends.resolved.DROPIN_PATH", tmp_path / "missing.conf"
        )
        assert ResolvedBackend().describe_current_state() == "baseline"

    def test_returns_external_for_foreign_dropin(self, monkeypatch, tmp_path):
        dropin = tmp_path / "00-dnser.conf"
        dropin.write_text("[Resolve]\nDNS=8.8.8.8\n")  # no 'Managed by dnser' header
        monkeypatch.setattr("dnser.backends.resolved.DROPIN_PATH", dropin)
        assert ResolvedBackend().describe_current_state() == "external"

    def test_identifies_known_provider(self, monkeypatch, tmp_path):
        dropin = tmp_path / "00-dnser.conf"
        dropin.write_text(
            "# Managed by dnser — do not edit by hand.\n"
            "[Resolve]\nDNS=9.9.9.9 149.112.112.112\n"
        )
        monkeypatch.setattr("dnser.backends.resolved.DROPIN_PATH", dropin)
        assert ResolvedBackend().describe_current_state() == "quad9"

    def test_identifies_provider_with_dot_suffix(self, monkeypatch, tmp_path):
        dropin = tmp_path / "00-dnser.conf"
        dropin.write_text(
            "# Managed by dnser — do not edit by hand.\n"
            "[Resolve]\nDNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com\n"
        )
        monkeypatch.setattr("dnser.backends.resolved.DROPIN_PATH", dropin)
        assert ResolvedBackend().describe_current_state() == "cloudflare"

    def test_returns_managed_for_unknown_ips(self, monkeypatch, tmp_path):
        dropin = tmp_path / "00-dnser.conf"
        dropin.write_text(
            "# Managed by dnser — do not edit by hand.\n"
            "[Resolve]\nDNS=203.0.113.1 203.0.113.2\n"  # RFC 5737 test IPs
        )
        monkeypatch.setattr("dnser.backends.resolved.DROPIN_PATH", dropin)
        assert ResolvedBackend().describe_current_state() == "managed"
