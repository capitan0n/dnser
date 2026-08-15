"""Unit tests for NetworkManagerBackend.

We mock subprocess.run so the tests don't touch the real system. Each test
sets up a specific nmcli output shape and verifies parsing + behavior.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from dnser.backends.base import BackendError, BackupPayload, Scope
from dnser.backends.networkmanager import NetworkManagerBackend


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    """Build a CompletedProcess-like object for subprocess.run mocks."""
    m = MagicMock()
    m.stdout = stdout
    m.stderr = stderr
    m.returncode = returncode
    return m


class _RunSequencer:
    """Return a queued sequence of CompletedProcess objects across calls.

    Usage:
        seq = _RunSequencer([
            _completed(stdout="wlan0:connected\\nlo:unmanaged\\n"),
            _completed(stdout="IP4.DNS[1]:1.1.1.1\\n"),
        ])
        monkeypatch.setattr(subprocess, "run", seq)
    """
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
    def test_returns_false_if_nmcli_missing(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: None)
        backend = NetworkManagerBackend()
        assert backend.is_available() is False

    def test_returns_true_when_nmcli_present_and_service_up(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmcli")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _completed(returncode=0))
        backend = NetworkManagerBackend()
        assert backend.is_available() is True

    def test_returns_false_when_service_down(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmcli")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _completed(returncode=1))
        backend = NetworkManagerBackend()
        assert backend.is_available() is False

    def test_returns_false_on_timeout(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmcli")
        def raise_timeout(*a, **kw):
            raise subprocess.TimeoutExpired(cmd=a[0], timeout=5)
        monkeypatch.setattr(subprocess, "run", raise_timeout)
        backend = NetworkManagerBackend()
        # Must not propagate — is_available never raises.
        assert backend.is_available() is False


# ----------------------------------------------------------------------
# get_current — output parsing
# ----------------------------------------------------------------------

class TestGetCurrent:
    def test_parses_single_connected_device(self, monkeypatch):
        seq = _RunSequencer([
            # `nmcli -t -f DEVICE,STATE device`
            _completed(stdout="wlp2s0:connected\nlo:unmanaged\nenp3s0:disconnected\n"),
            # `nmcli -t -f IP4.DNS,IP6.DNS device show wlp2s0`
            _completed(stdout="IP4.DNS[1]:9.9.9.9\nIP4.DNS[2]:149.112.112.112\nIP6.DNS:\n"),
        ])
        monkeypatch.setattr(subprocess, "run", seq)

        state = NetworkManagerBackend().get_current()

        assert state.per_interface == {"wlp2s0": ["9.9.9.9", "149.112.112.112"]}
        # No global override file expected in tests → no note about it
        assert not any("Global DNS override" in n for n in state.notes)

    def test_skips_loopback_and_disconnected(self, monkeypatch):
        seq = _RunSequencer([
            _completed(stdout="lo:unmanaged\nenp3s0:disconnected\n"),
        ])
        monkeypatch.setattr(subprocess, "run", seq)

        state = NetworkManagerBackend().get_current()
        assert state.per_interface == {}
        assert any("No active network devices" in n for n in state.notes)

    def test_records_device_with_no_dns_as_empty_list(self, monkeypatch):
        # A DHCP-only device with no override shows empty IP4.DNS
        seq = _RunSequencer([
            _completed(stdout="wlp2s0:connected\n"),
            _completed(stdout="IP4.DNS:\nIP6.DNS:\n"),
        ])
        monkeypatch.setattr(subprocess, "run", seq)

        state = NetworkManagerBackend().get_current()
        assert state.per_interface == {"wlp2s0": []}

    def test_reports_global_override_note_when_file_exists(self, monkeypatch, tmp_path):
        # Redirect the module-level constant to a temp file we control
        fake_path = tmp_path / "00-dnser-global.conf"
        fake_path.write_text("dummy")
        monkeypatch.setattr(
            "dnser.backends.networkmanager.GLOBAL_CONF_PATH", fake_path
        )
        seq = _RunSequencer([
            _completed(stdout="wlp2s0:connected\n"),
            _completed(stdout="IP4.DNS[1]:1.1.1.1\n"),
        ])
        monkeypatch.setattr(subprocess, "run", seq)

        state = NetworkManagerBackend().get_current()
        assert any("Global DNS override" in n for n in state.notes)


# ----------------------------------------------------------------------
# snapshot
# ----------------------------------------------------------------------

class TestSnapshot:
    def test_captures_per_connection_fields(self, monkeypatch, tmp_path):
        # No global conf file present in this test
        monkeypatch.setattr(
            "dnser.backends.networkmanager.GLOBAL_CONF_PATH",
            tmp_path / "does-not-exist.conf",
        )
        seq = _RunSequencer([
            # `nmcli -t -f NAME,TYPE connection show`
            _completed(stdout="Home-WiFi:802-11-wireless\nlo:loopback\n"),
            # `nmcli -t -f ipv4.dns,ipv4.ignore-auto-dns,ipv6.dns,ipv6.ignore-auto-dns connection show Home-WiFi`
            _completed(stdout=(
                "ipv4.dns:9.9.9.9\n"
                "ipv4.ignore-auto-dns:yes\n"
                "ipv6.dns:\n"
                "ipv6.ignore-auto-dns:no\n"
            )),
        ])
        monkeypatch.setattr(subprocess, "run", seq)

        payload = NetworkManagerBackend().snapshot()

        assert payload.backend_name == "networkmanager"
        assert "Home-WiFi" in payload.data["per_connection"]
        home = payload.data["per_connection"]["Home-WiFi"]
        assert home["ipv4.dns"] == "9.9.9.9"
        assert home["ipv4.ignore-auto-dns"] == "yes"
        assert payload.data["global_conf_content"] is None

    def test_captures_global_conf_when_present(self, monkeypatch, tmp_path):
        conf = tmp_path / "00-dnser-global.conf"
        conf.write_text("[global-dns-domain-*]\nservers=1.1.1.1\n")
        monkeypatch.setattr(
            "dnser.backends.networkmanager.GLOBAL_CONF_PATH", conf
        )
        seq = _RunSequencer([
            _completed(stdout="lo:loopback\n"),  # only loopback → no per-conn data
        ])
        monkeypatch.setattr(subprocess, "run", seq)

        payload = NetworkManagerBackend().snapshot()
        assert "servers=1.1.1.1" in payload.data["global_conf_content"]


# ----------------------------------------------------------------------
# set_dns — verifies the right commands are issued
# ----------------------------------------------------------------------

class TestSetDns:
    def test_rejects_empty_server_list(self):
        with pytest.raises(BackendError, match="empty server list"):
            NetworkManagerBackend().set_dns([], Scope.CURRENT)

    def test_current_scope_modifies_active_connection(self, monkeypatch):
        seq = _RunSequencer([
            # Get active connection name (rsplit gives us the last field = device)
            _completed(stdout="Home-WiFi:802-11-wireless:wlp2s0\nlo:loopback:lo\n"),
            # Set DNS on that connection
            _completed(stdout=""),
            # Get active connection name AGAIN for reactivation
            _completed(stdout="Home-WiFi:802-11-wireless:wlp2s0\n"),
            # Reactivate: nmcli connection up
            _completed(stdout=""),
        ])
        monkeypatch.setattr(subprocess, "run", seq)

        NetworkManagerBackend().set_dns(["9.9.9.9"], Scope.CURRENT)

        # Assert the modify command had the right shape
        modify_call = seq.calls[1]
        assert modify_call[:4] == ["nmcli", "connection", "modify", "Home-WiFi"]
        assert "ipv4.dns" in modify_call
        assert "9.9.9.9" in modify_call
        assert "ipv4.ignore-auto-dns" in modify_call

    def test_current_scope_errors_when_no_active_connection(self, monkeypatch):
        seq = _RunSequencer([
            _completed(stdout="lo:loopback:lo\n"),  # only loopback active
        ])
        monkeypatch.setattr(subprocess, "run", seq)

        with pytest.raises(BackendError, match="No active connection"):
            NetworkManagerBackend().set_dns(["9.9.9.9"], Scope.CURRENT)

    def test_separates_ipv4_and_ipv6_by_colon_presence(self, monkeypatch):
        seq = _RunSequencer([
            _completed(stdout="Home:802-11-wireless:wlp2s0\n"),
            _completed(stdout=""),
            _completed(stdout="Home:802-11-wireless:wlp2s0\n"),
            _completed(stdout=""),
        ])
        monkeypatch.setattr(subprocess, "run", seq)

        NetworkManagerBackend().set_dns(
            ["1.1.1.1", "2606:4700:4700::1111"], Scope.CURRENT
        )

        modify_call = seq.calls[1]
        assert "ipv4.dns" in modify_call
        assert "1.1.1.1" in modify_call
        assert "ipv6.dns" in modify_call
        assert "2606:4700:4700::1111" in modify_call
