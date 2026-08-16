"""Tests for conflict detection.

Regression coverage for the substring-match bug where 'DNS=' matched
inside 'MulticastDNS=no', 'DNSOverTLS=' and 'DNSSEC='.
"""

from __future__ import annotations

import pytest

from dnser import conflicts
from dnser.conflicts import (
    file_has_any_keys,
    line_starts_with_any,
    nm_file_conflicts,
    scan_conflicts,
)

RESOLVED_KEYS = ("DNS=", "FallbackDNS=", "Domains=")
NM_KEYS = ("servers=", "ignore-auto-dns")


# ----------------------------------------------------------------------
# Line matching
# ----------------------------------------------------------------------

class TestLineMatching:
    @pytest.mark.parametrize(
        "line",
        [
            "DNS=9.9.9.9",
            "FallbackDNS=1.1.1.1",
            "Domains=~.",
            "DNS=9.9.9.9#dns.quad9.net 149.112.112.112",
        ],
    )
    def test_matches_real_dns_lines(self, line):
        assert line_starts_with_any(line, RESOLVED_KEYS) is True

    @pytest.mark.parametrize(
        "line",
        [
            "DNSOverTLS=opportunistic",
            "DNSSEC=no",
            "MulticastDNS=no",
            "Cache=yes",
            "LLMNR=no",
            "DNSStubListener=yes",
        ],
    )
    def test_does_not_match_similar_keys(self, line):
        assert line_starts_with_any(line, RESOLVED_KEYS) is False

    @pytest.mark.parametrize(
        "line",
        ["ipv4.ignore-auto-dns=true", "ipv6.ignore-auto-dns=yes", "servers=1.1.1.1;1.0.0.1;"],
    )
    def test_matches_dotted_and_bare_keys(self, line):
        assert line_starts_with_any(line, NM_KEYS) is True

    @pytest.mark.parametrize(
        "line",
        ["dns=systemd-resolved", "systemd-resolved=true", "connection.autoconnect=yes"],
    )
    def test_does_not_match_unrelated_keys(self, line):
        assert line_starts_with_any(line, NM_KEYS) is False


# ----------------------------------------------------------------------
# File scanning
# ----------------------------------------------------------------------

CLEAN_RESOLVED_CONF = """\
[Resolve]
DNSOverTLS=opportunistic
DNSSEC=no
Cache=yes
DNSStubListener=yes
MulticastDNS=no
LLMNR=no
"""

DIRTY_RESOLVED_CONF = """\
[Resolve]
DNS=9.9.9.9
FallbackDNS=149.112.112.112
DNSOverTLS=yes
"""


class TestFileScanning:
    def test_clean_conf_has_no_active_dns_keys(self, tmp_path):
        conf = tmp_path / "resolved.conf"
        conf.write_text(CLEAN_RESOLVED_CONF)
        assert file_has_any_keys(conf, RESOLVED_KEYS) is False

    def test_dirty_conf_is_detected(self, tmp_path):
        conf = tmp_path / "resolved.conf"
        conf.write_text(DIRTY_RESOLVED_CONF)
        assert file_has_any_keys(conf, RESOLVED_KEYS) is True

    def test_commented_lines_are_ignored(self, tmp_path):
        conf = tmp_path / "resolved.conf"
        conf.write_text("[Resolve]\n#DNS=9.9.9.9\n#FallbackDNS=1.1.1.1\n")
        assert file_has_any_keys(conf, RESOLVED_KEYS) is False

    def test_unreadable_file_is_not_a_conflict(self, tmp_path):
        assert file_has_any_keys(tmp_path / "nope.conf", RESOLVED_KEYS) is False


# ----------------------------------------------------------------------
# NetworkManager drop-in classification
# ----------------------------------------------------------------------

NM_INTEGRATION_ONLY = """\
[main]
dns=systemd-resolved
systemd-resolved=true
"""

NM_CONFLICT_GLOBAL = """\
[main]
dns=default

[global-dns]
servers=1.1.1.1;1.0.0.1;
"""

NM_CONFLICT_IGNORE_AUTO = """\
[connection]
ipv4.ignore-auto-dns=true
ipv6.ignore-auto-dns=true
"""


class TestNmClassification:
    def test_integration_file_is_not_a_conflict(self, tmp_path):
        conf = tmp_path / "00-dns-resolved.conf"
        conf.write_text(NM_INTEGRATION_ONLY)
        assert nm_file_conflicts(conf) is False

    def test_global_dns_is_a_conflict(self, tmp_path):
        conf = tmp_path / "dns.conf"
        conf.write_text(NM_CONFLICT_GLOBAL)
        assert nm_file_conflicts(conf) is True

    def test_ignore_auto_dns_is_a_conflict(self, tmp_path):
        conf = tmp_path / "no-auto-dns.conf"
        conf.write_text(NM_CONFLICT_IGNORE_AUTO)
        assert nm_file_conflicts(conf) is True

    def test_empty_file_is_not_a_conflict(self, tmp_path):
        conf = tmp_path / "empty.conf"
        conf.write_text("# just a comment\n\n[main]\n")
        assert nm_file_conflicts(conf) is False


# ----------------------------------------------------------------------
# scan_conflicts end to end
# ----------------------------------------------------------------------

class TestScanConflicts:
    def test_reports_foreign_dropins_but_skips_our_own(self, tmp_path, monkeypatch):
        nm_dir = tmp_path / "nm"
        resolved_dir = tmp_path / "resolved.conf.d"
        nm_dir.mkdir()
        resolved_dir.mkdir()

        (nm_dir / "99-other.conf").write_text(NM_CONFLICT_GLOBAL)
        (nm_dir / "00-dnser-global.conf").write_text(NM_CONFLICT_GLOBAL)
        (resolved_dir / "50-foreign.conf").write_text(DIRTY_RESOLVED_CONF)
        (resolved_dir / "00-dnser.conf").write_text(DIRTY_RESOLVED_CONF)

        monkeypatch.setattr(conflicts, "NM_CONF_DIR", nm_dir)
        monkeypatch.setattr(conflicts, "RESOLVED_CONF_DIR", resolved_dir)
        monkeypatch.setattr(conflicts, "RESOLVED_CONF", tmp_path / "resolved.conf")

        warnings = scan_conflicts()

        assert len(warnings) == 2
        assert any("99-other.conf" in w for w in warnings)
        assert any("50-foreign.conf" in w for w in warnings)
        assert not any("dnser" in w.rsplit("/", 1)[-1] for w in warnings)

    def test_no_directories_means_no_warnings(self, tmp_path, monkeypatch):
        monkeypatch.setattr(conflicts, "NM_CONF_DIR", tmp_path / "missing-nm")
        monkeypatch.setattr(conflicts, "RESOLVED_CONF_DIR", tmp_path / "missing-resolved")
        monkeypatch.setattr(conflicts, "RESOLVED_CONF", tmp_path / "missing.conf")
        assert scan_conflicts() == []
