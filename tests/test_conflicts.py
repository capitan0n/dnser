"""Tests for conflict detection.

Regression coverage for the substring-match bug where 'DNS=' was matching
inside 'MulticastDNS=no', 'DNSOverTLS=', 'DNSSEC=', etc.
"""

from __future__ import annotations

import pytest

from dnser.conflicts import (
    _classify_nm_file,
    _file_has_any_keys,
    _line_starts_with_any,
    scan_conflicts,
)


# ----------------------------------------------------------------------
# Unit: line matching
# ----------------------------------------------------------------------

class TestLineStartsWithAny:
    keys = ("DNS=", "FallbackDNS=", "Domains=")

    @pytest.mark.parametrize("line", [
        "DNS=9.9.9.9",
        "FallbackDNS=1.1.1.1",
        "Domains=~.",
        "DNS=9.9.9.9#dns.quad9.net 149.112.112.112",
    ])
    def test_matches_real_dns_lines(self, line):
        assert _line_starts_with_any(line, self.keys) is True

    @pytest.mark.parametrize("line", [
        "DNSOverTLS=opportunistic",  # <-- previously false-positive
        "DNSSEC=no",                  # <-- previously false-positive
        "MulticastDNS=no",            # <-- the one that bit us
        "Cache=yes",
        "LLMNR=no",
        "DNSStubListener=yes",
    ])
    def test_does_not_match_similar_keys(self, line):
        assert _line_starts_with_any(line, self.keys) is False


class TestDottedKeys:
    """NM uses dotted key notation like ipv4.ignore-auto-dns=true.

    The matcher must recognize these as keys even though the line doesn't
    start with the bare key name.
    """
    conflict_keys = ("servers=", "ignore-auto-dns")

    @pytest.mark.parametrize("line", [
        "ipv4.ignore-auto-dns=true",
        "ipv6.ignore-auto-dns=yes",
        "servers=1.1.1.1;1.0.0.1;",
    ])
    def test_matches_dotted_and_bare_keys(self, line):
        assert _line_starts_with_any(line, self.conflict_keys) is True

    @pytest.mark.parametrize("line", [
        "dns=systemd-resolved",      # integration key, not a conflict
        "systemd-resolved=true",     # integration key, not a conflict
        "connection.autoconnect=yes", # unrelated dotted key
    ])
    def test_does_not_match_unrelated_dotted_keys(self, line):
        assert _line_starts_with_any(line, self.conflict_keys) is False


# ----------------------------------------------------------------------
# Unit: file scanning
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


def test_clean_resolved_conf_has_no_active_dns_keys(tmp_path):
    conf = tmp_path / "resolved.conf"
    conf.write_text(CLEAN_RESOLVED_CONF)
    assert _file_has_any_keys(conf, ("DNS=", "FallbackDNS=", "Domains=")) is False


def test_dirty_resolved_conf_is_detected(tmp_path):
    conf = tmp_path / "resolved.conf"
    conf.write_text(DIRTY_RESOLVED_CONF)
    assert _file_has_any_keys(conf, ("DNS=", "FallbackDNS=", "Domains=")) is True


def test_commented_lines_are_ignored(tmp_path):
    conf = tmp_path / "resolved.conf"
    conf.write_text("[Resolve]\n#DNS=9.9.9.9\n#FallbackDNS=1.1.1.1\n")
    assert _file_has_any_keys(conf, ("DNS=", "FallbackDNS=")) is False


# ----------------------------------------------------------------------
# Unit: NM file classification
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


def test_nm_integration_file_is_not_a_conflict(tmp_path):
    conf = tmp_path / "00-dns-resolved.conf"
    conf.write_text(NM_INTEGRATION_ONLY)
    assert _classify_nm_file(conf) == "integration"


def test_nm_global_dns_is_a_conflict(tmp_path):
    conf = tmp_path / "dns.conf"
    conf.write_text(NM_CONFLICT_GLOBAL)
    assert _classify_nm_file(conf) == "conflict"


def test_nm_ignore_auto_dns_is_a_conflict(tmp_path):
    conf = tmp_path / "no-auto-dns.conf"
    conf.write_text(NM_CONFLICT_IGNORE_AUTO)
    assert _classify_nm_file(conf) == "conflict"


def test_nm_empty_file_is_empty(tmp_path):
    conf = tmp_path / "empty.conf"
    conf.write_text("# just a comment\n\n[main]\n")
    assert _classify_nm_file(conf) == "empty"
