"""Tests for the raw DNS probing in dnser.check.

These cover packet construction and response interpretation, which are
pure functions — no socket is opened anywhere in this module.
"""

from __future__ import annotations

import struct

import pytest

from dnser.check import (
    _build_a_query,
    _check_one,
    _random_label,
    check_all,
    validate_response,
)
from dnser.providers import Provider


def _reply(packet: bytes, question: bytes, rcode: int = 0, qr: bool = True) -> bytes:
    """Build a minimal DNS reply to `packet`."""
    tx_id = packet[:2]
    flags = (0x8180 if qr else 0x0100) | rcode
    header = tx_id + struct.pack(">HHHHH", flags, 1, 1, 0, 0)
    return header + question


# ----------------------------------------------------------------------
# Query construction
# ----------------------------------------------------------------------

class TestBuildQuery:
    def test_header_and_question_shape(self):
        packet, question = _build_a_query("example.com")
        assert len(packet) == 12 + len(question)
        _, flags, qdcount, an, ns, ar = struct.unpack(">HHHHHH", packet[:12])
        assert flags == 0x0100  # standard query, recursion desired
        assert (qdcount, an, ns, ar) == (1, 0, 0, 0)

    def test_qname_is_length_prefixed(self):
        _, question = _build_a_query("example.com")
        assert question.startswith(b"\x07example\x03com\x00")
        assert question.endswith(struct.pack(">HH", 1, 1))  # QTYPE=A, QCLASS=IN

    def test_transaction_ids_differ_between_queries(self):
        ids = {_build_a_query("example.com")[0][:2] for _ in range(50)}
        assert len(ids) > 1


class TestRandomLabel:
    def test_is_a_valid_dns_label(self):
        label = _random_label()
        assert len(label) == 12
        assert label.isalnum()
        assert label.islower() or label.isdigit() or label.isalnum()

    def test_labels_are_unique(self):
        assert len({_random_label() for _ in range(100)}) == 100


# ----------------------------------------------------------------------
# Response validation
# ----------------------------------------------------------------------

class TestValidateResponse:
    def test_accepts_noerror(self):
        packet, question = _build_a_query("example.com")
        assert validate_response(_reply(packet, question, rcode=0), packet, question) is None

    def test_accepts_nxdomain(self):
        """NXDOMAIN is the *correct* answer for our random uncached labels.

        example.com publishes no wildcard, so treating RCODE=3 as failure
        made every uncached probe fail against every provider.
        """
        packet, question = _build_a_query("abc123.example.com")
        assert validate_response(_reply(packet, question, rcode=3), packet, question) is None

    @pytest.mark.parametrize(("rcode", "name"), [(2, "SERVFAIL"), (5, "REFUSED")])
    def test_rejects_real_errors(self, rcode, name):
        packet, question = _build_a_query("example.com")
        error = validate_response(_reply(packet, question, rcode=rcode), packet, question)
        assert error is not None
        assert str(rcode) in error

    def test_rejects_short_packet(self):
        packet, question = _build_a_query("example.com")
        assert validate_response(b"\x00" * 4, packet, question) == "malformed response"

    def test_rejects_transaction_id_mismatch(self):
        packet, question = _build_a_query("example.com")
        forged = b"\xff\xff" + _reply(packet, question)[2:]
        assert validate_response(forged, packet, question) == "transaction ID mismatch"

    def test_rejects_a_query_masquerading_as_a_response(self):
        packet, question = _build_a_query("example.com")
        assert (
            validate_response(_reply(packet, question, qr=False), packet, question)
            == "not a response packet"
        )

    def test_rejects_mismatched_question(self):
        packet, question = _build_a_query("example.com")
        _, other_question = _build_a_query("elsewhere.test")
        reply = _reply(packet, other_question)
        assert validate_response(reply, packet, question) == "question section mismatch"


# ----------------------------------------------------------------------
# Provider dispatch
# ----------------------------------------------------------------------

def _provider(key: str, **kwargs) -> Provider:
    defaults = {"name": key.title(), "description": "", "ipv4": ["203.0.113.1"]}
    defaults.update(kwargs)
    return Provider(key=key, **defaults)


class TestCheckOne:
    def test_provider_without_ipv4_fails_without_probing(self):
        result = _check_one(_provider("empty", ipv4=[]))
        assert result.ok is False
        assert result.error == "no IPv4 servers to probe"

    def test_dot_only_provider_is_skipped_not_failed(self):
        result = _check_one(_provider("mullvad", requires_dot=True))
        assert result.ok is True
        assert result.cached_ms is None
        assert result.uncached_ms is None
        assert "DoT-only" in (result.error or "")


class TestCheckAll:
    def test_empty_input_returns_empty(self):
        assert check_all({}) == []

    def test_results_follow_input_order(self, monkeypatch):
        providers = {k: _provider(k, requires_dot=True) for k in ("c", "a", "b")}
        assert [r.provider_key for r in check_all(providers)] == ["c", "a", "b"]
