"""Tests for provider loading."""

import json

import pytest

from dnser.providers import Provider, ProviderError, load_providers


def test_load_default_providers_returns_dict():
    providers = load_providers()
    assert isinstance(providers, dict)
    assert len(providers) > 0


def test_default_providers_include_common_ones():
    providers = load_providers()
    # These should always be in our bundled defaults
    for expected in ("cloudflare", "quad9"):
        assert expected in providers, f"Missing default provider: {expected}"


def test_provider_has_ipv4_servers():
    providers = load_providers()
    cf = providers["cloudflare"]
    assert isinstance(cf, Provider)
    assert cf.ipv4  # non-empty
    assert "1.1.1.1" in cf.ipv4


def test_all_servers_includes_ipv6_by_default():
    providers = load_providers()
    cf = providers["cloudflare"]
    servers = cf.all_servers()
    # IPv4 comes first
    assert servers[0] in cf.ipv4
    # IPv6 is included
    assert any(":" in s for s in servers)


def test_all_servers_can_exclude_ipv6():
    providers = load_providers()
    cf = providers["cloudflare"]
    servers = cf.all_servers(include_ipv6=False)
    assert all(":" not in s for s in servers)


def test_malformed_json_raises(tmp_path, monkeypatch):
    bad = tmp_path / "providers.json"
    bad.write_text("{ this is not json")
    monkeypatch.setattr("dnser.providers._USER_CONFIG", bad)
    with pytest.raises(ProviderError, match="Malformed JSON"):
        load_providers()


def test_empty_providers_file_raises(tmp_path, monkeypatch):
    empty = tmp_path / "providers.json"
    empty.write_text(json.dumps({}))
    monkeypatch.setattr("dnser.providers._USER_CONFIG", empty)
    with pytest.raises(ProviderError, match="No providers defined"):
        load_providers()


# ----------------------------------------------------------------------
# IP validation
# ----------------------------------------------------------------------

def test_invalid_ipv4_raises(tmp_path, monkeypatch):
    bad = tmp_path / "providers.json"
    bad.write_text(json.dumps({
        "bad": {"name": "Bad", "ipv4": ["not-an-ip"]}
    }))
    monkeypatch.setattr("dnser.providers._USER_CONFIG", bad)
    with pytest.raises(ProviderError, match="not a valid IP"):
        load_providers()


def test_ipv6_in_ipv4_field_raises(tmp_path, monkeypatch):
    """A common typo: putting an IPv6 address in the ipv4 list."""
    bad = tmp_path / "providers.json"
    bad.write_text(json.dumps({
        "bad": {"name": "Bad", "ipv4": ["2606:4700:4700::1111"]}
    }))
    monkeypatch.setattr("dnser.providers._USER_CONFIG", bad)
    with pytest.raises(ProviderError, match="IPv6, but appears in the ipv4 list"):
        load_providers()


def test_valid_provider_with_both_families_loads_ok(tmp_path, monkeypatch):
    ok = tmp_path / "providers.json"
    ok.write_text(json.dumps({
        "cf": {
            "name": "Cloudflare",
            "ipv4": ["1.1.1.1"],
            "ipv6": ["2606:4700:4700::1111"],
        }
    }))
    monkeypatch.setattr("dnser.providers._USER_CONFIG", ok)
    providers = load_providers()
    assert "cf" in providers
    assert providers["cf"].ipv4 == ["1.1.1.1"]
