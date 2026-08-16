"""Tests for provider loading and validation."""

from __future__ import annotations

import json

import pytest

from dnser.providers import (
    Provider,
    ProviderError,
    identify_provider,
    load_providers,
)


@pytest.fixture
def user_config(tmp_path, monkeypatch):
    """Write a providers.json and make it the highest-priority config."""

    def _write(data) -> None:
        path = tmp_path / "providers.json"
        path.write_text(data if isinstance(data, str) else json.dumps(data))
        monkeypatch.setattr("dnser.providers._USER_CONFIG", path)

    return _write


# ----------------------------------------------------------------------
# Bundled defaults
# ----------------------------------------------------------------------

class TestBundledDefaults:
    def test_loads_and_is_not_empty(self):
        providers = load_providers()
        assert isinstance(providers, dict)
        assert providers

    @pytest.mark.parametrize("key", ["cloudflare", "quad9", "mullvad"])
    def test_expected_providers_present(self, key):
        assert key in load_providers()

    def test_bundled_file_ships_with_the_package(self):
        """Guards against providers.json falling out of the wheel."""
        from dnser.providers import _bundled_config

        assert _bundled_config().is_file()

    def test_provider_has_ipv4(self):
        cloudflare = load_providers()["cloudflare"]
        assert isinstance(cloudflare, Provider)
        assert "1.1.1.1" in cloudflare.ipv4


# ----------------------------------------------------------------------
# Server list assembly
# ----------------------------------------------------------------------

class TestServerLists:
    def test_ipv4_comes_first_and_ipv6_is_included(self):
        cloudflare = load_providers()["cloudflare"]
        servers = cloudflare.all_servers()
        assert servers[0] in cloudflare.ipv4
        assert any(":" in s for s in servers)

    def test_ipv6_can_be_excluded(self):
        servers = load_providers()["cloudflare"].all_servers(include_ipv6=False)
        assert all(":" not in s for s in servers)

    def test_dot_servers_carry_the_hostname(self):
        servers = load_providers()["quad9"].all_servers_dot(include_ipv6=False)
        assert all(s.endswith("#dns.quad9.net") for s in servers)


# ----------------------------------------------------------------------
# Malformed input
# ----------------------------------------------------------------------

class TestValidation:
    def test_malformed_json_raises(self, user_config):
        user_config("{ this is not json")
        with pytest.raises(ProviderError, match="Malformed JSON"):
            load_providers()

    def test_empty_file_raises(self, user_config):
        user_config({})
        with pytest.raises(ProviderError, match="No providers defined"):
            load_providers()

    def test_invalid_ipv4_raises(self, user_config):
        user_config({"bad": {"name": "Bad", "ipv4": ["not-an-ip"]}})
        with pytest.raises(ProviderError, match="not a valid IP"):
            load_providers()

    def test_ipv6_in_ipv4_field_raises(self, user_config):
        user_config({"bad": {"name": "Bad", "ipv4": ["2606:4700:4700::1111"]}})
        with pytest.raises(ProviderError, match="IPv6, but appears in the ipv4 list"):
            load_providers()

    @pytest.mark.parametrize(
        "hostname",
        [
            "dns.quad9.net\nDNSSEC=no",  # newline injection into the drop-in
            "dns quad9 net",
            "-leading-hyphen.net",
            "",
        ],
    )
    def test_bad_dot_hostname_raises(self, user_config, hostname):
        """A hostname reaches a root-written config file verbatim.

        Anything that can carry a newline could append arbitrary
        directives to the resolved drop-in, so the check is strict.
        """
        user_config({"x": {"name": "X", "ipv4": ["1.1.1.1"], "dot_hostname": hostname}})
        with pytest.raises(ProviderError, match="not a valid hostname"):
            load_providers()

    def test_good_dot_hostname_accepted(self, user_config):
        user_config(
            {"x": {"name": "X", "ipv4": ["1.1.1.1"], "dot_hostname": "dns.example.com"}}
        )
        assert load_providers()["x"].dot_hostname == "dns.example.com"

    def test_empty_tag_raises(self, user_config):
        user_config({"x": {"name": "X", "ipv4": ["1.1.1.1"], "tags": ["  "]}})
        with pytest.raises(ProviderError, match="non-empty string"):
            load_providers()

    def test_valid_provider_with_both_families(self, user_config):
        user_config(
            {"cf": {"name": "Cloudflare", "ipv4": ["1.1.1.1"], "ipv6": ["2606:4700:4700::1111"]}}
        )
        providers = load_providers()
        assert providers["cf"].ipv4 == ["1.1.1.1"]


# ----------------------------------------------------------------------
# identify_provider
# ----------------------------------------------------------------------

class TestIdentifyProvider:
    def test_matches_plain_ip(self):
        assert identify_provider(["9.9.9.9"]) == "quad9"

    def test_strips_dot_suffix(self):
        assert identify_provider(["1.1.1.1#one.one.one.one"]) == "cloudflare"

    def test_unknown_ip_returns_none(self):
        assert identify_provider(["203.0.113.1"]) is None

    def test_empty_returns_none(self):
        assert identify_provider([]) is None

    def test_accepts_a_preloaded_provider_map(self):
        providers = load_providers()
        assert identify_provider(["8.8.8.8"], providers=providers) == "google"
