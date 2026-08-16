"""Load and validate DNS provider presets from providers.json."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path


# Provider file lookup order:
# 1. User override: ~/.config/dnser/providers.json (highest priority)
# 2. System install: /etc/dnser/providers.json
# 3. Bundled default: <repo-root>/providers.json (fallback)
_USER_CONFIG = Path.home() / ".config" / "dnser" / "providers.json"
_SYSTEM_CONFIG = Path("/etc/dnser/providers.json")
_BUNDLED_CONFIG = Path(__file__).parent.parent / "providers.json"


@dataclass
class Provider:
    """A DNS provider preset."""
    key: str                # short id, e.g. "cloudflare"
    name: str               # display name, e.g. "Cloudflare"
    description: str
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    dot_hostname: str | None = None   # DoT hostname for TLS cert verification
    tags: list[str] = field(default_factory=list)  # short labels for display

    def all_servers(self, include_ipv6: bool = True) -> list[str]:
        """Return all DNS server IPs (IPv4 first, then IPv6 if requested)."""
        servers = list(self.ipv4)
        if include_ipv6:
            servers.extend(self.ipv6)
        return servers

    def all_servers_dot(self, include_ipv6: bool = True) -> list[str]:
        """Return servers formatted with #hostname for DoT verification.

        systemd-resolved requires 'IP#hostname' syntax to verify the TLS
        certificate. Falls back to plain IPs if no dot_hostname is defined.
        """
        if not self.dot_hostname:
            return self.all_servers(include_ipv6=include_ipv6)
        return [f"{ip}#{self.dot_hostname}" for ip in self.all_servers(include_ipv6=include_ipv6)]


class ProviderError(Exception):
    """Raised when provider config is missing or malformed."""


def _find_config_file() -> Path:
    """Return the first existing provider config file, checking user → system → bundled."""
    for candidate in (_USER_CONFIG, _SYSTEM_CONFIG, _BUNDLED_CONFIG):
        if candidate.is_file():
            return candidate
    raise ProviderError(
        f"No providers config found. Looked in:\n"
        f"  {_USER_CONFIG}\n  {_SYSTEM_CONFIG}\n  {_BUNDLED_CONFIG}"
    )


def load_providers() -> dict[str, Provider]:
    """Load all providers from the first available config file.

    Returns a dict keyed by provider short-id (e.g. 'cloudflare').
    Raises ProviderError on missing file or malformed JSON.
    """
    config_path = _find_config_file()

    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ProviderError(f"Malformed JSON in {config_path}: {e}") from e

    if not isinstance(raw, dict):
        raise ProviderError(f"{config_path}: expected a JSON object at top level")

    providers: dict[str, Provider] = {}
    for key, data in raw.items():
        if not isinstance(data, dict):
            raise ProviderError(f"Provider '{key}': expected an object, got {type(data).__name__}")
        try:
            ipv4 = list(data.get("ipv4", []))
            ipv6 = list(data.get("ipv6", []))
            tags = list(data.get("tags", []))
            # Validate every IP before accepting the provider. Catching
            # typos here beats a cryptic nmcli/resolvectl failure later.
            _validate_ips(key, ipv4, expected_version=4)
            _validate_ips(key, ipv6, expected_version=6)
            _validate_tags(key, tags)
            providers[key] = Provider(
                key=key,
                name=data.get("name", key.title()),
                description=data.get("description", ""),
                ipv4=ipv4,
                ipv6=ipv6,
                dot_hostname=data.get("dot_hostname"),
                tags=tags,
            )
        except (TypeError, ValueError) as e:
            raise ProviderError(f"Provider '{key}' is malformed: {e}") from e

    if not providers:
        raise ProviderError(f"No providers defined in {config_path}")

    return providers


def _validate_ips(provider_key: str, ips: list[str], expected_version: int) -> None:
    """Raise ProviderError if any IP is malformed or of the wrong family."""
    for ip in ips:
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError as e:
            raise ProviderError(
                f"Provider '{provider_key}': '{ip}' is not a valid IP address ({e})."
            ) from e
        if parsed.version != expected_version:
            raise ProviderError(
                f"Provider '{provider_key}': '{ip}' is IPv{parsed.version}, "
                f"but appears in the ipv{expected_version} list."
            )


def _validate_tags(provider_key: str, tags: list[str]) -> None:
    """Ensure tags are simple strings — no schema enforcement beyond that."""
    for tag in tags:
        if not isinstance(tag, str) or not tag.strip():
            raise ProviderError(
                f"Provider '{provider_key}': tag {tag!r} must be a non-empty string."
            )


def identify_provider(ips: list[str]) -> str | None:
    """Return the provider key whose IP list contains any of `ips`, else None.

    Strips DoT '#hostname' suffixes before comparing. Matches on ANY common
    IP — providers rarely share IPs, so a single match is enough to identify.
    """
    if not ips:
        return None

    plain_ips = {ip.split("#", 1)[0] for ip in ips}

    try:
        providers = load_providers()
    except ProviderError:
        return None

    for key, provider in providers.items():
        provider_ips = set(provider.ipv4) | set(provider.ipv6)
        if plain_ips & provider_ips:
            return key
    return None


def get_config_path() -> Path:
    """Return the path of the active providers config file (for `dnser status` display)."""
    return _find_config_file()
