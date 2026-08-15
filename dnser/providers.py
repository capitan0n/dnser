"""Load and validate DNS provider presets from providers.json."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


# Provider file lookup order:
# 1. User override: ~/.config/dnser/providers.json (highest priority)
# 2. System install: /etc/dnser/providers.json
# 3. Bundled default: <package>/../config/providers.json (fallback)
_USER_CONFIG = Path.home() / ".config" / "dnser" / "providers.json"
_SYSTEM_CONFIG = Path("/etc/dnser/providers.json")
_BUNDLED_CONFIG = Path(__file__).parent.parent / "config" / "providers.json"


@dataclass
class Provider:
    """A DNS provider preset."""
    key: str                # short id, e.g. "cloudflare"
    name: str               # display name, e.g. "Cloudflare"
    description: str
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    dot_hostname: str | None = None   # for future DoT support
    doh_url: str | None = None        # for future DoH support

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
            providers[key] = Provider(
                key=key,
                name=data.get("name", key.title()),
                description=data.get("description", ""),
                ipv4=list(data.get("ipv4", [])),
                ipv6=list(data.get("ipv6", [])),
                dot_hostname=data.get("dot_hostname"),
                doh_url=data.get("doh_url"),
            )
        except (TypeError, ValueError) as e:
            raise ProviderError(f"Provider '{key}' is malformed: {e}") from e

    if not providers:
        raise ProviderError(f"No providers defined in {config_path}")

    return providers


def get_config_path() -> Path:
    """Return the path of the active providers config file (for `dnser status` display)."""
    return _find_config_file()
