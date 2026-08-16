"""Load and validate DNS provider presets from providers.json."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path

# Provider file lookup order:
#   1. User override:  ~/.config/dnser/providers.json  (highest priority)
#   2. System install: /etc/dnser/providers.json
#   3. Bundled default: the copy shipped inside the package
_USER_CONFIG = Path.home() / ".config" / "dnser" / "providers.json"
_SYSTEM_CONFIG = Path("/etc/dnser/providers.json")

# Hostnames end up inside a root-owned resolved drop-in as 'IP#hostname',
# so they are validated strictly: no whitespace, no newlines, no way to
# break out of the DNS= line and inject extra directives.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$",
    re.IGNORECASE,
)


def _bundled_config() -> Path:
    """Return the path of the providers.json shipped inside the package.

    Resolved through importlib.resources so it works identically for an
    editable install, a wheel, and an sdist — no '../' path games.
    """
    return Path(str(files("dnser") / "providers.json"))


@dataclass
class Provider:
    """A DNS provider preset."""

    key: str  # short id, e.g. "cloudflare"
    name: str  # display name, e.g. "Cloudflare"
    description: str
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    dot_hostname: str | None = None  # for DoT certificate verification
    tags: list[str] = field(default_factory=list)  # short labels for display
    # Some providers (notably Mullvad) refuse plain UDP/53 and answer only
    # over DoT/DoH. `dnser check` skips plain probes for these, and
    # `dnser set` refuses to configure them without --dot.
    requires_dot: bool = False

    def all_servers(self, include_ipv6: bool = True) -> list[str]:
        """Return all DNS server IPs (IPv4 first, then IPv6 if requested)."""
        servers = list(self.ipv4)
        if include_ipv6:
            servers.extend(self.ipv6)
        return servers

    def all_servers_dot(self, include_ipv6: bool = True) -> list[str]:
        """Return servers as 'IP#hostname' for DoT certificate verification.

        Falls back to plain IPs when the preset defines no DoT hostname.
        """
        if not self.dot_hostname:
            return self.all_servers(include_ipv6=include_ipv6)
        return [f"{ip}#{self.dot_hostname}" for ip in self.all_servers(include_ipv6=include_ipv6)]


class ProviderError(Exception):
    """Raised when provider config is missing or malformed."""


def _find_config_file() -> Path:
    """Return the first existing config file: user, then system, then bundled."""
    bundled = _bundled_config()
    for candidate in (_USER_CONFIG, _SYSTEM_CONFIG, bundled):
        if candidate.is_file():
            return candidate
    raise ProviderError(
        "No providers config found. Looked in:\n"
        f"  {_USER_CONFIG}\n  {_SYSTEM_CONFIG}\n  {bundled}"
    )


def load_providers() -> dict[str, Provider]:
    """Load all providers from the first available config file.

    Returns a dict keyed by provider short-id (e.g. 'cloudflare').
    Raises ProviderError on a missing file or malformed content.
    """
    config_path = _find_config_file()

    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ProviderError(f"Malformed JSON in {config_path}: {exc}") from exc
    except OSError as exc:
        raise ProviderError(f"Cannot read {config_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ProviderError(f"{config_path}: expected a JSON object at top level")

    providers: dict[str, Provider] = {}
    for key, data in raw.items():
        if not isinstance(data, dict):
            raise ProviderError(
                f"Provider '{key}': expected an object, got {type(data).__name__}"
            )
        try:
            ipv4 = list(data.get("ipv4", []))
            ipv6 = list(data.get("ipv6", []))
            tags = list(data.get("tags", []))
            # Validate everything before accepting the preset — catching a
            # typo here beats a cryptic nmcli/resolvectl failure later, and
            # catching a malicious hostname here stops a config injection.
            _validate_ips(key, ipv4, expected_version=4)
            _validate_ips(key, ipv6, expected_version=6)
            _validate_tags(key, tags)
            dot_hostname = _validate_dot_hostname(key, data.get("dot_hostname"))
            providers[key] = Provider(
                key=key,
                name=str(data.get("name", key.title())),
                description=str(data.get("description", "")),
                ipv4=ipv4,
                ipv6=ipv6,
                dot_hostname=dot_hostname,
                tags=tags,
                requires_dot=bool(data.get("requires_dot", False)),
            )
        except (TypeError, ValueError) as exc:
            raise ProviderError(f"Provider '{key}' is malformed: {exc}") from exc

    if not providers:
        raise ProviderError(f"No providers defined in {config_path}")

    return providers


def _validate_ips(provider_key: str, ips: list[str], expected_version: int) -> None:
    """Raise ProviderError if any IP is malformed or of the wrong family."""
    for ip in ips:
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ProviderError(
                f"Provider '{provider_key}': '{ip}' is not a valid IP address ({exc})."
            ) from exc
        if parsed.version != expected_version:
            raise ProviderError(
                f"Provider '{provider_key}': '{ip}' is IPv{parsed.version}, "
                f"but appears in the ipv{expected_version} list."
            )


def _validate_tags(provider_key: str, tags: list[str]) -> None:
    """Ensure tags are simple non-empty strings — no schema beyond that."""
    for tag in tags:
        if not isinstance(tag, str) or not tag.strip():
            raise ProviderError(
                f"Provider '{provider_key}': tag {tag!r} must be a non-empty string."
            )


def _validate_dot_hostname(provider_key: str, value: object) -> str | None:
    """Return a validated DoT hostname, or None when unset."""
    if value is None:
        return None
    if not isinstance(value, str) or not _HOSTNAME_RE.match(value):
        raise ProviderError(
            f"Provider '{provider_key}': dot_hostname {value!r} is not a valid hostname."
        )
    return value


def identify_provider(
    ips: list[str], providers: dict[str, Provider] | None = None
) -> str | None:
    """Return the provider key whose IP list contains any of `ips`, else None.

    Strips DoT '#hostname' suffixes before comparing. Matching on any
    single shared IP is enough — providers do not share addresses.
    Pass `providers` to avoid re-reading the config file.
    """
    if not ips:
        return None

    plain_ips = {ip.split("#", 1)[0] for ip in ips}

    if providers is None:
        try:
            providers = load_providers()
        except ProviderError:
            return None

    for key, provider in providers.items():
        if plain_ips & (set(provider.ipv4) | set(provider.ipv6)):
            return key
    return None


def get_config_path() -> Path:
    """Return the path of the active providers config file, for display."""
    return _find_config_file()
