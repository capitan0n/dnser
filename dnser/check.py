"""Provider reachability + latency check.

For each provider we send three DNS queries over UDP/53:
  1. A cached lookup for a stable, well-known name (example.com).
     Any real resolver will have this pre-cached, so this measures
     the resolver's raw responsiveness.
  2. Two uncached lookups for randomized subdomains of example.com.
     These force the resolver to actually reach out to authoritative
     servers, revealing real-world resolution latency (network path,
     authoritative server distance).

We report both numbers separately so the user sees the difference. A
resolver with fast cached-hit but slow uncached time is close to them
but far from origin authoritatives; one with slow cached-hit is just
slow / far / congested regardless of workload.

No external dependencies — we build DNS packets by hand. That's fine
because we only need one query type (A record) and don't parse the
answer beyond checking the response code.

We deliberately use example.com (IANA-reserved) as the base:
  - Never blocked, never geo-restricted, never disappears.
  - Random subdomains under it are guaranteed to be authoritative-only
    lookups since no one publishes wildcard records for it.
"""

from __future__ import annotations

import random
import socket
import string
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from dnser.providers import Provider


# The cached probe: a name every open resolver on Earth has in cache.
_CACHED_NAME = "example.com"
# Number of uncached probes per provider — averaged in the result.
_UNCACHED_PROBES = 2
_QUERY_TIMEOUT_S = 2.0
_DNS_PORT = 53


@dataclass
class CheckResult:
    """Outcome of probing a single provider.

    All latency numbers are milliseconds. `None` means the probe failed
    (see `error` for the reason). A provider is reported ok if AT LEAST
    the cached probe succeeded — a resolver that answers cached lookups
    but times out on authoritative queries is still usable, just slow
    for anything new.
    """
    provider_key: str
    provider_name: str
    ok: bool
    cached_ms: float | None      # single cached-hit latency
    uncached_ms: float | None    # average across uncached probes
    error: str | None            # short reason on failure, None on success


def check_all(providers: dict[str, Provider]) -> list[CheckResult]:
    """Probe every provider in parallel. Returns results in input order.

    We probe only the first IPv4 server per provider — enough to know if
    the provider is reachable at all. If the primary is down but a
    secondary works, that's an edge case for later.
    """
    keys = list(providers.keys())
    results_by_key: dict[str, CheckResult] = {}

    # One thread per provider, capped so we don't spawn hundreds if the
    # user has a huge custom list.
    max_workers = min(len(keys), 16)
    if max_workers == 0:
        return []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_check_one, providers[key]): key
            for key in keys
        }
        for future in as_completed(futures):
            key = futures[future]
            try:
                results_by_key[key] = future.result()
            except Exception as e:
                # Belt-and-suspenders: _check_one should never raise, but
                # if it does we still return a result rather than crash.
                results_by_key[key] = CheckResult(
                    provider_key=key,
                    provider_name=providers[key].name,
                    ok=False,
                    cached_ms=None,
                    uncached_ms=None,
                    error=f"internal error: {e}",
                )

    return [results_by_key[key] for key in keys]


def _check_one(provider: Provider) -> CheckResult:
    """Run cached + uncached probes for one provider. Never raises."""
    if not provider.ipv4:
        return CheckResult(
            provider.key, provider.name, ok=False,
            cached_ms=None, uncached_ms=None,
            error="no IPv4 servers to probe",
        )

    # DoT-only providers (e.g. Mullvad) will refuse plain UDP/53 queries
    # and answer with RCODE=5 (REFUSED). Rather than mislead users into
    # thinking the provider is broken, we skip the probe entirely and
    # tell them to test it via `dnser set <key> --dot` instead.
    if provider.requires_dot:
        return CheckResult(
            provider.key, provider.name, ok=True,
            cached_ms=None, uncached_ms=None,
            error="DoT-only — use `dnser set --dot` to try it",
        )

    target = provider.ipv4[0]

    # 1. Cached probe. If this fails, the provider is effectively down
    #    from our POV — don't bother running the uncached ones.
    cached_ms, cached_err = _probe(target, _CACHED_NAME)
    if cached_ms is None:
        return CheckResult(
            provider.key, provider.name, ok=False,
            cached_ms=None, uncached_ms=None,
            error=cached_err,
        )

    # 2. Uncached probes — random subdomains so the resolver has to
    #    walk to the authoritatives. Individual failures are ok; we
    #    average whatever succeeded and report if some timed out.
    uncached_samples: list[float] = []
    last_uncached_err: str | None = None
    for _ in range(_UNCACHED_PROBES):
        name = f"{_random_label()}.{_CACHED_NAME}"
        latency, err = _probe(target, name)
        if latency is not None:
            uncached_samples.append(latency)
        else:
            last_uncached_err = err

    if uncached_samples:
        uncached_avg: float | None = sum(uncached_samples) / len(uncached_samples)
        # Partial success: some uncached probes failed but not all.
        # Cached still works, average is meaningful, just note it.
        if len(uncached_samples) < _UNCACHED_PROBES:
            partial_note = (
                f"uncached partial ({len(uncached_samples)}/{_UNCACHED_PROBES})"
                + (f": {last_uncached_err}" if last_uncached_err else "")
            )
            return CheckResult(
                provider.key, provider.name, ok=True,
                cached_ms=cached_ms, uncached_ms=uncached_avg,
                error=partial_note,
            )
        return CheckResult(
            provider.key, provider.name, ok=True,
            cached_ms=cached_ms, uncached_ms=uncached_avg,
            error=None,
        )

    # All uncached probes failed but the cached one worked.
    # Still usable, just report the situation clearly.
    return CheckResult(
        provider.key, provider.name, ok=True,
        cached_ms=cached_ms, uncached_ms=None,
        error=f"uncached failed: {last_uncached_err or 'unknown'}",
    )


def _probe(target_ip: str, qname: str) -> tuple[float | None, str | None]:
    """Send one A-query, return (latency_ms, error). One is always None."""
    packet = _build_a_query(qname)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(_QUERY_TIMEOUT_S)
    try:
        start = time.perf_counter()
        try:
            sock.sendto(packet, (target_ip, _DNS_PORT))
            response, _ = sock.recvfrom(4096)
        except socket.timeout:
            return None, "timeout"
        except OSError as e:
            return None, f"network error: {e.strerror or e}"
        elapsed_ms = (time.perf_counter() - start) * 1000.0
    finally:
        sock.close()

    # Header sanity: must be >= 12 bytes and transaction ID must match.
    if len(response) < 12:
        return None, "malformed response"
    resp_id = struct.unpack(">H", response[:2])[0]
    sent_id = struct.unpack(">H", packet[:2])[0]
    if resp_id != sent_id:
        return None, "transaction ID mismatch"
    # Low nibble of byte 3 is RCODE. 0 = success; anything else means
    # the resolver answered but refused / failed — treat as failure.
    rcode = response[3] & 0x0F
    if rcode != 0:
        return None, f"resolver refused (RCODE={rcode})"

    return elapsed_ms, None


def _random_label() -> str:
    """Return a 12-char random lowercase-alphanumeric label.

    Length picked to make collision with an existing subdomain effectively
    impossible without being wasteful. Alphanumeric only so we never hit
    RFC 1035 label validation edge cases (no hyphen at start/end etc.).
    """
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=12))


def _build_a_query(qname: str) -> bytes:
    """Build a minimal DNS query packet for an A record.

    Layout (RFC 1035):
      Header (12 bytes): ID, flags=0x0100 (standard query, recursion desired),
                         QDCOUNT=1, other counts=0
      Question: QNAME (length-prefixed labels + null), QTYPE=A(1), QCLASS=IN(1)
    """
    tx_id = random.randint(0, 0xFFFF)
    flags = 0x0100          # standard query, recursion desired
    header = struct.pack(">HHHHHH", tx_id, flags, 1, 0, 0, 0)

    qname_bytes = b""
    for label in qname.split("."):
        encoded = label.encode("ascii")
        qname_bytes += bytes([len(encoded)]) + encoded
    qname_bytes += b"\x00"

    question = qname_bytes + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question
