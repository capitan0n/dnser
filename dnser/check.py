"""Provider reachability + latency check.

For each provider we send DNS queries over UDP/53:
  1. One cached lookup for a stable well-known name (example.com). Every
     real resolver has this in cache, so it measures raw responsiveness.
  2. Two uncached lookups for randomized subdomains of example.com. These
     force the resolver out to the authoritative servers, revealing
     real-world resolution latency.

Both numbers are reported separately. A resolver with a fast cached hit
but slow uncached time is near you but far from the origin; a slow cached
hit is just slow or congested regardless of workload.

No external dependencies — the query packets are built by hand. That is
fine because we only ever send one query type (A) and never parse the
answer beyond the header.

example.com (IANA-reserved) is the base name because it is never blocked,
never geo-restricted, and never disappears, and because nobody publishes
wildcard records under it — so a random label under it is guaranteed to
reach the authoritative servers.
"""

from __future__ import annotations

import secrets
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
_LABEL_ALPHABET = string.ascii_lowercase + string.digits

# RCODEs that mean "the resolver did its job and answered".
#   0 = NOERROR
#   3 = NXDOMAIN — the *correct* answer for our random uncached labels,
#       since example.com has no wildcard. Treating it as a failure would
#       make every uncached probe fail against every provider.
_OK_RCODES = frozenset({0, 3})


@dataclass
class CheckResult:
    """Outcome of probing a single provider.

    Latencies are milliseconds; None means that probe did not produce a
    number (see `error`). A provider counts as ok if at least the cached
    probe succeeded — one that answers cached lookups but times out on
    authoritative queries is still usable, just slow for anything new.
    """

    provider_key: str
    ok: bool
    cached_ms: float | None  # single cached-hit latency
    uncached_ms: float | None  # average across uncached probes
    error: str | None  # short reason, None on clean success


def check_all(providers: dict[str, Provider]) -> list[CheckResult]:
    """Probe every provider in parallel. Returns results in input order.

    Only the first IPv4 server per provider is probed — enough to know
    whether the provider is reachable at all.
    """
    keys = list(providers.keys())
    if not keys:
        return []

    results_by_key: dict[str, CheckResult] = {}
    # One thread per provider, capped so a huge custom list can't spawn hundreds.
    max_workers = min(len(keys), 16)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_check_one, providers[key]): key for key in keys}
        for future in as_completed(futures):
            key = futures[future]
            try:
                results_by_key[key] = future.result()
            except Exception as exc:  # noqa: BLE001 - never let one probe kill the run
                results_by_key[key] = CheckResult(
                    provider_key=key,
                    ok=False,
                    cached_ms=None,
                    uncached_ms=None,
                    error=f"internal error: {exc}",
                )

    return [results_by_key[key] for key in keys]


def _check_one(provider: Provider) -> CheckResult:
    """Run cached + uncached probes for one provider. Never raises."""
    if not provider.ipv4:
        return CheckResult(
            provider.key, ok=False, cached_ms=None, uncached_ms=None,
            error="no IPv4 servers to probe",
        )

    # DoT-only providers (Mullvad) answer plain UDP/53 with REFUSED. Rather
    # than mislead the user into thinking they are broken, skip the probe.
    if provider.requires_dot:
        return CheckResult(
            provider.key, ok=True, cached_ms=None, uncached_ms=None,
            error="DoT-only — use `dnser set <key> --dot` to try it",
        )

    target = provider.ipv4[0]

    # 1. Cached probe. If this fails the provider is down from our point of
    #    view, so don't waste two more timeouts on the uncached ones.
    cached_ms, cached_err = _probe(target, _CACHED_NAME)
    if cached_ms is None:
        return CheckResult(
            provider.key, ok=False, cached_ms=None, uncached_ms=None, error=cached_err
        )

    # 2. Uncached probes. Individual failures are tolerable; we average
    #    whatever came back and say so.
    samples: list[float] = []
    last_error: str | None = None
    for _ in range(_UNCACHED_PROBES):
        latency, err = _probe(target, f"{_random_label()}.{_CACHED_NAME}")
        if latency is None:
            last_error = err
        else:
            samples.append(latency)

    if not samples:
        return CheckResult(
            provider.key, ok=True, cached_ms=cached_ms, uncached_ms=None,
            error=f"uncached failed: {last_error or 'unknown'}",
        )

    average = sum(samples) / len(samples)
    if len(samples) < _UNCACHED_PROBES:
        note = f"uncached partial ({len(samples)}/{_UNCACHED_PROBES})"
        if last_error:
            note += f": {last_error}"
        return CheckResult(
            provider.key, ok=True, cached_ms=cached_ms, uncached_ms=average, error=note
        )

    return CheckResult(
        provider.key, ok=True, cached_ms=cached_ms, uncached_ms=average, error=None
    )


def _probe(target_ip: str, qname: str) -> tuple[float | None, str | None]:
    """Send one A-query, return (latency_ms, error). Exactly one is None."""
    packet, question = _build_a_query(qname)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as exc:
        return None, f"socket error: {exc}"

    sock.settimeout(_QUERY_TIMEOUT_S)
    try:
        # connect() binds the socket to this peer, so the kernel drops
        # datagrams from anyone else. Without it, any host on the path or
        # the local network could inject a reply and skew the measurement.
        try:
            sock.connect((target_ip, _DNS_PORT))
        except OSError as exc:
            return None, f"network error: {exc.strerror or exc}"

        start = time.perf_counter()
        try:
            sock.send(packet)
            response = sock.recv(4096)
        except TimeoutError:
            return None, "timeout"
        except OSError as exc:
            return None, f"network error: {exc.strerror or exc}"
        elapsed_ms = (time.perf_counter() - start) * 1000.0
    finally:
        sock.close()

    error = validate_response(response, packet, question)
    if error is not None:
        return None, error
    return elapsed_ms, None


def validate_response(response: bytes, packet: bytes, question: bytes) -> str | None:
    """Return an error string if the response isn't a valid reply, else None."""
    if len(response) < 12:
        return "malformed response"
    if struct.unpack(">H", response[:2])[0] != struct.unpack(">H", packet[:2])[0]:
        return "transaction ID mismatch"
    if not response[2] & 0x80:
        return "not a response packet"
    # Echo the question back verbatim, or it isn't an answer to our query.
    if response[12 : 12 + len(question)] != question:
        return "question section mismatch"
    rcode = response[3] & 0x0F
    if rcode not in _OK_RCODES:
        return f"resolver error (RCODE={rcode})"
    return None


def _random_label() -> str:
    """Return a 12-char random lowercase-alphanumeric DNS label.

    Long enough that collision with a real subdomain is impossible in
    practice, alphanumeric so we never trip RFC 1035 label rules (no
    leading or trailing hyphen). Drawn from `secrets` rather than
    `random` so the label — and with it the transaction ID space an
    off-path attacker would have to guess — is not predictable.
    """
    return "".join(secrets.choice(_LABEL_ALPHABET) for _ in range(12))


def _build_a_query(qname: str) -> tuple[bytes, bytes]:
    """Build a minimal A-record query. Returns (packet, question_section).

    Layout (RFC 1035):
      Header (12 bytes): ID, flags=0x0100 (standard query, recursion
                         desired), QDCOUNT=1, all other counts 0
      Question: QNAME (length-prefixed labels + null), QTYPE=A, QCLASS=IN
    """
    tx_id = secrets.randbelow(0x10000)
    header = struct.pack(">HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)

    qname_bytes = b""
    for label in qname.split("."):
        encoded = label.encode("ascii")
        qname_bytes += bytes([len(encoded)]) + encoded
    qname_bytes += b"\x00"

    question = qname_bytes + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question, question
