"""DNS backend implementations."""

from dnser.backends.base import (
    Backend,
    BackendError,
    BackupPayload,
    DNSState,
    Scope,
)
from dnser.backends.networkmanager import NetworkManagerBackend
from dnser.backends.resolved import ResolvedBackend

__all__ = [
    "Backend",
    "BackendError",
    "BackupPayload",
    "DNSState",
    "Scope",
    "NetworkManagerBackend",
    "ResolvedBackend",
]
