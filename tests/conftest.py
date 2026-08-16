"""Shared test fixtures.

The subprocess helpers used to be copy-pasted into both backend test
modules; they live here now so there is one definition to keep correct.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

import dnser.providers as providers_module


@pytest.fixture(autouse=True)
def isolated_provider_config(tmp_path, monkeypatch):
    """Force every test onto the bundled providers.json.

    Without this, a developer's own ~/.config/dnser/providers.json would
    silently become the fixture under test and results would differ
    between machines.
    """
    monkeypatch.setattr(providers_module, "_USER_CONFIG", tmp_path / "no-user.json")
    monkeypatch.setattr(providers_module, "_SYSTEM_CONFIG", tmp_path / "no-system.json")


def completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    """Build a CompletedProcess-like object for subprocess.run mocks."""
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


class RunSequencer:
    """Return a queued sequence of results across successive calls.

    Raises on an unexpected extra call, so a test fails loudly when the
    code under test starts issuing commands the test didn't anticipate.
    """

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[list[str]] = []

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        if not self.responses:
            raise AssertionError(f"Unexpected extra subprocess call: {args}")
        return self.responses.pop(0)

    @property
    def remaining(self) -> int:
        return len(self.responses)


@pytest.fixture
def sequencer(monkeypatch):
    """Install a RunSequencer over subprocess.run and hand it back."""

    def _install(stdouts: list[str]) -> RunSequencer:
        seq = RunSequencer([completed(stdout=out) for out in stdouts])
        monkeypatch.setattr(subprocess, "run", seq)
        return seq

    return _install


@pytest.fixture
def any_run(monkeypatch):
    """Stub subprocess.run so every command succeeds silently."""
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed())
