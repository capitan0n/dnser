"""Small utility helpers reused across the codebase."""

from __future__ import annotations

import os
import sys


def sudo_hint() -> str:
    """Build a copy-pasteable sudo command to re-run the current invocation.

    We echo the argv verbatim (with the resolved script path) so the user
    doesn't have to figure out venv paths themselves.
    """
    executable = sys.argv[0] if sys.argv else "dnser"
    args = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else ""
    return f"sudo {executable} {args}".rstrip()


def running_as_root() -> bool:
    """Return True if the current process runs with effective uid 0."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # geteuid is Unix-only; on other OSes we say "not root" and let
        # subsequent operations fail naturally with a permission error.
        return False
