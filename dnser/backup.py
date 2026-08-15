"""Backup storage for DNS state snapshots.

Snapshots are stored as JSON files under $XDG_STATE_HOME/dnser/backups/
(defaults to ~/.local/state/dnser/backups/). Filenames are timestamped so
they sort chronologically.

We keep the last N backups (default 10) and prune older ones automatically.

Sudo handling: when the tool is invoked with sudo, Path.home() returns
/root, which would silo backups away from the real user's account. We
detect SUDO_USER and write to the invoking user's home instead, so
`dnser restore` (without sudo) can still see and use the backups.
"""

from __future__ import annotations

import json
import os
import pwd
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from dnser.backends.base import BackupPayload


MAX_BACKUPS = 10


def _real_user_home() -> Path:
    """Return the invoking user's home directory, even under sudo.

    Order of resolution:
      1. If SUDO_USER is set (and not 'root'), use that user's pwd entry.
      2. Otherwise fall back to Path.home() (the current effective user).
    """
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            # SUDO_USER points to a nonexistent account — very unusual, fall through.
            pass
    return Path.home()


def _real_user_ids() -> tuple[int, int] | None:
    """Return (uid, gid) of the invoking user when running under sudo, else None.

    Used to chown newly-created backup files so the real user can read them
    without sudo. Returns None when not running under sudo (no chown needed).
    """
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")
    if sudo_uid and sudo_gid:
        try:
            return (int(sudo_uid), int(sudo_gid))
        except ValueError:
            return None
    return None


def _state_dir() -> Path:
    """Return the directory where backups live.

    Respects XDG_STATE_HOME, then falls back to $HOME/.local/state, using
    the real invoking user's home when running under sudo.
    """
    xdg = os.environ.get("XDG_STATE_HOME")
    if xdg:
        base = Path(xdg)
    else:
        base = _real_user_home() / ".local" / "state"
    return base / "dnser" / "backups"


def _chown_to_real_user(path: Path) -> None:
    """If running under sudo, hand ownership of `path` back to the real user."""
    ids = _real_user_ids()
    if ids is None:
        return
    uid, gid = ids
    try:
        os.chown(path, uid, gid)
    except OSError:
        # Best-effort; user can chown manually if needed.
        pass


def save(payload: BackupPayload) -> Path:
    """Serialize a snapshot to a timestamped JSON file. Returns its path.

    Also prunes old backups beyond MAX_BACKUPS.
    """
    directory = _state_dir()
    directory.mkdir(parents=True, exist_ok=True)
    # If we just created the directory tree while running under sudo, make
    # sure the user owns it — otherwise they can't write future backups.
    _chown_to_real_user(directory)
    # Walk up and chown intermediate dirs we may have created.
    for parent in (directory.parent, directory.parent.parent):
        if parent.exists():
            _chown_to_real_user(parent)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"{timestamp}.json"

    path.write_text(
        json.dumps(asdict(payload), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    _chown_to_real_user(path)

    _prune(directory)
    return path


def list_backups() -> list[Path]:
    """Return all backup paths, newest first."""
    directory = _state_dir()
    if not directory.exists():
        return []
    files = sorted(directory.glob("*.json"), reverse=True)
    return files


def load(path: Path) -> BackupPayload:
    """Load a snapshot from disk into a BackupPayload."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    return BackupPayload(
        backend_name=raw["backend_name"],
        data=raw["data"],
    )


def load_latest() -> BackupPayload | None:
    """Load the most recent snapshot, or None if none exists."""
    backups = list_backups()
    if not backups:
        return None
    return load(backups[0])


def _prune(directory: Path) -> None:
    """Delete oldest backups beyond MAX_BACKUPS."""
    files = sorted(directory.glob("*.json"), reverse=True)
    for old in files[MAX_BACKUPS:]:
        try:
            old.unlink()
        except OSError:
            pass
