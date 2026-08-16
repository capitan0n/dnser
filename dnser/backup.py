"""Backup storage for DNS state snapshots.

Snapshots are JSON files under $XDG_STATE_HOME/dnser/backups/ (default
~/.local/state/dnser/backups/). Filenames lead with a UTC timestamp so a
plain lexicographic sort is also a chronological sort:

    20260816T142201Z_quad9.json

We keep the last MAX_BACKUPS and prune older ones automatically.

Running under sudo: Path.home() would return /root and silo the backups
away from the account that will later run `dnser restore`. We resolve the
invoking user from SUDO_USER instead. Because that means root touching a
user-owned directory, every operation first checks the directory is not a
symlink and is owned by root or that same user — otherwise an unprivileged
process could steer root's writes and deletions elsewhere.
"""

from __future__ import annotations

import json
import os
import pwd
import stat
import string
from contextlib import suppress
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from dnser.backends.base import BackupPayload

MAX_BACKUPS = 10


class BackupError(Exception):
    """Raised when a backup cannot be written, read, or trusted."""


def _real_user_home() -> Path:
    """Return the invoking user's home directory, even under sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            # SUDO_USER names a nonexistent account — very unusual, fall through.
            pass
    return Path.home()


def _real_user_ids() -> tuple[int, int] | None:
    """Return (uid, gid) of the invoking user under sudo, else None."""
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

    Respects XDG_STATE_HOME, but when running as root that variable is
    attacker-controllable via `sudo XDG_STATE_HOME=... dnser ...`, and
    everything below gets chowned to the invoking user. So under root we
    only honor it if it actually points inside that user's home.
    """
    home = _real_user_home()
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else home / ".local" / "state"

    if os.geteuid() == 0 and xdg:
        try:
            resolved = base.resolve()
        except OSError:
            resolved = base
        if resolved != home and home not in resolved.parents:
            base = home / ".local" / "state"

    return base / "dnser" / "backups"


def _chown_to_real_user(path: Path) -> None:
    """Under sudo, hand ownership of `path` back to the invoking user."""
    ids = _real_user_ids()
    if ids is None:
        return
    uid, gid = ids
    with suppress(OSError):
        os.chown(path, uid, gid)


def _assert_safe_dir(directory: Path) -> None:
    """Refuse to write or delete as root inside a directory we don't trust."""
    if os.geteuid() != 0:
        return
    ids = _real_user_ids()
    allowed = {0, ids[0]} if ids else {0}
    for path in (directory, directory.parent):
        try:
            info = path.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise BackupError(f"{path} is a symlink — refusing to use it as root.")
        if info.st_uid not in allowed:
            raise BackupError(
                f"{path} is owned by uid {info.st_uid}, which is neither root nor "
                "the invoking user — refusing to write backups there."
            )


def _ensure_state_dir() -> Path:
    """Create the backup directory if needed and return it, safely."""
    directory = _state_dir()
    # Only chown what we actually create — never pre-existing parents.
    created: list[Path] = []
    for candidate in (directory.parent, directory):
        if not candidate.exists():
            created.append(candidate)
    directory.mkdir(parents=True, exist_ok=True)
    for path in created:
        _chown_to_real_user(path)
    _assert_safe_dir(directory)
    return directory


def save(payload: BackupPayload, label: str | None = None) -> Path:
    """Serialize a snapshot to a timestamped JSON file. Returns its path.

    The filename is '<timestamp>_<label>.json'. Timestamp first so that
    sorting by name is sorting by age — putting the label first would make
    'quad9_...' sort after 'cloudflare_...' regardless of when each ran,
    and `restore` would then hand back the wrong state.

    Labels are reduced to [a-z0-9_-]; anything else becomes '-'.
    """
    directory = _ensure_state_dir()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_label = _sanitize_label(label) if label else "snapshot"
    path = _unique_path(directory, timestamp, safe_label)

    content = json.dumps(asdict(payload), indent=2, ensure_ascii=False)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
    except OSError as exc:
        raise BackupError(f"Failed to write backup {path}: {exc}") from exc
    _chown_to_real_user(path)

    _prune(directory)
    return path


def _unique_path(directory: Path, timestamp: str, label: str) -> Path:
    """Return a non-colliding path for two saves within the same second.

    The disambiguator is a letter appended to the timestamp rather than a
    digit or dash, because it has to sort *after* the '_' separator —
    otherwise the second save of a given second would sort as the older
    one and `restore` would pick the wrong file.
    """
    path = directory / f"{timestamp}_{label}.json"
    if not path.exists():
        return path
    for suffix in string.ascii_lowercase:
        candidate = directory / f"{timestamp}{suffix}_{label}.json"
        if not candidate.exists():
            return candidate
    raise BackupError("Too many backups written within the same second.")


def _sanitize_label(label: str) -> str:
    """Reduce a label to characters safe for filenames on any filesystem."""
    cleaned = [ch if (ch.isalnum() or ch in "_-") else "-" for ch in label.lower()]
    return "".join(cleaned).strip("-") or "snapshot"


def list_backups() -> list[Path]:
    """Return all backup paths, newest first.

    Safe because filenames lead with a fixed-width UTC timestamp, so
    lexicographic order equals chronological order.
    """
    directory = _state_dir()
    if not directory.is_dir():
        return []
    return sorted(directory.glob("*.json"), reverse=True)


def load(path: Path) -> BackupPayload:
    """Load a snapshot from disk. Raises BackupError on corrupt files."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return BackupPayload(
            backend_name=str(raw["backend_name"]),
            data=raw["data"],
        )
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise BackupError(f"Corrupt backup {path.name}: {exc}") from exc


def _prune(directory: Path) -> None:
    """Delete the oldest backups beyond MAX_BACKUPS."""
    files = sorted(directory.glob("*.json"), reverse=True)
    for old in files[MAX_BACKUPS:]:
        with suppress(OSError):
            old.unlink()
