"""Tests for the backup module: filenames, ordering, loading, pruning."""

from __future__ import annotations

import json

import pytest

from dnser import backup
from dnser.backends.base import BackupPayload


@pytest.fixture
def backup_dir(tmp_path, monkeypatch):
    """Redirect backup storage to a temp directory for each test."""
    directory = tmp_path / "backups"
    monkeypatch.setattr(backup, "_state_dir", lambda: directory)
    return directory


def _payload(name: str = "resolved") -> BackupPayload:
    return BackupPayload(backend_name=name, data={"dropin_content": None})


# ----------------------------------------------------------------------
# Filename shape
# ----------------------------------------------------------------------

class TestSaveFilenames:
    def test_filename_leads_with_timestamp_not_label(self, backup_dir):
        path = backup.save(_payload(), label="quad9")
        assert path.suffix == ".json"
        # Timestamp first is what makes lexicographic order chronological.
        assert path.stem[:8].isdigit()
        assert path.stem.endswith("_quad9")

    def test_save_without_label_uses_snapshot_suffix(self, backup_dir):
        assert backup.save(_payload()).stem.endswith("_snapshot")

    def test_label_is_sanitized(self, backup_dir):
        path = backup.save(_payload(), label="my provider/x")
        assert "/" not in path.name
        assert " " not in path.name
        assert "my-provider-x" in path.name

    def test_all_bad_label_falls_back_to_snapshot(self, backup_dir):
        assert backup.save(_payload(), label="////").stem.endswith("_snapshot")

    def test_same_second_saves_do_not_collide(self, backup_dir):
        first = backup.save(_payload(), label="quad9")
        second = backup.save(_payload(), label="quad9")
        assert first != second
        # And the newer one must still sort first.
        assert backup.list_backups()[0] == second


class TestSanitizeLabel:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("quad9", "quad9"),
            ("QUAD9", "quad9"),
            ("my_custom-dns", "my_custom-dns"),
            ("a/b", "a-b"),
            ("///hello///", "hello"),
            ("!!!", "snapshot"),
        ],
    )
    def test_sanitize(self, raw, expected):
        assert backup._sanitize_label(raw) == expected


# ----------------------------------------------------------------------
# Ordering — regression for the label-first sorting bug
# ----------------------------------------------------------------------

class TestOrdering:
    def test_newest_first_regardless_of_label(self, backup_dir):
        """A later backup must win even when its label sorts earlier.

        The old filename format ('<label>_<timestamp>') sorted by label,
        so 'quad9_<old>' beat 'cloudflare_<new>' and `restore` handed back
        a stale state.
        """
        backup_dir.mkdir(parents=True)
        old = backup_dir / "20260101T000000Z_quad9.json"
        new = backup_dir / "20260816T120000Z_cloudflare.json"
        for path in (old, new):
            path.write_text(json.dumps({"backend_name": "resolved", "data": {}}))

        assert backup.list_backups() == [new, old]

    def test_missing_directory_returns_empty(self, backup_dir):
        assert backup.list_backups() == []


# ----------------------------------------------------------------------
# Load
# ----------------------------------------------------------------------

class TestLoad:
    def test_round_trip(self, backup_dir):
        original = BackupPayload(
            backend_name="resolved",
            data={"dropin_content": "[Resolve]\nDNS=1.1.1.1\n"},
        )
        loaded = backup.load(backup.save(original, label="cloudflare"))
        assert loaded.backend_name == "resolved"
        assert loaded.data["dropin_content"] == "[Resolve]\nDNS=1.1.1.1\n"

    def test_malformed_json_raises_backup_error(self, backup_dir):
        backup_dir.mkdir(parents=True)
        bad = backup_dir / "20260816T120000Z_broken.json"
        bad.write_text("{ not json")
        with pytest.raises(backup.BackupError, match="Corrupt backup"):
            backup.load(bad)

    def test_missing_key_raises_backup_error(self, backup_dir):
        backup_dir.mkdir(parents=True)
        bad = backup_dir / "20260816T120000Z_broken.json"
        bad.write_text(json.dumps({"data": {}}))
        with pytest.raises(backup.BackupError, match="Corrupt backup"):
            backup.load(bad)


# ----------------------------------------------------------------------
# Pruning
# ----------------------------------------------------------------------

def test_prune_keeps_only_the_newest(backup_dir, monkeypatch):
    monkeypatch.setattr(backup, "MAX_BACKUPS", 3)
    backup_dir.mkdir(parents=True)
    for day in range(1, 6):
        path = backup_dir / f"202601{day:02d}T000000Z_snapshot.json"
        path.write_text(json.dumps({"backend_name": "resolved", "data": {}}))

    backup._prune(backup_dir)

    remaining = sorted(p.name for p in backup_dir.glob("*.json"))
    assert remaining == [
        "20260103T000000Z_snapshot.json",
        "20260104T000000Z_snapshot.json",
        "20260105T000000Z_snapshot.json",
    ]


# ----------------------------------------------------------------------
# State directory hardening
# ----------------------------------------------------------------------

class TestStateDir:
    def test_xdg_state_home_is_honored_for_normal_users(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
        monkeypatch.setattr(backup.os, "geteuid", lambda: 1000)
        assert backup._state_dir() == tmp_path / "state" / "dnser" / "backups"

    def test_root_ignores_xdg_state_home_outside_the_user_home(self, tmp_path, monkeypatch):
        """`sudo XDG_STATE_HOME=/ dnser set ...` must not steer us to /.

        Everything under the state dir gets chowned to the invoking user,
        so an attacker-chosen path would be a privilege escalation.
        """
        home = tmp_path / "home" / "alex"
        home.mkdir(parents=True)
        monkeypatch.setenv("XDG_STATE_HOME", "/")
        monkeypatch.setattr(backup.os, "geteuid", lambda: 0)
        monkeypatch.setattr(backup, "_real_user_home", lambda: home)

        assert backup._state_dir() == home / ".local" / "state" / "dnser" / "backups"
