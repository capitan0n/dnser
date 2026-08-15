"""Tests for backup module: labeled filenames, sanitization, listing."""

from __future__ import annotations

import pytest

from dnser import backup
from dnser.backends.base import BackupPayload


@pytest.fixture
def isolated_backup_dir(tmp_path, monkeypatch):
    """Redirect backup storage to a temp directory for each test."""
    monkeypatch.setattr(backup, "_state_dir", lambda: tmp_path / "backups")
    return tmp_path / "backups"


def _payload(name: str = "resolved") -> BackupPayload:
    return BackupPayload(backend_name=name, data={"dropin_content": None})


# ----------------------------------------------------------------------
# Filename shape
# ----------------------------------------------------------------------

class TestSaveFilenames:
    def test_save_with_label_prefixes_filename(self, isolated_backup_dir):
        path = backup.save(_payload(), label="quad9")
        assert path.name.startswith("quad9_")
        assert path.suffix == ".json"

    def test_save_without_label_uses_snapshot_prefix(self, isolated_backup_dir):
        path = backup.save(_payload())
        assert path.name.startswith("snapshot_")

    def test_label_is_sanitized(self, isolated_backup_dir):
        # Slashes and spaces are unsafe in filenames — must be replaced.
        path = backup.save(_payload(), label="my provider/x")
        # No unsafe chars in the produced name
        assert "/" not in path.name
        assert " " not in path.name
        # But the sanitized shape is preserved as best-effort readable
        assert "my-provider-x" in path.name

    def test_empty_or_all_bad_label_falls_back_to_snapshot(self, isolated_backup_dir):
        path = backup.save(_payload(), label="////")
        assert path.name.startswith("snapshot_")


# ----------------------------------------------------------------------
# Listing order still works with labels
# ----------------------------------------------------------------------

def test_list_returns_labelled_backups_newest_first(isolated_backup_dir):
    import time
    p1 = backup.save(_payload(), label="cloudflare")
    time.sleep(1)  # ensure distinct timestamps (they have second resolution)
    p2 = backup.save(_payload(), label="quad9")

    backups = backup.list_backups()
    assert len(backups) == 2
    # Newest first — quad9 was saved second
    assert backups[0] == p2
    assert backups[1] == p1


# ----------------------------------------------------------------------
# Load still works after labelling
# ----------------------------------------------------------------------

def test_load_labelled_backup_returns_correct_payload(isolated_backup_dir):
    original = BackupPayload(
        backend_name="resolved",
        data={"dropin_content": "[Resolve]\nDNS=1.1.1.1\n"},
    )
    path = backup.save(original, label="cloudflare")
    loaded = backup.load(path)
    assert loaded.backend_name == "resolved"
    assert loaded.data["dropin_content"] == "[Resolve]\nDNS=1.1.1.1\n"


# ----------------------------------------------------------------------
# Sanitization function
# ----------------------------------------------------------------------

class TestSanitizeLabel:
    def test_lowercase_alphanumeric_passes_through(self):
        assert backup._sanitize_label("quad9") == "quad9"

    def test_uppercase_is_lowered(self):
        assert backup._sanitize_label("QUAD9") == "quad9"

    def test_underscore_and_hyphen_preserved(self):
        assert backup._sanitize_label("my_custom-dns") == "my_custom-dns"

    def test_slash_becomes_hyphen(self):
        assert backup._sanitize_label("a/b") == "a-b"

    def test_leading_trailing_hyphens_stripped(self):
        assert backup._sanitize_label("///hello///") == "hello"

    def test_all_bad_chars_yields_snapshot_fallback(self):
        assert backup._sanitize_label("!!!") == "snapshot"
