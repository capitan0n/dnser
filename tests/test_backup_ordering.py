from dnser import backup


def _touch(directory, name):
    """Create an empty backup file; contents are irrelevant to ordering."""
    (directory / name).write_text("{}", encoding="utf-8")


def test_list_backups_orders_by_embedded_timestamp(tmp_path, monkeypatch):
    """Newest-first ordering must follow the embedded UTC timestamp, not a
    plain lexicographic sort — otherwise legacy 'label_timestamp.json' files
    (label sorts after digits) masquerade as the newest backup.
    """
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    # Root ignores XDG_STATE_HOME outside the user's home (see _state_dir);
    # pretend to be unprivileged so the test also passes in root containers.
    monkeypatch.setattr(backup.os, "geteuid", lambda: 1000)

    backups_dir = tmp_path / "dnser" / "backups"
    backups_dir.mkdir(parents=True)

    # Mixed formats: current timestamp-first and legacy label-first.
    _touch(backups_dir, "20260823T104148Z_opendns.json")  # newest
    _touch(backups_dir, "20260823T104128Z_quad9.json")
    _touch(backups_dir, "quad9_20260816T132353Z.json")  # legacy, older
    _touch(backups_dir, "cloudflare_20260815T232936Z.json")  # legacy, oldest

    ordered = [p.name for p in backup.list_backups()]

    assert ordered == [
        "20260823T104148Z_opendns.json",
        "20260823T104128Z_quad9.json",
        "quad9_20260816T132353Z.json",
        "cloudflare_20260815T232936Z.json",
    ]


def test_prune_keeps_newest_across_mixed_formats(tmp_path, monkeypatch):
    """Pruning must delete the oldest by real age, so a legacy-named file that
    happens to sort high lexicographically is not mistaken for a keeper.
    """
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    monkeypatch.setattr(backup, "MAX_BACKUPS", 2)

    backups_dir = tmp_path / "dnser" / "backups"
    backups_dir.mkdir(parents=True)

    _touch(backups_dir, "20260823T104148Z_opendns.json")  # newest, keep
    _touch(backups_dir, "20260823T104128Z_quad9.json")  # keep
    _touch(backups_dir, "quad9_20260816T132353Z.json")  # legacy, prune

    backup._prune(backups_dir)

    remaining = sorted(p.name for p in backups_dir.glob("*.json"))
    assert remaining == [
        "20260823T104128Z_quad9.json",
        "20260823T104148Z_opendns.json",
    ]
