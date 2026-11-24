"""Tests for online SQLite backup, GFS retention, manifest verification, and safe restore."""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import tarfile
import io

import pytest

from bounded_ops.ops.sqlite_gfs_backup import (
    create_backup,
    prune_archives,
    retention_set,
    verify_and_extract,
)


def _create_sample_db(db_path: Path) -> None:
    with closing(sqlite3.connect(str(db_path))) as conn:
        conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, label TEXT NOT NULL)")
        conn.execute("INSERT INTO events (label) VALUES ('boot'), ('healthy')")
        conn.commit()


def test_backup_and_traversal_safe_restore_roundtrip(tmp_path: Path) -> None:
    db_path = tmp_path / "state.sqlite"
    _create_sample_db(db_path)

    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "snapshot.json").write_text('{"v":1}', encoding="utf-8")

    out_dir = tmp_path / "backups"
    marker = tmp_path / "last_backup.json"
    archive = create_backup(
        db_path,
        out_dir,
        artifact_tree=artifact_dir,
        status_file=marker,
        now=datetime(2026, 11, 20, 3, 20, tzinfo=timezone.utc),
    )
    assert archive.is_file()
    assert Path(f"{archive}.sha256").is_file()
    assert marker.is_file()

    restore_dir = tmp_path / "restored"
    manifest = verify_and_extract(archive, restore_dir)
    assert manifest["database"]["integrity_check"] == "ok"
    assert manifest["database"]["tables"]["events"] == 2
    assert (restore_dir / "artifact_tree" / "snapshot.json").read_text(encoding="utf-8") == '{"v":1}'

    with closing(sqlite3.connect(str(restore_dir / "state.sqlite"))) as conn:
        rows = conn.execute("SELECT label FROM events ORDER BY id").fetchall()
    assert rows == [("boot",), ("healthy",)]

    # Non-empty restore directory must be refused
    with pytest.raises(FileExistsError):
        verify_and_extract(archive, restore_dir)


def test_gfs_retention_policy_keeps_7_daily_4_weekly_6_monthly(tmp_path: Path) -> None:
    out_dir = tmp_path / "gfs"
    out_dir.mkdir()
    base = datetime(2026, 11, 20, 3, 20, tzinfo=timezone.utc)

    # Create 220 daily backup files spanning ~7.3 months
    created = []
    for day_offset in range(220):
        dt = base - timedelta(days=day_offset)
        name = f"bounded-ops-{dt.strftime('%Y%m%dT%H%M%SZ')}.tar.gz"
        p = out_dir / name
        p.write_bytes(b"tar")
        Path(f"{p}.sha256").write_text("0" * 64, encoding="ascii")
        created.append(p)

    keep = retention_set(created)
    # 7 most recent daily + up to 4 weekly + up to 6 monthly (with overlaps <= 17)
    assert len(keep) <= 17
    assert all(p in keep for p in created[:7])

    removed = prune_archives(out_dir)
    assert len(removed) == len(created) - len(keep)
    remaining = sorted(out_dir.glob("bounded-ops-*.tar.gz"))
    assert set(remaining) == keep


def test_restore_rejects_traversal_symlinks_and_tampered_checksum(tmp_path: Path) -> None:
    # 1. Path traversal archive
    traversal_tar = tmp_path / "traversal.tar.gz"
    with tarfile.open(traversal_tar, "w:gz") as tf:
        for name, data in (
            ("manifest.json", b'{"files":{}}'),
            ("state.sqlite", b"bad"),
            ("../escape.txt", b"pwn"),
        ):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

    with pytest.raises(ValueError, match="Unsafe backup member"):
        verify_and_extract(traversal_tar, tmp_path / "out1")

    # 2. Symlink member archive
    symlink_tar = tmp_path / "symlink.tar.gz"
    with tarfile.open(symlink_tar, "w:gz") as tf:
        for name, data in (("manifest.json", b'{"files":{}}'), ("state.sqlite", b"bad")):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        sym = tarfile.TarInfo(name="artifact_tree/link")
        sym.type = tarfile.SYMTYPE
        sym.linkname = "/etc/passwd"
        tf.addfile(sym)

    with pytest.raises(ValueError, match="Unsafe backup member"):
        verify_and_extract(symlink_tar, tmp_path / "out2")

    # 3. Tampered checksum in valid archive
    db_path = tmp_path / "db.sqlite"
    _create_sample_db(db_path)
    valid = create_backup(db_path, tmp_path / "bkp")

    tampered = tmp_path / "tampered.tar.gz"
    with tarfile.open(valid, "r:gz") as src, tarfile.open(tampered, "w:gz") as dst:
        for member in src.getmembers():
            raw = src.extractfile(member).read() if member.isreg() else b""
            if member.name == "manifest.json":
                manifest = __import__("json").loads(raw.decode("utf-8"))
                manifest["files"]["state.sqlite"]["sha256"] = "f" * 64
                raw = __import__("json").dumps(manifest).encode("utf-8")
            info = tarfile.TarInfo(name=member.name)
            info.size = len(raw)
            dst.addfile(info, io.BytesIO(raw))

    with pytest.raises(ValueError, match="checksum verification failed"):
        verify_and_extract(tampered, tmp_path / "out3")
