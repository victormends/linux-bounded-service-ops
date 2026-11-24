"""Online SQLite backup, SHA-256 manifest, GFS retention, and traversal-safe restore."""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import tarfile
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

DEFAULT_ARCHIVE_PREFIX = "bounded-ops-"
ALLOWED_BASE_FILES = frozenset({"manifest.json", "state.sqlite"})


def sha256_file(path: Path) -> str:
    """Compute streaming SHA-256 hex digest for a file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verified_sqlite_copy(source: Path, destination: Path) -> Dict[str, Any]:
    """Perform an online ``sqlite3.Connection.backup()`` and verify integrity."""
    if not source.is_file():
        raise FileNotFoundError(f"Operational SQLite database not found: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(str(source))) as source_db:
        with closing(sqlite3.connect(str(destination))) as backup_db:
            source_db.backup(backup_db)

    table_counts: Dict[str, int] = {}
    with closing(sqlite3.connect(str(destination))) as connection:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError(f"Backup SQLite integrity check failed: {integrity}")
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        ]
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            table_counts[table] = int(
                connection.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0]
            )
    return {"integrity_check": integrity, "tables": table_counts}


def copy_regular_tree(source: Path, destination: Path) -> Dict[str, Any]:
    """Copy a directory tree strictly rejecting symlinks and non-regular entries."""
    if not source.exists():
        return {"present": False, "files": 0, "bytes": 0}
    if not source.is_dir() or source.is_symlink():
        raise RuntimeError("Artifact archive source must be a regular directory")

    file_count = 0
    total_bytes = 0
    for base, directories, names in os.walk(source, followlinks=False):
        current = Path(base)
        relative = current.relative_to(source)
        target_dir = destination / relative
        target_dir.mkdir(parents=True, exist_ok=True)
        for directory in directories:
            item = current / directory
            if item.is_symlink():
                raise RuntimeError(f"Artifact tree contains a symlink: {item}")
        for name in names:
            item = current / name
            if item.is_symlink() or not item.is_file():
                raise RuntimeError(f"Artifact tree contains non-regular entry: {item}")
            copied = target_dir / name
            shutil.copy2(item, copied)
            file_count += 1
            total_bytes += copied.stat().st_size
    return {"present": True, "files": file_count, "bytes": total_bytes}


def retention_set(
    archives: Iterable[Path],
    *,
    prefix: str = DEFAULT_ARCHIVE_PREFIX,
    daily_keep: int = 7,
    weekly_keep: int = 4,
    monthly_keep: int = 6,
) -> Set[Path]:
    """Select backups to retain under Grandfather-Father-Son (GFS) rotation."""
    dated: List[Tuple[Path, datetime]] = []
    for archive in archives:
        name = archive.name
        if not name.startswith(prefix) or not name.endswith(".tar.gz"):
            continue
        stamp_str = name[len(prefix) : -len(".tar.gz")]
        try:
            stamp = datetime.strptime(stamp_str, "%Y%m%dT%H%M%SZ").replace(
                tzinfo=timezone.utc
            )
            dated.append((archive, stamp))
        except ValueError:
            continue

    dated.sort(key=lambda item: item[1], reverse=True)
    keep: Set[Path] = {path for path, _ in dated[:daily_keep]}

    for key_fn, limit in (
        (lambda dt: dt.isocalendar()[:2], weekly_keep),
        (lambda dt: (dt.year, dt.month), monthly_keep),
    ):
        seen: Set[Tuple[int, int]] = set()
        for path, stamp in dated:
            bucket = key_fn(stamp)
            if bucket in seen:
                continue
            keep.add(path)
            seen.add(bucket)
            if len(seen) >= limit:
                break
    return keep


def prune_archives(
    output_dir: Path,
    *,
    prefix: str = DEFAULT_ARCHIVE_PREFIX,
    daily_keep: int = 7,
    weekly_keep: int = 4,
    monthly_keep: int = 6,
) -> List[Path]:
    """Delete expired backup archives and their ``.sha256`` sidecars."""
    archives = sorted(output_dir.glob(f"{prefix}*.tar.gz"))
    keep = retention_set(
        archives,
        prefix=prefix,
        daily_keep=daily_keep,
        weekly_keep=weekly_keep,
        monthly_keep=monthly_keep,
    )
    removed: List[Path] = []
    for archive in archives:
        if archive in keep:
            continue
        checksum = Path(f"{archive}.sha256")
        archive.unlink()
        if checksum.exists():
            checksum.unlink()
        removed.append(archive)
    return removed


def write_success_marker(path: Path, archive: Path, *, now: Optional[datetime] = None) -> None:
    """Atomically publish a verified-backup status marker JSON."""
    if path.is_symlink():
        raise RuntimeError("backup status path must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
    payload = {
        "completed_at": timestamp,
        "archive": archive.name,
        "size": archive.stat().st_size,
        "sha256": sha256_file(archive),
    }
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    try:
        os.chmod(temporary, 0o640)
    except OSError:
        pass
    temporary.replace(path)


def create_backup(
    database: Path,
    output_dir: Path,
    *,
    extra_json_files: Optional[Dict[str, Path]] = None,
    artifact_tree: Optional[Path] = None,
    status_file: Optional[Path] = None,
    prefix: str = DEFAULT_ARCHIVE_PREFIX,
    daily_keep: int = 7,
    weekly_keep: int = 4,
    monthly_keep: int = 6,
    now: Optional[datetime] = None,
) -> Path:
    """Create a verified, checksummed backup archive and enforce GFS retention."""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )
    final_path = output_dir / f"{prefix}{timestamp}.tar.gz"
    temporary_archive = output_dir / f".{final_path.name}.{os.getpid()}.tmp"

    with tempfile.TemporaryDirectory(prefix="bounded-ops-backup-") as temporary:
        staging = Path(temporary)
        database_copy = staging / "state.sqlite"
        database_status = verified_sqlite_copy(database, database_copy)
        files: Dict[str, Path] = {"state.sqlite": database_copy}

        for arc_name, source_path in (extra_json_files or {}).items():
            if "/" in arc_name or "\\" in arc_name or arc_name in ALLOWED_BASE_FILES:
                raise ValueError(f"Invalid extra backup filename: {arc_name}")
            if source_path.is_file():
                destination = staging / arc_name
                shutil.copy2(source_path, destination)
                json.loads(destination.read_text(encoding="utf-8"))
                files[arc_name] = destination

        tree_status = (
            copy_regular_tree(artifact_tree, staging / "artifact_tree")
            if artifact_tree is not None
            else {"present": False, "files": 0, "bytes": 0}
        )

        manifest = {
            "schema": 1,
            "created_at": (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(),
            "database": database_status,
            "files": {
                name: {"size": path.stat().st_size, "sha256": sha256_file(path)}
                for name, path in files.items()
            },
            "artifact_tree": tree_status,
        }
        manifest_path = staging / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )

        with tarfile.open(temporary_archive, "w:gz") as archive:
            archive.add(manifest_path, arcname="manifest.json")
            for name, path in files.items():
                archive.add(path, arcname=name)
            if tree_status["present"]:
                archive.add(staging / "artifact_tree", arcname="artifact_tree")

    temporary_archive.replace(final_path)
    checksum_path = Path(f"{final_path}.sha256")
    checksum_path.write_text(
        f"{sha256_file(final_path)}  {final_path.name}\n", encoding="ascii"
    )
    prune_archives(
        output_dir,
        prefix=prefix,
        daily_keep=daily_keep,
        weekly_keep=weekly_keep,
        monthly_keep=monthly_keep,
    )
    if status_file is not None:
        write_success_marker(status_file, final_path, now=now)
    return final_path


def _is_safe_member_path(name: str) -> bool:
    if not name or "\\" in name:
        return False
    posix = PurePosixPath(name)
    if posix.is_absolute() or ".." in posix.parts:
        return False
    return True


def _is_allowed_member(name: str, allowed_extra: Set[str]) -> bool:
    if name in ALLOWED_BASE_FILES or name in allowed_extra:
        return True
    parts = PurePosixPath(name).parts
    return len(parts) >= 1 and parts[0] == "artifact_tree"


def verify_and_extract(
    archive_path: Path,
    output_dir: Path,
    *,
    allowed_extra_files: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Safely extract and cryptographically verify a backup into an empty directory."""
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"Restore directory must be empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    resolved_root = output_dir.resolve()
    allowed_extra = set(allowed_extra_files or ())

    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        names = {member.name for member in members}
        if "manifest.json" not in names or "state.sqlite" not in names:
            raise ValueError("Backup archive is missing manifest.json or state.sqlite")

        for member in members:
            if (
                member.issym()
                or member.islnk()
                or member.isdev()
                or member.isfifo()
                or not _is_safe_member_path(member.name)
            ):
                raise ValueError(f"Unsafe backup member: {member.name}")
            if not _is_allowed_member(member.name, allowed_extra):
                raise ValueError(f"Unexpected backup member: {member.name}")

        for member in members:
            destination = (resolved_root / PurePosixPath(member.name)).resolve()
            try:
                destination.relative_to(resolved_root)
            except ValueError as error:
                raise ValueError(f"Path traversal detected: {member.name}") from error

            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isreg():
                raise ValueError(f"Backup member is not a regular file: {member.name}")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"Cannot extract regular file: {member.name}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with source, destination.open("wb") as handle:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)

    manifest = json.loads((resolved_root / "manifest.json").read_text(encoding="utf-8"))
    for name, metadata in manifest["files"].items():
        if name not in allowed_extra and name != "state.sqlite":
            raise ValueError(f"Manifest references unexpected file: {name}")
        target = resolved_root / name
        if (
            not target.is_file()
            or target.stat().st_size != metadata["size"]
            or sha256_file(target) != metadata["sha256"]
        ):
            raise ValueError(f"Backup checksum verification failed for {name}")

    with closing(sqlite3.connect(str(resolved_root / "state.sqlite"))) as connection:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise ValueError(f"Restored SQLite integrity check failed: {integrity}")
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    backup_cmd = subparsers.add_parser("backup", help="Create a verified GFS backup")
    backup_cmd.add_argument("--database", type=Path, required=True)
    backup_cmd.add_argument("--output-dir", type=Path, required=True)
    backup_cmd.add_argument("--artifact-tree", type=Path, default=None)
    backup_cmd.add_argument("--status-file", type=Path, default=None)

    restore_cmd = subparsers.add_parser(
        "restore", help="Verify and extract a backup into an empty directory"
    )
    restore_cmd.add_argument("archive", type=Path)
    restore_cmd.add_argument("output_dir", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "backup":
        archive = create_backup(
            args.database,
            args.output_dir,
            artifact_tree=args.artifact_tree,
            status_file=args.status_file,
        )
        print(json.dumps({"verified_backup": str(archive), "sha256": sha256_file(archive)}))
        return 0
    manifest = verify_and_extract(args.archive, args.output_dir)
    print(json.dumps({"verified": True, "created_at": manifest["created_at"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
