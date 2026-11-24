"""Two-phase SHA-256 audited release and staging pruner with /proc/<pid> checks.

Phase 1 writes a deterministic JSON deletion plan and prints its SHA-256 digest.
Phase 2 requires ``--apply-sha256`` matching the plan, re-validates every target
and kept release inventory, checks ``/proc/<pid>`` and config roots for active
references, and logs each deletion with ``os.fsync()`` into an append-only JSONL
audit log.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

RELEASE_NAME_STR = r"\d{4}\.\d{2}\.\d{2}-rc\d+"
RELEASE_RE = re.compile(RELEASE_NAME_STR)
STAGING_ARCHIVE_RE = re.compile(
    r"bounded-ops-(?:\d{8}|\d{4}\.\d{2}\.\d{2})-rc\d+\.zip"
)
PERSISTENT_SUFFIXES = frozenset({".sqlite", ".sqlite3", ".db", ".pem"})


@dataclass
class PrunerConfig:
    """Paths and safety controls for release pruning (injectable for testing)."""

    releases_root: Path = Path("/opt/bounded-ops/releases")
    current_link: Path = Path("/opt/bounded-ops/current")
    state_dir: Path = Path("/var/lib/bounded-ops-maintenance")
    staging_dir: Path = Path("/tmp")
    proc_root: Path = Path("/proc")
    config_roots: Tuple[Path, ...] = field(
        default_factory=lambda: (
            Path("/etc/systemd/system"),
            Path("/etc/nginx"),
            Path("/etc/bounded-ops"),
            Path("/opt/bounded-ops/venv"),
        )
    )
    keep_count: int = 4
    require_safe_rmtree: bool = field(
        default_factory=lambda: bool(getattr(shutil.rmtree, "avoids_symlink_attacks", False))
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def release_key(name: str) -> Tuple[str, int]:
    require(RELEASE_RE.fullmatch(name) is not None, f"unexpected release name: {name}")
    date_part, rc_part = name.split("-rc")
    return date_part, int(rc_part)


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left)) == os.path.normcase(str(right))


def checked_directory(path: Path) -> None:
    require(path.is_absolute(), f"path must be absolute: {path}")
    resolved = path.resolve(strict=True)
    require(_same_path(resolved, path), f"directory redirected: {path}")
    lstat_info = path.lstat()
    require(
        stat.S_ISDIR(lstat_info.st_mode) and not path.is_symlink(),
        f"not a real directory: {path}",
    )


def _allocated_bytes(info: os.stat_result) -> int:
    if hasattr(info, "st_blocks"):
        return int(info.st_blocks) * 512
    return int(info.st_size)


def inventory(path: Path) -> Dict[str, Any]:
    """Build a tamper-detecting inventory without traversing links or special files."""
    checked_directory(path)
    require(not os.path.ismount(path), f"release is a mount: {path}")
    device = path.stat().st_dev
    digest = hashlib.sha256()
    file_count = 0
    allocated = 0

    for base, directories, files in os.walk(path, followlinks=False):
        directories.sort()
        for name in sorted(directories + files):
            child = Path(base) / name
            item = child.lstat()
            require(
                not child.is_symlink()
                and item.st_dev == device
                and not os.path.ismount(child),
                f"link or mount in release: {child}",
            )
            require(
                stat.S_ISREG(item.st_mode) or stat.S_ISDIR(item.st_mode),
                f"special entry in release: {child}",
            )
            if stat.S_ISREG(item.st_mode):
                require(item.st_nlink == 1, f"hardlinked release file: {child}")
                require(
                    child.suffix.lower() not in PERSISTENT_SUFFIXES
                    and child.name != ".env",
                    f"possible persistent data in release: {child}",
                )
                file_count += 1
            allocated += _allocated_bytes(item)
            digest.update(
                json.dumps(
                    [
                        child.relative_to(path).as_posix(),
                        item.st_mode,
                        item.st_ino,
                        item.st_size,
                        item.st_mtime_ns,
                        item.st_ctime_ns,
                    ]
                ).encode("utf-8")
            )

    info = path.lstat()
    return {
        "path": str(path),
        "kind": "release",
        "device": info.st_dev,
        "inode": info.st_ino,
        "files": file_count,
        "allocated_bytes": allocated,
        "inventory": digest.hexdigest(),
    }


def select_releases(
    releases_root: Path,
    active: Path,
    *,
    keep_count: int = 4,
) -> Tuple[List[Path], List[Path]]:
    """Split releases into ``(keep, old)`` requiring active to be the newest release."""
    checked_directory(releases_root)
    require(_same_path(active.parent, releases_root), "active release outside root")
    releases = sorted(releases_root.iterdir(), key=lambda p: release_key(p.name))
    require(
        any(_same_path(r, active) for r in releases) and _same_path(releases[-1], active),
        "active is not latest release; manual review required",
    )
    require(len(releases) >= keep_count, f"fewer than {keep_count} releases; no pruning")
    for path in releases:
        checked_directory(path)
    return releases[-keep_count:], releases[:-keep_count]


def referenced_releases(
    config: PrunerConfig,
    *,
    readlink_fn: Callable[[Path], str] = lambda p: os.readlink(p),
) -> Set[str]:
    """Detect release names referenced by configs, venv paths, or running ``/proc/<pid>``."""
    refs: Set[str] = set()
    root_variants = {
        re.escape(config.releases_root.as_posix()),
        re.escape(str(config.releases_root)),
    }
    pattern = re.compile(
        (
            r"(?:" + "|".join(sorted(root_variants)) + r")[/\\](" + RELEASE_NAME_STR + r")"
        ).encode("utf-8")
    )

    def collect(data: bytes) -> None:
        refs.update(match.decode("utf-8", errors="ignore") for match in pattern.findall(data))

    for base in config.config_roots:
        if not base.exists():
            continue
        is_venv = "venv" in base.parts
        for parent, dirs, files in os.walk(base, followlinks=False):
            for name in dirs + files:
                path = Path(parent) / name
                if path.is_symlink():
                    try:
                        collect(os.fsencode(os.path.realpath(path)))
                    except OSError:
                        pass
            for name in files:
                path = Path(parent) / name
                if is_venv and path.suffix not in (".pth", ".egg-link", ".cfg"):
                    continue
                try:
                    if not path.is_symlink() and path.is_file() and path.stat().st_size <= 262144:
                        collect(path.read_bytes())
                except OSError:
                    pass

    if config.proc_root.exists():
        for process in config.proc_root.iterdir():
            if not process.name.isdigit():
                continue
            try:
                links: List[Path] = [process / "cwd", process / "exe"]
                fd_dir = process / "fd"
                if fd_dir.is_dir():
                    links.extend(fd_dir.iterdir())
                for link in links:
                    try:
                        target = readlink_fn(link)
                        collect(os.fsencode(target))
                    except (FileNotFoundError, OSError):
                        pass
                for name in ("maps", "environ", "cmdline"):
                    entry = process / name
                    if entry.is_file():
                        collect(entry.read_bytes())
            except (FileNotFoundError, ProcessLookupError):
                pass
    return refs


def create_plan(
    config: PrunerConfig,
    local_zips: Optional[Dict[str, str]] = None,
    *,
    readlink_fn: Callable[[Path], str] = lambda p: os.readlink(p),
) -> Dict[str, Any]:
    """Create Phase-1 dry-run cleanup plan JSON without deleting any files."""
    active = config.current_link.resolve(strict=True)
    keep, old = select_releases(
        config.releases_root, active, keep_count=config.keep_count
    )
    references = referenced_releases(config, readlink_fn=readlink_fn)
    require(
        not references.intersection(p.name for p in old),
        "old release still referenced",
    )

    kept_inventory = [inventory(p) for p in keep]
    targets: List[Dict[str, Any]] = [inventory(p) for p in old]

    zip_hashes = local_zips or {}
    if config.staging_dir.is_dir():
        min_kept_rc = min(release_key(p.name)[1] for p in keep)
        for path in sorted(config.staging_dir.iterdir()):
            if not STAGING_ARCHIVE_RE.fullmatch(path.name) or path.name not in zip_hashes:
                continue
            rc = int(path.name.rsplit("-rc", 1)[1].split(".")[0])
            if rc >= min_kept_rc:
                continue
            info = path.lstat()
            require(
                stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not path.is_symlink(),
                f"staging archive is not an ordinary file: {path}",
            )
            digest = sha256_file(path)
            require(
                digest == zip_hashes[path.name],
                f"staging archive SHA-256 mismatch: {path}",
            )
            targets.append(
                {
                    "path": str(path),
                    "kind": "zip",
                    "sha256": digest,
                    "device": info.st_dev,
                    "inode": info.st_ino,
                    "size": info.st_size,
                    "mtime_ns": info.st_mtime_ns,
                    "allocated_bytes": _allocated_bytes(info),
                }
            )

    return {
        "version": 1,
        "active": str(active),
        "keep": [str(p) for p in keep],
        "kept_inventory": kept_inventory,
        "references": sorted(references),
        "targets": targets,
        "target_count": len(targets),
        "allocated_bytes": sum(t["allocated_bytes"] for t in targets),
    }


def validate_targets(
    plan: Dict[str, Any],
    config: PrunerConfig,
    *,
    readlink_fn: Callable[[Path], str] = lambda p: os.readlink(p),
) -> None:
    """Re-verify every kept and target release before performing any deletion."""
    active = config.current_link.resolve(strict=True)
    require(_same_path(active, Path(plan["active"])), "active release changed")
    keep, old = select_releases(
        config.releases_root, active, keep_count=config.keep_count
    )
    require([str(p) for p in keep] == plan["keep"], "kept releases changed")
    require(plan["target_count"] == len(plan["targets"]), "target count mismatch")
    require(
        len({t["path"] for t in plan["targets"]}) == len(plan["targets"]),
        "duplicate target",
    )
    require(
        not referenced_releases(config, readlink_fn=readlink_fn).intersection(
            p.name for p in old
        ),
        "old release still referenced",
    )
    require(
        [inventory(p) for p in keep] == plan["kept_inventory"],
        "retained files changed",
    )
    require(
        {t["path"] for t in plan["targets"] if t["kind"] == "release"}
        == {str(p) for p in old},
        "release targets changed",
    )

    for target in plan["targets"]:
        path = Path(target["path"])
        require(
            path.is_absolute() and _same_path(path.resolve(strict=True), path),
            f"target redirected: {path}",
        )
        if target["kind"] == "release":
            require(
                any(_same_path(path, o) for o in old)
                and _same_path(path.parent, config.releases_root),
                "release outside allowed children",
            )
            require(
                inventory(path) == target,
                f"release changed since dry run: {path}",
            )
        else:
            require(
                target["kind"] == "zip"
                and _same_path(path.parent, config.staging_dir)
                and STAGING_ARCHIVE_RE.fullmatch(path.name) is not None,
                "staging archive outside allowed targets",
            )
            info = path.lstat()
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1
                and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                == (
                    target["device"],
                    target["inode"],
                    target["size"],
                    target["mtime_ns"],
                )
                and sha256_file(path) == target["sha256"],
                f"staging archive changed since dry run: {path}",
            )


def apply_plan(
    plan_path: Path,
    expected_sha256: str,
    config: PrunerConfig,
    *,
    readlink_fn: Callable[[Path], str] = lambda p: os.readlink(p),
) -> List[Dict[str, Any]]:
    """Execute Phase-2 deletion after SHA-256 verification and re-validation."""
    require(
        len(expected_sha256) == 64 and sha256_file(plan_path) == expected_sha256,
        "dry-run plan SHA-256 mismatch",
    )
    audit_path = plan_path.with_suffix(".applied.jsonl")
    require(
        not audit_path.exists(),
        "attempt already recorded; refusing to retry deletion",
    )
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    validate_targets(plan, config, readlink_fn=readlink_fn)
    if config.require_safe_rmtree:
        require(
            bool(getattr(shutil.rmtree, "avoids_symlink_attacks", False)),
            "safe fd-based directory deletion unavailable",
        )

    events: List[Dict[str, Any]] = []
    with audit_path.open("x", encoding="utf-8") as log:
        for target in plan["targets"]:
            item = Path(target["path"])
            require(
                _same_path(config.current_link.resolve(strict=True), Path(plan["active"])),
                "active release changed during cleanup",
            )
            require(
                not item.is_symlink() and item.lstat().st_ino == target["inode"],
                f"target changed during cleanup: {item}",
            )
            if target["kind"] == "release":
                manifest = item / "release-manifest.json"
                if manifest.is_file():
                    saved = plan_path.parent / f"{item.name}.deleted-manifest.json"
                    with saved.open("xb") as output:
                        output.write(manifest.read_bytes())

            start_record = {"event": "starting", "path": str(item)}
            log.write(json.dumps(start_record) + "\n")
            log.flush()
            os.fsync(log.fileno())

            if target["kind"] == "release":
                shutil.rmtree(item)
            else:
                item.unlink()

            done_record = {
                "event": "removed",
                "path": str(item),
                "bytes": target["allocated_bytes"],
            }
            log.write(json.dumps(done_record) + "\n")
            log.flush()
            os.fsync(log.fileno())
            events.append(done_record)
    return events


def write_plan(
    plan_path: Path,
    config: PrunerConfig,
    local_zips: Optional[Dict[str, str]] = None,
    *,
    readlink_fn: Callable[[Path], str] = lambda p: os.readlink(p),
) -> Tuple[Dict[str, Any], str]:
    """Generate and persist a Phase-1 plan file, returning ``(plan, sha256)``."""
    plan = create_plan(config, local_zips, readlink_fn=readlink_fn)
    with plan_path.open("x", encoding="utf-8") as output:
        json.dump(plan, output, indent=2)
    return plan, sha256_file(plan_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--local-zips", type=Path, default=None)
    parser.add_argument("--apply-sha256", default=None)
    parser.add_argument("--releases-root", type=Path, default=Path("/opt/bounded-ops/releases"))
    parser.add_argument("--current-link", type=Path, default=Path("/opt/bounded-ops/current"))
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/bounded-ops-maintenance"))
    return parser


def main() -> int:
    args = build_parser().parse_args()
    geteuid = getattr(os, "geteuid", None)
    require(
        sys.platform == "linux" and geteuid is not None and geteuid() == 0,
        "run as root on Linux only",
    )
    config = PrunerConfig(
        releases_root=args.releases_root,
        current_link=args.current_link,
        state_dir=args.state_dir,
    )
    checked_directory(config.state_dir)
    require(
        _same_path(args.plan.parent, config.state_dir) and args.plan.name.endswith(".json"),
        "plan outside audit directory",
    )
    if args.apply_sha256:
        events = apply_plan(args.plan, args.apply_sha256, config)
        print(json.dumps({"applied": True, "removed": events}))
    else:
        local_zips = (
            json.loads(args.local_zips.read_text(encoding="utf-8"))
            if args.local_zips is not None
            else {}
        )
        plan, digest = write_plan(args.plan, config, local_zips)
        print(
            json.dumps(
                {
                    "plan": str(args.plan),
                    "sha256": digest,
                    "count": plan["target_count"],
                    "allocated_gib": round(plan["allocated_bytes"] / (1024 ** 3), 3),
                    "keep": plan["keep"],
                    "targets": [t["path"] for t in plan["targets"]],
                }
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
