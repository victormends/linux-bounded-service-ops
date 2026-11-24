"""Tests for two-phase SHA-256 audited release pruner with /proc/<pid> checks."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from bounded_ops.ops.release_pruner import (
    PrunerConfig,
    apply_plan,
    create_plan,
    write_plan,
)


def _link_current(current_link: Path, target: Path) -> None:
    if os.name == "nt":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(current_link), str(target)],
            check=True,
            capture_output=True,
        )
    else:
        os.symlink(target, current_link)


def _setup_releases(tmp_path: Path, count: int = 6) -> tuple[PrunerConfig, list[Path]]:
    root = (tmp_path / "opt" / "bounded-ops").resolve()
    releases_root = root / "releases"
    state_dir = (tmp_path / "state").resolve()
    staging_dir = (tmp_path / "tmp").resolve()
    proc_root = (tmp_path / "proc").resolve()
    etc_dir = (tmp_path / "etc").resolve()
    for d in (releases_root, state_dir, staging_dir, proc_root, etc_dir):
        d.mkdir(parents=True, exist_ok=True)

    releases: list[Path] = []
    for rc in range(1, count + 1):
        rel = releases_root / f"2026.11.20-rc{rc}"
        rel.mkdir()
        (rel / "app.py").write_text(f"VERSION = {rc}\n", encoding="utf-8")
        (rel / "release-manifest.json").write_text(
            json.dumps({"rc": rc}), encoding="utf-8"
        )
        releases.append(rel)

    current_link = root / "current"
    _link_current(current_link, releases[-1])

    cfg = PrunerConfig(
        releases_root=releases_root,
        current_link=current_link,
        state_dir=state_dir,
        staging_dir=staging_dir,
        proc_root=proc_root,
        config_roots=(etc_dir,),
        keep_count=4,
        require_safe_rmtree=False,
    )
    return cfg, releases


def test_two_phase_plan_and_apply_preserves_manifests_and_fsyncs_audit_log(tmp_path: Path) -> None:
    cfg, releases = _setup_releases(tmp_path, count=6)

    # Matching staging archive for old rc1
    old_zip = cfg.staging_dir / "bounded-ops-2026.11.20-rc1.zip"
    old_zip.write_bytes(b"zip-payload")
    zip_sha = hashlib.sha256(old_zip.read_bytes()).hexdigest()

    plan_path = cfg.state_dir / "prune-plan.json"
    plan, plan_sha = write_plan(plan_path, cfg, {old_zip.name: zip_sha})
    assert plan["target_count"] == 3  # rc1, rc2 + old_zip

    # Wrong SHA-256 fails fast
    with pytest.raises(RuntimeError, match="SHA-256 mismatch"):
        apply_plan(plan_path, "0" * 64, cfg)

    events = apply_plan(plan_path, plan_sha, cfg)
    assert len(events) == 3
    assert not releases[0].exists()
    assert not releases[1].exists()
    assert not old_zip.exists()
    for kept in releases[2:]:
        assert kept.exists()

    # Deleted release manifests preserved outside deletion tree
    assert (cfg.state_dir / "2026.11.20-rc1.deleted-manifest.json").is_file()
    assert (cfg.state_dir / "2026.11.20-rc2.deleted-manifest.json").is_file()

    audit_lines = (cfg.state_dir / "prune-plan.applied.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(audit_lines) == 6  # starting + removed per target

    # Re-applying same plan is refused
    with pytest.raises(RuntimeError, match="already recorded"):
        apply_plan(plan_path, plan_sha, cfg)


def test_pruner_aborts_on_proc_reference_and_post_plan_tampering(tmp_path: Path) -> None:
    cfg, releases = _setup_releases(tmp_path, count=5)

    # Simulate /proc/4321 referencing old release rc1 in cmdline
    pid_dir = cfg.proc_root / "4321"
    pid_dir.mkdir()
    (pid_dir / "cmdline").write_bytes(
        f"/usr/bin/python\x00{releases[0]}/server.py\x00".encode("utf-8")
    )
    with pytest.raises(RuntimeError, match="old release still referenced"):
        create_plan(cfg)

    # Clear cmdline, verify readlink_fn detection on fd/exe works too
    (pid_dir / "cmdline").write_bytes(b"python\x00")
    (pid_dir / "fd").mkdir()
    (pid_dir / "fd" / "3").write_text("", encoding="utf-8")
    with pytest.raises(RuntimeError, match="old release still referenced"):
        create_plan(
            cfg,
            readlink_fn=lambda p: str(releases[0] / "data.bin") if p.name == "3" else "",
        )

    # Clean /proc -> create plan, then tamper with kept release before apply
    (pid_dir / "fd" / "3").unlink()
    plan_path = cfg.state_dir / "plan.json"
    _plan, plan_sha = write_plan(plan_path, cfg)

    (releases[2] / "tampered.txt").write_text("changed", encoding="utf-8")
    with pytest.raises(RuntimeError, match="retained files changed"):
        apply_plan(plan_path, plan_sha, cfg)


def test_pruner_rejects_persistent_files_inside_release(tmp_path: Path) -> None:
    cfg, releases = _setup_releases(tmp_path, count=5)
    (releases[0] / "state.sqlite").write_bytes(b"sqlite")
    with pytest.raises(RuntimeError, match="persistent data in release"):
        create_plan(cfg)
