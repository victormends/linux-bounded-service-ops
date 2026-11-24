"""Tests for /proc/meminfo, cgroup v2, st_dev dedup, non-symlink cache walk, and hysteresis."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from bounded_ops.ops.healthcheck import (
    backup_status,
    cache_status,
    evaluate_alert_hysteresis,
    memory_status,
    run_healthcheck,
    save_alert_state,
    storage_status,
)


def _write_meminfo(path: Path, *, total_kib: int, avail_kib: int, swap_total_kib: int = 0, swap_free_kib: int = 0) -> None:
    path.write_text(
        f"MemTotal:       {total_kib} kB\n"
        f"MemAvailable:   {avail_kib} kB\n"
        f"SwapTotal:      {swap_total_kib} kB\n"
        f"SwapFree:       {swap_free_kib} kB\n",
        encoding="ascii",
    )


def _write_cgroup(cgroup_dir: Path, *, current_bytes: int, oom: int = 0, oom_kill: int = 0) -> None:
    cgroup_dir.mkdir(parents=True, exist_ok=True)
    (cgroup_dir / "memory.current").write_text(f"{current_bytes}\n", encoding="ascii")
    (cgroup_dir / "memory.events").write_text(
        f"low 0\nhigh 0\nmax 0\noom {oom}\noom_kill {oom_kill}\n",
        encoding="ascii",
    )


def test_memory_status_reads_meminfo_and_cgroup_v2_oom(tmp_path: Path) -> None:
    meminfo = tmp_path / "meminfo"
    cgroup = tmp_path / "cgroup"
    # 4 GiB host with 50% available, service using 512 MiB -> ok
    _write_meminfo(meminfo, total_kib=4 * 1024 * 1024, avail_kib=2 * 1024 * 1024)
    _write_cgroup(cgroup, current_bytes=512 * 1024 * 1024)
    res_ok = memory_status(str(meminfo), str(cgroup))
    assert res_ok["state"] == "ok"
    assert res_ok["service"]["state"] == "ok"
    assert res_ok["service"]["host_percent"] == 12.5

    # OOM event forces critical even when current memory is low
    _write_cgroup(cgroup, current_bytes=256 * 1024 * 1024, oom=1, oom_kill=1)
    res_oom = memory_status(str(meminfo), str(cgroup))
    assert res_oom["state"] == "critical"
    assert res_oom["service"]["state"] == "critical"
    assert res_oom["service"]["oom_kill"] == 1

    # Host low available memory triggers warning / critical
    _write_meminfo(meminfo, total_kib=4 * 1024 * 1024, avail_kib=300 * 1024)
    res_low = memory_status(str(meminfo), str(tmp_path / "missing-cgroup"))
    assert res_low["state"] == "critical"
    assert res_low["service"]["state"] == "unknown"


def test_storage_status_deduplicates_st_dev_and_cache_walk_rejects_redirection(tmp_path: Path) -> None:
    cache_dir = (tmp_path / "cache").resolve()
    sub = cache_dir / "nested"
    sub.mkdir(parents=True)
    (sub / "tile.bin").write_bytes(b"a" * 2048)

    # Same st_dev across multiple labels -> checked once, others deduplicated
    fake_stat = lambda p: SimpleNamespace(st_dev=42)
    fake_usage = lambda p: SimpleNamespace(total=100 * 1024**3, free=50 * 1024**3)
    checks, issues = storage_status(
        [("root", "/"), ("data", "/data"), ("backups", "/backups")],
        cache_path=str(cache_dir),
        stat_fn=fake_stat,
        disk_usage_fn=fake_usage,
    )
    assert issues == []
    assert "root" in checks
    assert checks["_deduplicated_labels"] == ["data", "backups"]
    assert checks["artifact_cache"]["entries"] == 2
    assert checks["artifact_cache"]["state"] == "ok"

    # Reject redirected directory (NTFS junction on Windows or symlink on POSIX)
    outside = (tmp_path / "outside").resolve()
    outside.mkdir()
    redirected = cache_dir / "escape"
    if os.name == "nt":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(redirected), str(outside)],
            check=True,
            capture_output=True,
        )
    else:
        os.symlink(outside, redirected)

    with pytest.raises(RuntimeError):
        cache_status(str(cache_dir))

    if os.name == "nt":
        redirected.rmdir()
    else:
        redirected.unlink()


def test_alert_hysteresis_transitions_and_reminder_suppression(tmp_path: Path) -> None:
    state_file = tmp_path / "alert_state.json"

    # 1. Initial healthy run must NOT fire recovery notification
    due, kind, st = evaluate_alert_hysteresis(False, state_file, now=1000)
    assert not due and kind is None
    save_alert_state(state_file, st)

    # 2. Transition healthy -> failing fires immediate "alert"
    due, kind, st = evaluate_alert_hysteresis(True, state_file, reminder_seconds=3600, now=1300)
    assert due and kind == "alert"
    save_alert_state(state_file, st)

    # 3. Still failing 10 min later is suppressed
    due, kind, st = evaluate_alert_hysteresis(True, state_file, reminder_seconds=3600, now=1900)
    assert not due and kind is None
    save_alert_state(state_file, st)

    # 4. Still failing >= 1 hour later fires "reminder"
    due, kind, st = evaluate_alert_hysteresis(True, state_file, reminder_seconds=3600, now=5000)
    assert due and kind == "reminder"
    save_alert_state(state_file, st)

    # 5. Recovery fires "recovery"
    due, kind, st = evaluate_alert_hysteresis(False, state_file, reminder_seconds=3600, now=5300)
    assert due and kind == "recovery"


def test_run_healthcheck_end_to_end(tmp_path: Path) -> None:
    meminfo = tmp_path / "meminfo"
    cgroup = tmp_path / "cgroup"
    cache_dir = (tmp_path / "cache").resolve()
    cache_dir.mkdir()
    _write_meminfo(meminfo, total_kib=4 * 1024 * 1024, avail_kib=3 * 1024 * 1024)
    _write_cgroup(cgroup, current_bytes=200 * 1024 * 1024)

    marker = tmp_path / "backup_marker.json"
    recent = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    marker.write_text(
        json.dumps({"completed_at": recent, "archive": "b.tar.gz", "sha256": "0" * 64}),
        encoding="utf-8",
    )
    assert backup_status(str(marker))["state"] == "ok"

    class _FakeResp:
        status = 200

        def __init__(self, data: bytes) -> None:
            self._data = data

        def read(self, _n: int = -1) -> bytes:
            return self._data

        def __enter__(self) -> "_FakeResp":
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def fake_opener(req: object, timeout: float = 10) -> _FakeResp:
        body = json.dumps({"status": "ok", "generated_at": recent, "dependencies": {"storage_ready": True}}).encode("utf-8")
        return _FakeResp(body)

    code, report = run_healthcheck(
        url="http://127.0.0.1:8765/api/v1/health",
        meminfo_path=str(meminfo),
        cgroup_path=str(cgroup),
        monitored_paths=[("tmp", str(tmp_path))],
        cache_path=str(cache_dir),
        backup_marker_path=str(marker),
        alert_state_path=tmp_path / "alert.json",
        opener=fake_opener,
    )
    assert code == 0
    assert report["ok"] is True
