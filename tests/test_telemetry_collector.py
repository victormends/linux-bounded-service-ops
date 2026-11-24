"""Tests for closed-cardinality 5-min telemetry collector and loopback dashboard."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from bounded_ops.telemetry.collector import (
    collect,
    host_snapshot,
    sum_sparse_histograms,
    summarize_percentiles,
)
from bounded_ops.telemetry.ops_server import OpsDashboardService


def _log_line(
    stamp: datetime,
    *,
    ip: str = "198.51.100.10",
    uri: str = "/api/v1/compute?tile_id=secret-token&q=abc",
    status: int = 200,
    request_time: float = 0.042,
    ua: str = "Mozilla/5.0 (X11; Linux x86_64) Chrome/128.0.0.0",
) -> str:
    return json.dumps(
        {
            "time": stamp.isoformat(),
            "remote_addr": ip,
            "method": "GET",
            "uri": uri,
            "status": status,
            "bytes": 1024,
            "request_time": request_time,
            "user_agent": ua,
        }
    )


def test_collector_closed_cardinality_zero_pii_percentiles_and_rotation_safety(tmp_path: Path) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    now = datetime(2026, 11, 20, 12, 30, tzinfo=timezone.utc)
    since = now - timedelta(hours=3)

    lines = [
        _log_line(now - timedelta(minutes=25), uri="/", request_time=0.008),
        _log_line(now - timedelta(minutes=24), uri="/api/v1/compute?secret=hunter2", request_time=0.045),
        _log_line(now - timedelta(minutes=23), uri="/api/v1/compute?secret=hunter2", request_time=0.450),
        _log_line(now - timedelta(minutes=22), uri="/api/v1/compute?secret=hunter2", status=503, request_time=0.015),
        _log_line(now - timedelta(minutes=21), uri="/api/v1/health", ua="curl/8.7.1", request_time=0.003),
    ]
    log_file = log_dir / "bounded-ops-access.log"
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = collect(log_dir, since, now=now)
    serialized = json.dumps(report)

    # Zero query strings, zero raw IPs, zero raw User-Agents in report
    assert "hunter2" not in serialized
    assert "198.51.100.10" not in serialized
    assert "Chrome/128.0.0.0" not in serialized

    assert report["summary"]["total_requests"] == 5
    assert report["summary"]["total_busy_503"] == 1

    # Sum sparse histograms across compute rows -> exact bucket percentiles
    compute_rows = [r for r in report["details"]["rows"] if r[1] == "compute"]
    merged_hist = sum_sparse_histograms(compute_rows)
    pct = summarize_percentiles(merged_hist)
    assert pct["samples"] == 3
    assert pct["p50_ms"] == 50
    assert pct["p95_ms"] == 500
    assert pct["p99_ms"] == 500

    # Simulate log rotation truncating the active log to only 1 line -> fuller snapshot preserved!
    log_file.write_text(lines[0] + "\n", encoding="utf-8")
    report2 = collect(log_dir, since, previous=report, now=now)
    assert report2["collector"]["preserved_hours"] >= 1
    assert report2["summary"]["total_requests"] == 5


def test_host_snapshot_parses_injected_proc_files(tmp_path: Path) -> None:
    meminfo = tmp_path / "meminfo"
    meminfo.write_text("MemTotal: 4194304 kB\nMemAvailable: 2097152 kB\n", encoding="ascii")
    stat_file = tmp_path / "stat"
    stat_file.write_text("cpu 100 0 50 850 0 0 0 0\n", encoding="ascii")

    class _Proc:
        stdout = (
            "Id=bounded-ops-gateway.service\n"
            "ActiveState=active\n"
            "Result=success\n"
            "NRestarts=0\n"
        )

    snap1 = host_snapshot(
        meminfo_path=meminfo,
        stat_path=stat_file,
        disk_path=tmp_path,
        systemctl_runner=lambda *a, **kw: _Proc(),
    )
    stat_file.write_text("cpu 200 0 100 900 0 0 0 0\n", encoding="ascii")
    snap2 = host_snapshot(
        previous=snap1,
        meminfo_path=meminfo,
        stat_path=stat_file,
        disk_path=tmp_path,
        systemctl_runner=lambda *a, **kw: _Proc(),
    )
    assert snap2["cpu_percent"] == 75.0
    assert snap2["services"][0]["ActiveState"] == "active"


def test_loopback_ops_server_host_allowlist_and_anti_csrf(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    now = datetime(2026, 11, 20, 12, 30, tzinfo=timezone.utc)
    (log_dir / "bounded-ops-access.log").write_text(
        _log_line(now - timedelta(minutes=5), request_time=0.020) + "\n",
        encoding="utf-8",
    )
    report = collect(log_dir, now - timedelta(hours=1), now=now)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    service = OpsDashboardService(report_path, port=0)
    service.start(background=True)
    try:
        port = service.server_port
        # Authorized loopback request succeeds
        with urlopen(f"http://127.0.0.1:{port}/summary", timeout=5) as resp:
            assert resp.status == 200
            summary = json.loads(resp.read().decode("utf-8"))
            assert summary["overall_latency"]["p95_ms"] == 25

        # Foreign Host header -> 403
        try:
            urlopen(
                Request(
                    f"http://127.0.0.1:{port}/healthz",
                    headers={"Host": "evil.example.invalid"},
                ),
                timeout=5,
            )
            raise AssertionError("Expected 403 for non-allowlisted Host")
        except HTTPError as err:
            assert err.code == 403

        # Sec-Fetch-Site: cross-site -> 403
        try:
            urlopen(
                Request(
                    f"http://127.0.0.1:{port}/report.json",
                    headers={"Sec-Fetch-Site": "cross-site"},
                ),
                timeout=5,
            )
            raise AssertionError("Expected 403 for cross-site fetch")
        except HTTPError as err:
            assert err.code == 403

        # Mismatched Origin -> 403
        try:
            urlopen(
                Request(
                    f"http://127.0.0.1:{port}/report.json",
                    headers={"Origin": "http://attacker.invalid"},
                ),
                timeout=5,
            )
            raise AssertionError("Expected 403 for foreign Origin")
        except HTTPError as err:
            assert err.code == 403

        # POST -> 405 Read only
        try:
            urlopen(
                Request(f"http://127.0.0.1:{port}/healthz", method="POST"),
                timeout=5,
            )
            raise AssertionError("Expected 405 for POST")
        except HTTPError as err:
            assert err.code == 405
    finally:
        service.stop()
