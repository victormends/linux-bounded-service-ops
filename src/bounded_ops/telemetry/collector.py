"""Read-only Nginx JSON log aggregator into closed-cardinality 5-minute cubes."""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from functools import lru_cache
import gzip
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

GRAIN_SECONDS = 300
RETENTION_DAYS = 7
MAX_ROWS = 40000

# Fixed latency bucket upper bounds (ms) bound memory regardless of traffic volume.
LATENCY_MS: Tuple[Optional[int], ...] = (
    5,
    10,
    25,
    50,
    100,
    200,
    300,
    500,
    750,
    1000,
    1500,
    2000,
    3000,
    5000,
    10000,
    20000,
    30000,
    60000,
    120000,
    300000,
    None,
)

ENDPOINTS: Dict[str, str] = {
    "page": "Landing page",
    "compute": "Compute API",
    "health": "Health and readiness",
    "metrics": "Metrics exposition",
    "stream": "SSE status stream",
    "api-other": "Other API routes",
    "assets": "Static assets",
    "other": "Other routes / scanners",
}

DEVICES: Dict[str, str] = {
    "mobile": "Mobile",
    "tablet": "Tablet",
    "desktop": "Desktop browser",
    "unknown": "Unknown client",
}

TRAFFIC: Dict[str, str] = {
    "browser": "Apparent browser",
    "bot": "Bot or automated probe",
    "other": "Other client",
}

BOT_RE = re.compile(
    r"bot|spider|crawl|slurp|headless|python|curl|wget|monitor|uptime|check|"
    r"preview|censys|inspect|scanner|zgrab|masscan|internetmeasurement|expanse|"
    r"paloalto|research|semrush|ahrefs|okhttp|axios|go-http-client",
    re.I,
)

SYSTEMD_UNITS = (
    "bounded-ops-gateway.service",
    "bounded-ops-healthcheck.service",
    "bounded-ops-healthcheck.timer",
    "bounded-ops-backup.service",
    "bounded-ops-backup.timer",
    "bounded-ops-telemetry-collect.service",
    "bounded-ops-telemetry-collect.timer",
    "bounded-ops-telemetry-ui.service",
)

SYSTEMD_PROPERTIES = (
    "Id",
    "ActiveState",
    "Result",
    "ExecMainStatus",
    "ExecMainExitTimestamp",
    "NextElapseUSecRealtime",
    "NRestarts",
)


@lru_cache(maxsize=512)
def is_bot(ua: str) -> bool:
    return bool(BOT_RE.search(ua))


@lru_cache(maxsize=256)
def classify_endpoint(uri_path: str) -> str:
    """Map raw URI path into a closed-cardinality endpoint category."""
    if uri_path in {"/", "/index.html"}:
        return "page"
    if uri_path == "/api/v1/compute":
        return "compute"
    if uri_path in {"/api/v1/health", "/api/v1/ready"}:
        return "health"
    if uri_path == "/api/v1/metrics":
        return "metrics"
    if uri_path == "/api/v1/stream":
        return "stream"
    if uri_path.startswith("/api/"):
        return "api-other"
    if uri_path.startswith(("/static/", "/assets/")) or uri_path in {
        "/app.js",
        "/style.css",
        "/favicon.ico",
    }:
        return "assets"
    return "other"


@lru_cache(maxsize=256)
def classify_device(ua: str) -> str:
    lower = ua.lower()
    if "ipad" in lower or "tablet" in lower or ("android" in lower and "mobile" not in lower):
        return "tablet"
    if "mobile" in lower or "iphone" in lower or "android" in lower:
        return "mobile"
    return "desktop" if "mozilla/5.0" in lower else "unknown"


@lru_cache(maxsize=256)
def hour_key(epoch_hour: int) -> str:
    return datetime.fromtimestamp(epoch_hour * 3600, timezone.utc).isoformat()


def parse_nginx_json_line(
    line: str,
) -> Optional[Tuple[datetime, str, str, str, int, str, Any, Any]]:
    """Parse one structured Nginx JSON log line, stripping any query string."""
    try:
        record = json.loads(line)
        if not isinstance(record, dict):
            return None
        stamp = datetime.fromisoformat(str(record["time"]).replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return None
        stamp = stamp.astimezone(timezone.utc)
        ip = str(record.get("remote_addr", ""))
        method = str(record.get("method", ""))
        raw_uri = str(record.get("uri", ""))
        clean_path = urlsplit(raw_uri).path or "/"
        status = int(record.get("status", 0))
        ua = str(record.get("user_agent", ""))
        duration = record.get("request_time")
        size = record.get("bytes")
        return stamp, ip, method, clean_path, status, ua, duration, size
    except (ValueError, TypeError, KeyError, OverflowError):
        return None


def _latency_bucket_index(duration_seconds: Any) -> Optional[int]:
    try:
        ms = float(duration_seconds) * 1000.0
    except (TypeError, ValueError):
        return None
    if not math.isfinite(ms) or ms < 0:
        return None
    for idx, bound in enumerate(LATENCY_MS):
        if bound is not None and ms <= bound:
            return idx
    return len(LATENCY_MS) - 1


def empty_hour_bucket() -> Dict[str, Any]:
    return {
        "requests": 0,
        "api_requests": 0,
        "pageviews": 0,
        "sessions_estimate": 0,
        "unique_ip_estimate": 0,
        "errors_5xx": 0,
        "busy_503": 0,
        "cancelled_499": 0,
        "latency_samples": 0,
        "latency_histogram": [0] * len(LATENCY_MS),
    }


def percentile_upper(histogram: Sequence[int], fraction: float) -> Optional[int]:
    """Return the histogram bucket upper bound for a quantile in ``(0, 1]``."""
    total = sum(histogram)
    if total <= 0:
        return None
    target = math.ceil(total * fraction)
    cumulative = 0
    for bound, count in zip(LATENCY_MS, histogram):
        cumulative += int(count)
        if cumulative >= target:
            return bound
    return LATENCY_MS[-1]


def sum_sparse_histograms(rows: Iterable[Sequence[Any]]) -> List[int]:
    """Sum sparse ``[bucket_idx, count, ...]`` histograms from cube rows."""
    merged = [0] * len(LATENCY_MS)
    for row in rows:
        sparse = row[10] if len(row) > 10 else ()
        for pos in range(0, len(sparse) - 1, 2):
            idx = int(sparse[pos])
            cnt = int(sparse[pos + 1])
            if 0 <= idx < len(merged) and cnt > 0:
                merged[idx] += cnt
    return merged


def summarize_percentiles(histogram: Sequence[int]) -> Dict[str, Optional[int]]:
    """Compute P50, P95, and P99 upper bounds from a summed bucket histogram."""
    return {
        "samples": int(sum(histogram)),
        "p50_ms": percentile_upper(histogram, 0.50),
        "p95_ms": percentile_upper(histogram, 0.95),
        "p99_ms": percentile_upper(histogram, 0.99),
    }


class FiveMinuteCube:
    """Closed-cardinality 5-minute rollups with bounded row cap and retention."""

    def __init__(self, now: datetime, previous: Optional[Dict[str, Any]] = None) -> None:
        self.end = int(now.timestamp())
        self.start = (self.end - RETENTION_DAYS * 86400) // GRAIN_SECONDS * GRAIN_SECONDS
        self.previous = previous or {}
        self.cells: Dict[Tuple[int, str, str, str, int], List[Any]] = {}

    def add(
        self,
        stamp: datetime,
        uri_path: str,
        ua: str,
        status: int,
        duration: Any,
        size: Any,
        is_pageview: bool,
        bot_flag: bool,
    ) -> Optional[Tuple[int, str, str, str, int]]:
        ts = int(stamp.timestamp()) // GRAIN_SECONDS * GRAIN_SECONDS
        if ts < self.start:
            return None
        traffic = (
            "bot"
            if bot_flag
            else "browser"
            if "mozilla/5.0" in ua.lower()
            else "other"
        )
        key = (
            ts,
            classify_endpoint(uri_path),
            classify_device(ua),
            traffic,
            status if 100 <= status <= 599 else 0,
        )
        cell = self.cells.get(key)
        if cell is None:
            cell = [0, 0, 0, 0, 0, [0] * len(LATENCY_MS)]
            self.cells[key] = cell
        cell[0] += 1
        cell[1] += int(is_pageview)
        try:
            byte_count = int(size)
            if byte_count >= 0:
                cell[3] += byte_count
                cell[4] += 1
        except (TypeError, ValueError):
            pass
        bucket_idx = _latency_bucket_index(duration)
        if bucket_idx is not None:
            cell[5][bucket_idx] += 1
        return key

    def record_session(self, key: Optional[Tuple[int, str, str, str, int]]) -> None:
        if key is not None and key in self.cells:
            self.cells[key][2] += 1

    def finish(self) -> Dict[str, Any]:
        old: Dict[int, List[List[Any]]] = defaultdict(list)
        fresh: Dict[int, List[List[Any]]] = defaultdict(list)

        for row in self.previous.get("rows", []):
            if row and row[0] >= self.start:
                old[row[0]].append(row)

        for key, cell in self.cells.items():
            sparse = [
                value
                for idx, count in enumerate(cell[5])
                if count
                for value in (idx, count)
            ]
            fresh[key[0]].append([*key, *cell[:5], sparse])

        for ts, rows in fresh.items():
            # Replace whole 5-minute populations so counters cannot shrink on rotation.
            if sum(r[5] for r in rows) >= sum(r[5] for r in old[ts]):
                old[ts] = rows

        stamps = sorted(old, reverse=True)
        rows: List[List[Any]] = []
        truncated = False
        for ts in stamps:
            if len(rows) + len(old[ts]) > MAX_ROWS:
                truncated = True
                break
            rows.extend(sorted(old[ts]))
        rows.sort()

        return {
            "grain_seconds": GRAIN_SECONDS,
            "retention_days": RETENTION_DAYS,
            "row_cap": MAX_ROWS,
            "truncated": truncated,
            "start": rows[0][0] if rows else None,
            "end": self.end,
            "columns": [
                "time",
                "endpoint",
                "device",
                "traffic",
                "status",
                "requests",
                "pageviews",
                "sessions_estimate",
                "bytes",
                "byte_samples",
                "histogram_sparse",
            ],
            "latency_bounds_ms": list(LATENCY_MS),
            "endpoints": ENDPOINTS,
            "devices": DEVICES,
            "traffic": TRAFFIC,
            "rows": rows,
        }


def collect(
    log_dir: Path,
    since: datetime,
    previous: Optional[Dict[str, Any]] = None,
    now: Optional[datetime] = None,
    *,
    log_prefix: str = "bounded-ops-access",
) -> Dict[str, Any]:
    """Aggregate rotated Nginx JSON logs into hourly summaries and 5-minute cubes."""
    started = time.monotonic()
    current_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    since_utc = since.astimezone(timezone.utc)
    prev = previous or {}

    scan_start = (
        max(since_utc, current_now - timedelta(hours=2))
        if prev.get("details")
        else since_utc
    )
    scan_start = scan_start.replace(minute=0, second=0, microsecond=0)
    if prev.get("generated_at"):
        prev_time = datetime.fromisoformat(
            str(prev["generated_at"]).replace("Z", "+00:00")
        ).astimezone(timezone.utc)
        scan_start = min(
            scan_start, prev_time.replace(minute=0, second=0, microsecond=0)
        )

    hours: Dict[str, Dict[str, Any]] = defaultdict(empty_hour_bucket)
    details = FiveMinuteCube(current_now, prev.get("details"))
    session_start = scan_start - timedelta(minutes=30)
    page_events: List[
        Tuple[datetime, str, str, str, Optional[Tuple[int, str, str, str, int]]]
    ] = []
    first_seen_log: Optional[datetime] = None
    last_seen_log: Optional[datetime] = None
    matched_files = 0

    name_re = re.compile(re.escape(log_prefix) + r"\.log(?:\.\d+(?:\.gz)?)?$")
    if log_dir.is_dir():
        for path in sorted(log_dir.iterdir()):
            if not name_re.fullmatch(path.name) or path.is_symlink() or not path.is_file():
                continue
            if datetime.fromtimestamp(path.stat().st_mtime, timezone.utc) < session_start:
                continue
            matched_files += 1
            opener = gzip.open if path.suffix == ".gz" else open
            with opener(path, "rt", encoding="utf-8", errors="replace") as stream:
                for line in stream:
                    row = parse_nginx_json_line(line)
                    if row is None:
                        continue
                    stamp, ip, method, uri_path, status, ua, duration, size = row
                    if not since_utc <= stamp <= current_now:
                        continue
                    first_seen_log = (
                        stamp if first_seen_log is None else min(first_seen_log, stamp)
                    )
                    last_seen_log = (
                        stamp if last_seen_log is None else max(last_seen_log, stamp)
                    )
                    bot_flag = is_bot(ua)
                    is_pageview = (
                        method == "GET"
                        and uri_path in {"/", "/index.html"}
                        and status in {200, 304}
                        and "mozilla/5.0" in ua.lower()
                        and not bot_flag
                    )
                    hr = hour_key(int(stamp.timestamp()) // 3600)
                    detail_key = (
                        details.add(
                            stamp,
                            uri_path,
                            ua,
                            status,
                            duration,
                            size,
                            is_pageview,
                            bot_flag,
                        )
                        if stamp >= scan_start
                        else None
                    )
                    if is_pageview and stamp >= session_start:
                        page_events.append((stamp, hr, ip, ua, detail_key))
                    if stamp < scan_start:
                        continue
                    bucket = hours[hr]
                    bucket["requests"] += 1
                    bucket["errors_5xx"] += int(status >= 500)
                    bucket["busy_503"] += int(status == 503)
                    bucket["cancelled_499"] += int(status == 499)
                    if uri_path.startswith("/api/"):
                        bucket["api_requests"] += 1
                        idx = _latency_bucket_index(duration)
                        if idx is not None:
                            bucket["latency_histogram"][idx] += 1
                            bucket["latency_samples"] += 1
                    if is_pageview:
                        bucket["pageviews"] += 1

    last_session: Dict[Tuple[str, str], datetime] = {}
    visitors: Dict[str, set] = defaultdict(set)
    for stamp, hr, ip, ua, detail_key in sorted(page_events, key=lambda item: item[0]):
        session_key = (ip, ua)
        if stamp >= scan_start:
            visitors[hr].add(ip)
            if (
                session_key not in last_session
                or stamp - last_session[session_key] > timedelta(minutes=30)
            ):
                hours[hr]["sessions_estimate"] += 1
                details.record_session(detail_key)
        last_session[session_key] = stamp

    result: Dict[str, Dict[str, Any]] = {
        h["time"]: h for h in prev.get("hours", [])
    }
    preserved_hours = 0
    for hr, bucket in hours.items():
        if hr in result and result[hr]["requests"] > bucket["requests"]:
            preserved_hours += 1
            continue
        bucket["unique_ip_estimate"] = len(visitors[hr])
        bucket["api_p50_upper_ms"] = percentile_upper(bucket["latency_histogram"], 0.50)
        bucket["api_p95_upper_ms"] = percentile_upper(bucket["latency_histogram"], 0.95)
        bucket["api_p99_upper_ms"] = percentile_upper(bucket["latency_histogram"], 0.99)
        result[hr] = {"time": hr, **bucket}

    if first_seen_log and last_seen_log:
        cursor = max(scan_start, first_seen_log.replace(minute=0, second=0, microsecond=0))
        end = last_seen_log.replace(minute=0, second=0, microsecond=0)
        while cursor <= end:
            key = cursor.isoformat()
            result.setdefault(
                key,
                {
                    "time": key,
                    **empty_hour_bucket(),
                    "api_p50_upper_ms": None,
                    "api_p95_upper_ms": None,
                    "api_p99_upper_ms": None,
                },
            )
            cursor += timedelta(hours=1)

    finished_details = details.finish()
    overall_hist = sum_sparse_histograms(finished_details["rows"])

    return {
        "schema": 2,
        "generated_at": current_now.isoformat(),
        "timezone": "UTC",
        "collection_since": since_utc.isoformat(),
        "coverage_first": prev.get("coverage_first")
        or (first_seen_log.isoformat() if first_seen_log else None),
        "coverage_last": (
            last_seen_log.isoformat() if last_seen_log else prev.get("coverage_last")
        ),
        "hours": [result[k] for k in sorted(result)],
        "details": finished_details,
        "summary": {
            "total_requests": sum(h["requests"] for h in result.values()),
            "total_api_requests": sum(h["api_requests"] for h in result.values()),
            "total_errors_5xx": sum(h["errors_5xx"] for h in result.values()),
            "total_busy_503": sum(h["busy_503"] for h in result.values()),
            "latency_percentiles": summarize_percentiles(overall_hist),
        },
        "collector": {
            "files": matched_files,
            "preserved_hours": preserved_hours,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        },
    }


def host_snapshot(
    previous: Optional[Dict[str, Any]] = None,
    *,
    meminfo_path: Path = Path("/proc/meminfo"),
    stat_path: Path = Path("/proc/stat"),
    disk_path: Path = Path("/var/lib/bounded-ops"),
    systemctl_runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
) -> Dict[str, Any]:
    """Read-only host and systemd unit snapshot without exposing env/cmdline/secrets."""
    result: Dict[str, Any] = {"captured_at": datetime.now(timezone.utc).isoformat()}
    try:
        mem = {
            line.split(":")[0]: int(line.split()[1]) * 1024
            for line in meminfo_path.read_text(encoding="ascii").splitlines()
            if ":" in line
        }
        values = [
            int(v)
            for v in stat_path.read_text(encoding="ascii").splitlines()[0].split()[1:9]
        ]
        total = sum(values)
        idle = values[3] + values[4]
        old = (previous or {}).get("cpu_ticks")
        usage: Optional[float] = None
        if old and total > old[0] and idle >= old[1]:
            usage = round(
                max(0.0, min(100.0, 100.0 * (1.0 - (idle - old[1]) / (total - old[0])))),
                1,
            )
        disk = shutil.disk_usage(str(disk_path))
        getloadavg = getattr(os, "getloadavg", None)
        load_1m = getloadavg()[0] if getloadavg is not None else None
        result.update(
            cpu_ticks=[total, idle],
            cpu_percent=usage,
            cpu_count=os.cpu_count(),
            cpu_interval_start=(previous or {}).get("captured_at"),
            load_1m=load_1m,
            memory_total=mem["MemTotal"],
            memory_available=mem["MemAvailable"],
            disk_total=disk.total,
            disk_free=disk.free,
        )
    except (OSError, ValueError, KeyError, AttributeError, IndexError):
        result["host_unavailable"] = True

    runner = systemctl_runner or subprocess.run
    try:
        proc = runner(
            ["systemctl", "show", *SYSTEMD_UNITS, "--property=" + ",".join(SYSTEMD_PROPERTIES)],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        services: List[Dict[str, str]] = []
        for block in proc.stdout.strip().split("\n\n"):
            fields = dict(
                line.split("=", 1) for line in block.splitlines() if "=" in line
            )
            if fields.get("Id") in SYSTEMD_UNITS:
                services.append(
                    {k: fields[k] for k in SYSTEMD_PROPERTIES if k in fields}
                )
        result["services"] = services
    except (OSError, subprocess.SubprocessError):
        result["services_unavailable"] = True
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-dir", type=Path, default=Path("/var/log/nginx"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--since",
        default=(datetime.now(timezone.utc) - timedelta(days=7)).isoformat(),
    )
    parser.add_argument("--log-prefix", default="bounded-ops-access")
    parser.add_argument("--allow-empty", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    since = datetime.fromisoformat(args.since)
    if since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)
    previous = (
        json.loads(args.output.read_text(encoding="utf-8"))
        if args.output.exists()
        else None
    )
    report = collect(
        args.log_dir, since, previous, log_prefix=args.log_prefix
    )
    report["operations"] = host_snapshot((previous or {}).get("operations"))
    if not report["hours"] and not args.allow_empty:
        raise SystemExit("No matching log records; previous snapshot was not replaced")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(f".{args.output.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(report, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    try:
        os.chmod(temporary, 0o640)
    except OSError:
        pass
    temporary.replace(args.output)
    print(json.dumps({"hours": len(report["hours"]), **report["collector"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
