"""Systemd-friendly availability, cgroup v2 / meminfo, storage, and hysteresis probe."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

GIB = 1024 ** 3
MIB = 1024 ** 2

DEFAULT_HEALTHCHECK_URL = "http://127.0.0.1:8765/api/v1/health"
DEFAULT_MEMINFO_PATH = "/proc/meminfo"
DEFAULT_CGROUP_PATH = "/sys/fs/cgroup/system.slice/bounded-ops-gateway.service"


def severity(*states: str) -> str:
    """Return the highest-severity status across multiple check states."""
    rank = {"ok": 0, "warning": 1, "unknown": 2, "critical": 3}
    return max(states or ("ok",), key=lambda value: rank.get(value, 2))


def disk_status(
    path: str,
    *,
    warn_used_percent: float = 75.0,
    critical_used_percent: float = 85.0,
    warn_free_gib: float = 10.0,
    critical_free_gib: float = 5.0,
    disk_usage_fn: Callable[[str], Any] = shutil.disk_usage,
) -> Dict[str, Any]:
    """Check filesystem usage available to the unprivileged service."""
    usage = disk_usage_fn(path)
    if usage.total <= 0:
        raise ValueError(f"Invalid total disk bytes for {path}")
    used_percent = 100.0 * (usage.total - usage.free) / usage.total
    free_gib = usage.free / GIB
    state = "ok"
    if used_percent >= critical_used_percent or free_gib <= critical_free_gib:
        state = "critical"
    elif used_percent >= warn_used_percent or free_gib <= warn_free_gib:
        state = "warning"
    return {
        "state": state,
        "used_percent": round(used_percent, 2),
        "free_gib": round(free_gib, 2),
    }


def cache_status(
    path: str,
    *,
    max_entries: int = 50000,
    warn_gib: float = 8.0,
    critical_gib: float = 12.0,
) -> Dict[str, Any]:
    """Walk a persistent artifact cache without following symlinks or mountpoints."""
    root = Path(path)
    resolved = root.resolve()
    if (
        root.is_symlink()
        or not root.is_dir()
        or os.path.normcase(str(resolved)) != os.path.normcase(str(root.absolute()))
    ):
        raise RuntimeError("cache monitoring path unavailable or redirected")

    size = 0
    count = 0
    pending: List[Path] = [root]
    while pending:
        current = pending.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                count += 1
                if count > max_entries:
                    raise RuntimeError("cache monitoring entry limit reached")
                if entry.is_symlink():
                    raise RuntimeError("unexpected symlink in monitored cache")
                try:
                    info = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    # Atomic temp-file writers may rename/unlink while walking.
                    continue
                if stat.S_ISDIR(info.st_mode):
                    entry_path = Path(entry.path)
                    if (
                        os.path.ismount(entry.path)
                        or os.path.normcase(str(entry_path.resolve()))
                        != os.path.normcase(str(entry_path.absolute()))
                    ):
                        raise RuntimeError("unexpected mount or junction in monitored cache")
                    pending.append(entry_path)
                elif stat.S_ISREG(info.st_mode):
                    size += info.st_size
                else:
                    raise RuntimeError("unexpected special file in monitored cache")

    gib = size / GIB
    state = (
        "critical" if gib >= critical_gib
        else "warning" if gib >= warn_gib
        else "ok"
    )
    return {
        "state": state,
        "size_gib": round(gib, 3),
        "entries": count,
        "warning_gib": warn_gib,
        "critical_gib": critical_gib,
        "eviction": "disabled",
    }


def storage_status(
    monitored_paths: Optional[Sequence[Tuple[str, str]]] = None,
    *,
    cache_path: Optional[str] = None,
    stat_fn: Callable[[str], Any] = os.stat,
    disk_usage_fn: Callable[[str], Any] = shutil.disk_usage,
) -> Tuple[Dict[str, Any], List[str]]:
    """Inspect storage devices once per unique ``st_dev`` plus optional cache walk."""
    paths = monitored_paths or (
        ("root", "/"),
        ("data", os.environ.get("BOUNDED_OPS_DATA_DIR", "/var/lib/bounded-ops")),
        ("cache", os.environ.get("BOUNDED_OPS_CACHE_DIR", "/var/cache/bounded-ops")),
        ("backups", os.environ.get("BOUNDED_OPS_BACKUP_DIR", "/var/backups/bounded-ops")),
    )
    checks: Dict[str, Any] = {}
    issues: List[str] = []
    seen_devices: set = set()
    deduplicated_labels: List[str] = []

    for label, target in paths:
        try:
            device = stat_fn(target).st_dev
            if device in seen_devices:
                deduplicated_labels.append(label)
                continue
            seen_devices.add(device)
            check = disk_status(target, disk_usage_fn=disk_usage_fn)
            check["st_dev"] = device
            checks[label] = check
            if check["state"] != "ok":
                issues.append(
                    f"storage {label}: {check['state']}, "
                    f"{check['used_percent']}% used, {check['free_gib']} GiB free"
                )
        except (OSError, ValueError):
            checks[label] = {"state": "unknown"}
            issues.append(f"storage {label}: cannot inspect filesystem")

    if deduplicated_labels:
        checks["_deduplicated_labels"] = deduplicated_labels

    effective_cache = cache_path or os.environ.get(
        "BOUNDED_OPS_CACHE_DIR", "/var/cache/bounded-ops"
    )
    if effective_cache:
        try:
            cache_check = cache_status(effective_cache)
            checks["artifact_cache"] = cache_check
            if cache_check["state"] != "ok":
                issues.append(
                    f"artifact cache: {cache_check['state']}, "
                    f"{cache_check['size_gib']} GiB (preserved; review capacity)"
                )
        except (OSError, RuntimeError):
            checks["artifact_cache"] = {"state": "unknown"}
            issues.append("artifact cache: monitoring unavailable; no files changed")

    return checks, issues


def memory_status(
    meminfo_path: str = DEFAULT_MEMINFO_PATH,
    cgroup_path: str = DEFAULT_CGROUP_PATH,
    *,
    warn_available_percent: float = 20.0,
    critical_available_percent: float = 10.0,
    service_warn_percent: float = 65.0,
    service_critical_percent: float = 78.0,
) -> Dict[str, Any]:
    """Read host ``/proc/meminfo`` and cgroup v2 memory accounting."""
    values: Dict[str, int] = {}
    for line in Path(meminfo_path).read_text(encoding="ascii").splitlines():
        if ":" not in line:
            continue
        name, raw = line.split(":", 1)
        fields = raw.strip().split()
        if fields:
            values[name] = int(fields[0]) * 1024

    total = values["MemTotal"]
    if total <= 0:
        raise ValueError("MemTotal must be positive")
    available = values["MemAvailable"]
    available_percent = 100.0 * available / total

    host_state = (
        "critical" if available_percent <= critical_available_percent
        else "warning" if available_percent <= warn_available_percent
        else "ok"
    )

    swap_total = values.get("SwapTotal", 0)
    swap_used = max(0, swap_total - values.get("SwapFree", 0))
    result: Dict[str, Any] = {
        "state": host_state,
        "available_percent": round(available_percent, 2),
        "available_mib": round(available / MIB, 1),
        "total_mib": round(total / MIB, 1),
        "warning_available_percent": warn_available_percent,
        "critical_available_percent": critical_available_percent,
        "swap": {
            "configured": swap_total > 0,
            "used_mib": round(swap_used / MIB, 1),
            "total_mib": round(swap_total / MIB, 1),
        },
    }

    cgroup = Path(cgroup_path)
    try:
        service_current = int(
            (cgroup / "memory.current").read_text(encoding="ascii").strip()
        )
        service_percent = 100.0 * service_current / total
        service_state = (
            "critical" if service_percent >= service_critical_percent
            else "warning" if service_percent >= service_warn_percent
            else "ok"
        )
        events: Dict[str, int] = {}
        for line in (cgroup / "memory.events").read_text(encoding="ascii").splitlines():
            parts = line.split()
            if len(parts) == 2:
                events[parts[0]] = int(parts[1])
        oom = events.get("oom", 0)
        oom_kill = events.get("oom_kill", 0)
        if oom > 0 or oom_kill > 0:
            service_state = "critical"

        result["service"] = {
            "state": service_state,
            "used_mib": round(service_current / MIB, 1),
            "host_percent": round(service_percent, 2),
            "warning_host_percent": service_warn_percent,
            "critical_host_percent": service_critical_percent,
            "oom": oom,
            "oom_kill": oom_kill,
        }
        result["state"] = severity(result["state"], service_state)
    except (FileNotFoundError, PermissionError, ValueError, OSError):
        result["service"] = {"state": "unknown"}
    return result


def backup_status(
    path: str,
    *,
    now: Optional[datetime] = None,
    warn_hours: float = 26.0,
    critical_hours: float = 36.0,
) -> Dict[str, Any]:
    """Verify the recency of the last completed verified backup marker."""
    marker = Path(path)
    if marker.is_symlink():
        raise RuntimeError("backup status marker must not be a symlink")
    payload = json.loads(marker.read_text(encoding="utf-8"))
    completed_at = datetime.fromisoformat(
        str(payload["completed_at"]).replace("Z", "+00:00")
    ).astimezone(timezone.utc)
    reference_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    age_hours = (reference_now - completed_at).total_seconds() / 3600.0
    state = (
        "critical" if age_hours >= critical_hours
        else "warning" if age_hours >= warn_hours
        else "ok"
    )
    return {
        "state": state,
        "completed_at": completed_at.isoformat(),
        "age_hours": round(age_hours, 2),
        "archive": Path(str(payload.get("archive", ""))).name,
        "sha256": str(payload.get("sha256", "")),
    }


def public_availability_status(
    urls: Iterable[str],
    *,
    timeout_seconds: float = 12.0,
    opener: Callable[..., Any] = urlopen,
) -> Tuple[Dict[str, Any], List[str]]:
    """Probe public edge URLs in addition to the local loopback gateway."""
    checks: Dict[str, Any] = {}
    issues: List[str] = []
    for url in urls:
        started = time.monotonic()
        try:
            request = Request(url, headers={"User-Agent": "bounded-ops-probe/1"})
            with opener(request, timeout=timeout_seconds) as response:
                status_code = int(getattr(response, "status", 200))
                response.read(256)
            elapsed_ms = round((time.monotonic() - started) * 1000)
            state = "ok" if 200 <= status_code < 400 else "critical"
            checks[url] = {
                "state": state,
                "status_code": status_code,
                "elapsed_ms": elapsed_ms,
            }
            if state != "ok":
                issues.append(f"public endpoint {url}: HTTP {status_code}")
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            checks[url] = {"state": "critical", "error": type(error).__name__}
            issues.append(f"public endpoint {url}: unavailable ({type(error).__name__})")
    return checks, issues


def evaluate_alert_hysteresis(
    failing: bool,
    state_path: Optional[Path],
    *,
    reminder_seconds: int = 3600,
    now: Optional[int] = None,
) -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """Suppress noisy repeat alerts while notifying on transitions and reminders.

    Returns ``(should_notify, event_kind, next_state)`` where ``event_kind`` is
    ``"alert"``, ``"reminder"``, ``"recovery"``, or ``None``.
    """
    current_ts = int(time.time()) if now is None else int(now)
    previous: Dict[str, Any] = {}
    if state_path is not None:
        if state_path.is_symlink():
            raise RuntimeError("alert state path must not be a symlink")
        try:
            previous = json.loads(state_path.read_text(encoding="utf-8"))
            if not isinstance(previous, dict):
                previous = {}
        except FileNotFoundError:
            previous = {}
        except (OSError, ValueError, TypeError):
            previous = {}

    was_failing = previous.get("failing") is True
    last_notification = int(previous.get("last_notification_at", 0) or 0)

    if failing:
        if not was_failing:
            event_kind: Optional[str] = "alert"
            due = True
        elif current_ts - last_notification >= reminder_seconds:
            event_kind = "reminder"
            due = True
        else:
            event_kind = None
            due = False
    else:
        if was_failing:
            event_kind = "recovery"
            due = True
        else:
            event_kind = None
            due = False

    next_state = {
        "failing": failing,
        "last_notification_at": current_ts if due else last_notification,
    }
    return due, event_kind, next_state


def save_alert_state(state_path: Path, state: Dict[str, Any]) -> None:
    """Atomically write alert hysteresis state without following symlinks."""
    if state_path.is_symlink():
        raise RuntimeError("alert state path must not be a symlink")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = state_path.with_name(f".{state_path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    temporary.replace(state_path)


def send_webhook(webhook_url: str, message: str, *, opener: Callable[..., Any] = urlopen) -> None:
    if not webhook_url:
        return
    body = json.dumps({"service": "bounded-ops", "message": message}).encode("utf-8")
    request = Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with opener(request, timeout=8):
            pass
    except (HTTPError, URLError, TimeoutError, OSError):
        pass


def run_healthcheck(
    *,
    url: str = DEFAULT_HEALTHCHECK_URL,
    meminfo_path: str = DEFAULT_MEMINFO_PATH,
    cgroup_path: str = DEFAULT_CGROUP_PATH,
    monitored_paths: Optional[Sequence[Tuple[str, str]]] = None,
    cache_path: Optional[str] = None,
    backup_marker_path: Optional[str] = None,
    public_urls: Sequence[str] = (),
    alert_state_path: Optional[Path] = None,
    reminder_seconds: int = 3600,
    webhook_url: str = "",
    max_update_age_hours: float = 2.0,
    opener: Callable[..., Any] = urlopen,
    now: Optional[int] = None,
) -> Tuple[int, Dict[str, Any]]:
    """Run all operational checks and return ``(exit_code, report_dict)``."""
    checks, issues = storage_status(monitored_paths, cache_path=cache_path)

    try:
        memory = memory_status(meminfo_path, cgroup_path)
        checks["memory"] = memory
        if memory["state"] != "ok":
            issues.append(
                "memory: "
                f"{memory['state']}, {memory['available_percent']}% host available, "
                f"service {memory.get('service', {}).get('host_percent', 'unknown')}% of host"
            )
    except (OSError, ValueError, KeyError, ZeroDivisionError):
        checks["memory"] = {"state": "unknown"}
        issues.append("memory: monitoring unavailable")

    if backup_marker_path:
        try:
            backup = backup_status(backup_marker_path)
            checks["backup"] = backup
            if backup["state"] != "ok":
                issues.append(
                    f"backup: {backup['state']}, last verified backup is "
                    f"{backup['age_hours']} hours old"
                )
        except (OSError, ValueError, KeyError, TypeError, RuntimeError):
            checks["backup"] = {"state": "unknown"}
            issues.append("backup: verified-success marker unavailable")

    if public_urls:
        pub_checks, pub_issues = public_availability_status(public_urls, opener=opener)
        checks["public_endpoints"] = pub_checks
        issues.extend(pub_issues)

    payload: Dict[str, Any] = {}
    try:
        with opener(
            Request(url, headers={"User-Agent": "bounded-ops-healthcheck/1"}),
            timeout=10,
        ) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if payload.get("status") != "ok":
            raise RuntimeError(f"health status is {payload.get('status', 'missing')}")
        if not payload.get("dependencies", {}).get("storage_ready", True):
            raise RuntimeError("storage dependency is unavailable")
        updater = payload.get("updater", {})
        if updater.get("configured"):
            if updater.get("last_exit_code") not in (None, 0):
                raise RuntimeError(
                    f"updater last exit code is {updater['last_exit_code']}"
                )
            last_success = updater.get("last_success_at")
            if last_success:
                parsed = datetime.fromisoformat(str(last_success).replace("Z", "+00:00"))
                age_hours = (
                    datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)
                ).total_seconds() / 3600.0
                if age_hours > max_update_age_hours:
                    raise RuntimeError(
                        f"updater last success is {age_hours:.1f} hours old"
                    )
    except (HTTPError, URLError, TimeoutError, ValueError, RuntimeError, OSError) as error:
        issues.append(str(error))

    failing = bool(issues)
    due, event_kind, next_state = evaluate_alert_hysteresis(
        failing,
        alert_state_path,
        reminder_seconds=reminder_seconds,
        now=now,
    )
    if due and webhook_url:
        if failing:
            send_webhook(
                webhook_url,
                f"bounded-ops healthcheck {event_kind}: " + "; ".join(issues),
                opener=opener,
            )
        elif event_kind == "recovery":
            send_webhook(
                webhook_url,
                "bounded-ops healthcheck recovered: all monitored checks are healthy",
                opener=opener,
            )

    if alert_state_path is not None:
        try:
            save_alert_state(alert_state_path, next_state)
        except (OSError, RuntimeError):
            pass

    report = {
        "ok": not failing,
        "url": url,
        "generated_at": payload.get("generated_at"),
        "alert_event": event_kind,
        "issues": issues,
        "checks": checks,
    }
    return (1 if failing else 0), report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--url",
        default=os.environ.get("BOUNDED_OPS_HEALTHCHECK_URL", DEFAULT_HEALTHCHECK_URL),
    )
    parser.add_argument(
        "--meminfo",
        default=os.environ.get("BOUNDED_OPS_MEMINFO_PATH", DEFAULT_MEMINFO_PATH),
    )
    parser.add_argument(
        "--cgroup",
        default=os.environ.get("BOUNDED_OPS_CGROUP_PATH", DEFAULT_CGROUP_PATH),
    )
    parser.add_argument(
        "--backup-status",
        default=os.environ.get("BOUNDED_OPS_BACKUP_STATUS_PATH", ""),
    )
    parser.add_argument(
        "--alert-state",
        default=os.environ.get("BOUNDED_OPS_ALERT_STATE_PATH", ""),
    )
    args = parser.parse_args()

    public_urls = tuple(
        item.strip()
        for item in os.environ.get("BOUNDED_OPS_PUBLIC_PROBE_URLS", "").split(",")
        if item.strip()
    )
    exit_code, report = run_healthcheck(
        url=args.url,
        meminfo_path=args.meminfo,
        cgroup_path=args.cgroup,
        backup_marker_path=args.backup_status or None,
        public_urls=public_urls,
        alert_state_path=Path(args.alert_state) if args.alert_state else None,
        reminder_seconds=int(os.environ.get("BOUNDED_OPS_ALERT_REMINDER_SECONDS", "3600")),
        webhook_url=os.environ.get("BOUNDED_OPS_ALERT_WEBHOOK", ""),
    )
    print(json.dumps(report, separators=(",", ":")))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
