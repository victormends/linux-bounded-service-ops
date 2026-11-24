"""Bounded HTTP/SSE gateway built on ``ThreadingHTTPServer``.

Endpoints:
  - ``GET /api/v1/compute``: dual-lane singleflight CPU workload with ETag/gzip/304
  - ``GET /api/v1/health``: runtime saturation, pool status, and dependency state
  - ``GET /api/v1/ready``: readiness gate returning 200 or 503 with ``reasons[]``
  - ``GET /api/v1/metrics``: JSON or Prometheus text counters and latency buckets
  - ``GET /api/v1/stream``: Server-Sent Events stream backed by ``SSEHub``
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip as _gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import select
import socket
import sys
import threading
import time
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from .singleflight import (
    ClientDisconnectedError,
    JobTimeoutError,
    ServiceBusyError,
    SingleFlightCoordinator,
)
from .sse_hub import SSEHub
from .worker import TILE_ID_RE, compute_grid_digest

MAX_REQUEST_TARGET_LENGTH = 4096
MAX_QUERY_FIELDS = 32


def parse_query(raw_query: str) -> Dict[str, List[str]]:
    """Parse query string with bounded field count to prevent parameter abuse."""
    return parse_qs(
        raw_query,
        keep_blank_values=True,
        max_num_fields=MAX_QUERY_FIELDS,
    )


def validate_query_fields(
    query: Dict[str, List[str]],
    allowed: FrozenSet[str],
) -> None:
    """Enforce strict parameter allowlist and reject repeated parameters."""
    unknown = sorted(set(query) - set(allowed))
    if unknown:
        raise ValueError(f"Unknown query parameter: {unknown[0]}")
    repeated = sorted(key for key, values in query.items() if len(values) != 1)
    if repeated:
        raise ValueError(f"Repeated query parameter: {repeated[0]}")


def one_param(
    query: Dict[str, List[str]],
    key: str,
    *,
    required: bool = True,
) -> Optional[str]:
    values = query.get(key)
    if not values or values[0] == "":
        if required:
            raise ValueError(f"Missing {key}")
        return None
    if len(values) != 1:
        raise ValueError(f"Repeated {key}")
    return values[0]


def bounded_int(
    query: Dict[str, List[str]],
    key: str,
    minimum: int,
    maximum: int,
    *,
    default: Optional[int] = None,
) -> int:
    raw = one_param(query, key, required=(default is None))
    if raw is None:
        assert default is not None
        return default
    value = int(raw)
    if value < minimum or value > maximum:
        raise ValueError(f"{key} outside allowed range [{minimum}, {maximum}]")
    return value


def read_updater_status(status_path: Optional[Path]) -> Dict[str, Any]:
    """Read optional external sync/updater status JSON safely."""
    if status_path is None:
        return {"configured": False, "last_success_at": None, "last_exit_code": None}
    try:
        payload = json.loads(status_path.read_text(encoding="utf-8"))
        return {
            "configured": True,
            "last_started_at": payload.get("last_started_at"),
            "last_finished_at": payload.get("last_finished_at"),
            "last_success_at": payload.get("last_success_at"),
            "last_exit_code": payload.get("last_exit_code"),
        }
    except (OSError, ValueError, TypeError):
        return {"configured": True, "last_success_at": None, "last_exit_code": None}


def evaluate_readiness(
    health: Dict[str, Any],
    *,
    now: Optional[float] = None,
    max_update_age_hours: float = 2.0,
    require_worker_pools: bool = False,
) -> Tuple[bool, List[str]]:
    """Evaluate health state into an HTTP readiness gate and human-readable reasons."""
    reasons: List[str] = []
    if health.get("status") != "ok":
        reasons.append("service health is degraded")

    runtime = health.get("runtime", {})
    workers = runtime.get("workers", {})
    if require_worker_pools and not workers.get("pools_active"):
        reasons.append("worker pools are not active")

    if not health.get("dependencies", {}).get("storage_ready", True):
        reasons.append("storage dependency is unavailable")

    updater = health.get("updater", {})
    if updater.get("configured"):
        if updater.get("last_exit_code") not in (None, 0):
            reasons.append("updater failed")
        last_success = updater.get("last_success_at")
        if not last_success:
            reasons.append("updater has no successful run")
        else:
            try:
                parsed = datetime.fromisoformat(str(last_success).replace("Z", "+00:00"))
                current_ts = time.time() if now is None else now
                age_seconds = current_ts - parsed.timestamp()
                if age_seconds > max_update_age_hours * 3600:
                    reasons.append("updater data is stale")
            except (ValueError, TypeError, OverflowError):
                reasons.append("updater success time is invalid")

    return (not reasons), reasons


def format_prometheus_metrics(
    runtime: Dict[str, Any],
    sse_stats: Dict[str, Any],
) -> str:
    """Render bounded counters and cumulative latency buckets in Prometheus text format."""
    lines: List[str] = [
        "# HELP bounded_ops_requests_total Total compute requests received.",
        "# TYPE bounded_ops_requests_total counter",
        f"bounded_ops_requests_total {runtime['requests']}",
        "# HELP bounded_ops_submitted_total Total unique jobs submitted to workers.",
        "# TYPE bounded_ops_submitted_total counter",
        f"bounded_ops_submitted_total {runtime['submitted']}",
        "# HELP bounded_ops_joined_total Requests coalesced onto an inflight job.",
        "# TYPE bounded_ops_joined_total counter",
        f"bounded_ops_joined_total {runtime['joined']}",
        "# HELP bounded_ops_busy_total Requests rejected with 503 due to capacity limits.",
        "# TYPE bounded_ops_busy_total counter",
        f"bounded_ops_busy_total {runtime['busy']}",
        "# HELP bounded_ops_waiter_busy_total Requests rejected due to waiter queue limits.",
        "# TYPE bounded_ops_waiter_busy_total counter",
        f"bounded_ops_waiter_busy_total {runtime['waiter_busy']}",
        "# HELP bounded_ops_timed_out_total Requests that exceeded job timeout.",
        "# TYPE bounded_ops_timed_out_total counter",
        f"bounded_ops_timed_out_total {runtime['timed_out']}",
        "# HELP bounded_ops_completed_total Jobs completed successfully.",
        "# TYPE bounded_ops_completed_total counter",
        f"bounded_ops_completed_total {runtime['completed']}",
        "# HELP bounded_ops_failed_total Jobs that failed with an exception.",
        "# TYPE bounded_ops_failed_total counter",
        f"bounded_ops_failed_total {runtime['failed']}",
        "# HELP bounded_ops_disconnected_total Waiters that disconnected before completion.",
        "# TYPE bounded_ops_disconnected_total counter",
        f"bounded_ops_disconnected_total {runtime['disconnected']}",
        "# HELP bounded_ops_cancelled_total Queued jobs cancelled after last waiter left.",
        "# TYPE bounded_ops_cancelled_total counter",
        f"bounded_ops_cancelled_total {runtime['cancelled']}",
        "# HELP bounded_ops_cache_hits_total Singleflight result LRU cache hits.",
        "# TYPE bounded_ops_cache_hits_total counter",
        f"bounded_ops_cache_hits_total {runtime['cache_hits']}",
        "# HELP bounded_ops_cache_evictions_total Singleflight result LRU cache evictions.",
        "# TYPE bounded_ops_cache_evictions_total counter",
        f"bounded_ops_cache_evictions_total {runtime['cache_evictions']}",
        "# HELP bounded_ops_inflight_jobs Current active inflight worker jobs.",
        "# TYPE bounded_ops_inflight_jobs gauge",
        f"bounded_ops_inflight_jobs {runtime['inflight']}",
        "# HELP bounded_ops_waiters Current waiting HTTP callers.",
        "# TYPE bounded_ops_waiters gauge",
        f"bounded_ops_waiters {runtime['waiters']}",
        "# HELP bounded_ops_sse_connected_clients Current open SSE client connections.",
        "# TYPE bounded_ops_sse_connected_clients gauge",
        f"bounded_ops_sse_connected_clients {sse_stats['connected_clients']}",
        "# HELP bounded_ops_compute_duration_ms Compute job duration histogram in milliseconds.",
        "# TYPE bounded_ops_compute_duration_ms histogram",
    ]
    cumulative = 0
    for bucket in runtime["latency_ms"]["buckets"]:
        cumulative += int(bucket["count"])
        le = bucket["le"]
        lines.append(f'bounded_ops_compute_duration_ms_bucket{{le="{le}"}} {cumulative}')
    lines.append(f"bounded_ops_compute_duration_ms_sum {runtime['latency_ms']['sum_ms']}")
    lines.append(f"bounded_ops_compute_duration_ms_count {runtime['latency_ms']['samples']}")
    return "\n".join(lines) + "\n"


class GatewayConfig:
    """Configuration container for the bounded HTTP/SSE gateway."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 8765,
        app_version: str = "0.1.0",
        environment: str = "production",
        max_iterations: int = 200_000,
        max_payload_bytes: int = 65_536,
        heartbeat_seconds: float = 15.0,
        max_update_age_hours: float = 2.0,
        require_worker_pools: bool = False,
        updater_status_path: Optional[Path] = None,
        allowed_cors_origins: Optional[FrozenSet[str]] = None,
        degraded_check: Optional[Callable[[], bool]] = None,
        storage_check: Optional[Callable[[], bool]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.app_version = app_version
        self.environment = environment
        self.max_iterations = max_iterations
        self.max_payload_bytes = max_payload_bytes
        self.heartbeat_seconds = heartbeat_seconds
        self.max_update_age_hours = max_update_age_hours
        self.require_worker_pools = require_worker_pools
        self.updater_status_path = updater_status_path
        self.allowed_cors_origins = allowed_cors_origins or frozenset()
        self.degraded_check = degraded_check
        self.storage_check = storage_check


class BoundedHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer carrying shared coordinator, SSE hub, and config."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: Tuple[str, int],
        coordinator: SingleFlightCoordinator,
        sse_hub: SSEHub,
        config: GatewayConfig,
        stop_event: threading.Event,
    ) -> None:
        self.coordinator = coordinator
        self.sse_hub = sse_hub
        self.config = config
        self.stop_event = stop_event
        super().__init__(server_address, GatewayRequestHandler)


class GatewayRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler enforcing bounded query parsing, ETag/304, gzip, and SSE."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        if args and len(args) >= 2 and str(args[1]) not in ("200", "304"):
            super().log_message(format, *args)

    def _client_disconnected(self) -> bool:
        try:
            readable, _, _ = select.select([self.connection], [], [], 0)
            if not readable:
                return False
            return self.connection.recv(1, socket.MSG_PEEK) == b""
        except (OSError, ValueError):
            return False

    def _send_cors_headers(self) -> None:
        origin = self.headers.get("Origin")
        if origin and origin in self.server.config.allowed_cors_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def _write_bytes(self, body: bytes) -> bool:
        if self.command == "HEAD":
            return True
        try:
            self.wfile.write(body)
            self.wfile.flush()
            return True
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            return False

    def _send_json(
        self,
        code: int,
        payload: Dict[str, Any],
        *,
        cache_seconds: int = 0,
        allow_fresh_cache: bool = False,
        headers: Optional[Dict[str, str]] = None,
        body_cache_key: Optional[Any] = None,
    ) -> None:
        accept_encoding = self.headers.get("Accept-Encoding", "").lower()
        use_gzip = "gzip" in accept_encoding

        def encode_raw() -> bytes:
            return json.dumps(
                payload, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")

        etag: Optional[str] = None
        if body_cache_key is not None:
            etag, body, _ = self.server.coordinator.body_cache.get_or_encode(
                body_cache_key,
                encode_raw,
                use_gzip=use_gzip,
            )
            if self.headers.get("If-None-Match") == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Cache-Control", f"public, max-age={cache_seconds}")
                self.send_header("Vary", "Accept-Encoding")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
        else:
            raw = encode_raw()
            body = _gzip.compress(raw, compresslevel=6, mtime=0) if use_gzip else raw

        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._send_cors_headers()
            cache_control = (
                f"public, max-age={cache_seconds}"
                if allow_fresh_cache and cache_seconds > 0
                else f"no-cache, max-age={cache_seconds}"
            )
            self.send_header("Cache-Control", cache_control)
            self.send_header("Vary", "Accept-Encoding")
            if etag is not None:
                self.send_header("ETag", etag)
            if use_gzip:
                self.send_header("Content-Encoding", "gzip")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            return
        self._write_bytes(body)

    def _send_text(
        self,
        code: int,
        text: str,
        *,
        content_type: str = "text/plain; version=0.0.4; charset=utf-8",
    ) -> None:
        raw = text.encode("utf-8")
        use_gzip = "gzip" in self.headers.get("Accept-Encoding", "").lower()
        body = _gzip.compress(raw, compresslevel=6, mtime=0) if use_gzip else raw
        try:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Vary", "Accept-Encoding")
            if use_gzip:
                self.send_header("Content-Encoding", "gzip")
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            return
        self._write_bytes(body)

    def _build_health_payload(self) -> Dict[str, Any]:
        cfg = self.server.config
        degraded = bool(cfg.degraded_check()) if cfg.degraded_check else False
        storage_ready = bool(cfg.storage_check()) if cfg.storage_check else True
        return {
            "status": "degraded" if degraded else "ok",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "application": {
                "version": cfg.app_version,
                "environment": cfg.environment,
            },
            "dependencies": {
                "storage_ready": storage_ready,
            },
            "runtime": self.server.coordinator.status(),
            "sse": self.server.sse_hub.stats(),
            "updater": read_updater_status(cfg.updater_status_path),
        }

    def do_GET(self) -> None:
        if len(self.path) > MAX_REQUEST_TARGET_LENGTH:
            self._send_json(414, {"error": "Request URI too long."})
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/v1/compute":
            try:
                qs = parse_query(parsed.query)
                validate_query_fields(
                    qs,
                    frozenset({"tile_id", "iterations", "payload_bytes", "lane"}),
                )
                tile_id = one_param(qs, "tile_id")
                assert tile_id is not None
                if not TILE_ID_RE.fullmatch(tile_id):
                    raise ValueError("Invalid tile_id")
                iterations = bounded_int(
                    qs, "iterations", 1, self.server.config.max_iterations, default=2500
                )
                payload_bytes = bounded_int(
                    qs,
                    "payload_bytes",
                    64,
                    self.server.config.max_payload_bytes,
                    default=4096,
                )
                lane = one_param(qs, "lane", required=False) or "background"
                if lane not in {"interactive", "background"}:
                    raise ValueError("lane must be interactive or background")
                result = self.server.coordinator.execute(
                    compute_grid_digest,
                    tile_id,
                    iterations,
                    payload_bytes,
                    lane=lane,
                    disconnect_check=self._client_disconnected,
                    coalesce_key=("compute", tile_id, iterations, payload_bytes),
                    job_kind="compute",
                )
            except (KeyError, ValueError) as error:
                self._send_json(400, {"error": f"Invalid compute request: {error}"})
                return
            except ServiceBusyError as error:
                self._send_json(
                    503,
                    {"error": str(error)},
                    headers={"Retry-After": "2"},
                )
                return
            except JobTimeoutError:
                self._send_json(
                    504,
                    {"error": "Compute request timed out"},
                    headers={"Retry-After": "2"},
                )
                return
            except ClientDisconnectedError:
                return
            except (OSError, RuntimeError) as error:
                self._send_json(500, {"error": str(error)})
                return

            self._send_json(
                200,
                result,
                cache_seconds=3600,
                allow_fresh_cache=True,
                body_cache_key=("compute", tile_id, iterations, payload_bytes),
            )
            return

        if path == "/api/v1/health":
            try:
                qs = parse_query(parsed.query)
                validate_query_fields(qs, frozenset())
            except ValueError as error:
                self._send_json(400, {"error": str(error)})
                return
            self._send_json(200, self._build_health_payload(), cache_seconds=0)
            return

        if path == "/api/v1/ready":
            try:
                qs = parse_query(parsed.query)
                validate_query_fields(qs, frozenset())
            except ValueError as error:
                self._send_json(400, {"error": str(error)})
                return
            health = self._build_health_payload()
            ready, reasons = evaluate_readiness(
                health,
                max_update_age_hours=self.server.config.max_update_age_hours,
                require_worker_pools=self.server.config.require_worker_pools,
            )
            code = 200 if ready else 503
            self._send_json(
                code,
                {
                    "ready": ready,
                    "generated_at": health["generated_at"],
                    "reasons": reasons,
                    "application": health["application"],
                },
                cache_seconds=0,
            )
            return

        if path == "/api/v1/metrics":
            try:
                qs = parse_query(parsed.query)
                validate_query_fields(qs, frozenset({"format"}))
                fmt = one_param(qs, "format", required=False)
                if fmt is not None and fmt not in {"json", "prometheus"}:
                    raise ValueError("format must be json or prometheus")
            except ValueError as error:
                self._send_json(400, {"error": str(error)})
                return

            runtime = self.server.coordinator.status()
            sse_stats = self.server.sse_hub.stats()
            accept = self.headers.get("Accept", "").lower()
            want_json = fmt == "json" or (fmt is None and "application/json" in accept)
            if want_json:
                self._send_json(
                    200,
                    {
                        "generated_at": datetime.now(timezone.utc).isoformat(),
                        "runtime": runtime,
                        "sse": sse_stats,
                    },
                    cache_seconds=0,
                )
            else:
                self._send_text(200, format_prometheus_metrics(runtime, sse_stats))
            return

        if path == "/api/v1/stream":
            try:
                qs = parse_query(parsed.query)
                validate_query_fields(qs, frozenset())
            except ValueError as error:
                self._send_json(400, {"error": str(error)})
                return

            self.close_connection = True
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache, no-store")
                self.send_header("Connection", "close")
                self.send_header("X-Accel-Buffering", "no")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                return

            if self.command == "HEAD":
                return

            try:
                self.server.sse_hub.stream(
                    self.wfile,
                    heartbeat_seconds=self.server.config.heartbeat_seconds,
                    stop_event=self.server.stop_event,
                )
            except RuntimeError:
                return
            return

        self._send_json(404, {"error": "Endpoint not found"})

    do_HEAD = do_GET

    def do_POST(self) -> None:
        self._send_json(
            405,
            {"error": "Method not allowed."},
            headers={"Allow": "GET, HEAD"},
        )

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST


class GatewayService:
    """Lifecycle wrapper for the bounded HTTP/SSE gateway and SSE snapshot publisher."""

    def __init__(
        self,
        *,
        coordinator: Optional[SingleFlightCoordinator] = None,
        sse_hub: Optional[SSEHub] = None,
        config: Optional[GatewayConfig] = None,
        start_pools: bool = False,
    ) -> None:
        self.config = config or GatewayConfig()
        self.coordinator = coordinator or SingleFlightCoordinator()
        self.sse_hub = sse_hub or SSEHub()
        self.stop_event = threading.Event()
        self._start_pools = start_pools
        self._http_server: Optional[BoundedHTTPServer] = None
        self._serve_thread: Optional[threading.Thread] = None

    def publish_snapshot(self) -> int:
        """Publish the current runtime and readiness summary to connected SSE clients."""
        health = {
            "status": (
                "degraded"
                if (self.config.degraded_check and self.config.degraded_check())
                else "ok"
            ),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "dependencies": {
                "storage_ready": (
                    bool(self.config.storage_check())
                    if self.config.storage_check
                    else True
                ),
            },
            "runtime": self.coordinator.status(),
            "sse": self.sse_hub.stats(),
            "updater": read_updater_status(self.config.updater_status_path),
        }
        ready, reasons = evaluate_readiness(
            health,
            max_update_age_hours=self.config.max_update_age_hours,
            require_worker_pools=self.config.require_worker_pools,
        )
        return self.sse_hub.publish(
            {
                "status": health["status"],
                "ready": ready,
                "reasons": reasons,
                "runtime": health["runtime"],
            },
            event="snapshot",
        )

    @property
    def server_port(self) -> int:
        if self._http_server is None:
            return self.config.port
        return int(self._http_server.server_address[1])

    def start(self, *, background: bool = True) -> None:
        self.stop_event.clear()
        self.sse_hub.reopen()
        if self._start_pools:
            self.coordinator.start_pools()
        self.coordinator.set_state_change_callback(self.publish_snapshot)
        self.publish_snapshot()
        self._http_server = BoundedHTTPServer(
            (self.config.host, self.config.port),
            self.coordinator,
            self.sse_hub,
            self.config,
            self.stop_event,
        )
        if background:
            self._serve_thread = threading.Thread(
                target=self._http_server.serve_forever,
                name="bounded-ops-gateway",
                daemon=True,
            )
            self._serve_thread.start()
        else:
            self._http_server.serve_forever()

    def stop(self) -> None:
        self.stop_event.set()
        self.sse_hub.close()
        self.coordinator.set_state_change_callback(None)
        if self._http_server is not None:
            self._http_server.shutdown()
            self._http_server.server_close()
            self._http_server = None
        if self._serve_thread is not None:
            self._serve_thread.join(timeout=5)
            self._serve_thread = None
        if self._start_pools:
            self.coordinator.shutdown(wait=True, cancel_futures=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("BOUNDED_OPS_HOST", "127.0.0.1"))
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("BOUNDED_OPS_PORT", "8765")),
    )
    parser.add_argument(
        "--interactive-workers",
        type=int,
        default=int(os.environ.get("BOUNDED_OPS_INTERACTIVE_WORKERS", "2")),
    )
    parser.add_argument(
        "--background-workers",
        type=int,
        default=int(os.environ.get("BOUNDED_OPS_BACKGROUND_WORKERS", "2")),
    )
    parser.add_argument(
        "--no-process-pools",
        action="store_true",
        help="Run jobs inline instead of spawning worker processes.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    coordinator = SingleFlightCoordinator(
        interactive_workers=args.interactive_workers,
        background_workers=args.background_workers,
    )
    config = GatewayConfig(
        host=args.host,
        port=args.port,
        require_worker_pools=not args.no_process_pools,
    )
    service = GatewayService(
        coordinator=coordinator,
        config=config,
        start_pools=not args.no_process_pools,
    )
    print(
        f"[bounded-ops] Gateway listening on http://{args.host}:{args.port}",
        flush=True,
    )
    try:
        service.start(background=False)
    except KeyboardInterrupt:
        print("\n[bounded-ops] Shutting down.", flush=True)
    finally:
        service.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
