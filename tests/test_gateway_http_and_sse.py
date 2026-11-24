"""Integration tests for the HTTP/SSE gateway, ETag/304, readiness, metrics, and SSE."""

from __future__ import annotations

import gzip
import http.client
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Tuple
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from bounded_ops.gateway.server import GatewayConfig, GatewayService
from bounded_ops.gateway.singleflight import SingleFlightCoordinator


def _http_get(
    port: int, path: str, headers: Dict[str, str] = None  # type: ignore[assignment]
) -> Tuple[int, Dict[str, str], bytes]:
    req = Request(f"http://127.0.0.1:{port}{path}", headers=headers or {})
    try:
        with urlopen(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except HTTPError as err:
        return err.code, dict(err.headers), err.read()


def test_gateway_compute_spawn_pool_etag_gzip_validation_and_methods() -> None:
    coord = SingleFlightCoordinator(
        interactive_workers=1,
        background_workers=1,
        result_cache_max=4,
        body_cache_max=8,
    )
    service = GatewayService(
        coordinator=coord,
        config=GatewayConfig(port=0, require_worker_pools=True),
        start_pools=True,
    )
    service.start(background=True)
    try:
        port = service.server_port
        query = "/api/v1/compute?tile_id=grid-01&iterations=120&payload_bytes=128&lane=interactive"

        status, hdrs, body = _http_get(port, query, {"Accept-Encoding": "gzip"})
        assert status == 200
        assert hdrs.get("Content-Encoding") == "gzip"
        etag = hdrs.get("ETag")
        assert etag
        payload = json.loads(gzip.decompress(body).decode("utf-8"))
        assert payload["tile_id"] == "grid-01"
        assert payload["worker_pid"] != os.getpid()

        # Conditional 304 Not Modified via ETag
        status_304, _, body_304 = _http_get(
            port, query, {"If-None-Match": etag, "Accept-Encoding": "gzip"}
        )
        assert status_304 == 304
        assert body_304 == b""

        # Cache hit on repeat plain JSON call
        status2, _, body2 = _http_get(port, query)
        assert status2 == 200
        assert json.loads(body2.decode("utf-8")) == payload
        assert coord.status()["cache_hits"] >= 1

        # Query allowlist and bounds validation -> 400
        bad_status, _, _ = _http_get(port, "/api/v1/compute?tile_id=grid-01&unknown=1")
        assert bad_status == 400
        rep_status, _, _ = _http_get(port, "/api/v1/compute?tile_id=a&tile_id=b")
        assert rep_status == 400

        # URI length > 4096 -> 414
        long_status, _, _ = _http_get(port, "/api/v1/compute?tile_id=" + ("x" * 4100))
        assert long_status == 414

        # Write methods -> 405
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request("POST", "/api/v1/compute")
            resp = conn.getresponse()
            assert resp.status == 405
            assert "GET" in resp.getheader("Allow", "")
        finally:
            conn.close()
    finally:
        service.stop()


def test_gateway_health_ready_metrics_and_updater_gates(tmp_path: Path) -> None:
    state = {"degraded": False, "storage": True}
    updater_file = tmp_path / "updater_status.json"
    updater_file.write_text(
        json.dumps({"last_exit_code": 0, "last_success_at": "2099-01-01T00:00:00+00:00"}),
        encoding="utf-8",
    )

    service = GatewayService(
        config=GatewayConfig(
            port=0,
            updater_status_path=updater_file,
            degraded_check=lambda: state["degraded"],
            storage_check=lambda: state["storage"],
        ),
        start_pools=False,
    )
    service.start(background=True)
    try:
        port = service.server_port
        s, _, b = _http_get(port, "/api/v1/compute?tile_id=tile-m&iterations=50&payload_bytes=64")
        assert s == 200

        s_health, _, b_health = _http_get(port, "/api/v1/health")
        assert s_health == 200
        health = json.loads(b_health.decode("utf-8"))
        assert health["status"] == "ok"
        assert health["runtime"]["completed"] == 1

        s_ready, _, b_ready = _http_get(port, "/api/v1/ready")
        assert s_ready == 200
        ready = json.loads(b_ready.decode("utf-8"))
        assert ready["ready"] is True
        assert ready["reasons"] == []

        # Degrade updater + storage -> 503 with explicit reasons[]
        state["degraded"] = True
        state["storage"] = False
        updater_file.write_text(
            json.dumps({"last_exit_code": 2, "last_success_at": "2020-01-01T00:00:00+00:00"}),
            encoding="utf-8",
        )
        s_unready, _, b_unready = _http_get(port, "/api/v1/ready")
        assert s_unready == 503
        unready = json.loads(b_unready.decode("utf-8"))
        assert unready["ready"] is False
        assert "service health is degraded" in unready["reasons"]
        assert "storage dependency is unavailable" in unready["reasons"]
        assert "updater failed" in unready["reasons"]
        assert "updater data is stale" in unready["reasons"]

        # Prometheus metrics text + JSON metrics
        s_prom, hdrs_prom, b_prom = _http_get(port, "/api/v1/metrics?format=prometheus")
        assert s_prom == 200
        assert "text/plain" in hdrs_prom["Content-Type"]
        prom_text = b_prom.decode("utf-8")
        assert "bounded_ops_completed_total 1" in prom_text
        assert 'bounded_ops_compute_duration_ms_bucket{le="+Inf"} 1' in prom_text

        s_json, _, b_json = _http_get(port, "/api/v1/metrics?format=json")
        assert s_json == 200
        metrics_json = json.loads(b_json.decode("utf-8"))
        assert metrics_json["runtime"]["completed"] == 1
        assert len(metrics_json["runtime"]["latency_ms"]["buckets"]) > 5
    finally:
        service.stop()


def test_sse_stream_delivers_snapshot_updates_heartbeat_and_cleans_up() -> None:
    service = GatewayService(
        config=GatewayConfig(port=0, heartbeat_seconds=0.15),
        start_pools=False,
    )
    service.start(background=True)
    try:
        port = service.server_port
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/api/v1/stream")
        resp = conn.getresponse()
        assert resp.status == 200
        assert "text/event-stream" in resp.getheader("Content-Type", "")

        collected: list[str] = []

        def read_until(target_substring: str, timeout_s: float = 3.0) -> str:
            deadline = time.monotonic() + timeout_s
            while time.monotonic() < deadline:
                line = resp.fp.readline().decode("utf-8", errors="replace")
                if line:
                    collected.append(line)
                    joined = "".join(collected)
                    if target_substring in joined:
                        return joined
            raise AssertionError(f"Did not observe {target_substring!r} in {collected!r}")

        # Initial snapshot delivered immediately
        text1 = read_until('"status":"ok"')
        assert "event: snapshot" in text1

        # Trigger a compute job -> broadcasts new monotonic SSE event
        s, _, _ = _http_get(port, "/api/v1/compute?tile_id=sse-1&iterations=40&payload_bytes=64")
        assert s == 200
        text2 = read_until('"completed":1')
        assert "id: " in text2

        # Wait briefly for heartbeat comment frame
        text3 = read_until(": heartbeat")
        assert ": heartbeat" in text3

        assert service.sse_hub.stats()["connected_clients"] == 1
        resp.close()
        conn.close()

        # Wait for server stream thread to notice disconnect and remove client
        deadline = time.monotonic() + 2.0
        while service.sse_hub.stats()["connected_clients"] > 0 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert service.sse_hub.stats()["connected_clients"] == 0
    finally:
        service.stop()
