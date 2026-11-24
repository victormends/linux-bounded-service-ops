"""Tests for worker isolation, dual-lane singleflight coalescing, and dual LRU caches."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import gzip
import multiprocessing
import os
import threading
import time
from typing import Dict

import pytest

from bounded_ops.gateway.singleflight import (
    ClientDisconnectedError,
    EncodedBodyCache,
    JobTimeoutError,
    ServiceBusyError,
    SingleFlightCoordinator,
    freeze_argument,
)
from bounded_ops.gateway.worker import compute_grid_digest, initialize_worker


def _slow_compute(tag: str, delay: float, counter: Dict[str, int], lock: threading.Lock) -> Dict[str, object]:
    with lock:
        counter["calls"] = counter.get("calls", 0) + 1
    time.sleep(delay)
    return {"tag": tag, "ok": True}


def test_compute_grid_digest_is_deterministic_and_runs_in_spawn_pool() -> None:
    direct = compute_grid_digest("tile-alpha", iterations=150, payload_bytes=256)
    repeat = compute_grid_digest("tile-alpha", iterations=150, payload_bytes=256)
    assert direct["digest"] == repeat["digest"]
    assert direct["grid_checksum"] == repeat["grid_checksum"]
    assert direct["worker_pid"] == os.getpid()

    mp_ctx = multiprocessing.get_context("spawn")
    from concurrent.futures import ProcessPoolExecutor

    with ProcessPoolExecutor(
        max_workers=1, mp_context=mp_ctx, initializer=initialize_worker
    ) as pool:
        spawned = pool.submit(compute_grid_digest, "tile-alpha", 150, 256).result(timeout=20)
    assert spawned["digest"] == direct["digest"]
    assert spawned["worker_pid"] != os.getpid()

    with pytest.raises(ValueError):
        compute_grid_digest("../bad", 10, 128)
    with pytest.raises(ValueError):
        compute_grid_digest("tile-alpha", 0, 128)


def test_freeze_argument_normalizes_key_order_and_floats() -> None:
    k1 = freeze_argument({"b": 2, "a": [1, 2.0000001], "s": {"y", "x"}})
    k2 = freeze_argument({"a": [1, 2.0000002], "b": 2, "s": {"x", "y"}})
    assert k1 == k2


def test_singleflight_coalesces_concurrent_identical_requests() -> None:
    calls: Dict[str, int] = {}
    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=4) as pool:
        coord = SingleFlightCoordinator(
            interactive_executor=pool,
            background_executor=pool,
            max_inflight=4,
            interactive_max_inflight=4,
            background_max_inflight=4,
        )

        def call_one() -> Dict[str, object]:
            return coord.execute(
                _slow_compute,
                "same",
                0.15,
                calls,
                lock,
                lane="background",
                coalesce_key=("job", "same"),
            )

        with ThreadPoolExecutor(max_workers=8) as callers:
            futures = [callers.submit(call_one) for _ in range(8)]
            results = [f.result(timeout=5) for f in futures]

    assert all(r == {"tag": "same", "ok": True} for r in results)
    status = coord.status()
    assert calls["calls"] == 1
    assert status["submitted"] == 1
    assert status["joined"] == 7
    assert status["completed"] == 1


def test_dual_lane_isolation_keeps_interactive_available_when_background_saturated() -> None:
    bg_entered = threading.Event()
    bg_release = threading.Event()

    def blocking_bg() -> str:
        bg_entered.set()
        bg_release.wait(timeout=5)
        return "bg-done"

    def fast_fg() -> str:
        return "fg-done"

    with ThreadPoolExecutor(max_workers=2) as bg_pool, ThreadPoolExecutor(max_workers=2) as fg_pool:
        coord = SingleFlightCoordinator(
            interactive_executor=fg_pool,
            background_executor=bg_pool,
            max_inflight=3,
            background_max_inflight=1,
            interactive_max_inflight=2,
        )
        with ThreadPoolExecutor(max_workers=4) as callers:
            bg1 = callers.submit(
                coord.execute, blocking_bg, lane="background", coalesce_key=("bg", 1)
            )
            assert bg_entered.wait(timeout=2)

            with pytest.raises(ServiceBusyError):
                coord.execute(
                    blocking_bg, lane="background", coalesce_key=("bg", 2)
                )

            assert coord.execute(fast_fg, lane="interactive", coalesce_key=("fg", 1)) == "fg-done"
            bg_release.set()
            assert bg1.result(timeout=5) == "bg-done"

    assert coord.status()["background_busy"] == 1


def test_waiter_cap_and_timeout_handling() -> None:
    entered = threading.Event()
    release = threading.Event()

    def slow_job() -> str:
        entered.set()
        release.wait(timeout=5)
        return "ok"

    with ThreadPoolExecutor(max_workers=2) as pool:
        coord = SingleFlightCoordinator(
            interactive_executor=pool,
            background_executor=pool,
            max_inflight=2,
            interactive_max_inflight=2,
            background_max_inflight=2,
            max_waiters=3,
            max_waiters_per_job=2,
            poll_interval_seconds=0.01,
        )
        with ThreadPoolExecutor(max_workers=4) as callers:
            f1 = callers.submit(
                coord.execute, slow_job, lane="background", coalesce_key=("k", 1), timeout_seconds=2.0
            )
            assert entered.wait(timeout=2)
            f2 = callers.submit(
                coord.execute, slow_job, lane="background", coalesce_key=("k", 1), timeout_seconds=0.08
            )
            # Wait for f2 to attach before hitting per-job waiter cap = 2.
            deadline = time.monotonic() + 2
            while coord.status()["waiters"] < 2 and time.monotonic() < deadline:
                time.sleep(0.01)

            with pytest.raises(ServiceBusyError):
                coord.execute(
                    slow_job, lane="background", coalesce_key=("k", 1), timeout_seconds=1.0
                )

            with pytest.raises(JobTimeoutError):
                f2.result(timeout=2)

            release.set()
            assert f1.result(timeout=5) == "ok"

    status = coord.status()
    assert status["waiter_busy"] == 1
    assert status["timed_out"] == 1


def test_disconnect_cancels_queued_future_only_when_waiters_reach_zero() -> None:
    worker_busy = threading.Event()
    release_worker = threading.Event()

    def hold_worker() -> str:
        worker_busy.set()
        release_worker.wait(timeout=5)
        return "held"

    def queued_work() -> str:
        return "queued"

    with ThreadPoolExecutor(max_workers=1) as pool:
        coord = SingleFlightCoordinator(
            interactive_executor=pool,
            background_executor=pool,
            max_inflight=4,
            interactive_max_inflight=4,
            background_max_inflight=4,
            poll_interval_seconds=0.01,
        )
        with ThreadPoolExecutor(max_workers=4) as callers:
            holder = callers.submit(
                coord.execute, hold_worker, lane="background", coalesce_key=("hold",)
            )
            assert worker_busy.wait(timeout=2)

            # Submit queued job with two waiters; first waiter disconnects, second stays.
            disconnect_first = threading.Event()
            q1 = callers.submit(
                coord.execute,
                queued_work,
                lane="background",
                coalesce_key=("queued", 1),
                disconnect_check=disconnect_first.is_set,
            )
            q2 = callers.submit(
                coord.execute,
                queued_work,
                lane="background",
                coalesce_key=("queued", 1),
            )
            time.sleep(0.05)
            disconnect_first.set()
            with pytest.raises(ClientDisconnectedError):
                q1.result(timeout=2)
            assert coord.status()["cancelled"] == 0

            # Submit a second queued job with a single waiter and disconnect it -> cancelled!
            disconnect_only = threading.Event()
            q3 = callers.submit(
                coord.execute,
                queued_work,
                lane="background",
                coalesce_key=("queued", 2),
                disconnect_check=disconnect_only.is_set,
            )
            time.sleep(0.05)
            disconnect_only.set()
            with pytest.raises(ClientDisconnectedError):
                q3.result(timeout=2)

            release_worker.set()
            assert holder.result(timeout=5) == "held"
            assert q2.result(timeout=5) == "queued"

    status = coord.status()
    assert status["disconnected"] == 2
    assert status["cancelled"] == 1


def test_dual_lru_result_and_encoded_body_caches() -> None:
    coord = SingleFlightCoordinator(result_cache_max=2, body_cache_max=2)
    calls = 0

    def compute_value(x: int) -> Dict[str, int]:
        nonlocal calls
        calls += 1
        return {"value": x}

    assert coord.execute(compute_value, 1) == {"value": 1}
    assert coord.execute(compute_value, 1) == {"value": 1}
    assert calls == 1
    assert coord.execute(compute_value, 2) == {"value": 2}
    assert coord.execute(compute_value, 3) == {"value": 3}  # Evicts key 1
    assert coord.execute(compute_value, 1) == {"value": 1}  # Recomputes
    assert calls == 4
    assert coord.status()["cache_hits"] == 1
    assert coord.status()["cache_evictions"] == 2

    body_cache = EncodedBodyCache(max_entries=2)
    payload = b'{"tile":"a","data":"' + b"x" * 200 + b'"}'
    etag1, gz1, hit1 = body_cache.get_or_encode("a", lambda: payload, use_gzip=True)
    etag2, gz2, hit2 = body_cache.get_or_encode("a", lambda: payload, use_gzip=True)
    assert not hit1 and hit2
    assert etag1 == etag2
    assert gzip.decompress(gz1) == payload
    assert gz1 == gz2

    body_cache.get_or_encode("b", lambda: b'{"b":2}', use_gzip=False)
    body_cache.get_or_encode("c", lambda: b'{"c":3}', use_gzip=False)
    stats = body_cache.stats()
    assert stats["entries"] == 2
    assert stats["evictions"] == 1
