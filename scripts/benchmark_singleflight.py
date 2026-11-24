"""Local burst benchmark for SingleFlightCoordinator coalescing and dual-lane isolation."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from bounded_ops.gateway.singleflight import ServiceBusyError, SingleFlightCoordinator
from bounded_ops.gateway.worker import compute_grid_digest


def run_burst_benchmark(callers: int = 20) -> Dict[str, Any]:
    """Verify N concurrent identical requests coalesce to 1 execution plus interactive lane bypass."""
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="bg-bench") as bg_pool, ThreadPoolExecutor(
        max_workers=2, thread_name_prefix="fg-bench"
    ) as fg_pool:
        coord = SingleFlightCoordinator(
            interactive_workers=2,
            background_workers=4,
            max_inflight=6,
            interactive_max_inflight=2,
            background_max_inflight=4,
            max_waiters=max(32, callers * 2),
            max_waiters_per_job=max(32, callers * 2),
            interactive_executor=fg_pool,
            background_executor=bg_pool,
        )

        # Phase 1: N concurrent identical compute requests coalesce onto 1 worker execution.
        barrier = threading.Barrier(callers)

        def call_shared() -> Dict[str, Any]:
            barrier.wait(timeout=5.0)
            return coord.execute(
                compute_grid_digest,
                "burst-tile-01",
                80_000,
                4096,
                lane="background",
                job_kind="burst_coalesce",
            )

        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=callers) as client_pool:
            results = [fut.result(timeout=15.0) for fut in [client_pool.submit(call_shared) for _ in range(callers)]]
        coalesce_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        digests = {item["digest"] for item in results}
        assert len(digests) == 1, "All coalesced callers must receive identical digest"

        coalesce_status = coord.status()["by_kind"]["burst_coalesce"]

        # Phase 2: Saturate background_max_inflight=1 vs interactive lane bypass.
        bg_entered = threading.Event()
        bg_release = threading.Event()

        def hold_background() -> str:
            bg_entered.set()
            bg_release.wait(timeout=5.0)
            return "bg-released"

        lane_coord = SingleFlightCoordinator(
            max_inflight=3,
            background_max_inflight=1,
            interactive_max_inflight=2,
            interactive_executor=fg_pool,
            background_executor=bg_pool,
        )
        with ThreadPoolExecutor(max_workers=2) as lane_callers:
            bg_holder = lane_callers.submit(
                lane_coord.execute,
                hold_background,
                lane="background",
                coalesce_key=("lane-hold", 1),
            )
            assert bg_entered.wait(timeout=2.0)

            background_rejected = False
            try:
                lane_coord.execute(
                    hold_background,
                    lane="background",
                    coalesce_key=("lane-hold", 2),
                )
            except ServiceBusyError:
                background_rejected = True

            fg_res = lane_coord.execute(
                compute_grid_digest,
                "interactive-fast",
                500,
                1024,
                lane="interactive",
                job_kind="interactive_bypass",
            )
            bg_release.set()
            assert bg_holder.result(timeout=5.0) == "bg-released"

    return {
        "concurrent_callers": callers,
        "coalesce_elapsed_ms": coalesce_ms,
        "submitted": coalesce_status["submitted"],
        "joined": coalesce_status["joined"],
        "cache_hits": coalesce_status["cache_hits"],
        "completed": coalesce_status["completed"],
        "background_saturated_rejected": background_rejected,
        "interactive_bypass_digest": fg_res["digest"][:16],
    }


def main() -> int:
    summary = run_burst_benchmark(callers=20)
    assert summary["submitted"] == 1
    assert summary["joined"] + summary["cache_hits"] == summary["concurrent_callers"] - 1
    assert summary["background_saturated_rejected"] is True
    print("=== Singleflight & Dual-Lane Burst Benchmark ===")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
