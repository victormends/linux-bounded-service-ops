"""Dual-lane singleflight coordinator, bounded admission control, and dual LRU caches."""

from __future__ import annotations

from collections import OrderedDict
from concurrent.futures import (
    Executor,
    Future,
    ProcessPoolExecutor,
    TimeoutError as FuturesTimeoutError,
)
import gzip as _gzip
import hashlib
import multiprocessing
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple

from .worker import initialize_worker

JobTimeoutError = FuturesTimeoutError

COMPUTE_LATENCY_MS_BOUNDS: Tuple[Optional[int], ...] = (
    5,
    10,
    25,
    50,
    100,
    250,
    500,
    1000,
    2500,
    5000,
    10000,
    30000,
    None,
)


class ServiceBusyError(Exception):
    """Raised when global, per-lane, or waiter admission bounds are saturated."""


class ClientDisconnectedError(Exception):
    """Raised when the downstream HTTP client disconnects while waiting."""


class _InlineExecutor(Executor):
    """Fallback synchronous executor used only when process pools are disabled."""

    def submit(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Future:
        future: Future = Future()
        try:
            result = fn(*args, **kwargs)
        except BaseException as exc:
            future.set_exception(exc)
        else:
            future.set_result(result)
        return future


def freeze_argument(value: Any) -> Any:
    """Return a deterministic, hashable representation for singleflight keys."""
    if isinstance(value, dict):
        return tuple(
            sorted((str(key), freeze_argument(item)) for key, item in value.items())
        )
    if isinstance(value, (list, tuple)):
        return tuple(freeze_argument(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return tuple(sorted(freeze_argument(item) for item in value))
    if isinstance(value, float):
        return round(value, 6)
    if value is None or isinstance(value, (str, int, bool)):
        return value
    return repr(value)


class EncodedBodyCache:
    """Bounded LRU cache storing raw and pre-gzipped HTTP response payloads."""

    def __init__(self, max_entries: int = 12, compresslevel: int = 6) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self.max_entries = max_entries
        self.compresslevel = compresslevel
        self._lock = threading.Lock()
        self._entries: OrderedDict[Tuple[Any, bool], Tuple[str, bytes]] = OrderedDict()
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def get_or_encode(
        self,
        cache_key: Any,
        raw_bytes_fn: Callable[[], bytes],
        *,
        use_gzip: bool,
    ) -> Tuple[str, bytes, bool]:
        """Return ``(etag, encoded_bytes, cache_hit)`` from LRU or encode once."""
        full_key = (cache_key, bool(use_gzip))
        with self._lock:
            cached = self._entries.get(full_key)
            if cached is not None:
                self._entries.move_to_end(full_key)
                self.hits += 1
                return cached[0], cached[1], True
            self.misses += 1

        raw = raw_bytes_fn()
        etag = f'"{hashlib.sha256(raw).hexdigest()[:24]}"'
        encoded = (
            _gzip.compress(raw, compresslevel=self.compresslevel, mtime=0)
            if use_gzip
            else raw
        )

        with self._lock:
            existing = self._entries.get(full_key)
            if existing is not None:
                self._entries.move_to_end(full_key)
                return existing[0], existing[1], True
            self._entries[full_key] = (etag, encoded)
            self._entries.move_to_end(full_key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)
                self.evictions += 1
        return etag, encoded, False

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "entries": len(self._entries),
                "max_entries": self.max_entries,
                "hits": self.hits,
                "misses": self.misses,
                "evictions": self.evictions,
            }


class SingleFlightCoordinator:
    """Bounded dual-lane compute coordinator with coalescing and LRU caching."""

    def __init__(
        self,
        *,
        interactive_workers: int = 2,
        background_workers: int = 2,
        max_inflight: int = 12,
        interactive_max_inflight: int = 8,
        background_max_inflight: int = 4,
        max_waiters: int = 128,
        max_waiters_per_job: int = 64,
        job_timeout_seconds: float = 90.0,
        result_cache_max: int = 8,
        body_cache_max: int = 12,
        poll_interval_seconds: float = 0.05,
        interactive_executor: Optional[Executor] = None,
        background_executor: Optional[Executor] = None,
        on_state_change: Optional[Callable[[], None]] = None,
    ) -> None:
        if max_inflight < 1:
            raise ValueError("max_inflight must be >= 1")
        if interactive_max_inflight < 1 or interactive_max_inflight > max_inflight:
            raise ValueError("interactive_max_inflight must be in [1, max_inflight]")
        if background_max_inflight < 1 or background_max_inflight > max_inflight:
            raise ValueError("background_max_inflight must be in [1, max_inflight]")
        if max_waiters < 1 or max_waiters_per_job < 1 or max_waiters_per_job > max_waiters:
            raise ValueError("invalid waiter caps")
        if result_cache_max < 1:
            raise ValueError("result_cache_max must be >= 1")

        self.interactive_workers = interactive_workers
        self.background_workers = background_workers
        self.max_inflight = max_inflight
        self.interactive_max_inflight = interactive_max_inflight
        self.background_max_inflight = background_max_inflight
        self.max_waiters = max_waiters
        self.max_waiters_per_job = max_waiters_per_job
        self.job_timeout_seconds = job_timeout_seconds
        self.result_cache_max = result_cache_max
        self.poll_interval_seconds = poll_interval_seconds
        self._on_state_change = on_state_change

        self._lock = threading.RLock()
        self._capacity = threading.BoundedSemaphore(max_inflight)
        self._inflight: Dict[Tuple[Any, ...], Future] = {}
        self._inflight_lanes: Dict[Tuple[Any, ...], str] = {}
        self._waiters: Dict[Tuple[Any, ...], int] = {}
        self._result_cache: OrderedDict[Tuple[Any, ...], Any] = OrderedDict()
        self.body_cache = EncodedBodyCache(max_entries=body_cache_max)

        self._interactive_executor = interactive_executor
        self._background_executor = background_executor
        self._owns_executors = False
        self._inline_fallback = _InlineExecutor()

        self._metrics: Dict[str, int] = {
            "requests": 0,
            "submitted": 0,
            "joined": 0,
            "busy": 0,
            "background_busy": 0,
            "interactive_busy": 0,
            "waiter_busy": 0,
            "timed_out": 0,
            "completed": 0,
            "failed": 0,
            "disconnected": 0,
            "cancelled": 0,
            "cache_hits": 0,
            "cache_evictions": 0,
        }
        self._kind_metrics: Dict[str, Dict[str, int]] = {}
        self._latency_histogram = [0] * len(COMPUTE_LATENCY_MS_BOUNDS)
        self._latency_total_ms = 0
        self._latency_samples = 0

    def start_pools(self) -> None:
        """Start isolated ``spawn`` process pools for interactive and background lanes."""
        with self._lock:
            if self._interactive_executor is not None or self._background_executor is not None:
                return
            mp_ctx = multiprocessing.get_context("spawn")
            self._background_executor = ProcessPoolExecutor(
                max_workers=self.background_workers,
                mp_context=mp_ctx,
                initializer=initialize_worker,
            )
            self._interactive_executor = ProcessPoolExecutor(
                max_workers=self.interactive_workers,
                mp_context=mp_ctx,
                initializer=initialize_worker,
            )
            self._owns_executors = True

    def shutdown(self, wait: bool = True, cancel_futures: bool = True) -> None:
        """Shut down owned process pools cleanly."""
        with self._lock:
            bg = self._background_executor
            fg = self._interactive_executor
            owns = self._owns_executors
            if owns:
                self._background_executor = None
                self._interactive_executor = None
                self._owns_executors = False
        if owns:
            for pool in (bg, fg):
                if pool is not None:
                    pool.shutdown(wait=wait, cancel_futures=cancel_futures)

    def set_state_change_callback(self, callback: Optional[Callable[[], None]]) -> None:
        with self._lock:
            self._on_state_change = callback

    def _notify(self) -> None:
        cb = self._on_state_change
        if cb is not None:
            try:
                cb()
            except Exception:
                pass

    def _kind_bucket(self, kind: str) -> Dict[str, int]:
        return self._kind_metrics.setdefault(
            kind,
            {
                "requests": 0,
                "submitted": 0,
                "joined": 0,
                "busy": 0,
                "timed_out": 0,
                "completed": 0,
                "failed": 0,
                "disconnected": 0,
                "cancelled": 0,
                "cache_hits": 0,
                "job_total_ms": 0,
                "job_max_ms": 0,
            },
        )

    def _observe_latency(self, elapsed_ms: int) -> None:
        self._latency_total_ms += elapsed_ms
        self._latency_samples += 1
        for idx, bound in enumerate(COMPUTE_LATENCY_MS_BOUNDS):
            if bound is None or elapsed_ms <= bound:
                self._latency_histogram[idx] += 1
                break

    def _finish_job(
        self,
        key: Tuple[Any, ...],
        kind: str,
        future: Future,
        started_at: float,
    ) -> None:
        elapsed_ms = max(0, round((time.monotonic() - started_at) * 1000))
        with self._lock:
            km = self._kind_bucket(kind)
            if self._inflight.get(key) is future:
                self._inflight.pop(key, None)
                self._inflight_lanes.pop(key, None)
            if future.cancelled():
                pass
            elif future.exception() is not None:
                self._metrics["failed"] += 1
                km["failed"] += 1
            else:
                self._result_cache[key] = future.result()
                self._result_cache.move_to_end(key)
                while len(self._result_cache) > self.result_cache_max:
                    self._result_cache.popitem(last=False)
                    self._metrics["cache_evictions"] += 1
                self._metrics["completed"] += 1
                km["completed"] += 1
            km["job_total_ms"] += elapsed_ms
            km["job_max_ms"] = max(km["job_max_ms"], elapsed_ms)
            self._observe_latency(elapsed_ms)
            self._capacity.release()
        self._notify()

    def _select_executor(self, lane: str) -> Executor:
        if lane == "interactive":
            return self._interactive_executor or self._background_executor or self._inline_fallback
        return self._background_executor or self._interactive_executor or self._inline_fallback

    def execute(
        self,
        fn: Callable[..., Any],
        *args: Any,
        lane: str = "background",
        disconnect_check: Optional[Callable[[], bool]] = None,
        timeout_seconds: Optional[float] = None,
        coalesce_key: Optional[Tuple[Any, ...]] = None,
        job_kind: str = "compute",
    ) -> Any:
        """Execute or coalesce a bounded compute job in ``interactive`` or ``background`` lane."""
        if lane not in {"interactive", "background"}:
            raise ValueError(f"Unsupported lane: {lane}")

        key = (
            coalesce_key
            if coalesce_key is not None
            else (
                job_kind,
                getattr(fn, "__qualname__", repr(fn)),
                tuple(freeze_argument(arg) for arg in args),
            )
        )
        lane_limit = (
            self.interactive_max_inflight
            if lane == "interactive"
            else self.background_max_inflight
        )
        effective_timeout = (
            self.job_timeout_seconds if timeout_seconds is None else float(timeout_seconds)
        )

        busy_error: Optional[str] = None
        with self._lock:
            km = self._kind_bucket(job_kind)
            self._metrics["requests"] += 1
            km["requests"] += 1

            cached = self._result_cache.get(key)
            if cached is not None:
                self._result_cache.move_to_end(key)
                self._metrics["cache_hits"] += 1
                km["cache_hits"] += 1
                return cached

            future = self._inflight.get(key)
            if future is not None:
                total_waiters = sum(self._waiters.values())
                job_waiters = self._waiters.get(key, 0)
                if (
                    total_waiters >= self.max_waiters
                    or job_waiters >= self.max_waiters_per_job
                ):
                    self._metrics["busy"] += 1
                    self._metrics["waiter_busy"] += 1
                    km["busy"] += 1
                    busy_error = "Waiter queue capacity is full"
                else:
                    self._metrics["joined"] += 1
                    km["joined"] += 1
            else:
                lane_inflight = sum(
                    1
                    for existing_lane in self._inflight_lanes.values()
                    if existing_lane == lane
                )
                if lane_inflight >= lane_limit:
                    self._metrics["busy"] += 1
                    self._metrics[f"{lane}_busy"] += 1
                    km["busy"] += 1
                    busy_error = f"{lane} lane capacity is full"
                elif not self._capacity.acquire(blocking=False):
                    self._metrics["busy"] += 1
                    km["busy"] += 1
                    busy_error = "Global compute capacity is full"
                else:
                    started_at = time.monotonic()
                    executor = self._select_executor(lane)
                    try:
                        future = executor.submit(fn, *args)
                    except Exception:
                        self._capacity.release()
                        raise

                    self._inflight[key] = future
                    self._inflight_lanes[key] = lane
                    self._metrics["submitted"] += 1
                    km["submitted"] += 1
                    future.add_done_callback(
                        lambda completed, job_key=key, kind_name=job_kind, t0=started_at: (
                            self._finish_job(job_key, kind_name, completed, t0)
                        )
                    )

            if busy_error is None:
                self._waiters[key] = self._waiters.get(key, 0) + 1

        if busy_error is not None:
            self._notify()
            raise ServiceBusyError(busy_error)

        self._notify()
        disconnected = False
        timed_out = False
        deadline = time.monotonic() + effective_timeout
        try:
            while True:
                if disconnect_check is not None and disconnect_check():
                    disconnected = True
                    with self._lock:
                        self._metrics["disconnected"] += 1
                        self._kind_bucket(job_kind)["disconnected"] += 1
                    raise ClientDisconnectedError("Downstream client disconnected")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise JobTimeoutError("Compute job timed out")
                try:
                    return future.result(
                        timeout=min(self.poll_interval_seconds, remaining)
                    )
                except (FuturesTimeoutError, TimeoutError):
                    if time.monotonic() < deadline:
                        continue
                    raise JobTimeoutError("Compute job timed out")
        except (FuturesTimeoutError, TimeoutError):
            timed_out = True
            with self._lock:
                self._metrics["timed_out"] += 1
                self._kind_bucket(job_kind)["timed_out"] += 1
            self._notify()
            raise
        finally:
            with self._lock:
                remaining_waiters = self._waiters.get(key, 1) - 1
                if remaining_waiters > 0:
                    self._waiters[key] = remaining_waiters
                else:
                    self._waiters.pop(key, None)
                    if (disconnected or timed_out) and not future.done() and future.cancel():
                        self._metrics["cancelled"] += 1
                        self._kind_bucket(job_kind)["cancelled"] += 1
            if disconnected or timed_out:
                self._notify()

    def status(self) -> Dict[str, Any]:
        """Return non-sensitive saturation counters, cache telemetry, and latency buckets."""
        with self._lock:
            by_kind: Dict[str, Dict[str, int]] = {}
            for kind, km in sorted(self._kind_metrics.items()):
                finished = km["completed"] + km["failed"]
                entry = {k: v for k, v in km.items() if k != "job_total_ms"}
                entry["average_job_ms"] = (
                    round(km["job_total_ms"] / finished) if finished else 0
                )
                by_kind[kind] = entry

            buckets = [
                {
                    "le": "+Inf" if bound is None else str(bound),
                    "count": count,
                }
                for bound, count in zip(
                    COMPUTE_LATENCY_MS_BOUNDS, self._latency_histogram
                )
            ]

            return {
                "workers": {
                    "interactive": self.interactive_workers,
                    "background": self.background_workers,
                    "pools_active": (
                        self._interactive_executor is not None
                        or self._background_executor is not None
                    ),
                },
                "max_inflight": self.max_inflight,
                "inflight": len(self._inflight),
                "max_waiters": self.max_waiters,
                "waiters": sum(self._waiters.values()),
                "lanes": {
                    "background": {
                        "inflight": sum(
                            1 for lane in self._inflight_lanes.values() if lane == "background"
                        ),
                        "limit": self.background_max_inflight,
                    },
                    "interactive": {
                        "inflight": sum(
                            1 for lane in self._inflight_lanes.values() if lane == "interactive"
                        ),
                        "limit": self.interactive_max_inflight,
                    },
                },
                **self._metrics,
                "result_cache": {
                    "entries": len(self._result_cache),
                    "max_entries": self.result_cache_max,
                },
                "body_cache": self.body_cache.stats(),
                "latency_ms": {
                    "samples": self._latency_samples,
                    "sum_ms": self._latency_total_ms,
                    "buckets": buckets,
                },
                "by_kind": by_kind,
            }
