"""Top-level picklable synthetic CPU workload for ``ProcessPoolExecutor("spawn")``.

The HTTP parent imports this module without pulling heavy native libraries
into the gateway process. Worker entrypoints stay module-level so Windows and
Linux ``spawn`` contexts can pickle and execute them cleanly across processes.
"""

from __future__ import annotations

import hashlib
import os
import re
import signal
import time
from typing import Any, Dict

TILE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MAX_ITERATIONS = 10_000_000
MAX_PAYLOAD_BYTES = 1_048_576
MIN_PAYLOAD_BYTES = 64


def initialize_worker() -> None:
    """Ignore SIGINT in child workers so the HTTP parent coordinates shutdown."""
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (ValueError, OSError):
        pass


def compute_grid_digest(
    tile_id: str,
    iterations: int = 2500,
    payload_bytes: int = 4096,
) -> Dict[str, Any]:
    """Execute a deterministic synthetic CPU-bound digest over a byte grid.

    Returns a JSON-serializable summary including the worker process ID so
    callers and integration tests can verify process isolation.
    """
    if not isinstance(tile_id, str) or not TILE_ID_RE.fullmatch(tile_id):
        raise ValueError("tile_id must match ^[A-Za-z0-9_.-]{1,64}$")
    if isinstance(iterations, bool) or not isinstance(iterations, int):
        raise ValueError("iterations must be an integer")
    if not 1 <= iterations <= MAX_ITERATIONS:
        raise ValueError(f"iterations must be between 1 and {MAX_ITERATIONS}")
    if isinstance(payload_bytes, bool) or not isinstance(payload_bytes, int):
        raise ValueError("payload_bytes must be an integer")
    if not MIN_PAYLOAD_BYTES <= payload_bytes <= MAX_PAYLOAD_BYTES:
        raise ValueError(
            f"payload_bytes must be between {MIN_PAYLOAD_BYTES} and {MAX_PAYLOAD_BYTES}"
        )

    started = time.monotonic()
    seed = hashlib.blake2b(
        f"{tile_id}:{payload_bytes}".encode("ascii"), digest_size=32
    ).digest()

    # Expand deterministic byte grid from seed in 32-byte blocks without huge allocations.
    blocks = (payload_bytes + 31) // 32
    grid = bytearray()
    current = seed
    for idx in range(blocks):
        current = hashlib.blake2b(
            current + idx.to_bytes(4, "big"), digest_size=32
        ).digest()
        grid.extend(current)
    del grid[payload_bytes:]

    accumulator = hashlib.sha256(grid).digest()
    window = 64 if payload_bytes >= 64 else payload_bytes
    max_offset = max(0, payload_bytes - window)
    for step in range(iterations):
        offset = ((accumulator[0] << 8) | accumulator[1]) % (max_offset + 1)
        h = hashlib.sha256()
        h.update(accumulator)
        h.update(step.to_bytes(4, "big"))
        h.update(memoryview(grid)[offset : offset + window])
        accumulator = h.digest()

    elapsed_ms = max(0, round((time.monotonic() - started) * 1000))
    return {
        "tile_id": tile_id,
        "iterations": iterations,
        "payload_bytes": payload_bytes,
        "digest": accumulator.hex(),
        "grid_checksum": hashlib.blake2b(grid, digest_size=16).hexdigest(),
        "elapsed_ms": elapsed_ms,
        "worker_pid": os.getpid(),
    }
