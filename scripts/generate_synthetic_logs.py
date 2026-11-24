"""Generate synthetic structured Nginx JSON access logs for testing."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import random
from typing import Dict, List, Tuple

ENDPOINTS: Tuple[Tuple[str, float, Tuple[int, ...], Tuple[float, float]], ...] = (
    ("/", 0.20, (200, 304), (0.002, 0.015)),
    ("/api/v1/compute?tile_id=grid-a&iterations=5000", 0.35, (200, 200, 200, 503, 499), (0.015, 0.450)),
    ("/api/v1/health", 0.20, (200,), (0.001, 0.006)),
    ("/api/v1/ready", 0.10, (200, 503), (0.001, 0.008)),
    ("/api/v1/metrics?format=prometheus", 0.08, (200,), (0.002, 0.012)),
    ("/api/v1/stream", 0.04, (200,), (0.500, 5.000)),
    ("/static/app.js", 0.03, (200, 304), (0.001, 0.005)),
)

USER_AGENTS: Tuple[str, ...] = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) Safari/604.1",
    "curl/8.7.1",
    "BoundedOpsProbe/1.0 monitor",
)

# RFC 5737 TEST-NET-2 / TEST-NET-3 documentation-only synthetic client addresses.
CLIENT_IPS: Tuple[str, ...] = tuple(
    [f"198.51.100.{i}" for i in range(10, 40)]
    + [f"203.0.113.{i}" for i in range(10, 30)]
)


def generate_lines(
    *,
    count: int = 500,
    hours: int = 6,
    seed: int = 42,
    end_time: datetime = None,  # type: ignore[assignment]
) -> List[str]:
    rng = random.Random(seed)
    anchor = (end_time or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start = anchor - timedelta(hours=hours)
    weights = [item[1] for item in ENDPOINTS]

    lines: List[str] = []
    for idx in range(count):
        offset_seconds = rng.uniform(0, hours * 3600)
        ts = start + timedelta(seconds=offset_seconds)
        uri, _weight, statuses, latency_range = rng.choices(ENDPOINTS, weights=weights, k=1)[0]
        status = rng.choice(statuses)
        req_time = round(rng.uniform(*latency_range), 4)
        # Strip query string in synthetic nginx `$uri` format by default,
        # occasionally include a query string to verify collector strips it.
        logged_uri = uri if idx % 10 == 0 else uri.split("?", 1)[0]
        payload: Dict[str, object] = {
            "time": ts.isoformat(),
            "request_id": f"req-{seed}-{idx:06d}",
            "remote_addr": rng.choice(CLIENT_IPS),
            "method": "GET",
            "uri": logged_uri,
            "status": status,
            "bytes": rng.randint(128, 16384),
            "request_time": req_time,
            "upstream_time": str(round(max(0.0, req_time - 0.001), 4)),
            "connection_requests": rng.randint(1, 8),
            "protocol": "HTTP/2.0",
            "user_agent": rng.choice(USER_AGENTS),
        }
        lines.append(json.dumps(payload, separators=(",", ":")))
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=500)
    parser.add_argument("--hours", type=int, default=6)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    lines = generate_lines(count=args.count, hours=args.hours, seed=args.seed)
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {len(lines)} synthetic Nginx JSON lines to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
