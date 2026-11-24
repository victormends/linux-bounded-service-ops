# linux-bounded-service-ops

A Python 3.11+ standard-library runtime (CI-verified on Ubuntu 3.11 and 3.12; stdlib-compatible with 3.9+) and operational toolkit for running a CPU-bound HTTP/SSE service on a single 4 GiB memory-constrained Linux host without external message brokers, database servers, or heavy monitoring agents.

---

## Why This Exists

Running CPU-bound workloads behind an HTTP API on a small VPS usually breaks in four predictable ways:

1. Heavy compute inside the web process hits the GIL, starves health/SSE connections, and pushes RSS past cgroup limits under traffic spikes.
2. Duplicate concurrent requests trigger redundant worker runs unless inflight futures are coalesced and bounded by lane and waiter caps.
3. Copying a live SQLite database leaves torn WAL pages, while blind timer cleanup (`rm -rf`) deletes releases still referenced by systemd units or `/proc/<pid>`.
4. Nginx query-string logging leaks user search terms and raw IP addresses to disk.

`linux-bounded-service-ops` isolates heavy compute into dual-lane `ProcessPoolExecutor("spawn")` pools with singleflight coalescing, pairs it with stdlib cgroup v2 / `st_dev` healthchecks, online GFS SQLite backups, a manual two-phase release pruner, and privacy-preserving 5-minute telemetry cubes.

## Origin & Sanitization

These modules were extracted and rewritten from a live single-host Linux service operated under burst traffic on constrained hardware. All proprietary domain computation, upstream third-party integrations, hostnames, IP addresses, and client references were removed and replaced by a deterministic synthetic CPU-bound digest workload and RFC 5737 synthetic access logs.

## What It Intentionally Does Not Do

This toolkit is scoped specifically to a single-host Linux + systemd + Nginx deployment.

It does **not**:

- orchestrate multi-node clusters or replace Kubernetes, Prometheus, or Grafana
- preempt an already-executing Python worker process mid-computation without killing the child process (timeout/disconnect cancellation drops queued futures once waiters reach zero)
- delete old releases automatically on a timer (storage pruning is intentionally manual and gated by a SHA-256 verification digest)

---

## System Architecture (4 GiB Host Budget)

```text
                        +--------------------------------------------+
                        |         Nginx Edge (TLS / Rate Limit)      |
                        |  - proxy_read_timeout 100s (> 90s job)     |
                        |  - proxy_buffering off on /api/v1/stream   |
                        |  - $uri only in JSON logs (no querystring) |
                        +---------------------+----------------------+
                                              | 127.0.0.1:8765
                                              v
+----------------------------------------------------------------------------------------+
|  Gateway Process (systemd: MemoryHigh=1500M, MemoryMax=2500M, TasksMax=256)            |
|                                                                                        |
|  GET /api/v1/compute --> Query Allowlist (400) & URI <= 4096 (414)                     |
|                              |                                                         |
|                              v                                                         |
|                    SingleFlightCoordinator                                             |
|                      |-- Result LRU Cache (hit -> immediate return)                    |
|                      |-- Waiter Coalescing (global & per-job caps -> 503 Retry-After)  |
|                      |-- Global BoundedSemaphore(max_inflight)                         |
|                      +-- Dual-Lane Admission Control:                                  |
|                            |-- interactive lane --> ProcessPoolExecutor("spawn")       |
|                            +-- background lane  --> ProcessPoolExecutor("spawn")       |
|                                                                                        |
|  Response Encoding ----> EncodedBodyCache (pre-gzipped wire bytes + ETag / 304)        |
|  GET /api/v1/stream ---> SSEHub (monotonic version, Condition broadcast, heartbeats)   |
|  GET /api/v1/health ---> runtime saturation + pool state + dependency checks           |
|  GET /api/v1/ready ----> 200 / 503 gate with explicit reasons[]                        |
|  GET /api/v1/metrics --> Prometheus text & JSON (counters + latency buckets)           |
+----------------------------------------------------------------------------------------+

Out-of-Band Systemd Timers & Maintenance (isolated memory/CPU budgets)
  |-- bounded-ops-healthcheck.timer --------> /proc/meminfo + cgroup v2 + st_dev dedup + hysteresis
  |-- bounded-ops-backup.timer -------------> online sqlite3.backup() + SHA-256 manifest + GFS prune
  |-- bounded-ops-telemetry-collect.timer --> 5-min closed-cardinality cubes (zero PII / querystring)
  |-- bounded-ops-telemetry-ui.service -----> 127.0.0.1:8766 Host-allowlisted + anti-CSRF dashboard
  +-- manual two-phase release_pruner ------> dry-run plan SHA-256 + /proc/<pid> check + fsync JSONL
```

## Engineering Tradeoffs

1. **Dual-lane `spawn` pools instead of threads or one shared queue:** CPU-bound work inside a single Python process hits the GIL and stalls HTTP/SSE reads. Separating `interactive` and `background` lanes prevents batch saturation from blocking interactive calls, trading worker preemption for hard `iterations`, `payload_bytes`, and `job_timeout_seconds` limits.
2. **Singleflight coalescing with dual LRU caches:** Caching both decoded objects (`result_cache_max=8`) and pre-gzipped bytes (`body_cache_max=12`) avoids repeated JSON encoding and gzip passes during burst refreshes at the cost of small bounded memory duplication.
3. **Cgroup v2 accounting + `st_dev` deduplication + hysteresis:** Reading `memory.current` and `memory.events` (`oom`, `oom_kill`) flags unit pressure before host swap exhaustion. Alert hysteresis fires immediately on state transitions and suppresses repeat failure pages until `reminder_seconds` elapses, meaning brief sub-interval recovery blips between timer ticks go unpaged.
4. **Online `sqlite3.Connection.backup()` + GFS rotation + safe restore:** Uses SQLite's online backup API + `PRAGMA integrity_check` + SHA-256 manifests and enforces empty-directory restores that reject symlinks, hardlinks, device nodes, or `..` traversal.
5. **Two-phase SHA-256 release pruner:** Scans `/proc/<pid>` (`cwd`, `exe`, `fd/*`, `maps`, `environ`, `cmdline`) and config roots before emitting an immutable plan JSON, then requires `--apply-sha256` and `os.fsync()` audit logging before deleting anything.
6. **Closed-cardinality 5-minute telemetry cubes:** Logs `$uri` without `$args`, drops raw IPs and User-Agents, and tracks sparse latency histograms capped at 40,000 rows over 7 days. P50/P95/P99 values represent upper-bound approximations at fixed bucket edges.

## Repository Layout

| Path | Responsibility |
| :--- | :--- |
| `src/bounded_ops/gateway/worker.py` | Picklable `compute_grid_digest` workload for `spawn` process pools |
| `src/bounded_ops/gateway/singleflight.py` | Dual-lane `BoundedSemaphore` admission, coalescing, disconnect/timeout cancellation, dual LRU |
| `src/bounded_ops/gateway/sse_hub.py` | Thread-safe SSE broadcast hub with monotonic snapshots and heartbeats |
| `src/bounded_ops/gateway/server.py` | `ThreadingHTTPServer` gateway (`/compute`, `/health`, `/ready`, `/metrics`, `/stream`) |
| `src/bounded_ops/ops/healthcheck.py` | `/proc/meminfo`, cgroup v2 `memory.current`/`memory.events`, `st_dev` dedup, hysteresis |
| `src/bounded_ops/ops/sqlite_gfs_backup.py` | Online SQLite backup, SHA-256 manifest, GFS retention, traversal-safe restore |
| `src/bounded_ops/ops/release_pruner.py` | Two-phase SHA-256 cleanup plan, `/proc/<pid>` checks, `fsync` JSONL audit log |
| `src/bounded_ops/ops/secret_scanner.py` | Working tree and `git log` secret literal scanner |
| `src/bounded_ops/telemetry/collector.py` | Closed-cardinality 5-minute cube aggregator and fixed-bucket percentiles |
| `src/bounded_ops/telemetry/ops_server.py` | Loopback-only telemetry API (`Host` allowlist + anti-CSRF headers) |
| `scripts/generate_synthetic_logs.py` | Synthetic Nginx JSON log generator (RFC 5737 addresses only) |
| `scripts/benchmark_singleflight.py` | Local 20-caller burst coalescing and dual-lane saturation benchmark |
| `infra/systemd/*.service`, `*.timer` | Hardened systemd units and timers tuned for a 4 GiB VPS |
| `infra/nginx/*.conf` | Reverse proxy timeouts, SSE buffering rules, rate limits, security headers |

## Local Quickstart (Zero External Dependencies)

Requires **Python 3.11+** (CI-verified on Ubuntu 3.11 and 3.12; stdlib-compatible with 3.9+, `pytest` for running the test suite).

```bash
pytest -v
PYTHONPATH=src python scripts/benchmark_singleflight.py
PYTHONPATH=src python -m bounded_ops.ops.secret_scanner --git-history
```

Start the HTTP/SSE gateway locally:

```bash
PYTHONPATH=src python -m bounded_ops.gateway.server --host 127.0.0.1 --port 8765
```

Probe endpoints in another terminal:

```bash
curl -s "http://127.0.0.1:8765/api/v1/compute?tile_id=grid-a&iterations=2500&payload_bytes=4096&lane=interactive"
curl -s "http://127.0.0.1:8765/api/v1/health"
curl -s "http://127.0.0.1:8765/api/v1/ready"
curl -s "http://127.0.0.1:8765/api/v1/metrics?format=prometheus"
curl -N "http://127.0.0.1:8765/api/v1/stream"
```

Generate synthetic logs, aggregate cubes, and query the loopback dashboard:

```bash
PYTHONPATH=src python scripts/generate_synthetic_logs.py --output ./tmp-logs/bounded-ops-access.log --count 500 --hours 4
PYTHONPATH=src python -m bounded_ops.telemetry.collector --log-dir ./tmp-logs --output ./tmp-logs/report.json
PYTHONPATH=src python -m bounded_ops.telemetry.ops_server --report ./tmp-logs/report.json --port 8766
```

## Measured Singleflight Benchmark

Output from `PYTHONPATH=src python scripts/benchmark_singleflight.py` (`20` concurrent identical callers synchronized behind a `threading.Barrier` followed by background saturation + interactive bypass):

| Metric | Measured Value | Behavior Verified |
| :--- | :--- | :--- |
| Concurrent Identical Callers | `20` | Barrier-released burst on `background` lane |
| Worker Executions Submitted | `1` | Singleflight coalescing collapsed 20 callers to 1 run |
| Joined In-Flight + Cache Hits | `19` joined + `0` cache hits | All 19 followers received identical digest (`1` completed) |
| Coalesce Window Elapsed | `593.66 ms` | Wall-clock time for all 20 callers to resolve |
| Saturated Background Rejection | `true` (`ServiceBusyError`) | 2nd concurrent job rejected when `background_max_inflight=1` |
| Interactive Lane Bypass | `digest=211a96786416d38d` | `interactive` lane executed while `background` lane was saturated |

## License

MIT - see [LICENSE](LICENSE).
