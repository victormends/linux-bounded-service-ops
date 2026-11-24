# linux-bounded-service-ops

Production-oriented Python 3.9+ standard-library toolkit for operating a CPU-bound HTTP/SSE service on a **4 GiB memory-constrained Linux host** without external message brokers, database servers, or third-party monitoring agents.

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

## Engineering Decisions and Real Tradeoffs

1. **Dual-lane `spawn` process pools instead of threads or single shared queue**
   - CPU-bound work inside a single Python process hits the GIL and degrades HTTP/SSE responsiveness. Isolating compute into `ProcessPoolExecutor("spawn")` keeps the gateway lightweight and lets `interactive` requests bypass a saturated `background` lane.
   - *Tradeoff:* Python's `Future.cancel()` can drop a *queued* future once `waiters == 0` and the downstream socket closes, freeing capacity for the queue, but it cannot preempt a worker already mid-execution without terminating the child process. Bounding `iterations`, `payload_bytes`, and `job_timeout_seconds` prevents runaway jobs.

2. **Singleflight coalescing with waiter caps and dual LRU caches**
   - Identical concurrent requests coalesce onto one `Future` after argument normalization (`freeze_argument`), preventing duplicate worker execution on bursty refreshes. Waiter caps (`max_waiters`, `max_waiters_per_job`) shed load with `503 Retry-After: 2` before threads pile up past `TasksMax=256`.
   - *Tradeoff:* Two small LRU caches (decoded objects in `SingleFlightCoordinator` and pre-gzipped bytes + ETags in `EncodedBodyCache`) double-cache hot payloads in exchange for eliminating repeated JSON serialization and gzip compression overhead on burst reads. Cache sizes remain strictly capped (`8` and `12` entries by default).

3. **Cgroup v2 accounting + `st_dev` deduplication + alert hysteresis**
   - Reading `memory.current` and `memory.events` (`oom`, `oom_kill`) inside the service cgroup catches container/unit memory pressure before host-wide swap exhaustion. Filesystem checks deduplicate by `st_dev` so multiple directories on the same block device are measured once. Cache walks reject symlinks/junctions and special files without mutating files.
   - *Tradeoff:* Alert hysteresis suppresses repeated failure webhooks until `reminder_seconds` elapses (while firing immediately on healthy-to-failing and failing-to-healthy transitions), meaning transient sub-interval blips between timer ticks are intentionally unobserved.

4. **Online `sqlite3.Connection.backup()` + GFS rotation + traversal-safe restore**
   - File-copying a live SQLite database risks torn WAL pages. `sqlite3.Connection.backup()` produces a consistent snapshot verified immediately with `PRAGMA integrity_check`, wrapped with a SHA-256 `manifest.json`, and pruned under Grandfather-Father-Son retention (7 daily, 4 weekly, 6 monthly). Restore requires an empty directory and rejects symlinks, hardlinks, device nodes, `..` traversal, or backslash paths before extracting.

5. **Two-phase SHA-256 release pruner (manual only)**
   - Storage cleanup never runs on a timer. Phase 1 inspects release directories (forbidding symlinks, mount crossings, hardlinks, and persistent `.sqlite`/`.env`/`.pem` files) plus `/proc/<pid>` (`cwd`, `exe`, `fd/*`, `maps`, `environ`, `cmdline`) and config roots, writing an immutable JSON plan. Phase 2 requires the exact `--apply-sha256`, re-validates every kept and target inventory, preserves `release-manifest.json`, and calls `os.fsync()` before and after each deletion in an append-only `.applied.jsonl` log.

6. **Closed-cardinality 5-minute telemetry cubes without raw PII**
   - Nginx writes JSON access logs using `$uri` (never `$request_uri`). The aggregator discards query strings, raw IPs, and raw User-Agents, folding counts and sparse latency histograms into allowlisted `(time_bucket, endpoint, device, traffic, status)` cubes capped at 40,000 rows over 7 days.
   - *Tradeoff:* P50/P95/P99 latencies computed by summing sparse bucket histograms are upper-bound approximations of the fixed bucket edges, and per-hour `unique_ip_estimate` values cannot be summed across hours. The private dashboard binds exclusively to `127.0.0.1` and enforces `Host`, `Sec-Fetch-Site`, and `Origin` checks.

## Repository Layout

| Path | Responsibility |
| :--- | :--- |
| `src/bounded_ops/gateway/worker.py` | Picklable `compute_grid_digest` workload for `spawn` process pools |
| `src/bounded_ops/gateway/singleflight.py` | Dual-lane `BoundedSemaphore` admission, coalescing, disconnect cancellation, dual LRU |
| `src/bounded_ops/gateway/sse_hub.py` | Thread-safe SSE broadcast hub with monotonic snapshots and heartbeats |
| `src/bounded_ops/gateway/server.py` | `ThreadingHTTPServer` gateway (`/compute`, `/health`, `/ready`, `/metrics`, `/stream`) |
| `src/bounded_ops/ops/healthcheck.py` | `/proc/meminfo`, cgroup v2 `memory.current`/`memory.events`, `st_dev` dedup, hysteresis |
| `src/bounded_ops/ops/sqlite_gfs_backup.py` | Online SQLite backup, SHA-256 manifest, GFS retention, traversal-safe restore |
| `src/bounded_ops/ops/release_pruner.py` | Two-phase SHA-256 cleanup plan, `/proc/<pid>` checks, `fsync` JSONL audit log |
| `src/bounded_ops/ops/secret_scanner.py` | Working tree and `git log` secret literal scanner |
| `src/bounded_ops/telemetry/collector.py` | Closed-cardinality 5-minute cube aggregator and fixed-bucket percentiles |
| `src/bounded_ops/telemetry/ops_server.py` | Loopback-only telemetry API (`Host` allowlist + anti-CSRF headers) |
| `scripts/generate_synthetic_logs.py` | Synthetic Nginx JSON log generator (RFC 5737 addresses only) |
| `infra/systemd/*.service`, `*.timer` | Hardened systemd units and timers tuned for a 4 GiB VPS |
| `infra/nginx/*.conf` | Reverse proxy timeouts, SSE buffering rules, rate limits, security headers |
| `tests/` | Unit and integration test suites across all subsystems |

## Local Quickstart (Zero External Dependencies)

Requires **Python 3.9+** (`pytest` for running the test suite).

### 1. Run the test suite and secret scanner

```bash
pytest -v
PYTHONPATH=src python -m bounded_ops.ops.secret_scanner --git-history
```

On Windows PowerShell 5.1 (`pytest.ini` configures `pythonpath = src`):

```powershell
pytest -v
$env:PYTHONPATH = "src"; python -m bounded_ops.ops.secret_scanner --git-history
```

### 2. Run the HTTP/SSE gateway locally

```powershell
$env:PYTHONPATH = "src"
python -m bounded_ops.gateway.server --host 127.0.0.1 --port 8765
```

Probe endpoints in another terminal:

```powershell
curl.exe -s "http://127.0.0.1:8765/api/v1/compute?tile_id=grid-a&iterations=2500&payload_bytes=4096&lane=interactive"
curl.exe -s "http://127.0.0.1:8765/api/v1/health"
curl.exe -s "http://127.0.0.1:8765/api/v1/ready"
curl.exe -s "http://127.0.0.1:8765/api/v1/metrics?format=prometheus"
curl.exe -N "http://127.0.0.1:8765/api/v1/stream"
```

### 3. Generate synthetic logs, aggregate cubes, and query the loopback dashboard

```powershell
$env:PYTHONPATH = "src"
python scripts/generate_synthetic_logs.py --output .\tmp-logs\bounded-ops-access.log --count 500 --hours 4
python -m bounded_ops.telemetry.collector --log-dir .\tmp-logs --output .\tmp-logs\report.json
python -m bounded_ops.telemetry.ops_server --report .\tmp-logs\report.json --port 8766
```

Query `http://127.0.0.1:8766/summary` or `http://127.0.0.1:8766/report.json` over loopback.

## License

MIT — see [LICENSE](LICENSE).
