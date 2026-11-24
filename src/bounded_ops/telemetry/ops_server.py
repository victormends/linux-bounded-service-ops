"""Loopback-only private telemetry API and status server.

Security invariants:
  - Binds exclusively to ``127.0.0.1`` (never ``0.0.0.0``).
  - Enforces a strict ``Host`` header allowlist.
  - Rejects cross-site requests via ``Sec-Fetch-Site`` and ``Origin`` validation.
  - Refuses symlinked or oversized (> 12 MiB) snapshot files.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from typing import Any, Dict, FrozenSet, List, Optional, Tuple
from urllib.parse import urlsplit

from .collector import sum_sparse_histograms, summarize_percentiles

MAX_REPORT_BYTES = 12 * 1024 * 1024
ALLOWED_SEC_FETCH_SITES = frozenset({"same-origin", "same-site", "none"})


def build_summary_from_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """Compute endpoint rollups and P50/P95/P99 latency from 5-minute cubes."""
    details = report.get("details", {})
    rows = details.get("rows", [])
    by_endpoint_rows: Dict[str, List[Any]] = defaultdict(list)
    by_endpoint_requests: Dict[str, int] = defaultdict(int)
    for row in rows:
        if len(row) < 6:
            continue
        endpoint_name = str(row[1])
        by_endpoint_rows[endpoint_name].append(row)
        by_endpoint_requests[endpoint_name] += int(row[5])

    endpoints_summary: Dict[str, Dict[str, Any]] = {}
    for endpoint_name, ep_rows in sorted(by_endpoint_rows.items()):
        hist = sum_sparse_histograms(ep_rows)
        endpoints_summary[endpoint_name] = {
            "requests": by_endpoint_requests[endpoint_name],
            "latency": summarize_percentiles(hist),
        }

    overall_hist = sum_sparse_histograms(rows)
    return {
        "generated_at": report.get("generated_at"),
        "row_count": len(rows),
        "overall_latency": summarize_percentiles(overall_hist),
        "endpoints": endpoints_summary,
    }


class LoopbackOpsServer(ThreadingHTTPServer):
    """Loopback-bound HTTPServer serving private aggregated telemetry."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: Tuple[str, int],
        report_path: Path,
        allowed_hosts: Optional[FrozenSet[str]] = None,
    ) -> None:
        self.report_path = report_path
        super().__init__(server_address, OpsRequestHandler)
        bound_port = int(self.server_address[1])
        self.allowed_hosts = allowed_hosts or frozenset(
            {f"127.0.0.1:{bound_port}", f"localhost:{bound_port}"}
        )


class OpsRequestHandler(BaseHTTPRequestHandler):
    """Strict loopback-only read-only handler with anti-CSRF header guards."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _reply(
        self,
        code: int,
        body: bytes,
        content_type: str = "application/json; charset=utf-8",
    ) -> None:
        accepts_gzip = "gzip" in self.headers.get("Accept-Encoding", "").lower()
        compressible = content_type.startswith(
            ("application/json", "application/javascript", "text/")
        )
        compressed = accepts_gzip and compressible and len(body) >= 1024
        if compressed:
            body = gzip.compress(body, compresslevel=6, mtime=0)
        try:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            if compressed:
                self.send_header("Content-Encoding", "gzip")
                self.send_header("Vary", "Accept-Encoding")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; "
                "base-uri 'none'; form-action 'none'",
            )
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            pass

    def _is_loopback_request_authorized(self) -> bool:
        host = self.headers.get("Host", "")
        if host not in self.server.allowed_hosts:
            return False
        sec_fetch_site = self.headers.get("Sec-Fetch-Site")
        if sec_fetch_site is not None and sec_fetch_site.lower() not in ALLOWED_SEC_FETCH_SITES:
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin != f"http://{host}":
            return False
        return True

    def _load_report_bytes(self) -> Optional[bytes]:
        source = self.server.report_path
        try:
            if source.is_symlink() or not source.is_file():
                return None
            if source.stat().st_size > MAX_REPORT_BYTES:
                return None
            return source.read_bytes()
        except OSError:
            return None

    def do_GET(self) -> None:
        if not self._is_loopback_request_authorized():
            self._reply(403, b'{"error":"Local loopback access only"}')
            return

        path = urlsplit(self.path).path
        if path == "/healthz":
            self._reply(
                200,
                b'{"service":"bounded-ops-telemetry","access":"loopback-only"}',
            )
            return

        if path == "/report.json":
            raw = self._load_report_bytes()
            if raw is None:
                self._reply(503, b'{"error":"Report unavailable"}')
                return
            self._reply(200, raw, "application/json; charset=utf-8")
            return

        if path == "/summary":
            raw = self._load_report_bytes()
            if raw is None:
                self._reply(503, b'{"error":"Report unavailable"}')
                return
            try:
                report = json.loads(raw.decode("utf-8"))
                summary = build_summary_from_report(report)
            except (ValueError, UnicodeDecodeError):
                self._reply(503, b'{"error":"Invalid report payload"}')
                return
            self._reply(
                200,
                json.dumps(summary, separators=(",", ":")).encode("utf-8"),
                "application/json; charset=utf-8",
            )
            return

        if path == "/":
            html = (
                "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
                "<title>Bounded Ops Telemetry</title></head>"
                "<body><h1>Bounded Ops Telemetry (Loopback Only)</h1>"
                "<p>Endpoints: <code>/healthz</code>, <code>/summary</code>, "
                "<code>/report.json</code></p></body></html>"
            ).encode("utf-8")
            self._reply(200, html, "text/html; charset=utf-8")
            return

        self._reply(404, b'{"error":"Not found"}')

    do_HEAD = do_GET

    def do_POST(self) -> None:
        self._reply(405, b'{"error":"Read only"}')

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST


class OpsDashboardService:
    """Lifecycle wrapper for testing and running the loopback ops dashboard."""

    def __init__(
        self,
        report_path: Path,
        *,
        port: int = 8766,
        allowed_hosts: Optional[FrozenSet[str]] = None,
    ) -> None:
        self.report_path = report_path
        self.port = port
        self.allowed_hosts = allowed_hosts
        self._server: Optional[LoopbackOpsServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def server_port(self) -> int:
        if self._server is None:
            return self.port
        return int(self._server.server_address[1])

    def start(self, *, background: bool = True) -> None:
        self._server = LoopbackOpsServer(
            ("127.0.0.1", self.port),
            self.report_path,
            allowed_hosts=self.allowed_hosts,
        )
        if background:
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                name="bounded-ops-dashboard",
                daemon=True,
            )
            self._thread.start()
        else:
            self._server.serve_forever()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--port", type=int, choices=(8766, 18766), default=8766)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    service = OpsDashboardService(args.report, port=args.port)
    print(f"Private telemetry dashboard at http://127.0.0.1:{args.port}", flush=True)
    try:
        service.start(background=False)
    except KeyboardInterrupt:
        pass
    finally:
        service.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
