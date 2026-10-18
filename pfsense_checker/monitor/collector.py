"""HTTP collector that receives beacon reports and stores them in SQLite."""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from pfsense_checker.monitor.models import BeaconReport
from pfsense_checker.monitor.store import MonitorStore


class CollectorState:
    def __init__(self, store: MonitorStore, token: str = "") -> None:
        self.store = store
        self.token = token
        self.lock = threading.Lock()


def make_handler(state: CollectorState):  # noqa: ANN201
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:  # noqa: ANN002
            print(f"[collector] {self.address_string()} - {fmt % args}")

        def _check_auth(self) -> bool:
            if not state.token:
                return True
            auth = self.headers.get("Authorization", "")
            if auth == f"Bearer {state.token}":
                return True
            if self.headers.get("X-Beacon-Token") == state.token:
                return True
            return False

        def _json(self, code: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            qs = parse_qs(parsed.query)

            if path == "/health":
                self._json(200, {"status": "ok"})
                return

            if not self._check_auth() and path != "/health":
                self._json(401, {"error": "unauthorized"})
                return

            if path == "/api/beacons":
                offline = int((qs.get("offline_after") or ["180"])[0])
                with state.lock:
                    beacons = [b.to_dict() for b in state.store.list_beacons(offline)]
                self._json(200, {"beacons": beacons})
                return

            if path == "/api/results":
                kind = (qs.get("kind") or [None])[0]
                beacon_id = (qs.get("beacon_id") or [None])[0]
                fails = (qs.get("fails_only") or ["0"])[0] in {"1", "true", "yes"}
                limit = int((qs.get("limit") or ["200"])[0])
                with state.lock:
                    results = [
                        r.to_dict()
                        for r in state.store.recent_results(
                            limit=limit,
                            kind=kind,
                            beacon_id=beacon_id,
                            fails_only=fails,
                        )
                    ]
                self._json(200, {"results": results})
                return

            self._json(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"

            if path not in {"/api/report", "/api/v1/report"}:
                self._json(404, {"error": "not found"})
                return

            if not self._check_auth():
                self._json(401, {"error": "unauthorized"})
                return

            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 2_000_000:
                self._json(400, {"error": "invalid content length"})
                return
            raw = self.rfile.read(length)
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                self._json(400, {"error": f"invalid json: {exc}"})
                return

            report = BeaconReport.from_dict(data)
            if not report.beacon_id:
                self._json(400, {"error": "beacon_id required"})
                return

            with state.lock:
                rows = state.store.ingest(report)
            self._json(
                200,
                {"ok": True, "stored": rows, "beacon_id": report.beacon_id},
            )

    return Handler


def run_collector(
    host: str = "0.0.0.0",
    port: int = 8787,
    db_path: Path | str = "data/monitor.db",
    token: str = "",
) -> None:
    store = MonitorStore(db_path)
    state = CollectorState(store, token=token)
    server = ThreadingHTTPServer((host, port), make_handler(state))
    print(f"[collector] listening on http://{host}:{port}")
    print(f"[collector] database: {Path(db_path).resolve()}")
    if token:
        print("[collector] auth token required")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[collector] shutting down")
        server.shutdown()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="pfSense beacon collector")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument(
        "--db",
        default=str(Path(__file__).resolve().parents[2] / "data" / "monitor.db"),
    )
    parser.add_argument("--token", default="", help="Optional shared bearer token")
    args = parser.parse_args(argv)
    run_collector(host=args.host, port=args.port, db_path=args.db, token=args.token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
