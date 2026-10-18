"""SQLite persistence for continuous monitoring."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from pfsense_checker.monitor.models import BeaconReport, BeaconStatus, ProbeResult


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class MonitorStore:
    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS beacons (
                    beacon_id   TEXT PRIMARY KEY,
                    hostname    TEXT NOT NULL DEFAULT '',
                    site        TEXT NOT NULL DEFAULT '',
                    version     TEXT NOT NULL DEFAULT '',
                    last_seen   TEXT NOT NULL,
                    meta_json   TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS probe_results (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    beacon_id   TEXT NOT NULL,
                    ts          TEXT NOT NULL,
                    kind        TEXT NOT NULL,
                    status      TEXT NOT NULL,
                    target      TEXT NOT NULL DEFAULT '',
                    subnet      TEXT NOT NULL DEFAULT '',
                    interface   TEXT NOT NULL DEFAULT '',
                    message     TEXT NOT NULL DEFAULT '',
                    latency_ms  REAL,
                    detail_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY (beacon_id) REFERENCES beacons(beacon_id)
                );
                CREATE INDEX IF NOT EXISTS idx_probe_ts
                    ON probe_results(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_probe_beacon
                    ON probe_results(beacon_id, ts DESC);
                CREATE INDEX IF NOT EXISTS idx_probe_kind
                    ON probe_results(kind, status, ts DESC);
                """
            )

    def ingest(self, report: BeaconReport) -> int:
        """Store a beacon report. Returns number of probe rows written."""
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO beacons(beacon_id, hostname, site, version, last_seen, meta_json)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(beacon_id) DO UPDATE SET
                    hostname=excluded.hostname,
                    site=excluded.site,
                    version=excluded.version,
                    last_seen=excluded.last_seen,
                    meta_json=excluded.meta_json
                """,
                (
                    report.beacon_id,
                    report.hostname,
                    report.site,
                    report.version,
                    now,
                    json.dumps(report.meta),
                ),
            )
            rows = 0
            for r in report.results:
                ts = r.ts or now
                conn.execute(
                    """
                    INSERT INTO probe_results(
                        beacon_id, ts, kind, status, target, subnet,
                        interface, message, latency_ms, detail_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        report.beacon_id,
                        ts,
                        r.kind,
                        r.status,
                        r.target,
                        r.subnet,
                        r.interface,
                        r.message,
                        r.latency_ms,
                        json.dumps(r.detail),
                    ),
                )
                rows += 1
            # Always record a heartbeat row for presence
            conn.execute(
                """
                INSERT INTO probe_results(
                    beacon_id, ts, kind, status, target, subnet,
                    interface, message, latency_ms, detail_json
                ) VALUES (?, ?, 'heartbeat', 'ok', '', '', '', ?, NULL, '{}')
                """,
                (report.beacon_id, now, f"{len(report.results)} probe(s)"),
            )
            return rows

    def list_beacons(self, offline_after_sec: int = 180) -> list[BeaconStatus]:
        cutoff = (
            datetime.now(timezone.utc) - timedelta(seconds=offline_after_sec)
        ).replace(microsecond=0).isoformat()
        with self._connect() as conn:
            beacons = conn.execute(
                "SELECT beacon_id, hostname, site, last_seen, meta_json FROM beacons "
                "ORDER BY site, beacon_id"
            ).fetchall()
            out: list[BeaconStatus] = []
            for b in beacons:
                counts = conn.execute(
                    """
                    SELECT kind, status, COUNT(*) AS n
                    FROM probe_results
                    WHERE beacon_id = ?
                      AND ts >= datetime('now', '-1 hour')
                      AND kind IN ('ping', 'dhcp')
                    GROUP BY kind, status
                    """,
                    (b["beacon_id"],),
                ).fetchall()
                ping_ok = ping_fail = dhcp_ok = dhcp_fail = 0
                for c in counts:
                    if c["kind"] == "ping" and c["status"] == "ok":
                        ping_ok = c["n"]
                    elif c["kind"] == "ping":
                        ping_fail += c["n"]
                    elif c["kind"] == "dhcp" and c["status"] == "ok":
                        dhcp_ok = c["n"]
                    elif c["kind"] == "dhcp":
                        dhcp_fail += c["n"]
                last = conn.execute(
                    """
                    SELECT message FROM probe_results
                    WHERE beacon_id = ? AND kind IN ('ping', 'dhcp', 'speed')
                    ORDER BY id DESC LIMIT 1
                    """,
                    (b["beacon_id"],),
                ).fetchone()
                try:
                    meta = json.loads(b["meta_json"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    meta = {}
                if not isinstance(meta, dict):
                    meta = {}
                out.append(
                    BeaconStatus(
                        beacon_id=b["beacon_id"],
                        hostname=b["hostname"],
                        site=b["site"],
                        last_seen=b["last_seen"],
                        online=b["last_seen"] >= cutoff,
                        ping_ok=ping_ok,
                        ping_fail=ping_fail,
                        dhcp_ok=dhcp_ok,
                        dhcp_fail=dhcp_fail,
                        last_message=(last["message"] if last else ""),
                        meta=meta,
                    )
                )
            return out

    def recent_results(
        self,
        limit: int = 200,
        kind: str | None = None,
        beacon_id: str | None = None,
        fails_only: bool = False,
    ) -> list[ProbeResult]:
        clauses = ["kind != 'heartbeat'"]
        params: list[Any] = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if beacon_id:
            clauses.append("beacon_id = ?")
            params.append(beacon_id)
        if fails_only:
            clauses.append("status != 'ok'")
        where = " AND ".join(clauses)
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT beacon_id, kind, status, target, subnet, interface, message,
                       latency_ms, detail_json, ts
                FROM probe_results
                WHERE {where}
                ORDER BY id DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
        return [
            ProbeResult(
                kind=r["kind"],
                status=r["status"],
                target=r["target"],
                subnet=r["subnet"],
                interface=r["interface"],
                message=r["message"],
                latency_ms=r["latency_ms"],
                detail=json.loads(r["detail_json"] or "{}"),
                ts=r["ts"],
                beacon_id=r["beacon_id"],
            )
            for r in rows
        ]

    def prune(self, keep_days: int = 14) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """
                DELETE FROM probe_results
                WHERE ts < datetime('now', ?)
                """,
                (f"-{keep_days} days",),
            )
            return cur.rowcount
