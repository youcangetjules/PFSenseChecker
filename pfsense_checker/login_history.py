"""Sign-in history: who signed in, from which address, and for how long.

Rows live in PostgreSQL ``login_sessions`` (schema in ``netcheck_schema``).
A successful sign-in opens a session; a heartbeat keeps ``last_seen_at``
fresh while NetCheck runs, so a crash still leaves a sensible duration;
quitting closes it. Failed attempts are recorded too, with the username
only when it is a real account — anything else is stored as "(unknown)",
so a password typed into the username box never reaches the database.
Passwords are never stored here.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from pfsense_checker import postgres_db as pg

OUTCOME_SUCCESS = "success"
OUTCOME_FAILED = "failed"
UNKNOWN_USER = "(unknown)"
HEARTBEAT_SECONDS = 60
# A session with no heartbeat for this long and no end is shown as ended
# at its last heartbeat ("no heartbeat" — crash, power loss, killed).
STALE_AFTER = timedelta(seconds=HEARTBEAT_SECONDS * 3)


@dataclass(frozen=True)
class LoginRecord:
    id: int
    username: str
    outcome: str
    client_ip: str
    client_host: str
    started_at: datetime
    last_seen_at: datetime
    ended_at: datetime | None
    end_reason: str
    app_version: str = ""

    def active(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return (
            self.outcome == OUTCOME_SUCCESS
            and self.ended_at is None
            and now - self.last_seen_at <= STALE_AFTER
        )

    def duration(self, now: datetime | None = None) -> timedelta | None:
        if self.outcome != OUTCOME_SUCCESS:
            return None
        now = now or datetime.now(timezone.utc)
        end = self.ended_at or (now if self.active(now) else self.last_seen_at)
        return max(timedelta(0), end - self.started_at)

    def how_it_ended(self, now: datetime | None = None) -> str:
        if self.outcome != OUTCOME_SUCCESS:
            return self.end_reason or "sign-in refused"
        if self.ended_at is not None:
            return self.end_reason or "signed out"
        return "still signed in" if self.active(now) else "no heartbeat (crash or killed)"


def format_duration(delta: timedelta | None) -> str:
    if delta is None:
        return ""
    secs = int(delta.total_seconds())
    days, secs = divmod(secs, 86400)
    hours, secs = divmod(secs, 3600)
    mins, secs = divmod(secs, 60)
    if days:
        return f"{days}d {hours}h {mins}m"
    if hours:
        return f"{hours}h {mins}m"
    if mins:
        return f"{mins}m {secs}s"
    return f"{secs}s"


def client_address() -> tuple[str, str]:
    """(IPv4 of this PC's outbound interface, hostname). No packets are sent."""
    host = socket.gethostname()
    ip = ""
    try:
        # UDP connect only picks a route; nothing goes on the wire.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # TEST-NET-1, never routed to anyone
            ip = s.getsockname()[0]
    except OSError:
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            ip = ""
    return ip, host


def _app_version() -> str:
    try:
        from pfsense_checker.version import VERSION

        return str(VERSION)
    except Exception:  # noqa: BLE001
        return ""


ConnectFn = Callable[[], Any]


def _connect():  # noqa: ANN202
    return pg.connect()


def start_session(username: str, *, connect: ConnectFn = _connect) -> int | None:
    """Record a successful sign-in; returns the session id."""
    ip, host = client_address()
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO login_sessions (username, outcome, client_ip, client_host, app_version) "
            "VALUES (%s, %s, %s, %s, %s) RETURNING id",
            (username, OUTCOME_SUCCESS, ip, host, _app_version()),
        )
        row = cur.fetchone()
    return int(row[0]) if row else None


def record_failed(username: str, *, known_user: bool, reason: str = "",
                  connect: ConnectFn = _connect) -> None:
    """Record a refused sign-in (no password; unknown names are not stored)."""
    ip, host = client_address()
    name = username if known_user else UNKNOWN_USER
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO login_sessions (username, outcome, client_ip, client_host, ended_at, "
            "end_reason, app_version) VALUES (%s, %s, %s, %s, NOW(), %s, %s)",
            (name, OUTCOME_FAILED, ip, host, reason[:200], _app_version()),
        )


def heartbeat(session_id: int, *, connect: ConnectFn = _connect) -> None:
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE login_sessions SET last_seen_at = NOW() WHERE id = %s AND ended_at IS NULL",
            (session_id,),
        )


def end_session(session_id: int, reason: str = "signed out", *, connect: ConnectFn = _connect) -> None:
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE login_sessions SET ended_at = NOW(), last_seen_at = NOW(), end_reason = %s "
            "WHERE id = %s AND ended_at IS NULL",
            (reason[:200], session_id),
        )


def list_sessions(limit: int = 500, *, connect: ConnectFn = _connect) -> list[LoginRecord]:
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, username, outcome, client_ip, client_host, started_at, last_seen_at, "
            "ended_at, end_reason, app_version FROM login_sessions "
            "ORDER BY started_at DESC LIMIT %s",
            (int(limit),),
        )
        rows = cur.fetchall()
    return [LoginRecord(*row) for row in rows]


class SessionTracker:
    """The running app's own session: start, heartbeat, end. Never raises."""

    def __init__(self, connect: ConnectFn = _connect) -> None:
        self._connect = connect
        self.session_id: int | None = None

    def start(self, username: str) -> None:
        try:
            self.session_id = start_session(username, connect=self._connect)
        except Exception as exc:  # noqa: BLE001
            _log().warning("Login history unavailable: %s", exc)

    def beat(self) -> None:
        if self.session_id is None:
            return
        try:
            heartbeat(self.session_id, connect=self._connect)
        except Exception as exc:  # noqa: BLE001
            _log().debug("Login heartbeat failed: %s", exc)

    def end(self, reason: str = "signed out") -> None:
        if self.session_id is None:
            return
        try:
            end_session(self.session_id, reason, connect=self._connect)
        except Exception as exc:  # noqa: BLE001
            _log().warning("Could not close login session: %s", exc)
        self.session_id = None


def _log():  # noqa: ANN202
    from pfsense_checker import app_log

    return app_log.get_logger("auth")
