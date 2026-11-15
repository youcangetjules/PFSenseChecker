"""Logs → Login History: sessions, failed attempts, page."""

from __future__ import annotations

import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pfsense_checker import login_history as lh  # noqa: E402

NOW = datetime(2026, 11, 7, 17, 0, tzinfo=timezone.utc)


def _rec(**kw) -> lh.LoginRecord:
    base = dict(id=1, username="julian", outcome=lh.OUTCOME_SUCCESS, client_ip="222.10.50.25",
                client_host="WS1", started_at=NOW - timedelta(hours=2), last_seen_at=NOW - timedelta(seconds=30),
                ended_at=None, end_reason="", app_version="1.3.91")
    base.update(kw)
    return lh.LoginRecord(**base)


def test_record_states_and_durations() -> None:
    live = _rec()
    assert live.active(NOW) and live.how_it_ended(NOW) == "still signed in"
    assert lh.format_duration(live.duration(NOW)) == "2h 0m"
    closed = _rec(ended_at=NOW - timedelta(hours=1), end_reason="signed out (NetCheck closed)")
    assert not closed.active(NOW) and lh.format_duration(closed.duration(NOW)) == "1h 0m"
    crashed = _rec(last_seen_at=NOW - timedelta(minutes=40))
    assert not crashed.active(NOW)
    assert crashed.how_it_ended(NOW) == "no heartbeat (crash or killed)"
    assert lh.format_duration(crashed.duration(NOW)) == "1h 20m"  # up to the last heartbeat
    refused = _rec(outcome=lh.OUTCOME_FAILED, ended_at=NOW, end_reason="Invalid username or password")
    assert refused.duration(NOW) is None and refused.how_it_ended(NOW) == "Invalid username or password"
    assert lh.format_duration(timedelta(days=1, hours=2, minutes=3)) == "1d 2h 3m"
    assert lh.format_duration(timedelta(seconds=42)) == "42s"


class _FakeCursor:
    def __init__(self, log):  # noqa: ANN001
        self.log = log

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=()):  # noqa: ANN001
        self.log.append((sql, params))

    def fetchone(self):
        return (7,)

    def fetchall(self):
        return []


class _FakeConn:
    def __init__(self, log):  # noqa: ANN001
        self.log = log

    def cursor(self):
        return _FakeCursor(self.log)


def _fake_connect(log):  # noqa: ANN001
    @contextmanager
    def connect():
        yield _FakeConn(log)
    return connect


def test_sql_is_parameterised_and_unknown_names_are_not_stored(monkeypatch) -> None:
    monkeypatch.setattr(lh, "client_address", lambda: ("222.10.50.25", "WS1"))
    log: list = []
    connect = _fake_connect(log)
    assert lh.start_session("julian", connect=connect) == 7
    lh.heartbeat(7, connect=connect)
    lh.end_session(7, connect=connect)
    lh.record_failed("Hunter2isMyPass", known_user=False, reason="Invalid", connect=connect)
    lh.record_failed("julian", known_user=True, reason="Invalid", connect=connect)
    for sql, params in log:
        assert "%s" in sql and "julian" not in sql and "Hunter2" not in sql  # values only as parameters
    assert log[0][1][:4] == ("julian", "success", "222.10.50.25", "WS1")
    assert log[3][1][0] == lh.UNKNOWN_USER  # the typed text is not stored
    assert all("Hunter2isMyPass" not in str(p) for _s, p in log)
    assert log[4][1][0] == "julian"


def test_tracker_never_raises(monkeypatch) -> None:
    def boom():
        raise RuntimeError("database down")

    tracker = lh.SessionTracker(connect=boom)
    tracker.start("julian")  # logs a warning, no exception
    tracker.beat()
    tracker.end()
    assert tracker.session_id is None


def test_round_trip_in_real_database() -> None:
    from pfsense_checker import netcheck_schema, postgres_db as pg

    if not pg.psycopg_available():
        return
    try:
        pg.test_connection(pg.load_settings())
    except Exception:  # noqa: BLE001
        return
    netcheck_schema._SCHEMA_ENSURED = False
    netcheck_schema.ensure_schema()
    name = f"testuser_{uuid.uuid4().hex[:8]}"
    sid = lh.start_session(name)
    try:
        lh.heartbeat(sid)
        lh.end_session(sid, "test")
        rec = next(r for r in lh.list_sessions(50) if r.id == sid)
        assert rec.username == name and rec.ended_at is not None and rec.end_reason == "test"
        assert rec.client_host
    finally:
        with pg.connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM login_sessions WHERE username = %s", (name,))


def test_logs_section_shows_login_history(monkeypatch) -> None:
    from PySide6.QtWidgets import QApplication

    from pfsense_checker.home_screen import HomeScreen

    QApplication.instance() or QApplication([])
    now = datetime.now(timezone.utc)
    records = [
        _rec(id=9, started_at=now - timedelta(minutes=5), last_seen_at=now),
        _rec(id=8, outcome=lh.OUTCOME_FAILED, username=lh.UNKNOWN_USER, ended_at=now - timedelta(minutes=6),
             started_at=now - timedelta(minutes=6), last_seen_at=now - timedelta(minutes=6),
             end_reason="Invalid username or password"),
        _rec(id=7, started_at=now - timedelta(days=1), last_seen_at=now - timedelta(days=1, minutes=-30),
             ended_at=now - timedelta(days=1, minutes=-30), end_reason="signed out (NetCheck closed)"),
    ]
    monkeypatch.setattr(lh, "list_sessions", lambda limit=500: list(records))
    home = HomeScreen()
    home.current_login_session_id = 9
    home.show_section("logs.logins")
    assert home.current_section_key() == "logs.logins" and home.nav.parent_of("logs.logins") == "logs"
    t = home.login_hist_table
    assert t.rowCount() == 3
    assert t.item(0, 7).text() == "this session · still signed in"
    assert t.item(1, 1).text() == "Refused" and t.item(1, 0).text() == lh.UNKNOWN_USER
    assert t.item(2, 6).text() == "30m 0s"
    assert "2 sign-in(s), 1 active now, 1 refused attempt(s)" in home.login_hist_summary.text()
    home.login_hist_failed.setChecked(False)
    assert t.rowCount() == 2


def test_failed_sign_in_keeps_only_real_account_names(monkeypatch) -> None:
    from pfsense_checker import auth, login_screen

    stored: list[tuple[str, bool]] = []
    monkeypatch.setattr(lh, "record_failed",
                        lambda username, known_user, reason="", **k: stored.append((username, known_user)))
    monkeypatch.setattr(auth, "fetch_login_row", lambda name: ("hash", "user", False) if name == "julian" else None)
    login_screen._record_failed_sign_in("julian", "Invalid username or password")
    login_screen._record_failed_sign_in("s3cret-typed-here", "Invalid username or password")
    assert stored == [("julian", True), ("s3cret-typed-here", False)]  # record_failed drops the unknown name
