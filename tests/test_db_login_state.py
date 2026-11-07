"""Database page: logged-in and SSL status next to Save login."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pfsense_checker import postgres_db as pg  # noqa: E402


class _Cur:
    def __init__(self, ssl_row, fail_ssl=False):
        self._rows, self._fail = [("postgres", "netcheck"), ssl_row], fail_ssl
        self._q = ""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, q, *a):
        self._q = q
        if "pg_stat_ssl" in q and self._fail:
            raise RuntimeError("no pg_stat_ssl")

    def fetchone(self):
        return self._rows.pop(0)


class _Conn:
    def __init__(self, ssl_row, fail_ssl=False, in_use=False):
        self._cur = _Cur(ssl_row, fail_ssl)
        self.pgconn = type("P", (), {"ssl_in_use": in_use})()

    def cursor(self):
        return self._cur


def test_ssl_on_is_reported_with_protocol() -> None:
    sec = pg.connection_security(_Conn((True, "TLSv1.3", "TLS_AES_256_GCM_SHA384")))
    assert (sec.user, sec.database, sec.ssl, sec.protocol) == ("postgres", "netcheck", True, "TLSv1.3")
    text, color, tip = pg.security_summary(sec, "prefer")
    assert text == "● Logged in as postgres@netcheck · SSL on (TLSv1.3)"
    assert color == "#2e7d32"
    assert "require" in tip and "not verified" in tip


def test_ssl_off_is_a_red_warning() -> None:
    sec = pg.connection_security(_Conn((False, None, None)))
    text, color, _tip = pg.security_summary(sec, "disable")
    assert "SSL OFF" in text and color == "#c62828"


def test_fallback_to_ssl_in_use() -> None:
    sec = pg.connection_security(_Conn(None, fail_ssl=True, in_use=True))
    assert sec.ssl is True


def test_not_logged_in() -> None:
    assert pg.security_summary(None)[0] == "● Not logged in"


def test_database_page_shows_state(monkeypatch) -> None:
    from PySide6.QtWidgets import QApplication

    from pfsense_checker.db_admin_screen import DatabaseScreen

    QApplication.instance() or QApplication([])
    page = DatabaseScreen()
    assert page.login_state.text() == "● Not logged in"
    page._conn = _Conn((True, "TLSv1.3", "TLS_AES_256_GCM_SHA384"))
    page._refresh_login_state()
    assert "SSL on (TLSv1.3)" in page.login_state.text()
    page._conn = None
    page._refresh_login_state()
    assert page.login_state.text() == "● Not logged in"
