"""Status bar: which PostgreSQL server and database, its version, and whether SSL is in use."""

from __future__ import annotations

from pfsense_checker import postgres_db as pg


def _settings(mode: str = "prefer") -> pg.PostgresSettings:
    return pg.PostgresSettings(host="localhost", port=5432, database="netcheck", username="postgres",
                               sslmode=mode)


def _info(ssl: bool = True) -> pg.ServerInfo:
    return pg.ServerInfo(host="localhost", hostaddr="::1", port=5432, database="netcheck", user="postgres",
                         version="18.1", version_full="PostgreSQL 18.1 on x86_64-windows",
                         ssl_in_use=ssl, ssl_protocol="TLSv1.3" if ssl else "",
                         ssl_cipher="TLS_AES_256_GCM_SHA384" if ssl else "", ssl_bits=256 if ssl else 0,
                         server_ssl="on" if ssl else "off", extensions=[("postgis", "3.5.0")])


def test_summary_names_server_version_and_ssl() -> None:
    text = pg.status_bar_summary(True, _settings(), _info())
    assert text == ("DB: netcheck on localhost:5432 · PostgreSQL 18.1 · user postgres"
                    " · SSL on (TLSv1.3, sslmode prefer)")
    rows = pg.status_bar_summary(True, _settings(), _info(), two_rows=True).split("\n")
    assert rows == ["DB: netcheck on localhost:5432 · PostgreSQL 18.1 · user postgres",
                    "SSL on (TLSv1.3, sslmode prefer)"]
    plain = pg.status_bar_summary(True, _settings("disable"), _info(ssl=False))
    assert "SSL off — not encrypted (sslmode disable)" in plain


def test_details_list_cipher_and_extensions() -> None:
    tip = pg.status_bar_details(True, _settings(), _info())
    assert "Server: localhost (::1)" in tip and "Version: PostgreSQL 18.1 on x86_64-windows" in tip
    assert "TLSv1.3 · TLS_AES_256_GCM_SHA384 · 256-bit" in tip and "Extensions: postgis 3.5.0" in tip
    bare = pg.ServerInfo(version="16.4")
    assert "Extensions: none (no PostGIS / TimescaleDB)" in pg.status_bar_details(True, _settings(), bare)
    assert "NOT in use" in pg.status_bar_details(True, _settings(), bare)


def test_offline_says_where_it_tried() -> None:
    text = pg.status_bar_summary(False, _settings(), "connection refused")
    assert text == "DB: offline · netcheck on localhost:5432 · sslmode prefer"
    assert pg.status_bar_summary(False, _settings(), "x", two_rows=True).endswith("5432\nsslmode prefer")
    assert "connection refused" in pg.status_bar_details(False, _settings(), "connection refused")


class _Cur:
    def __init__(self) -> None:
        self.rows = iter([
            ("netcheck", "postgres", "PostgreSQL 18.1 on x86_64-windows", "18.1"),
            ("on",),
            (True, "TLSv1.3", "TLS_AES_256_GCM_SHA384", 256),
        ])

    def __enter__(self):  # noqa: ANN204
        return self

    def __exit__(self, *a) -> None:  # noqa: ANN002
        return None

    def execute(self, sql, params=None) -> None:  # noqa: ANN001
        self.last = sql

    def fetchone(self):  # noqa: ANN201
        return next(self.rows)

    def fetchall(self):  # noqa: ANN201
        return [("timescaledb", "2.17.0")]


class _Conn:
    class info:  # noqa: N801
        host, hostaddr, port = "db.lan", "10.0.0.5", 5433

        class pgconn:  # noqa: N801
            ssl_in_use = True

    def cursor(self) -> _Cur:
        return _Cur()


def test_server_info_reads_the_connection() -> None:
    info = pg.server_info(_Conn())
    assert (info.host, info.port, info.version, info.ssl_protocol, info.server_ssl) == (
        "db.lan", 5433, "18.1", "TLSv1.3", "on")
    assert info.ssl_in_use and info.extensions == [("timescaledb", "2.17.0")]
