"""PostgreSQL connection settings and helpers for the Database section.

Passwords live in gitignored ``secrets.local.json``; host/db/user/options in
``data/postgres.json``. Uses optional ``psycopg`` (v3); the UI degrades cleanly
when the driver is missing.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from typing import Any, Generator

from pfsense_checker.paths import PROJECT_ROOT, ensure_data_dir

_SECRETS_FILE = PROJECT_ROOT / "secrets.local.json"
_SETTINGS_FILE = PROJECT_ROOT / "data" / "postgres.json"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5432
DEFAULT_DATABASE = "netcheck"
DEFAULT_USER = "postgres"


@dataclass
class PostgresSettings:
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    database: str = DEFAULT_DATABASE
    username: str = DEFAULT_USER
    password: str = ""
    sslmode: str = "prefer"  # disable | allow | prefer | require
    connect_timeout: int = 5
    schema: str = "public"
    save_password: bool = True

    def normalised(self) -> PostgresSettings:
        return PostgresSettings(
            host=(self.host or DEFAULT_HOST).strip() or DEFAULT_HOST,
            port=max(1, min(65535, int(self.port or DEFAULT_PORT))),
            database=(self.database or DEFAULT_DATABASE).strip() or DEFAULT_DATABASE,
            username=(self.username or DEFAULT_USER).strip() or DEFAULT_USER,
            password=self.password or "",
            sslmode=(self.sslmode or "prefer").strip().lower() or "prefer",
            connect_timeout=max(1, min(60, int(self.connect_timeout or 5))),
            schema=(self.schema or "public").strip() or "public",
            save_password=bool(self.save_password),
        )

    def dsn(self, *, include_password: bool = True) -> str:
        s = self.normalised()
        parts = [
            f"host={s.host}",
            f"port={s.port}",
            f"dbname={s.database}",
            f"user={s.username}",
            f"connect_timeout={s.connect_timeout}",
            f"sslmode={s.sslmode}",
        ]
        if include_password and s.password:
            # Escape spaces in password for libpq keyword style
            pw = s.password.replace("\\", "\\\\").replace("'", "\\'")
            parts.append(f"password='{pw}'")
        return " ".join(parts)


@dataclass
class TableInfo:
    schema: str
    name: str
    approx_rows: int | None = None
    comment: str = ""

    @property
    def qualified(self) -> str:
        return f"{self.schema}.{self.name}"


@dataclass
class ColumnInfo:
    name: str
    data_type: str
    is_nullable: bool = True
    column_default: str = ""
    is_primary: bool = False


@dataclass
class ForeignKeyInfo:
    constraint_name: str
    schema: str
    table: str
    column: str
    foreign_schema: str
    foreign_table: str
    foreign_column: str


@dataclass
class QueryResult:
    columns: list[str] = field(default_factory=list)
    rows: list[tuple[Any, ...]] = field(default_factory=list)
    rowcount: int = 0
    message: str = ""
    is_select: bool = False


def psycopg_available() -> bool:
    try:
        import psycopg  # noqa: F401
    except ImportError:
        return False
    return True


def _read_json(path) -> dict:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def load_settings() -> PostgresSettings:
    public = _read_json(_SETTINGS_FILE)
    secrets = _read_json(_SECRETS_FILE)
    return PostgresSettings(
        host=str(public.get("pg_host", public.get("host", DEFAULT_HOST)) or DEFAULT_HOST),
        port=int(public.get("pg_port", public.get("port", DEFAULT_PORT)) or DEFAULT_PORT),
        database=str(
            public.get("pg_database", public.get("database", DEFAULT_DATABASE))
            or DEFAULT_DATABASE
        ),
        username=str(
            public.get("pg_username", public.get("username", DEFAULT_USER)) or DEFAULT_USER
        ),
        password=str(secrets.get("postgres_password", secrets.get("pg_password", "")) or ""),
        sslmode=str(public.get("pg_sslmode", public.get("sslmode", "prefer")) or "prefer"),
        connect_timeout=int(
            public.get("pg_connect_timeout", public.get("connect_timeout", 5)) or 5
        ),
        schema=str(public.get("pg_schema", public.get("schema", "public")) or "public"),
        save_password=bool(public.get("pg_save_password", True)),
    ).normalised()


def save_settings(settings: PostgresSettings) -> None:
    settings = settings.normalised()
    ensure_data_dir()
    public = _read_json(_SETTINGS_FILE)
    public.update(
        {
            "pg_host": settings.host,
            "pg_port": settings.port,
            "pg_database": settings.database,
            "pg_username": settings.username,
            "pg_sslmode": settings.sslmode,
            "pg_connect_timeout": settings.connect_timeout,
            "pg_schema": settings.schema,
            "pg_save_password": settings.save_password,
            "pg_engine": "postgresql",
        }
    )
    _SETTINGS_FILE.write_text(json.dumps(public, indent=2), encoding="utf-8")

    secrets = _read_json(_SECRETS_FILE)
    if settings.save_password:
        secrets["postgres_password"] = settings.password
    else:
        secrets.pop("postgres_password", None)
        secrets.pop("pg_password", None)
    _SECRETS_FILE.write_text(json.dumps(secrets, indent=2), encoding="utf-8")


@contextmanager
def connect(settings: PostgresSettings | None = None) -> Generator[Any, None, None]:
    """Yield an open psycopg connection; caller must not keep it after exit."""
    if not psycopg_available():
        raise RuntimeError(
            "PostgreSQL driver not installed. Run: pip install \"psycopg[binary]\""
        )
    import psycopg

    cfg = (settings or load_settings()).normalised()
    conn = psycopg.connect(cfg.dsn(), autocommit=True)
    try:
        yield conn
    finally:
        conn.close()


def test_connection(settings: PostgresSettings) -> str:
    """Return server version string or raise."""
    with connect(settings) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT version()")
            row = cur.fetchone()
            return str(row[0]) if row else "connected"


def connection_type_label(settings: PostgresSettings | None = None) -> str:
    """Human label for how we connect (PostgreSQL + sslmode)."""
    s = (settings or load_settings()).normalised()
    ssl = (s.sslmode or "prefer").strip().lower() or "prefer"
    return f"PostgreSQL/{ssl}"


def status_bar_text(
    connected: bool,
    settings: PostgresSettings | None = None,
) -> str:
    """Compact status-bar text: db name, port, connection type."""
    s = (settings or load_settings()).normalised()
    detail = f"{s.database} | {s.port} | {connection_type_label(s)}"
    if connected:
        return f"DB: {detail}"
    return f"DB: offline · {detail}"


def status_bar_tooltip(
    connected: bool,
    settings: PostgresSettings | None = None,
    *,
    detail: str = "",
) -> str:
    s = (settings or load_settings()).normalised()
    lines = [
        f"Host: {s.host}",
        f"Port: {s.port}",
        f"Database: {s.database}",
        f"User: {s.username}",
        f"Connection: {connection_type_label(s)}",
        f"State: {'connected' if connected else 'not connected'}",
    ]
    if detail:
        lines.append(detail)
    return "\n".join(lines)


def probe_connection(
    settings: PostgresSettings | None = None,
    *,
    timeout: int = 2,
) -> tuple[bool, PostgresSettings, str]:
    """Quick reachability check. Returns (ok, settings, version_or_error)."""
    s = (settings or load_settings()).normalised()
    s.connect_timeout = max(1, min(int(timeout), 60))
    if not psycopg_available():
        return False, s, "psycopg not installed"
    try:
        version = test_connection(s)
        return True, s, version
    except Exception as exc:  # noqa: BLE001
        return False, s, str(exc)


@dataclass
class ServerInfo:
    """What the status bar shows about the live database connection."""

    host: str = ""  # as configured / resolved by libpq
    hostaddr: str = ""
    port: int = 0
    database: str = ""
    user: str = ""
    version: str = ""  # short, e.g. "18.1"
    version_full: str = ""
    ssl_in_use: bool = False
    ssl_protocol: str = ""  # e.g. TLSv1.3
    ssl_cipher: str = ""
    ssl_bits: int = 0
    server_ssl: str = ""  # the server's own `ssl` setting: on / off
    extensions: list[tuple[str, str]] = field(default_factory=list)  # (name, version), plpgsql left out


def server_info(conn: Any) -> ServerInfo:
    """Read version, SSL state and extensions from an open connection."""
    info = ServerInfo()
    ci = getattr(conn, "info", None)
    if ci is not None:
        info.host = str(getattr(ci, "host", "") or "")
        info.hostaddr = str(getattr(ci, "hostaddr", "") or "")
        info.port = int(getattr(ci, "port", 0) or 0)
        pgconn = getattr(ci, "pgconn", None)
        info.ssl_in_use = bool(getattr(pgconn, "ssl_in_use", False))
    with conn.cursor() as cur:
        cur.execute("SELECT current_database(), current_user, version(), current_setting('server_version')")
        row = cur.fetchone() or ("", "", "", "")
        info.database, info.user, info.version_full, info.version = (str(x or "") for x in row)
        cur.execute("SELECT current_setting('ssl', true)")
        info.server_ssl = str((cur.fetchone() or [""])[0] or "")
        try:
            cur.execute(
                "SELECT ssl, version, cipher, bits FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
            )
            row = cur.fetchone()
            if row:
                info.ssl_in_use = bool(row[0]) or info.ssl_in_use
                info.ssl_protocol = str(row[1] or "")
                info.ssl_cipher = str(row[2] or "")
                info.ssl_bits = int(row[3] or 0)
        except Exception:  # noqa: BLE001 - very old servers / no permission: libpq's flag stands
            pass
        cur.execute("SELECT extname, extversion FROM pg_extension WHERE extname <> 'plpgsql' ORDER BY 1")
        info.extensions = [(str(n), str(v)) for n, v in cur.fetchall()]
    return info


def probe_details(
    settings: PostgresSettings | None = None,
    *,
    timeout: int = 2,
) -> tuple[bool, PostgresSettings, ServerInfo | str]:
    """Like probe_connection, but returns the ServerInfo (or the error text)."""
    s = (settings or load_settings()).normalised()
    s.connect_timeout = max(1, min(int(timeout), 60))
    if not psycopg_available():
        return False, s, "psycopg not installed"
    try:
        with connect(s) as conn:
            return True, s, server_info(conn)
    except Exception as exc:  # noqa: BLE001
        return False, s, str(exc)


def _ssl_phrase(s: PostgresSettings, info: ServerInfo) -> str:
    mode = (s.sslmode or "prefer").strip().lower() or "prefer"
    if info.ssl_in_use:
        proto = info.ssl_protocol or "TLS"
        return f"SSL on ({proto}, sslmode {mode})"
    return f"SSL off — not encrypted (sslmode {mode})"


def status_bar_summary(ok: bool, settings: PostgresSettings, info: ServerInfo | str,
                       *, two_rows: bool = False) -> str:
    """Status bar text: which server and database, its version, the user, and
    whether SSL is in use. ``two_rows`` puts the SSL part on a second line."""
    s = settings.normalised()
    sep = "\n" if two_rows else " · "
    if not ok or not isinstance(info, ServerInfo):
        return f"DB: offline · {s.database} on {s.host}:{s.port}{sep}sslmode {s.sslmode or 'prefer'}"
    where = f"{info.host or s.host}:{info.port or s.port}"
    bits = [
        f"DB: {info.database or s.database} on {where}",
        f"PostgreSQL {info.version}" if info.version else "PostgreSQL",
        f"user {info.user}" if info.user else "",
    ]
    return " · ".join(b for b in bits if b) + sep + _ssl_phrase(s, info)


def status_bar_details(ok: bool, settings: PostgresSettings, info: ServerInfo | str) -> str:
    """Hover text for the status bar: everything we know about the connection."""
    s = settings.normalised()
    if not ok or not isinstance(info, ServerInfo):
        return status_bar_tooltip(False, s, detail=str(info))
    lines = [
        f"Server: {info.host or s.host}" + (f" ({info.hostaddr})" if info.hostaddr and info.hostaddr != info.host else ""),
        f"Port: {info.port or s.port}",
        f"Database: {info.database or s.database}",
        f"User: {info.user or s.username}",
        f"Version: {info.version_full or info.version}",
        f"SSL: {'in use' if info.ssl_in_use else 'NOT in use — traffic is not encrypted'}",
    ]
    if info.ssl_in_use:
        lines.append(f"  {info.ssl_protocol or 'TLS'} · {info.ssl_cipher or '?'}"
                     + (f" · {info.ssl_bits}-bit" if info.ssl_bits else ""))
    lines.append(f"sslmode (this app): {s.sslmode or 'prefer'}")
    if info.server_ssl:
        lines.append(f"Server ssl setting: {info.server_ssl}")
    exts = ", ".join(f"{n} {v}" for n, v in info.extensions) or "none (no PostGIS / TimescaleDB)"
    lines.append(f"Extensions: {exts}")
    return "\n".join(lines)


def list_tables(conn: Any, schema: str = "public") -> list[TableInfo]:
    sql = """
        SELECT n.nspname AS schema,
               c.relname AS name,
               COALESCE(s.n_live_tup, c.reltuples)::bigint AS approx_rows,
               COALESCE(d.description, '') AS comment
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_stat_user_tables s
          ON s.relid = c.oid
        LEFT JOIN pg_description d
          ON d.objoid = c.oid AND d.objsubid = 0
        WHERE c.relkind IN ('r', 'p')
          AND n.nspname = %s
        ORDER BY c.relname
    """
    with conn.cursor() as cur:
        cur.execute(sql, (schema,))
        rows = cur.fetchall()
    return [
        TableInfo(
            schema=str(r[0]),
            name=str(r[1]),
            approx_rows=int(r[2]) if r[2] is not None else None,
            comment=str(r[3] or ""),
        )
        for r in rows
    ]


def list_schemas(conn: Any) -> list[str]:
    sql = """
        SELECT nspname FROM pg_namespace
        WHERE nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
          AND nspname <> 'information_schema'
        ORDER BY nspname
    """
    with conn.cursor() as cur:
        cur.execute(sql)
        return [str(r[0]) for r in cur.fetchall()]


def describe_table(conn: Any, schema: str, table: str) -> list[ColumnInfo]:
    sql = """
        SELECT a.attname AS name,
               pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type,
               NOT a.attnotnull AS is_nullable,
               COALESCE(pg_get_expr(ad.adbin, ad.adrelid), '') AS column_default,
               EXISTS (
                 SELECT 1 FROM pg_index i
                 WHERE i.indrelid = a.attrelid
                   AND i.indisprimary
                   AND a.attnum = ANY(i.indkey)
               ) AS is_primary
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
        WHERE n.nspname = %s
          AND c.relname = %s
          AND a.attnum > 0
          AND NOT a.attisdropped
        ORDER BY a.attnum
    """
    with conn.cursor() as cur:
        cur.execute(sql, (schema, table))
        rows = cur.fetchall()
    return [
        ColumnInfo(
            name=str(r[0]),
            data_type=str(r[1]),
            is_nullable=bool(r[2]),
            column_default=str(r[3] or ""),
            is_primary=bool(r[4]),
        )
        for r in rows
    ]


def fetch_table_rows(
    conn: Any,
    schema: str,
    table: str,
    *,
    limit: int = 200,
) -> QueryResult:
    # Identifiers cannot be parameterised — validate carefully.
    _assert_ident(schema)
    _assert_ident(table)
    sql = f'SELECT * FROM "{schema}"."{table}" LIMIT %s'
    with conn.cursor() as cur:
        cur.execute(sql, (max(1, min(int(limit), 5000)),))
        cols = [d.name for d in (cur.description or [])]
        rows = [tuple(r) for r in cur.fetchall()]
    return QueryResult(
        columns=cols,
        rows=rows,
        rowcount=len(rows),
        message=f"{len(rows)} row(s)",
        is_select=True,
    )


def list_foreign_keys(conn: Any, schema: str = "public") -> list[ForeignKeyInfo]:
    sql = """
        SELECT
            tc.constraint_name,
            tc.table_schema,
            tc.table_name,
            kcu.column_name,
            ccu.table_schema AS foreign_schema,
            ccu.table_name AS foreign_table,
            ccu.column_name AS foreign_column
        FROM information_schema.table_constraints AS tc
        JOIN information_schema.key_column_usage AS kcu
          ON tc.constraint_name = kcu.constraint_name
         AND tc.table_schema = kcu.table_schema
        JOIN information_schema.constraint_column_usage AS ccu
          ON ccu.constraint_name = tc.constraint_name
         AND ccu.table_schema = tc.table_schema
        WHERE tc.constraint_type = 'FOREIGN KEY'
          AND tc.table_schema = %s
        ORDER BY tc.table_name, tc.constraint_name
    """
    with conn.cursor() as cur:
        cur.execute(sql, (schema,))
        rows = cur.fetchall()
    return [
        ForeignKeyInfo(
            constraint_name=str(r[0]),
            schema=str(r[1]),
            table=str(r[2]),
            column=str(r[3]),
            foreign_schema=str(r[4]),
            foreign_table=str(r[5]),
            foreign_column=str(r[6]),
        )
        for r in rows
    ]


def _assert_ident(name: str) -> None:
    import re

    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name or ""):
        raise ValueError(f"Invalid SQL identifier: {name!r}")


def execute_sql(conn: Any, sql: str, *, max_rows: int = 500) -> QueryResult:
    """Run arbitrary SQL. SELECT-like statements return a grid; others commit message."""
    text = (sql or "").strip()
    if not text:
        raise ValueError("SQL is empty")
    # Strip a single trailing semicolon for convenience
    if text.endswith(";"):
        text = text[:-1].rstrip()
    with conn.cursor() as cur:
        cur.execute(text)
        if cur.description is None:
            return QueryResult(
                rowcount=cur.rowcount if cur.rowcount is not None else 0,
                message=f"OK — {cur.rowcount if cur.rowcount is not None else 0} row(s) affected",
                is_select=False,
            )
        cols = [d.name for d in cur.description]
        rows = [tuple(r) for r in cur.fetchmany(max(1, min(int(max_rows), 5000)))]
        return QueryResult(
            columns=cols,
            rows=rows,
            rowcount=len(rows),
            message=f"{len(rows)} row(s) returned",
            is_select=True,
        )


def drop_table(conn: Any, schema: str, table: str, *, cascade: bool = False) -> None:
    _assert_ident(schema)
    _assert_ident(table)
    suffix = " CASCADE" if cascade else ""
    with conn.cursor() as cur:
        cur.execute(f'DROP TABLE "{schema}"."{table}"{suffix}')


def create_table_sql(schema: str, table: str, columns_sql: str) -> str:
    _assert_ident(schema)
    _assert_ident(table)
    body = (columns_sql or "").strip().rstrip(",")
    if not body:
        raise ValueError("Column definitions are required")
    return f'CREATE TABLE "{schema}"."{table}" (\n{body}\n)'


def cell_to_str(value: Any) -> str:
    if value is None:
        return "NULL"
    return str(value)


# ---- Login / transport status for the Database page ----

@dataclass(frozen=True)
class ConnectionSecurity:
    """What the open connection really is (not what was asked for)."""

    user: str
    database: str
    ssl: bool
    protocol: str = ""
    cipher: str = ""


def connection_security(conn: Any) -> ConnectionSecurity:
    """Read login and TLS state from a live connection."""
    ssl, protocol, cipher = False, "", ""
    with conn.cursor() as cur:
        cur.execute("SELECT current_user, current_database()")
        user, database = cur.fetchone()
        try:
            cur.execute(
                "SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
            )
            row = cur.fetchone()
            if row:
                ssl, protocol, cipher = bool(row[0]), str(row[1] or ""), str(row[2] or "")
        except Exception:  # noqa: BLE001 — older servers / no pg_stat_ssl
            ssl = bool(getattr(getattr(conn, "pgconn", None), "ssl_in_use", False))
    return ConnectionSecurity(
        user=str(user), database=str(database), ssl=ssl, protocol=protocol, cipher=cipher
    )


def security_summary(
    sec: ConnectionSecurity | None, sslmode: str = "prefer"
) -> tuple[str, str, str]:
    """(text, colour, tooltip) for the login status next to Save login."""
    if sec is None:
        return "● Not logged in", "#78909c", "Connect to log in to PostgreSQL"
    who = f"Logged in as {sec.user}@{sec.database}"
    mode = (sslmode or "prefer").strip().lower()
    if sec.ssl:
        tls = " · ".join(x for x in (sec.protocol, sec.cipher) if x)
        tip = f"Connection is encrypted ({tls or 'TLS'}). sslmode={mode}."
        if mode in {"prefer", "allow"}:
            tip += (
                " With sslmode=prefer a server that stops offering TLS would be "
                "used in plain text without warning; set require to refuse that."
            )
        if mode in {"prefer", "allow", "require"}:
            tip += " The server certificate is not verified at this mode."
        return f"● {who} · SSL on ({sec.protocol or 'TLS'})", "#2e7d32", tip
    return (
        f"● {who} · SSL OFF — password and data in plain text",
        "#c62828",
        f"The connection is not encrypted (sslmode={mode}). Set SSL mode to "
        "require, and enable ssl on the server.",
    )
