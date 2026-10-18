"""Tests for NetCheck PostgreSQL schema."""

from __future__ import annotations

from pfsense_checker import netcheck_schema, postgres_db as pg


def test_ensure_schema_creates_expected_tables() -> None:
    if not pg.psycopg_available():
        return
    settings = pg.load_settings()
    try:
        pg.test_connection(settings)
    except Exception:  # noqa: BLE001
        return

    with pg.connect(settings) as conn:
        netcheck_schema.ensure_schema(conn)
        present = set(netcheck_schema.list_netcheck_tables(conn))
    missing = [t for t in netcheck_schema.EXPECTED_TABLES if t not in present]
    assert not missing, f"missing tables: {missing}"

    with pg.connect(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT mode FROM topology_sites ORDER BY mode"
            )
            modes = [r[0] for r in cur.fetchall()]
    assert "live" in modes
    assert "experimental" in modes
