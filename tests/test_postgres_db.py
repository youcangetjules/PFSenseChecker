"""PostgreSQL settings / helper tests (no live server required)."""

from __future__ import annotations

import json

import pytest

from pfsense_checker import postgres_db as pg


def test_settings_roundtrip(tmp_path, monkeypatch) -> None:
    settings_file = tmp_path / "postgres.json"
    secrets_file = tmp_path / "secrets.local.json"
    monkeypatch.setattr(pg, "_SETTINGS_FILE", settings_file)
    monkeypatch.setattr(pg, "_SECRETS_FILE", secrets_file)
    monkeypatch.setattr(pg, "ensure_data_dir", lambda: tmp_path)

    cfg = pg.PostgresSettings(
        host="db.example",
        port=5433,
        database="netcheck",
        username="nc",
        password="secret",
        sslmode="require",
        schema="public",
        save_password=True,
    )
    pg.save_settings(cfg)
    loaded = pg.load_settings()
    assert loaded.host == "db.example"
    assert loaded.port == 5433
    assert loaded.password == "secret"
    public = json.loads(settings_file.read_text(encoding="utf-8"))
    secrets = json.loads(secrets_file.read_text(encoding="utf-8"))
    assert "password" not in public
    assert secrets["postgres_password"] == "secret"
    assert public["pg_engine"] == "postgresql"


def test_assert_ident_rejects_injection() -> None:
    with pytest.raises(ValueError):
        pg._assert_ident('devices"; DROP TABLE users; --')


def test_create_table_sql() -> None:
    sql = pg.create_table_sql("public", "devices", "id SERIAL PRIMARY KEY")
    assert 'CREATE TABLE "public"."devices"' in sql
    assert "id SERIAL PRIMARY KEY" in sql


def test_dsn_includes_sslmode() -> None:
    dsn = pg.PostgresSettings(host="h", password="p").dsn()
    assert "sslmode=prefer" in dsn
    assert "password='p'" in dsn
