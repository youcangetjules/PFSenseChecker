"""Tests for auth hashing and login DB access."""

from __future__ import annotations

import uuid

from pfsense_checker import auth, netcheck_schema, postgres_db as pg


def test_hash_roundtrip() -> None:
    stored = auth.hash_password("correct-horse-battery")
    assert stored.startswith("nc1$")
    assert auth.verify_password("correct-horse-battery", stored)
    assert not auth.verify_password("wrong-password", stored)


def test_public_key_loads() -> None:
    pem = auth.load_public_key_pem()
    assert "BEGIN PUBLIC KEY" in pem
    pepper = auth.public_pepper()
    assert len(pepper) == 32


def test_authenticate_against_db() -> None:
    if not pg.psycopg_available():
        return
    try:
        pg.test_connection(pg.load_settings())
    except Exception:  # noqa: BLE001
        return

    netcheck_schema.ensure_schema()
    name = f"testuser_{uuid.uuid4().hex[:8]}"
    password = "test-pass-12345"
    auth.create_user(name, password, role="user", must_change_password=True)
    user = auth.authenticate(name, password)
    assert user.username == name
    assert user.must_change_password is True

    # Login query only exposes username + hash (+ role / must_change) via the view.
    with pg.connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT username, password_hash FROM users_login_v "
                "WHERE username = %s",
                (name,),
            )
            row = cur.fetchone()
    assert row is not None
    assert row[0] == name
    assert str(row[1]).startswith("nc1$")
    assert auth.verify_password(password, str(row[1]))
    assert not auth.verify_password("nope", str(row[1]))

    changed = auth.change_password(name, password, "new-pass-67890")
    assert changed.must_change_password is False
    assert auth.authenticate(name, "new-pass-67890").must_change_password is False
