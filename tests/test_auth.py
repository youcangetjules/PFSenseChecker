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
    try:
        _exercise_db_user(name, password)
    finally:
        # The password is in this file. Never leave the account behind as an
        # active login on the operator's database.
        with pg.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM users WHERE username = %s", (name,))


def _exercise_db_user(name: str, password: str) -> None:
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


def test_throttle_backs_off_after_free_attempts() -> None:
    now = [100.0]
    t = auth.LoginThrottle(free_attempts=3, base_wait=2.0, max_wait=10.0, clock=lambda: now[0])
    for _ in range(3):
        t.record_failure("Julian")
    assert t.wait_seconds("julian") == 0
    t.record_failure("julian")
    assert t.wait_seconds("JULIAN") == 2.0
    t.record_failure("julian")
    assert t.wait_seconds("julian") == 4.0
    for _ in range(5):
        t.record_failure("julian")
    assert t.wait_seconds("julian") == 10.0  # capped
    now[0] += 10.0
    assert t.wait_seconds("julian") == 0
    t.record_success("julian")
    t.record_failure("julian")
    assert t.wait_seconds("julian") == 0  # counter cleared by success


def _row_for(password: str):
    return (auth.hash_password(password), auth.ROLE_USER, False)


def test_authenticate_throttles_and_logs_reason_without_secret(monkeypatch) -> None:
    from pfsense_checker import app_log

    secret = "right-horse-99"
    monkeypatch.setattr(auth, "fetch_login_row", lambda name: _row_for(secret))
    monkeypatch.setattr(
        auth, "LOGIN_THROTTLE", auth.LoginThrottle(free_attempts=2, base_wait=30.0)
    )
    for _ in range(2):
        try:
            auth.authenticate("julian", " wrong-pass ", source="1password")
        except auth.AuthError as exc:
            assert str(exc) == "Invalid username or password"
    try:
        auth.authenticate("julian", "wrong-again")
    except auth.AuthError:
        pass
    # Now blocked: even the right password is refused until the wait passes.
    try:
        auth.authenticate("julian", secret)
        raise AssertionError("throttle did not block")
    except auth.AuthError as exc:
        assert "Too many failed sign-ins" in str(exc)

    lines = [e.message for e in app_log.get_hub().recent()]
    rejected = [m for m in lines if m.startswith("Login rejected")]
    assert rejected and "reason=password_mismatch" in rejected[0]
    assert "source=1password" in rejected[0]
    assert "edge_whitespace=True" in rejected[0]
    joined = "\n".join(lines)
    assert "wrong-pass" not in joined and secret not in joined


def test_unknown_user_name_is_not_logged(monkeypatch) -> None:
    from pfsense_checker import app_log

    monkeypatch.setattr(auth, "fetch_login_row", lambda name: None)
    try:
        auth.authenticate("Hunter2isMyPass", "x")
    except auth.AuthError:
        pass
    joined = "\n".join(e.message for e in app_log.get_hub().recent())
    assert "reason=unknown_or_inactive_user" in joined
    assert "Hunter2isMyPass" not in joined


def test_success_clears_failures(monkeypatch) -> None:
    secret = "right-horse-99"
    monkeypatch.setattr(auth, "fetch_login_row", lambda name: _row_for(secret))
    monkeypatch.setattr(auth, "LOGIN_THROTTLE", auth.LoginThrottle(free_attempts=1))
    try:
        auth.authenticate("julian", "nope")
    except auth.AuthError:
        pass
    assert auth.authenticate("julian", secret).username == "julian"
    assert auth.LOGIN_THROTTLE.wait_seconds("julian") == 0
