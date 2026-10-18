"""Tests for per-IP SSH credential DB persistence (salted hash only)."""

from __future__ import annotations

from pfsense_checker import auth, postgres_db as pg, ssh_credentials_db
from pfsense_checker.topology_site import Device, SshAccess


def test_save_host_credentials_stores_salted_hash_not_password() -> None:
    if not pg.psycopg_available():
        return
    settings = pg.load_settings()
    try:
        pg.test_connection(settings)
    except Exception:  # noqa: BLE001
        return

    host = "203.0.113.51"
    secret = "device-ssh-secret-9"
    dev = Device(
        name="test-cred-host-hash",
        kind="pfsense",
        mgmt_ip=host,
        ssh=SshAccess(
            host=host,
            port=22,
            username="admin",
            credential_ref="test-ref-hash-only",
            key_path="",
        ),
    )
    result = ssh_credentials_db.save_host_credentials(
        dev, secret, settings=settings
    )
    assert result.ssh_host == host
    assert result.password_hash_stored is True

    loaded = ssh_credentials_db.get_host_credentials(host, settings=settings)
    assert loaded is not None
    assert "password" not in loaded
    assert loaded["password_hash"].startswith("nc1$")
    assert secret not in loaded["password_hash"]
    assert auth.verify_password(secret, loaded["password_hash"])
    assert ssh_credentials_db.verify_host_password(
        host, secret, settings=settings
    )
    assert not ssh_credentials_db.verify_host_password(
        host, "wrong-password", settings=settings
    )
