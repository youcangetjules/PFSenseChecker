"""Persist SSH login metadata per host IP into the netcheck database.

The database stores only a salted password hash (``auth.hash_password`` /
PBKDF2) plus username/host metadata. The plaintext password is never written
to PostgreSQL — it is kept only in the OS keyring for live SSH use.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from pfsense_checker import auth, netcheck_schema, postgres_db as pg
from pfsense_checker.topology_site import Device


@dataclass(frozen=True)
class SshCredentialSaveResult:
    ssh_host: str
    ssh_user: str
    ssh_port: int
    device_name: str
    credential_ref: str
    password_hash_stored: bool
    updated_at: str
    row_id: int


def ensure_schema(conn: Any | None = None) -> None:
    netcheck_schema.ensure_schema(conn)


def save_host_credentials(
    device: Device,
    password: str,
    *,
    settings: pg.PostgresSettings | None = None,
) -> SshCredentialSaveResult:
    """Upsert SSH credential metadata for the device's SSH host (IP).

    ``password`` is hashed (salted PBKDF2) then discarded from this path — it
    is never inserted into PostgreSQL. The OS keyring still holds the secret
    for SSH (via ``credential_ref``).
    """
    ssh = device.ssh
    if ssh is None:
        raise ValueError("Device has no SSH access record")
    host = (ssh.host or device.mgmt_ip or "").strip()
    if not host:
        raise ValueError("No SSH host / IP — select a device first")
    user = (ssh.username or "").strip()
    if not user:
        raise ValueError("Set a username before saving credentials")
    if not (password or "").strip():
        raise ValueError("Password is required to create the salted hash")
    # Device SSH passwords may be shorter than app-login passwords.
    password_hash = auth.hash_password(password, min_length=1)
    ref = (ssh.credential_ref or "").strip()
    port = int(ssh.port or 22) or 22
    key_path = (ssh.key_path or "").strip()
    kind = (device.kind or "").strip()
    name = (device.name or "").strip()

    with pg.connect(settings) as conn:
        ensure_schema(conn)
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ssh_host_credentials(
                    ssh_host, ssh_port, ssh_user, ssh_key_path,
                    ssh_credential_ref, password_hash,
                    device_name, device_kind, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (ssh_host) DO UPDATE SET
                    ssh_port = EXCLUDED.ssh_port,
                    ssh_user = EXCLUDED.ssh_user,
                    ssh_key_path = EXCLUDED.ssh_key_path,
                    ssh_credential_ref = EXCLUDED.ssh_credential_ref,
                    password_hash = EXCLUDED.password_hash,
                    device_name = EXCLUDED.device_name,
                    device_kind = EXCLUDED.device_kind,
                    updated_at = NOW()
                RETURNING id, updated_at
                """,
                (host, port, user, key_path, ref, password_hash, name, kind),
            )
            row = cur.fetchone()
            if not row:
                raise RuntimeError("Database did not return the saved credential row")
            row_id = int(row[0])
            updated = row[1]
            if hasattr(updated, "isoformat"):
                updated_str = updated.isoformat()
            else:
                updated_str = str(updated)

    # password / password_hash locals end here; only the hash went to the DB.
    return SshCredentialSaveResult(
        ssh_host=host,
        ssh_user=user,
        ssh_port=port,
        device_name=name,
        credential_ref=ref,
        password_hash_stored=True,
        updated_at=updated_str,
        row_id=row_id,
    )


def verify_host_password(
    ssh_host: str,
    password: str,
    *,
    settings: pg.PostgresSettings | None = None,
) -> bool:
    """True if *password* matches the salted hash stored for *ssh_host*."""
    row = get_host_credentials(ssh_host, settings=settings)
    if not row:
        return False
    stored = str(row.get("password_hash") or "")
    if not stored:
        return False
    return auth.verify_password(password, stored)


def get_host_credentials(
    ssh_host: str,
    *,
    settings: pg.PostgresSettings | None = None,
) -> dict[str, Any] | None:
    """Return the stored credential row for *ssh_host*, or None.

    Never includes a plaintext password — only ``password_hash`` when present.
    """
    host = (ssh_host or "").strip()
    if not host:
        return None
    rows = get_credentials_map([host], settings=settings)
    return rows.get(host)


def get_credentials_map(
    ssh_hosts: list[str],
    *,
    settings: pg.PostgresSettings | None = None,
) -> dict[str, dict[str, Any]]:
    """Fetch credential rows for many hosts in one round-trip."""
    hosts = sorted({(h or "").strip() for h in ssh_hosts if (h or "").strip()})
    if not hosts:
        return {}
    try:
        with pg.connect(settings) as conn:
            ensure_schema(conn)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT ssh_host, ssh_port, ssh_user, ssh_key_path,
                           ssh_credential_ref, password_hash,
                           device_name, device_kind, updated_at
                    FROM ssh_host_credentials
                    WHERE ssh_host = ANY(%s)
                    """,
                    (hosts,),
                )
                rows = cur.fetchall()
    except Exception:  # noqa: BLE001
        return {}
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        updated = row[8]
        host = str(row[0] or "")
        if not host:
            continue
        out[host] = {
            "ssh_host": host,
            "ssh_port": int(row[1] or 22),
            "ssh_user": str(row[2] or ""),
            "ssh_key_path": str(row[3] or ""),
            "ssh_credential_ref": str(row[4] or ""),
            "password_hash": str(row[5] or ""),
            "device_name": str(row[6] or ""),
            "device_kind": str(row[7] or ""),
            "updated_at": (
                updated.isoformat() if hasattr(updated, "isoformat") else str(updated)
            ),
        }
    return out


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
