"""Persist Login / topology connectivity snapshots into the netcheck database.

Stores subnets, devices (SSH status — never passwords), and links under a
timestamped snapshot. Schema is created on first save via netcheck_schema.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from pfsense_checker import netcheck_schema, postgres_db as pg
from pfsense_checker.topology_site import Device, SiteTopology


@dataclass(frozen=True)
class ConnectivitySaveResult:
    snapshot_id: int
    saved_at: str
    device_count: int
    link_count: int
    subnet_count: int
    connected_count: int


def ensure_schema(conn: Any | None = None) -> None:
    """Create connectivity (and all NetCheck) tables if they do not exist."""
    netcheck_schema.ensure_schema(conn)


def save_connectivity(
    site: SiteTopology,
    *,
    included_names: Iterable[str] | None = None,
    notes: str = "",
    settings: pg.PostgresSettings | None = None,
) -> ConnectivitySaveResult:
    """Write a connectivity snapshot for ``site`` into PostgreSQL.

    ``included_names`` marks which Login-table devices had Use ticked; when
    None, every device is treated as included.
    """
    included = {n for n in (included_names or []) if n}
    include_all = included_names is None

    devices = list(site.devices)
    links = list(site.links)
    subnets = [s for s in site.subnets if str(s).strip()]
    connected = sum(
        1
        for d in devices
        if d.ssh and (d.ssh.last_status or "") == "ok"
    )

    with pg.connect(settings) as conn:
        ensure_schema(conn)
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO connectivity_snapshots(
                    site_name, device_count, link_count, subnet_count,
                    connected_count, notes
                ) VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id, saved_at
                """,
                (
                    site.name or "",
                    len(devices),
                    len(links),
                    len(subnets),
                    connected,
                    notes or "",
                ),
            )
            row = cur.fetchone()
            snapshot_id = int(row[0])
            saved_at = row[1]
            if hasattr(saved_at, "isoformat"):
                saved_at_str = saved_at.isoformat()
            else:
                saved_at_str = str(saved_at)

            for dev in devices:
                _insert_device(cur, snapshot_id, dev, include_all or dev.name in included)

            for link in links:
                cur.execute(
                    """
                    INSERT INTO connectivity_links(
                        snapshot_id, a_device, a_port, b_device, b_port,
                        kind, speed, descr
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        snapshot_id,
                        link.a_device or "",
                        link.a_port or "",
                        link.b_device or "",
                        link.b_port or "",
                        link.kind or "",
                        link.speed or "",
                        link.descr or "",
                    ),
                )

            for cidr in subnets:
                cur.execute(
                    """
                    INSERT INTO connectivity_subnets(snapshot_id, cidr)
                    VALUES (%s, %s)
                    """,
                    (snapshot_id, str(cidr)),
                )

    return ConnectivitySaveResult(
        snapshot_id=snapshot_id,
        saved_at=saved_at_str,
        device_count=len(devices),
        link_count=len(links),
        subnet_count=len(subnets),
        connected_count=connected,
    )


def _insert_device(cur: Any, snapshot_id: int, dev: Device, included: bool) -> None:
    ssh = dev.ssh
    config_path = ""
    if dev.config_source and dev.config_source.path:
        config_path = dev.config_source.path
    elif dev.config_file:
        config_path = dev.config_file
    cur.execute(
        """
        INSERT INTO connectivity_devices(
            snapshot_id, name, kind, mgmt_ip,
            ssh_host, ssh_port, ssh_user, ssh_status, ssh_error,
            included, config_path
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            snapshot_id,
            dev.name or "",
            dev.kind or "",
            dev.mgmt_ip or "",
            (ssh.host if ssh else "") or "",
            int(ssh.port if ssh else 22) or 22,
            (ssh.username if ssh else "") or "",
            (ssh.last_status if ssh else "") or "",
            (ssh.last_error if ssh else "") or "",
            bool(included),
            config_path,
        ),
    )


def latest_snapshot_summary(
    settings: pg.PostgresSettings | None = None,
) -> dict[str, Any] | None:
    """Return the newest snapshot row, or None if none / unreachable."""
    try:
        with pg.connect(settings) as conn:
            ensure_schema(conn)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, saved_at, site_name, device_count, link_count,
                           subnet_count, connected_count
                    FROM connectivity_snapshots
                    ORDER BY id DESC
                    LIMIT 1
                    """
                )
                row = cur.fetchone()
    except Exception:  # noqa: BLE001
        return None
    if not row:
        return None
    saved = row[1]
    return {
        "id": int(row[0]),
        "saved_at": saved.isoformat() if hasattr(saved, "isoformat") else str(saved),
        "site_name": str(row[2] or ""),
        "device_count": int(row[3] or 0),
        "link_count": int(row[4] or 0),
        "subnet_count": int(row[5] or 0),
        "connected_count": int(row[6] or 0),
    }


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
