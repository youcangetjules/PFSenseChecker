"""Tests for connectivity snapshot persistence."""

from __future__ import annotations

from pfsense_checker import connectivity_db, postgres_db as pg
from pfsense_checker.topology_site import Device, Link, SiteTopology, SshAccess


def test_save_connectivity_roundtrip() -> None:
    if not pg.psycopg_available():
        return
    settings = pg.load_settings()
    if settings.database != "netcheck":
        # Still try — credentials should point at netcheck after setup.
        pass
    try:
        pg.test_connection(settings)
    except Exception:  # noqa: BLE001
        return

    site = SiteTopology(
        name="Test Site",
        subnets=["192.168.1.0/24", "10.0.0.0/24"],
        devices=[
            Device(
                name="fw1",
                kind="pfsense",
                mgmt_ip="192.168.1.1",
                ssh=SshAccess(
                    host="192.168.1.1",
                    port=22,
                    username="admin",
                    last_status="ok",
                ),
            ),
            Device(
                name="sw1",
                kind="mikrotik",
                mgmt_ip="192.168.1.2",
                ssh=SshAccess(host="192.168.1.2", last_status="never"),
            ),
        ],
        links=[
            Link(a_device="fw1", a_port="igb0", b_device="sw1", b_port="ether1"),
        ],
    )
    result = connectivity_db.save_connectivity(
        site, included_names=["fw1"], settings=settings
    )
    assert result.snapshot_id > 0
    assert result.device_count == 2
    assert result.link_count == 1
    assert result.subnet_count == 2
    assert result.connected_count == 1

    with pg.connect(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT included, ssh_status FROM connectivity_devices "
                "WHERE snapshot_id = %s AND name = %s",
                (result.snapshot_id, "fw1"),
            )
            row = cur.fetchone()
            assert row is not None
            assert row[0] is True
            assert row[1] == "ok"
            cur.execute(
                "SELECT included FROM connectivity_devices "
                "WHERE snapshot_id = %s AND name = %s",
                (result.snapshot_id, "sw1"),
            )
            row2 = cur.fetchone()
            assert row2 is not None
            assert row2[0] is False
