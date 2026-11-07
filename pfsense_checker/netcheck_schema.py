"""NetCheck PostgreSQL schema — topology, config checks, connectivity.

All DDL is idempotent (``CREATE TABLE IF NOT EXISTS``). Call
:func:`ensure_schema` after connecting to create / refresh tables.
Passwords are never stored in these tables.
"""

from __future__ import annotations

from typing import Any

from pfsense_checker import postgres_db as pg

# Keep statement list separate so drivers that disallow multi-statement
# executes still work.
SCHEMA_STATEMENTS: tuple[str, ...] = (
    # --- Topology (live / experimental site slots) ---
    """
    CREATE TABLE IF NOT EXISTS topology_sites (
        id          BIGSERIAL PRIMARY KEY,
        mode        TEXT NOT NULL UNIQUE,
        name        TEXT NOT NULL DEFAULT '',
        grid_size   INT NOT NULL DEFAULT 20,
        updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        payload_json JSONB
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS topology_devices (
        id                  BIGSERIAL PRIMARY KEY,
        site_id             BIGINT NOT NULL REFERENCES topology_sites(id) ON DELETE CASCADE,
        name                TEXT NOT NULL,
        kind                TEXT NOT NULL DEFAULT '',
        model               TEXT NOT NULL DEFAULT '',
        role                TEXT NOT NULL DEFAULT '',
        secpol              TEXT NOT NULL DEFAULT '',
        priority            TEXT NOT NULL DEFAULT '',
        hardware            TEXT NOT NULL DEFAULT '',
        notes               TEXT NOT NULL DEFAULT '',
        mgmt_ip             TEXT NOT NULL DEFAULT '',
        config_file         TEXT NOT NULL DEFAULT '',
        x                   DOUBLE PRECISION,
        y                   DOUBLE PRECISION,
        w                   DOUBLE PRECISION,
        h                   DOUBLE PRECISION,
        ssh_host            TEXT NOT NULL DEFAULT '',
        ssh_port            INT NOT NULL DEFAULT 22,
        ssh_user            TEXT NOT NULL DEFAULT '',
        ssh_auth            TEXT NOT NULL DEFAULT 'password',
        ssh_key_path        TEXT NOT NULL DEFAULT '',
        ssh_credential_ref  TEXT NOT NULL DEFAULT '',
        ssh_last_status     TEXT NOT NULL DEFAULT '',
        ssh_last_error      TEXT NOT NULL DEFAULT '',
        ssh_last_ok_at      TEXT NOT NULL DEFAULT '',
        UNIQUE (site_id, name)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_topology_devices_site
        ON topology_devices(site_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS topology_device_components (
        id          BIGSERIAL PRIMARY KEY,
        device_id   BIGINT NOT NULL REFERENCES topology_devices(id) ON DELETE CASCADE,
        name        TEXT NOT NULL,
        media       TEXT NOT NULL DEFAULT '',
        slot        TEXT NOT NULL DEFAULT '',
        side        TEXT NOT NULL DEFAULT 'right'
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_topology_device_components_device
        ON topology_device_components(device_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS topology_links (
        id            BIGSERIAL PRIMARY KEY,
        site_id       BIGINT NOT NULL REFERENCES topology_sites(id) ON DELETE CASCADE,
        a_device      TEXT NOT NULL DEFAULT '',
        a_port        TEXT NOT NULL DEFAULT '',
        b_device      TEXT NOT NULL DEFAULT '',
        b_port        TEXT NOT NULL DEFAULT '',
        kind          TEXT NOT NULL DEFAULT 'copper',
        speed         TEXT NOT NULL DEFAULT '',
        descr         TEXT NOT NULL DEFAULT '',
        vlans         TEXT NOT NULL DEFAULT '',
        native_vlan   TEXT NOT NULL DEFAULT '',
        bridge        TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_topology_links_site
        ON topology_links(site_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS topology_vlans (
        id            BIGSERIAL PRIMARY KEY,
        site_id       BIGINT NOT NULL REFERENCES topology_sites(id) ON DELETE CASCADE,
        vlan_id       TEXT NOT NULL,
        name          TEXT NOT NULL DEFAULT '',
        subnet        TEXT NOT NULL DEFAULT '',
        if_label      TEXT NOT NULL DEFAULT '',
        s_ip          TEXT NOT NULL DEFAULT '',
        dhcp_pool     TEXT NOT NULL DEFAULT '',
        gateway       TEXT NOT NULL DEFAULT '',
        notes         TEXT NOT NULL DEFAULT '',
        UNIQUE (site_id, vlan_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS topology_vlan_devices (
        vlan_row_id   BIGINT NOT NULL REFERENCES topology_vlans(id) ON DELETE CASCADE,
        device_name   TEXT NOT NULL,
        PRIMARY KEY (vlan_row_id, device_name)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS topology_bridges (
        id            BIGSERIAL PRIMARY KEY,
        site_id       BIGINT NOT NULL REFERENCES topology_sites(id) ON DELETE CASCADE,
        name          TEXT NOT NULL,
        vlan          TEXT NOT NULL DEFAULT '',
        notes         TEXT NOT NULL DEFAULT '',
        devices       TEXT NOT NULL DEFAULT '',
        ports         TEXT NOT NULL DEFAULT '',
        UNIQUE (site_id, name)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS topology_vpn (
        id                BIGSERIAL PRIMARY KEY,
        site_id           BIGINT NOT NULL REFERENCES topology_sites(id) ON DELETE CASCADE,
        name              TEXT NOT NULL,
        kind              TEXT NOT NULL DEFAULT 'wireguard',
        a_device          TEXT NOT NULL DEFAULT '',
        b_device          TEXT NOT NULL DEFAULT '',
        local_endpoint    TEXT NOT NULL DEFAULT '',
        remote_endpoint   TEXT NOT NULL DEFAULT '',
        networks          TEXT NOT NULL DEFAULT '',
        notes             TEXT NOT NULL DEFAULT '',
        UNIQUE (site_id, name)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS topology_egress (
        id            BIGSERIAL PRIMARY KEY,
        site_id       BIGINT NOT NULL REFERENCES topology_sites(id) ON DELETE CASCADE,
        name          TEXT NOT NULL,
        device        TEXT NOT NULL DEFAULT '',
        uplink_port   TEXT NOT NULL DEFAULT '',
        upstream      TEXT NOT NULL DEFAULT '',
        wan_subnet    TEXT NOT NULL DEFAULT '',
        default_for   TEXT NOT NULL DEFAULT '',
        notes         TEXT NOT NULL DEFAULT '',
        UNIQUE (site_id, name)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS topology_subnets (
        id            BIGSERIAL PRIMARY KEY,
        site_id       BIGINT NOT NULL REFERENCES topology_sites(id) ON DELETE CASCADE,
        cidr          TEXT NOT NULL,
        UNIQUE (site_id, cidr)
    )
    """,
    # --- Config file registry + check history ---
    """
    CREATE TABLE IF NOT EXISTS config_files (
        id                  BIGSERIAL PRIMARY KEY,
        device_name         TEXT NOT NULL DEFAULT '',
        source_type         TEXT NOT NULL DEFAULT 'local_file',
        path                TEXT NOT NULL DEFAULT '',
        backup_artifact     TEXT NOT NULL DEFAULT '',
        host                TEXT NOT NULL DEFAULT '',
        port                INT,
        username            TEXT NOT NULL DEFAULT '',
        last_status         TEXT NOT NULL DEFAULT '',
        last_collected_at   TEXT NOT NULL DEFAULT '',
        export_hash         TEXT NOT NULL DEFAULT '',
        updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_config_files_device
        ON config_files(device_name)
    """,
    """
    CREATE TABLE IF NOT EXISTS config_checks (
        id              BIGSERIAL PRIMARY KEY,
        checked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        source_path     TEXT NOT NULL DEFAULT '',
        device_name     TEXT NOT NULL DEFAULT '',
        platform        TEXT NOT NULL DEFAULT '',
        hostname        TEXT NOT NULL DEFAULT '',
        domain          TEXT NOT NULL DEFAULT '',
        version         TEXT NOT NULL DEFAULT '',
        verdict         TEXT NOT NULL DEFAULT '',
        valid_xml       BOOLEAN NOT NULL DEFAULT FALSE,
        error_count     INT NOT NULL DEFAULT 0,
        warning_count   INT NOT NULL DEFAULT 0,
        info_count      INT NOT NULL DEFAULT 0,
        summary_json    JSONB,
        report_text     TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_config_checks_checked_at
        ON config_checks(checked_at DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS config_findings (
        id              BIGSERIAL PRIMARY KEY,
        check_id        BIGINT NOT NULL REFERENCES config_checks(id) ON DELETE CASCADE,
        severity        TEXT NOT NULL,
        category        TEXT NOT NULL DEFAULT '',
        message         TEXT NOT NULL,
        path            TEXT NOT NULL DEFAULT '',
        line_no         INT
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_config_findings_check
        ON config_findings(check_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS config_interfaces (
        id              BIGSERIAL PRIMARY KEY,
        check_id        BIGINT NOT NULL REFERENCES config_checks(id) ON DELETE CASCADE,
        name            TEXT NOT NULL,
        descr           TEXT NOT NULL DEFAULT '',
        device          TEXT NOT NULL DEFAULT '',
        enabled         BOOLEAN NOT NULL DEFAULT FALSE,
        ipaddr          TEXT NOT NULL DEFAULT '',
        subnet          TEXT NOT NULL DEFAULT '',
        kind            TEXT NOT NULL DEFAULT '',
        media           TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_config_interfaces_check
        ON config_interfaces(check_id)
    """,
    # --- Connectivity snapshots (Login → Save Connectivity to DB) ---
    """
    CREATE TABLE IF NOT EXISTS connectivity_snapshots (
        id              BIGSERIAL PRIMARY KEY,
        saved_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        site_name       TEXT NOT NULL DEFAULT '',
        device_count    INT NOT NULL DEFAULT 0,
        link_count      INT NOT NULL DEFAULT 0,
        subnet_count    INT NOT NULL DEFAULT 0,
        connected_count INT NOT NULL DEFAULT 0,
        notes           TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS connectivity_devices (
        id            BIGSERIAL PRIMARY KEY,
        snapshot_id   BIGINT NOT NULL REFERENCES connectivity_snapshots(id) ON DELETE CASCADE,
        name          TEXT NOT NULL,
        kind          TEXT NOT NULL DEFAULT '',
        mgmt_ip       TEXT NOT NULL DEFAULT '',
        ssh_host      TEXT NOT NULL DEFAULT '',
        ssh_port      INT NOT NULL DEFAULT 22,
        ssh_user      TEXT NOT NULL DEFAULT '',
        ssh_status    TEXT NOT NULL DEFAULT '',
        ssh_error     TEXT NOT NULL DEFAULT '',
        included      BOOLEAN NOT NULL DEFAULT TRUE,
        config_path   TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_connectivity_devices_snapshot
        ON connectivity_devices(snapshot_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS connectivity_links (
        id            BIGSERIAL PRIMARY KEY,
        snapshot_id   BIGINT NOT NULL REFERENCES connectivity_snapshots(id) ON DELETE CASCADE,
        a_device      TEXT NOT NULL DEFAULT '',
        a_port        TEXT NOT NULL DEFAULT '',
        b_device      TEXT NOT NULL DEFAULT '',
        b_port        TEXT NOT NULL DEFAULT '',
        kind          TEXT NOT NULL DEFAULT '',
        speed         TEXT NOT NULL DEFAULT '',
        descr         TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_connectivity_links_snapshot
        ON connectivity_links(snapshot_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS connectivity_subnets (
        id            BIGSERIAL PRIMARY KEY,
        snapshot_id   BIGINT NOT NULL REFERENCES connectivity_snapshots(id) ON DELETE CASCADE,
        cidr          TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_connectivity_subnets_snapshot
        ON connectivity_subnets(snapshot_id)
    """,
    # --- SSH host credentials (Login → Save credentials; password never stored) ---
    """
    CREATE TABLE IF NOT EXISTS ssh_host_credentials (
        id                  BIGSERIAL PRIMARY KEY,
        ssh_host            TEXT NOT NULL UNIQUE,
        ssh_port            INT NOT NULL DEFAULT 22,
        ssh_user            TEXT NOT NULL DEFAULT '',
        ssh_key_path        TEXT NOT NULL DEFAULT '',
        ssh_credential_ref  TEXT NOT NULL DEFAULT '',
        password_hash       TEXT NOT NULL DEFAULT '',
        device_name         TEXT NOT NULL DEFAULT '',
        device_kind         TEXT NOT NULL DEFAULT '',
        updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """,
    """
    ALTER TABLE ssh_host_credentials
        ADD COLUMN IF NOT EXISTS password_hash TEXT NOT NULL DEFAULT ''
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_ssh_host_credentials_host
        ON ssh_host_credentials(ssh_host)
    """,
    # --- Application users (login gate) ---
    """
    CREATE TABLE IF NOT EXISTS users (
        id              BIGSERIAL PRIMARY KEY,
        username        TEXT NOT NULL UNIQUE,
        password_hash   TEXT NOT NULL,
        role            TEXT NOT NULL DEFAULT 'user',
        is_active       BOOLEAN NOT NULL DEFAULT TRUE,
        must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """,
    """
    ALTER TABLE users
        ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE
    """,
    """
    CREATE OR REPLACE VIEW users_login_v AS
        SELECT username, password_hash, role, must_change_password
        FROM users
        WHERE is_active IS TRUE
    """,
    # Sign-in history (Logs → Login History). No passwords, ever.
    """
    CREATE TABLE IF NOT EXISTS login_sessions (
        id              BIGSERIAL PRIMARY KEY,
        username        TEXT NOT NULL,
        outcome         TEXT NOT NULL DEFAULT 'success',
        client_ip       TEXT NOT NULL DEFAULT '',
        client_host     TEXT NOT NULL DEFAULT '',
        started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        ended_at        TIMESTAMPTZ,
        end_reason      TEXT NOT NULL DEFAULT '',
        app_version     TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS login_sessions_started_idx
        ON login_sessions (started_at DESC)
    """,
    # Subnet Health device age: one row per device per subnet (device_scan).
    # device_key is the MAC, or "ip:<address>" when no MAC was seen.
    """
    CREATE TABLE IF NOT EXISTS subnet_devices (
        cidr            TEXT NOT NULL,
        device_key      TEXT NOT NULL,
        ip              TEXT NOT NULL DEFAULT '',
        mac             TEXT NOT NULL DEFAULT '',
        hostname        TEXT NOT NULL DEFAULT '',
        vendor          TEXT NOT NULL DEFAULT '',
        conn_type       TEXT NOT NULL DEFAULT '',
        os_guess        TEXT NOT NULL DEFAULT '',
        sources         TEXT NOT NULL DEFAULT '',
        beacon_id       TEXT NOT NULL DEFAULT '',
        answered        BOOLEAN NOT NULL DEFAULT FALSE,
        first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_seen       TIMESTAMPTZ,
        last_listed     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (cidr, device_key)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS subnet_devices_ip_idx
        ON subnet_devices (cidr, ip)
    """,
    # Seed empty live / experimental site slots (ignore if already present).
    """
    INSERT INTO topology_sites (mode, name, grid_size)
    VALUES
        ('live', 'Live', 20),
        ('experimental', 'Experimental', 20)
    ON CONFLICT (mode) DO NOTHING
    """,
)

EXPECTED_TABLES: tuple[str, ...] = (
    "topology_sites",
    "topology_devices",
    "topology_device_components",
    "topology_links",
    "topology_vlans",
    "topology_vlan_devices",
    "topology_bridges",
    "topology_vpn",
    "topology_egress",
    "topology_subnets",
    "config_files",
    "config_checks",
    "config_findings",
    "config_interfaces",
    "connectivity_snapshots",
    "connectivity_devices",
    "connectivity_links",
    "connectivity_subnets",
    "ssh_host_credentials",
    "users",
    "login_sessions",
    "subnet_devices",
)


_SCHEMA_ENSURED = False


def ensure_schema(conn: Any | None = None) -> int:
    """Create all NetCheck tables if missing. Returns statements executed."""
    global _SCHEMA_ENSURED

    def _run(c: Any) -> int:
        n = 0
        with c.cursor() as cur:
            for stmt in SCHEMA_STATEMENTS:
                cur.execute(stmt)
                n += 1
        return n

    if _SCHEMA_ENSURED:
        return 0
    if conn is not None:
        n = _run(conn)
        _SCHEMA_ENSURED = True
        return n
    with pg.connect() as c:
        n = _run(c)
    _SCHEMA_ENSURED = True
    return n


def list_netcheck_tables(conn: Any | None = None) -> list[str]:
    """Return public tables that belong to the NetCheck schema set."""

    def _run(c: Any) -> list[str]:
        with c.cursor() as cur:
            cur.execute(
                """
                SELECT tablename FROM pg_tables
                WHERE schemaname = 'public'
                  AND tablename = ANY(%s)
                ORDER BY tablename
                """,
                (list(EXPECTED_TABLES),),
            )
            return [str(r[0]) for r in cur.fetchall()]

    if conn is not None:
        return _run(conn)
    with pg.connect() as c:
        return _run(c)
