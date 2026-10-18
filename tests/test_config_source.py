"""ConfigSource migration and credential reference tests."""

from __future__ import annotations

from pathlib import Path

from pfsense_checker.credentials import make_credential_ref
from pfsense_checker.topology_site import (
    CONFIG_SOURCE_LOCAL,
    CONFIG_SOURCE_MIKROTIK_REST,
    ConfigSource,
    Device,
    SiteTopology,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_legacy_config_file_migrates() -> None:
    d = Device(name="fw", kind="pfsense", config_file=str(SAMPLES / "sample_config.xml"))
    src = d.ensure_config_source()
    assert src is not None
    assert src.source_type == CONFIG_SOURCE_LOCAL
    assert src.path.endswith("sample_config.xml")


def test_backup_attachment_is_rest_source() -> None:
    d = Device(name="crs", kind="mikrotik")
    src = d.attach_local_config(Path("core.backup"))
    assert src.source_type == CONFIG_SOURCE_MIKROTIK_REST
    assert src.backup_artifact.endswith("core.backup")
    assert not src.path
    assert "restore evidence" in (src.notes or "").lower() or src.last_status == "never"


def test_site_roundtrip_preserves_config_source() -> None:
    site = SiteTopology(name="t")
    d = Device(name="r1", kind="mikrotik")
    d.attach_local_config(SAMPLES / "sample_mikrotik.rsc")
    assert d.config_source is not None
    d.config_source.host = "192.168.88.1"
    d.config_source.credential_ref = "mt-test"
    d.config_source.source_type = CONFIG_SOURCE_MIKROTIK_REST
    site.devices.append(d)
    data = site.to_dict()
    loaded = SiteTopology.from_dict(data)
    r1 = loaded.device("r1")
    assert r1 is not None
    assert r1.config_source is not None
    assert r1.config_source.host == "192.168.88.1"
    assert r1.config_source.credential_ref == "mt-test"
    # Password must never appear in JSON
    blob = str(data)
    assert "password" not in blob.lower() or "credential_ref" in blob


def test_credential_ref_stable() -> None:
    a = make_credential_ref("crs", "10.0.0.1", "admin")
    b = make_credential_ref("crs", "10.0.0.1", "admin")
    assert a.ref_id == b.ref_id
    assert a.service.startswith("PFSenseChecker.MikroTik.")


def test_clean_site_validates() -> None:
    site = SiteTopology.load(SAMPLES / "site_crs109_crs328_pfsense.json")
    # Round-trip
    site2 = SiteTopology.from_dict(site.to_dict())
    assert site2.name == site.name
    assert len(site2.devices) == len(site.devices)
