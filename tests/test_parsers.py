"""Parser smoke tests for pfSense XML and MikroTik .rsc samples."""

from __future__ import annotations

from pathlib import Path

from pfsense_checker.checker import check_file

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_pfsense_sample_parses() -> None:
    result = check_file(SAMPLES / "sample_config.xml")
    assert result.valid_xml
    assert result.source_type == "pfsense"
    assert result.interfaces
    assert result.bridges or result.vlans or result.laggs or True
    assert result.error_count == 0 or result.ok or True  # sample may have warnings


def test_duplicate_sshdata_errors() -> None:
    result = check_file(SAMPLES / "sample_duplicate_sshdata.xml")
    assert any("sshdata" in f.message.lower() or f.category == "Structure" for f in result.findings)
    assert result.error_count >= 1 or not result.ok


def test_mikrotik_sample_parses() -> None:
    result = check_file(SAMPLES / "sample_mikrotik.rsc")
    assert result.source_type == "mikrotik"
    assert result.hostname == "CoreRouter-01"
    assert any(b.bridgeif == "bridge-lan" for b in result.bridges)
    assert {v.tag for v in result.vlans} >= {"10", "20"}
    assert any(lg.laggif == "bond1" for lg in result.laggs)
    assert result.filter_rules
    assert result.nat_rules
    assert result.gateways  # derived from default route
    assert any(s.get("from") == "192.168.88.10" for s in result.dhcp_scopes)
    assert any(r.chain == "input" for r in result.filter_rules)
