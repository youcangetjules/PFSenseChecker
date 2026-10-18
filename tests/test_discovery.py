"""Tests for strict batch matching, link auto-detection, and anomaly checks."""

from __future__ import annotations

from pfsense_checker.discovery import infer_links
from pfsense_checker.mikrotik import parse_routeros
from pfsense_checker.models import Severity
from pfsense_checker.resiliency import analyze_site
from pfsense_checker.topology_site import SiteTopology, enrich_from_result

CORE_RSC = """
/interface bridge
add name=core-bridge vlan-filtering=yes
/interface ethernet
set [ find default-name=sfp1 ] comment="edge-1 (Office) (VL600)"
set [ find default-name=sfp2 ] comment="KVM1 (VL646)"
set [ find default-name=sfp-sfpplus1 ] comment=">> Main uplink to PFSense"
/interface vlan
add interface=core-bridge name=V1-VL600-MAN vlan-id=600
/interface bridge port
add bridge=core-bridge comment="edge-1 (Office)" interface=sfp1 pvid=600
add bridge=core-bridge comment="KVM1 (VL646)" interface=sfp2 pvid=630
/interface bridge vlan
add bridge=core-bridge tagged=core-bridge,sfp-sfpplus1,sfp1 vlan-ids=600
/ip address
add address=10.0.0.2/24 interface=V1-VL600-MAN network=10.0.0.0
/ip dns
set servers=192.168.99.1
/system identity
set name=core-1
"""

EDGE_RSC = """
/interface bridge
add name=edge-bridge
/interface ethernet
set [ find default-name=sfp1 ] comment=">> Uplink"
/interface vlan
add interface=edge-bridge name=V1-VL600-MGMT vlan-id=600
/ip address
add address=10.0.0.3/24 interface=V1-VL600-MGMT network=10.0.0.0
/ip dns
set servers=8.8.8.8
/system identity
set name=edge-1
"""


def _build_site() -> tuple[SiteTopology, dict]:
    site = SiteTopology()
    results = {}
    for text in (CORE_RSC, EDGE_RSC):
        result = parse_routeros(text)
        report = enrich_from_result(site, result, create_if_missing=True, strict_match=True)
        results[report.device_name] = result
    return site, results


def test_strict_match_keeps_devices_separate() -> None:
    site, _ = _build_site()
    assert sorted(d.name for d in site.devices) == ["core-1", "edge-1"]


def test_infer_links_from_port_comments() -> None:
    site, results = _build_site()
    report = infer_links(site, results)
    assert len(report.links_added) == 1
    link = report.links_added[0]
    assert {link.a_device, link.b_device} == {"core-1", "edge-1"}
    assert link.a_port == "sfp1"
    assert link.b_port == "sfp1"  # reverse-matched from ">> Uplink"
    assert "600" in link.vlans

    # Second run must not duplicate the pair
    report2 = infer_links(site, results)
    assert not report2.links_added


def test_anomaly_pvid_vs_comment_and_naming_drift() -> None:
    site, results = _build_site()
    for name, result in results.items():
        dev = site.device(name)
        dev.config_source = None
        dev.config_file = ""
    # Analyze with in-memory snapshot instead of files
    from pfsense_checker.resiliency import DeviceSnapshot, SiteSnapshot, _check_consistency

    snap = SiteSnapshot(site=site)
    for dev in site.devices:
        snap.devices[dev.name] = DeviceSnapshot(
            device=dev, result=results[dev.name], status="ok"
        )
    findings = _check_consistency(snap)
    messages = [f.message for f in findings]

    assert any("VL646 but bridge PVID is 630" in m for m in messages)
    assert any("VLAN 600 is named inconsistently" in m for m in messages)
    assert any(
        "192.168.99.1 is private but not on any known site subnet" in m
        for m in messages
    )


def test_duplicate_ip_detected() -> None:
    dup = EDGE_RSC.replace("10.0.0.3/24", "10.0.0.2/24").replace(
        "network=10.0.0.0", "network=10.0.0.0"
    )
    site = SiteTopology()
    results = {}
    for text in (CORE_RSC, dup):
        result = parse_routeros(text)
        report = enrich_from_result(site, result, create_if_missing=True, strict_match=True)
        results[report.device_name] = result

    from pfsense_checker.resiliency import DeviceSnapshot, SiteSnapshot, _check_consistency

    snap = SiteSnapshot(site=site)
    for dev in site.devices:
        snap.devices[dev.name] = DeviceSnapshot(
            device=dev, result=results[dev.name], status="ok"
        )
    findings = _check_consistency(snap)
    dups = [f for f in findings if "Duplicate IP address 10.0.0.2" in f.message]
    assert dups and dups[0].severity is Severity.ERROR
