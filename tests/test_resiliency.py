"""Cross-device resiliency analysis tests."""

from __future__ import annotations

from pathlib import Path

from pfsense_checker.models import Severity
from pfsense_checker.resiliency import analyze_site, load_site_snapshot
from pfsense_checker.topology_site import (
    Device,
    Link,
    SiteTopology,
    SiteVlan,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def _paired_site() -> SiteTopology:
    site = SiteTopology(name="paired")
    fw = Device(
        name="pfSense-FW",
        kind="pfsense",
        role="firewall",
        ports=["em0", "igb0"],
    )
    fw.attach_local_config(SAMPLES / "sample_config.xml")
    mt = Device(
        name="CoreRouter-01",
        kind="mikrotik",
        role="router",
        ports=["ether1-wan", "bridge-lan", "ether2"],
    )
    mt.attach_local_config(SAMPLES / "sample_mikrotik.rsc")
    site.devices.extend([fw, mt])
    site.links.append(
        Link(
            a_device="pfSense-FW",
            a_port="em0",
            b_device="CoreRouter-01",
            b_port="ether2",
            kind="trunk",
            vlans=["10", "20"],
            native_vlan="1",
        )
    )
    site.vlans.append(
        SiteVlan(id="10", name="servers", subnet="10.10.10.0/24", gateway="CoreRouter-01")
    )
    return site


def test_load_snapshot_ok() -> None:
    site = _paired_site()
    snap = load_site_snapshot(site)
    assert snap.devices["pfSense-FW"].status == "ok"
    assert snap.devices["CoreRouter-01"].status == "ok"
    assert snap.devices["CoreRouter-01"].result is not None
    assert snap.devices["CoreRouter-01"].result.hostname == "CoreRouter-01"


def test_analyze_runs_on_paired_site() -> None:
    report = analyze_site(_paired_site())
    assert report.summary["with_config"] == 2
    assert isinstance(report.findings, list)
    # Should not crash; may still have warnings about VLAN presence etc.


def test_backup_only_flagged() -> None:
    site = SiteTopology(name="bak")
    d = Device(name="mt1", kind="mikrotik", role="router")
    d.attach_local_config(Path("foo.backup"))
    site.devices.append(d)
    report = analyze_site(site)
    assert report.summary["incomplete"] is True
    assert any(
        f.category == "Source" and "backup" in f.message.lower() for f in report.findings
    )


def test_missing_config_on_firewall() -> None:
    site = SiteTopology(name="empty")
    site.devices.append(Device(name="fw", kind="pfsense", role="firewall"))
    report = analyze_site(site)
    assert any(f.category == "Source" and "no attached" in f.message.lower() for f in report.findings)


def test_incompatible_link_addresses() -> None:
    site = SiteTopology(name="bad-l3")
    a = Device(name="A", kind="mikrotik", role="router", ports=["ether1"])
    b = Device(name="B", kind="mikrotik", role="router", ports=["ether1"])
    # Minimal synthetic results via attached empty — instead build snapshot manually
    from pfsense_checker.models import CheckResult, InterfaceInfo
    from pfsense_checker.resiliency import DeviceSnapshot, SiteSnapshot, _check_l3_dhcp

    site.devices.extend([a, b])
    site.links.append(
        Link(a_device="A", a_port="ether1", b_device="B", b_port="ether1", kind="copper")
    )
    ra = CheckResult(valid_xml=True, source_type="mikrotik")
    ra.interfaces.append(
        InterfaceInfo(name="ether1", device="ether1", enabled=True, ipaddr="10.0.0.1", subnet="24")
    )
    rb = CheckResult(valid_xml=True, source_type="mikrotik")
    rb.interfaces.append(
        InterfaceInfo(name="ether1", device="ether1", enabled=True, ipaddr="192.168.1.1", subnet="24")
    )
    snap = SiteSnapshot(
        site=site,
        devices={
            "A": DeviceSnapshot(device=a, result=ra, status="ok"),
            "B": DeviceSnapshot(device=b, result=rb, status="ok"),
        },
    )
    findings = _check_l3_dhcp(snap)
    assert any(f.severity is Severity.ERROR and "incompatible" in f.message.lower() for f in findings)


def test_spof_critical_link() -> None:
    site = SiteTopology(name="spof")
    site.devices.extend(
        [
            Device(name="access", kind="host", role="workstation"),
            Device(name="core", kind="mikrotik", role="core-switch"),
            Device(name="fw", kind="pfsense", role="firewall"),
        ]
    )
    site.links.append(Link(a_device="access", a_port="eth0", b_device="core", b_port="1"))
    site.links.append(Link(a_device="core", a_port="24", b_device="fw", b_port="em0"))
    from pfsense_checker.topology_site import EgressPath

    site.egress.append(EgressPath(name="wan", device="fw", upstream="ISP"))
    report = analyze_site(site)
    assert any(f.category == "Resilience" for f in report.findings)
