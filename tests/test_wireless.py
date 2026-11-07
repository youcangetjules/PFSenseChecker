"""Wireless / CAPsMAN path checks (wireline OK, WLAN marginal class)."""

from __future__ import annotations

from pfsense_checker.mikrotik import parse_routeros
from pfsense_checker.models import Severity
from pfsense_checker.resiliency import DeviceSnapshot, SiteSnapshot, _check_wireless
from pfsense_checker.topology_site import SiteTopology, enrich_from_result

MANAGER_RSC = """
/interface bridge
add name=MGR-Bridge vlan-filtering=yes
/caps-man datapath
add client-to-client-forwarding=yes local-forwarding=yes name=DP-VL630 vlan-id=630 vlan-mode=use-tag
/caps-man configuration
add datapath=DP-VL630 .bridge=MGR-Bridge .client-to-client-forwarding=no .local-forwarding=yes .vlan-id=630 .vlan-mode=use-tag mode=ap name=\\
    CFG-VL630 security=SEC1 ssid=LAN-WIFI
/caps-man interface
add configuration=CFG-VL630 disabled=yes master-interface=none name=AP-1 radio-mac=AA:BB:CC:00:00:01
add configuration=CFG-VL630 disabled=no master-interface=none name=AP-2 radio-mac=AA:BB:CC:00:00:02
/caps-man manager
set enabled=yes
/ip address
add address=10.0.0.5/24 interface=MGR-Bridge network=10.0.0.0
/system identity
set name=core-mgr
"""

CAP_RSC = """
/interface bridge
add name=CAP-Bridge
/interface wireless
set [ find default-name=wlan1 ] ssid=MikroTik
/interface bridge vlan
add bridge=CAP-Bridge tagged=CAP-Bridge,sfp1,wlan1 vlan-ids=630
/interface wireless cap
set bridge=CAP-Bridge caps-man-addresses=10.0.0.5 enabled=yes interfaces=wlan1
/ip address
add address=10.0.0.10/24 interface=CAP-Bridge network=10.0.0.0
/system identity
set name=ap-office
"""


def _snapshot() -> SiteSnapshot:
    site = SiteTopology()
    results = {}
    for text in (MANAGER_RSC, CAP_RSC):
        result = parse_routeros(text)
        report = enrich_from_result(site, result, create_if_missing=True, strict_match=True)
        results[report.device_name] = result
    snap = SiteSnapshot(site=site)
    for dev in site.devices:
        snap.devices[dev.name] = DeviceSnapshot(
            device=dev, result=results[dev.name], status="ok"
        )
    return snap


def test_wireless_findings() -> None:
    findings = _check_wireless(_snapshot())
    messages = [f.message for f in findings]

    # local-forwarding with a manager-only bridge override
    assert any(
        "local-forwarding but overrides bridge to 'MGR-Bridge'" in m for m in messages
    )
    # datapath vs config override conflict
    assert any("client-to-client-forwarding=no" in m for m in messages)
    # disabled radio on the manager
    assert any("radio(s) disabled on the manager: AP-1" in m for m in messages)
    # CAP bridge without vlan-filtering or switch-chip VLANs: a warning that
    # offers the switch chip first, not an error demanding vlan-filtering.
    vf = [f for f in findings if "vlan-filtering=no" in f.message]
    assert vf and vf[0].severity is Severity.WARNING and "CAP-Bridge" in vf[0].message
    assert "switch chip" in vf[0].remediation


def test_wireless_ok_when_switch_chip_carries_the_vlans() -> None:
    global CAP_RSC
    original = CAP_RSC
    CAP_RSC = original + (
        "/interface ethernet switch vlan\nadd ports=sfp1,switch1-cpu vlan-id=630\n"
        "/interface ethernet switch egress-vlan-tag\nadd tagged-ports=sfp1,switch1-cpu vlan-id=630\n"
    )
    try:
        findings = _check_wireless(_snapshot())
    finally:
        CAP_RSC = original
    assert not any("vlan-filtering=no" in f.message or "switch-chip VLAN table" in f.message for f in findings)



def test_wireless_ok_when_vlan_filtering_enabled() -> None:
    snap = _snapshot()
    # Simulate the fix: enable vlan-filtering on the CAP bridge
    for ds in snap.devices.values():
        vf = ds.result.summary.get("bridge_vlan_filtering", {})
        if "CAP-Bridge" in vf:
            vf["CAP-Bridge"] = True
    findings = _check_wireless(snap)
    assert not any("vlan-filtering=no" in f.message for f in findings)
