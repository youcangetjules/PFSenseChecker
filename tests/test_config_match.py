"""Two devices side by side: do their configs agree where they have to?"""

from __future__ import annotations

from pfsense_checker import config_match as cm
from pfsense_checker import log_analysis as la
from pfsense_checker.topology_site import Device, Link, SiteTopology

CORE = """\
# 2026-11-07 by RouterOS 7.22.3
# model = CRS328-4C-20S-4S+
/interface bridge
add name=BR vlan-filtering=yes protocol-mode=rstp
/interface ethernet
set [ find default-name=sfp7 ] name=sfp7 mtu=1500 speed=1G-baseX auto-negotiation=no comment="to office"
/interface vlan
add interface=BR name=V600-MAN vlan-id=600
add interface=BR name=V630-LAN vlan-id=630
add interface=BR name=V662-JAP vlan-id=662
/interface bridge port
add bridge=BR interface=sfp7 frame-types=admit-only-vlan-tagged
/interface bridge vlan
add bridge=BR tagged=BR,sfp7 vlan-ids=600
add bridge=BR tagged=BR,sfp7 vlan-ids=630
add bridge=BR tagged=BR,sfp7 vlan-ids=638
add bridge=BR tagged=BR,sfp7 vlan-ids=662
/ip address
add address=222.10.1.5/24 interface=V600-MAN
add address=222.10.50.5/24 interface=V630-LAN
add address=222.10.70.5/24 interface=V662-JAP
/ip dns
set servers=8.8.8.8
/ip route
add dst-address=0.0.0.0/0 gateway=222.10.50.1
/caps-man manager
set enabled=yes
/interface wifi capsman
set enabled=no
/system identity
set name=CORE
"""

# Switch-chip model: VLAN 662 is on sfp1 but not in its egress tag list (so untagged there),
# VLAN 638 is missing, VLAN 662's address is in another network, and both CAP kinds are on.
EDGE = """\
# 2026-11-07 by RouterOS 7.22.3
# model = CRS109-8G-1S-2HnD
/interface bridge
add name=BR vlan-filtering=no protocol-mode=rstp
/interface ethernet
set [ find default-name=sfp1 ] name=sfp1 mtu=1500 speed=1G-baseX auto-negotiation=no
/interface vlan
add interface=BR name=V600-MAN vlan-id=600
add interface=BR name=V630-OFFICE vlan-id=630
add interface=BR name=V662-JAP vlan-id=662
/interface bridge port
add bridge=BR interface=ether1 pvid=630
add bridge=BR interface=sfp1
/interface ethernet switch egress-vlan-tag
add tagged-ports=sfp1,switch1-cpu vlan-id=600
add tagged-ports=sfp1,switch1-cpu vlan-id=630
/interface ethernet switch vlan
add ports=sfp1,switch1-cpu vlan-id=600
add ports=ether1,sfp1,switch1-cpu vlan-id=630
add ports=sfp1,switch1-cpu vlan-id=662
/ip address
add address=222.10.1.10/24 interface=V600-MAN
add address=222.10.50.10/24 interface=V630-OFFICE
add address=222.10.80.10/24 interface=V662-JAP
/ip dns
set servers=1.1.1.1
/ip route
add dst-address=0.0.0.0/0 gateway=222.10.1.5
/interface wireless cap
set enabled=yes caps-man-addresses=222.10.1.5 interfaces=wlan1
/interface wifi cap
set enabled=yes
/system identity
set name=EDGE
"""


def _site(tmp_path, edge: str = EDGE, *, cable: bool = True) -> SiteTopology:
    (tmp_path / "core.rsc").write_text(CORE, encoding="utf-8")
    (tmp_path / "edge.rsc").write_text(edge, encoding="utf-8")
    site = SiteTopology(name="t")
    site.devices = [
        Device(name="core", kind="mikrotik", config_file=str(tmp_path / "core.rsc")),
        Device(name="edge", kind="mikrotik", config_file=str(tmp_path / "edge.rsc")),
        Device(name="bare", kind="mikrotik"),
    ]
    if cable:
        site.links = [Link(a_device="edge", a_port="sfp1", b_device="core", b_port="sfp7", kind="vlan", vlans=["630"])]
    return site


def _find(findings: list[la.Finding], part: str) -> la.Finding:
    return next(f for f in findings if part in f.title)


def _rows(finding: la.Finding) -> list[str]:
    return [row for row, _n in finding.table]


def test_cable_ends_addresses_and_controller(tmp_path) -> None:
    site = _site(tmp_path)
    core, edge = site.devices[0], site.devices[1]
    found = cm.compare(core, edge, site)
    assert {f.area for f in found} == {"Config match: CORE ↔ EDGE"}
    assert found[0].severity == la.ERROR and found[-1].severity == la.INFO  # worst first

    # The cable is found whichever way round it was drawn.
    bad = _find(found, "VLANs that do not match on the cable CORE sfp7 ↔ EDGE sfp1")
    assert bad.severity == la.ERROR and _rows(bad) == [
        "VLAN 638: tagged on CORE sfp7, not carried on EDGE sfp1",
        "VLAN 662: tagged on CORE sfp7, untagged on EDGE sfp1",
    ]
    assert bad.notes[0].startswith("CORE sfp7 “to office”: VLANs: tagged 600, 630, 638, 662")
    assert any("with the VLAN tag" in n for n in bad.notes) and any("stops at this cable" in n for n in bad.notes)
    assert _rows(_find(found, "VLANs that match on the cable")) == [
        "VLAN 600: tagged on both ends", "VLAN 630: tagged on both ends"]

    addr = _find(found, "Addresses that do not line up")
    assert addr.severity == la.ERROR
    assert _rows(addr) == ["VLAN 662: 222.10.70.5/24 on CORE, 222.10.80.10/24 on EDGE "
                           "(different networks: they cannot reach each other there)"]
    assert "VLAN 600: 222.10.1.5 and 222.10.1.10 in 222.10.1.0/24" in _rows(_find(found, "Networks they share"))

    wifi = _find(found, "CAPsMAN) settings that do not match")
    assert wifi.severity == la.WARN and "new-style CAP" in _rows(wifi)[0]
    assert _rows(_find(found, "CAPsMAN) settings that match")) == [
        "EDGE finds its controller at 222.10.1.5 (CORE, V600-MAN)"]

    assert _rows(_find(found, "VLAN names that differ")) == ["VLAN 630: “V630-LAN” on CORE, “V630-OFFICE” on EDGE"]
    assert _rows(_find(found, "VLANs only one of them has")) == ["VLAN 638: only on CORE"]
    other = _rows(_find(found, "Other settings that differ"))
    assert "DNS servers: 8.8.8.8 on CORE, 1.1.1.1 on EDGE" in other
    assert _find(found, "EDGE routes through CORE").detail.startswith("Its default route is 222.10.1.5")


def test_controller_address_and_mask_and_duplicate(tmp_path) -> None:
    edge = (EDGE.replace("caps-man-addresses=222.10.1.5", "caps-man-addresses=222.10.1.99")
            .replace("222.10.80.10/24", "222.10.70.10/32")
            .replace("222.10.50.10/24", "222.10.50.5/24"))
    site = _site(tmp_path, edge)
    found = cm.compare(site.devices[0], site.devices[1], site)
    wifi = _find(found, "CAPsMAN) settings that do not match")
    assert wifi.severity == la.ERROR
    assert "EDGE looks for its controller at 222.10.1.99; CORE has none of those addresses" in _rows(wifi)
    rows = _rows(_find(found, "Addresses that do not line up"))
    assert "VLAN 662: 222.10.70.5/24 on CORE, 222.10.70.10/32 on EDGE (same network, different mask)" in rows
    assert "222.10.50.5 is set on both: CORE (V630-LAN) and EDGE (V630-OFFICE)" in rows


def test_no_cable_no_config_and_a_clean_pair(tmp_path) -> None:
    site = _site(tmp_path, cable=False)
    core, edge, bare = site.devices
    found = cm.compare(core, edge, site)
    assert _find(found, "No cable between them").severity == la.INFO
    assert not any("on the cable" in f.title for f in found)

    missing = cm.compare(core, bare, site)
    assert len(missing) == 1 and missing[0].severity == la.WARN
    assert missing[0].title == "No config to compare for bare" and "Load Config" in missing[0].detail

    # The same config on both ends of a cable: nothing to report but what was compared.
    (tmp_path / "twin.rsc").write_text(CORE.replace("name=CORE", "name=TWIN").replace(".5/24", ".6/24"),
                                       encoding="utf-8")
    twin = Device(name="twin", kind="mikrotik", config_file=str(tmp_path / "twin.rsc"))
    site.devices.append(twin)
    site.links = [Link(a_device="core", a_port="sfp7", b_device="twin", b_port="sfp7")]
    clean = cm.compare(core, twin, site)
    assert not [f for f in clean if f.severity != la.INFO]
    assert clean[0].title == "Nothing found that does not match" and len(clean[0].table) == len(cm.COMPARED)


def test_disabled_port_and_mtu_on_the_cable(tmp_path) -> None:
    edge = EDGE.replace("name=sfp1 mtu=1500", "name=sfp1 disabled=yes mtu=9000")
    site = _site(tmp_path, edge)
    phys = _find(cm.compare(site.devices[0], site.devices[1], site), "Port settings that differ")
    assert phys.severity == la.ERROR
    assert _rows(phys) == ["EDGE sfp1 is disabled", "MTU: 1500 on CORE sfp7, 9000 on EDGE sfp1"]


def test_notes_are_shown_where_log_lines_would_be() -> None:
    a = la.Analysis()
    f = la.Finding("Config match: A ↔ B", "x", la.ERROR, 2, notes=["first end", "second end"])
    assert la.lines_text(a, f) == "first end\nsecond end"  # no "… and 2 more": there are no log lines
