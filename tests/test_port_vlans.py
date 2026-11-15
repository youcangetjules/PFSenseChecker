"""Ports coloured by VLAN, trunks striped, bridges around their ports."""

from __future__ import annotations

from pfsense_checker import port_vlans as pv
from pfsense_checker.checker import check_file

CHIP = """\
# 2026-11-07 by RouterOS 7.22.3
# model = CRS109-8G-1S-2HnD
/interface bridge
add name=BR vlan-filtering=no
/interface vlan
add interface=BR name=V630-LAN vlan-id=630
add interface=BR name=V710-IOT vlan-id=710
/interface bridge port
add bridge=BR interface=ether1 pvid=630
add bridge=BR interface=ether2 pvid=710
add bridge=BR interface=sfp1 frame-types=admit-only-vlan-tagged
add bridge=BR interface=ether3 disabled=yes
/interface ethernet switch egress-vlan-tag
add tagged-ports=sfp1,switch1-cpu vlan-id=630
add tagged-ports=sfp1,switch1-cpu vlan-id=710
/interface ethernet switch vlan
add ports=ether1,sfp1,switch1-cpu vlan-id=630
add ports=ether2,sfp1,switch1-cpu vlan-id=710
"""

BRIDGE_TABLE = """\
# 2026-11-07 by RouterOS 7.22.3
# model = CRS328-24P-4S+
/interface bridge
add name=BR vlan-filtering=yes
/interface bridge port
add bridge=BR interface=ether1 pvid=630
add bridge=BR interface=ether2 pvid=630
add bridge=BR interface=sfp1 pvid=600
/interface bridge vlan
add bridge=BR tagged=BR,sfp1 untagged=ether1 vlan-ids=630
add bridge=BR tagged=BR,sfp1 untagged=ether2 vlan-ids=710
add bridge=BR tagged=BR,sfp1 vlan-ids=600
"""


def _load(tmp_path, name: str, text: str):  # noqa: ANN001, ANN202
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return pv.from_result(check_file(p))


def test_switch_chip_access_and_trunk(tmp_path) -> None:
    info = _load(tmp_path, "chip.rsc", CHIP)
    assert info.port("ether1").untagged == ["630"] and not info.port("ether1").is_trunk
    assert info.port("ether2").untagged == ["710"]
    trunk = info.port("sfp1")
    assert trunk.is_trunk and trunk.tagged == ["630", "710"]
    assert info.port("switch1-cpu") is None  # the CPU port is not a front-panel port
    assert {"v630-lan", "v710-iot"} <= info.vlan_ifaces and "br" in info.hidden
    assert info.bridge_of("ether1") == "BR" and info.bridge_of("ether3") == ""  # disabled member
    assert info.names["630"] == "V630-LAN"


def test_bridge_table_and_pvid_mismatch(tmp_path) -> None:
    info = _load(tmp_path, "br.rsc", BRIDGE_TABLE)
    assert info.port("ether1").untagged == ["630"] and not info.port("ether1").notes
    e2 = info.port("ether2")
    assert e2.untagged == ["710"] and any("PVID 630" in n for n in e2.notes)
    sfp = info.port("sfp1")
    assert sfp.is_trunk and sfp.untagged == []  # PVID 600 is one of its tagged VLANs
    assert sorted(sfp.tagged) == ["600", "630", "710"]


def test_pfsense_nic_trunks_and_vlan_bridge(tmp_path) -> None:
    xml = tmp_path / "fw.xml"
    xml.write_text("""<?xml version="1.0"?><pfsense><version>24.6</version><system><hostname>fw</hostname></system>
<interfaces>
 <lan><if>igb1</if><enable/><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
 <opt1><if>igb1.30</if><enable/><ipaddr>10.0.30.1</ipaddr><subnet>24</subnet></opt1>
 <opt2><if>igb2.30</if><enable/></opt2>
 <opt3><if>igb2</if><enable/></opt3>
 <opt4><if>bridge0</if><enable/></opt4>
</interfaces>
<vlans>
 <vlan><if>igb1</if><tag>30</tag><vlanif>igb1.30</vlanif><descr>IOT</descr></vlan>
 <vlan><if>igb2</if><tag>30</tag><vlanif>igb2.30</vlanif><descr>IOT</descr></vlan>
</vlans>
<bridges><bridged><bridgeif>bridge0</bridgeif><members>opt1,opt2</members></bridged></bridges>
</pfsense>""", encoding="utf-8")
    info = pv.from_result(check_file(xml))
    assert info.port("lan").tagged == ["30"]
    assert "opt1" in info.vlan_ifaces and "opt4" in info.hidden
    # The bridge joins the VLAN 30 segment of each NIC, not the whole NIC.
    assert info.bridges == {"bridge0 (VLAN 30)": []}
    assert info.segments == {"bridge0 (VLAN 30)": [("lan", "30"), ("opt3", "30")]}
    assert info.bridge_of("lan") == "" and info.bridge_group("lan") == "bridge0 (VLAN 30)"
    assert info.segments_of("OPT3") == [("bridge0 (VLAN 30)", "30")]


def test_palette_distinct_in_vlan_order() -> None:
    pal = pv.assign_palette(["710", "600", "630", "638"])
    assert list(pal) == ["600", "630", "638", "710"]
    assert len(set(pal.values())) == 4
    assert pv.vlan_color("630", pal) == pal["630"]
    assert pv.vlan_color("999").startswith("#")


def test_canvas_hides_vlans_and_bridges_colours_ports_and_shows_legend(tmp_path, monkeypatch) -> None:
    from PySide6.QtWidgets import QApplication

    from pfsense_checker import site_canvas as sc
    from pfsense_checker.topology_site import Device, PortComponent, SiteTopology

    QApplication.instance() or QApplication([])
    cfg = tmp_path / "chip.rsc"
    cfg.write_text(CHIP, encoding="utf-8")
    dev = Device(name="sw", kind="mikrotik", model="CRS109-8G-1S-2HnD", config_file=str(cfg),
                 components=[PortComponent(n) for n in ("ether1", "ether2", "ether3", "sfp1", "BR",
                                                         "V630-LAN", "V710-IOT")])
    site = SiteTopology(name="t")
    site.devices.append(dev)
    view = sc.SiteTopologyView()
    view.resize(1000, 400)
    view.render_site(site)
    view.show()
    QApplication.processEvents()
    ch = view._chassis["sw"]  # noqa: SLF001
    assert set(ch.port_items) == {"ether1", "ether2", "ether3", "sfp1"}  # no VLANs, no bridge cell
    assert len(ch.port_items["sfp1"].vlan_colors) == 2  # trunk: one stripe per VLAN
    assert ch.port_items["ether1"].vlan_colors == [view._palette["630"]]  # noqa: SLF001
    tip = ch.port_items["sfp1"].toolTip()
    assert "Trunk" in tip and "630 (V630-LAN)" in tip and "In bridge BR" in tip
    assert "Access port" in ch.port_items["ether1"].toolTip()
    bridges = ch._bridge_rects  # noqa: SLF001
    assert bridges and all(b == "BR" for b, _ in bridges)
    assert view.vlan_legend.isVisible() and "630" in view.vlan_legend.label.text()
    view.close()


def test_cut_off_inventory_name_matches_the_config_name() -> None:
    info = pv.DeviceVlans(bridges={"BR": ["fujitsu pc (vl630)", "ether2", "fujitsu laptop"]},
                          ports={"fujitsu pc (vl630)": pv.PortVlans(untagged=["630"])})
    info.bridges["BR"].remove("fujitsu laptop")
    assert info.key("Fujitsu") == "fujitsu pc (vl630)"  # older inventory cut it at the space
    assert info.bridge_of("Fujitsu") == "BR" and info.port("Fujitsu").untagged == ["630"]
    info.bridges["BR"].append("fujitsu laptop")
    assert info.key("Fujitsu") == "fujitsu"  # two candidates: no guessing


def test_mikrotik_port_comments_are_kept(tmp_path) -> None:
    rsc = tmp_path / "sw.rsc"
    rsc.write_text('/interface ethernet\nset [ find default-name=ether3 ] comment="Mavenir E72 (VL630)"\n'
                   'set [ find default-name=ether1 ] name="Fujitsu PC (VL630)" comment="desk"\n', encoding="utf-8")
    info = pv.from_result(check_file(rsc))
    assert info.comments["ether3"] == "Mavenir E72 (VL630)"
    assert info.comments["fujitsu pc (vl630)"] == "desk" and info.comments["ether1"] == "desk"
