"""Add VLAN to a port: a planned stripe on the map and the commands to make it real."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pfsense_checker import port_vlans as pv  # noqa: E402
from pfsense_checker import vlan_plan as vp  # noqa: E402
from pfsense_checker.checker import check_file  # noqa: E402
from pfsense_checker.topology_site import Device, PortComponent, SiteTopology  # noqa: E402

CHIP_SWITCH = """# model = CRS109-8G-1S-2HnD
/interface bridge
add name=BR vlan-filtering=no
/interface bridge port
add bridge=BR interface=ether3
add bridge=BR interface=sfp1
/interface ethernet switch vlan
add ports=sfp1,ether3,switch1-cpu vlan-id=630
/interface ethernet switch egress-vlan-tag
add tagged-ports=sfp1,switch1-cpu vlan-id=630
/interface ethernet switch
set 0 drop-if-invalid-or-src-port-not-member-of-vlan-on-ports=ether3,sfp1
"""

FILTERING_SWITCH = """# model = CRS326-24G-2S+
/interface bridge
add name=BR vlan-filtering=yes
/interface bridge port
add bridge=BR interface=ether3 pvid=630
add bridge=BR interface=sfp1
/interface bridge vlan
add bridge=BR tagged=BR,sfp1 untagged=ether3 vlan-ids=630
"""


def _dev(name: str = "sw") -> Device:
    return Device(name=name, kind="mikrotik")


def test_plan_rules() -> None:
    dev = _dev()
    have = pv.PortVlans(untagged=["630"], tagged=["600"])
    assert "number from 1 to 4094" in vp.add(dev, "sfp1", "5000", True)
    assert "already on sfp1" in vp.add(dev, "sfp1", "600", True, have)
    assert vp.add(dev, "sfp1", "662", True, have) == ""
    assert "already planned" in vp.add(dev, "SFP1", "662", True, have)
    assert "only have one" in vp.add(dev, "sfp1", "710", False, have)  # already has access VLAN 630
    assert vp.planned_on(dev, "sfp1") == [("662", True)]
    merged, planned = vp.merged(have, vp.plan_of(dev)["sfp1"])
    assert merged.tagged == ["600", "662"] and planned == {"662"} and have.tagged == ["600"]  # config untouched
    assert Device.from_dict(dev.to_dict()).planned_vlans == {"sfp1": {"tagged": ["662"], "untagged": []}}
    assert vp.remove(dev, "sfp1", "662") and vp.plan_of(dev) == {}


def test_commands_for_a_switch_chip_switch(tmp_path) -> None:
    path = tmp_path / "sw.rsc"
    path.write_text(CHIP_SWITCH, encoding="utf-8")
    result = check_file(path)
    dev = _dev()
    vp.add(dev, "sfp1", "662", True)  # a VLAN new to this switch, tagged on the uplink
    vp.add(dev, "ether3", "630", True)  # an existing VLAN, tagged on another port
    text = "\n".join(vp.commands(dev, result))
    assert "/interface ethernet switch vlan add vlan-id=662 ports=sfp1" in text
    assert "/interface ethernet switch egress-vlan-tag add vlan-id=662 tagged-ports=sfp1" in text
    assert "VLAN 662 is new on this switch" in text
    assert "/interface ethernet switch egress-vlan-tag set [find vlan-id=630] tagged-ports=sfp1,switch1-cpu,ether3" in text
    assert "bridge vlan" not in text  # the bridge table is not used on this switch
    assert "NetCheck has not changed the device" in text


def test_commands_for_a_vlan_filtering_bridge(tmp_path) -> None:
    path = tmp_path / "sw.rsc"
    path.write_text(FILTERING_SWITCH, encoding="utf-8")
    result = check_file(path)
    dev = _dev()
    vp.add(dev, "sfp1", "710", True)
    vp.add(dev, "ether4", "630", False)
    text = "\n".join(vp.commands(dev, result))
    assert "/interface bridge vlan add bridge=BR vlan-ids=710 tagged=sfp1" in text
    assert "# ether4 is not in a bridge" in text  # ether4 was never added to BR
    dev2 = _dev()
    vp.add(dev2, "sfp1", "630", False)
    text2 = "\n".join(vp.commands(dev2, result))
    assert "/interface bridge vlan set [find bridge=BR vlan-ids=630] untagged=ether3,sfp1" in text2
    assert "/interface bridge port set [find interface=sfp1] pvid=630" in text2


def test_no_config_says_so() -> None:
    dev = Device(name="x", kind="switch")
    vp.add(dev, "g1", "30", True)
    assert "no config is loaded" in "\n".join(vp.commands(dev, None))


def test_canvas_draws_the_planned_stripe_and_saves(monkeypatch) -> None:
    from PySide6.QtWidgets import QApplication

    from pfsense_checker import site_canvas as sc

    QApplication.instance() or QApplication([])
    trunk = {"sfp1": pv.PortVlans(tagged=["600", "630"])}
    monkeypatch.setattr(pv, "for_device", lambda d: pv.DeviceVlans(ports=trunk, names={"630": "LAN"}))
    site = SiteTopology(devices=[Device(name="sw", kind="mikrotik", model="CRS109-8G-1S-2HnD", role="access-switch",
                                        components=[PortComponent(name="sfp1", media="ether")])])
    view = sc.SiteTopologyView()
    view.render_site(site)
    saved = []
    view.positions_changed.connect(lambda: saved.append(1))
    assert view.add_vlan_to_port(view._chassis["sw"], "sfp1", vid="662", tagged=True) == ""  # noqa: SLF001
    item = view._chassis["sw"].port_items["sfp1"]  # noqa: SLF001
    assert item.vlans.vlans == ["600", "630", "662"] and item.planned == {"662"} and saved
    assert "PLANNED" in item.vlan_tip("662") and "PLANNED" not in item.vlan_tip("630")
    assert "662" in view._palette  # noqa: SLF001 - coloured like any VLAN
    assert view.known_vlans()["630"] == "LAN" and "662" in view.known_vlans()
    assert "already on sfp1" in view.add_vlan_to_port(view._chassis["sw"], "sfp1", vid="630")  # noqa: SLF001
    assert "VLAN 662" in view.planned_commands_text(site.devices[0])
    assert view.remove_planned_vlan(view._chassis["sw"], "sfp1", "662")  # noqa: SLF001
    assert view._chassis["sw"].port_items["sfp1"].planned == set()  # noqa: SLF001


def test_add_vlan_dialog(monkeypatch) -> None:
    from PySide6.QtWidgets import QApplication

    from pfsense_checker.add_vlan_dialog import AddVlanDialog

    QApplication.instance() or QApplication([])
    dev = _dev()
    have = pv.PortVlans(tagged=["600"])
    dlg = AddVlanDialog(dev, "sfp1", have, {"600": "MAN", "630": "LAN", "710": "IOT"})
    assert [dlg.vlan.itemData(i) for i in range(dlg.vlan.count())] == ["630", "710"]  # 600 is already there
    dlg.vlan.setEditText("abc")
    dlg._accept()  # noqa: SLF001
    assert "1 to 4094" in dlg.error.text() and vp.plan_of(dev) == {}
    dlg.vlan.setCurrentIndex(1)
    dlg.untagged.setChecked(True)
    dlg._accept()  # noqa: SLF001
    assert vp.planned_on(dev, "sfp1") == [("710", False)]


def test_switch_ports_paint_the_planned_overlay(monkeypatch) -> None:
    """Front-panel (switch) ports return early in paint(): the overlay must still be drawn."""
    from PySide6.QtGui import QImage, QPainter
    from PySide6.QtWidgets import QApplication, QStyleOptionGraphicsItem

    from pfsense_checker import site_canvas as sc

    QApplication.instance() or QApplication([])
    for faceplate in (True, False):
        item = sc.PortItem("sw", "sfp1", faceplate=faceplate, sfp=faceplate, width=60,
                           vlans=pv.PortVlans(tagged=["600", "662"]), planned={"662"})
        drawn = []
        monkeypatch.setattr(item, "_paint_planned", lambda painter: drawn.append(1))
        img = QImage(80, 40, QImage.Format.Format_ARGB32)
        painter = QPainter(img)
        item.paint(painter, QStyleOptionGraphicsItem())
        painter.end()
        assert drawn == [1], faceplate
