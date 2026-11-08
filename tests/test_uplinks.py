"""Uplinks (WANs, outbound tunnels) sit in the chassis title bar; cables leave upwards."""

from __future__ import annotations

from PySide6.QtCore import QPointF
from PySide6.QtWidgets import QApplication, QGraphicsScene

from pfsense_checker import port_vlans
from pfsense_checker import site_canvas as sc
from pfsense_checker.models import InterfaceInfo
from pfsense_checker.topology_site import Device, PortComponent


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_pfsense_uplink_rules() -> None:
    up = port_vlans.is_pfsense_uplink
    assert up(InterfaceInfo(name="wan", device="igb3"))
    assert up(InterfaceInfo(name="opt1", device="em0", ipaddr="dhcp"))
    assert up(InterfaceInfo(name="opt2", device="igb4", ipaddr="10.0.0.2", raw={"gateway": "GW2"}))
    assert up(InterfaceInfo(name="opt8", device="ovpnc1", kind="openvpn"))
    assert up(InterfaceInfo(name="opt9", device="igb5", descr="0_S1_P0_1G_F_WAN1_main"))
    assert up(InterfaceInfo(name="opt3", device="igb6", descr="3_EVL0_EXVPNAN"))
    assert not up(InterfaceInfo(name="lan", device="igb1", ipaddr="192.168.1.1", descr="LAN"))
    assert not up(InterfaceInfo(name="opt4", device="ovpns1", descr="road warriors"))  # a VPN server
    assert not up(InterfaceInfo(name="opt5", device="igb7", descr="SWANSEA office"))  # "wan" inside a word


def _router(**kw) -> Device:  # noqa: ANN003
    comps = [PortComponent(name=n) for n in ("ether2", "ether3", "wan", "wan2", "ether4")]
    return Device(name="edge", kind="ubiquiti", model="EdgeRouter 4", components=comps, **kw)


def test_uplinks_sit_centred_in_the_title_bar() -> None:
    _app()
    ch = sc.ChassisItem(_router(w=1200.0), snap=False)
    w = ch.boundingRect().width()
    left, right = ch._header_reserve()  # noqa: SLF001
    ups = [ch.port_items[n] for n in ("wan", "wan2")]
    for item in ups:
        assert item.pos().y() + item.h <= sc.HEADER_H - 2  # inside the title bar
        assert left <= item.pos().x() and item.pos().x() + item.w <= w - right
    span = ch._uplink_span  # noqa: SLF001
    assert abs((span[0] + span[1]) / 2 - w / 2) < 1  # centred when there is room
    for name in ("ether2", "ether3", "ether4"):
        assert ch.port_items[name].pos().y() >= sc.HEADER_H  # the rest stay below
    assert ch.is_uplink("WAN2") and not ch.is_uplink("ether2")


def test_narrow_box_grows_to_fit_name_uplinks_and_logo() -> None:
    _app()
    ch = sc.ChassisItem(_router(w=200.0), snap=False)
    left, right = ch._header_reserve()  # noqa: SLF001
    w = ch.boundingRect().width()
    assert w >= left + right + 2 * sc.NIC_W
    span = ch._uplink_span  # noqa: SLF001
    assert span[0] >= left - 0.5 and span[1] <= w - right + 0.5


def test_cable_leaves_an_uplink_from_the_top() -> None:
    _app()
    scene = QGraphicsScene()
    edge = sc.ChassisItem(_router(), snap=False)
    edge.setPos(0, 400)
    isp = sc.ChassisItem(Device(name="isp", kind="router", components=[PortComponent(name="eth0")]), snap=False)
    isp.setPos(0, 0)
    scene.addItem(edge)
    scene.addItem(isp)
    link = sc.LinkItem(edge, isp, a_port="wan", b_port="eth0")
    start = link.path().elementAt(0)
    top = edge.port_items["wan"].anchor_scene("top")
    assert QPointF(start.x, start.y) == top
    # The other way round (ISP below the edge router): the cable climbs out
    # of the edge box first, then goes round its side.
    isp.setPos(0, 800)
    link.rebuild()
    pts = [link.path().elementAt(i) for i in range(link.path().elementCount())]
    assert pts[1].y < edge.sceneBoundingRect().top()
    side = pts[2].x
    box = edge.sceneBoundingRect()
    assert side < box.left() or side > box.right()


def test_any_port_can_be_set_as_uplink_by_hand() -> None:
    _app()
    comps = [PortComponent(name=n, media="ether") for n in ("ether1", "ether2", "sfp1")]
    dev = Device(name="crs", kind="mikrotik", model="CRS109-8G-1S-2HnD", role="access-switch", components=comps)
    ch = sc.ChassisItem(dev, snap=False)
    edits = []
    ch.edit_finished.connect(edits.append)
    assert not ch.is_uplink("sfp1") and ch.port_items["sfp1"].pos().y() >= sc.HEADER_H
    ch.set_uplink("sfp1", True)
    assert ch.is_uplink("sfp1") and dev.uplink_overrides == {"sfp1": True}
    item = ch.port_items["sfp1"]
    assert item.pos().y() + item.h <= sc.HEADER_H - 2  # moved into the title bar
    assert edits == ["crs"]  # saved like any other layout change
    # Survives a save / load.
    again = Device.from_dict(dev.to_dict())
    assert again.uplink_overrides == {"sfp1": True}
    ch.set_uplink("sfp1", False)  # back to the config's view: no override kept
    assert dev.uplink_overrides == {} and ch.port_items["sfp1"].pos().y() >= sc.HEADER_H
    # An automatic uplink can be turned off too.
    ch.set_uplink("ether1", True)
    wan_dev = _router()
    wan_ch = sc.ChassisItem(wan_dev, snap=False)
    wan_ch.set_uplink("wan", False)
    assert wan_dev.uplink_overrides == {"wan": False} and wan_ch.port_items["wan"].pos().y() >= sc.HEADER_H
