"""Per-VLAN cables: click a stripe to pick it, drag from it, a cable for that VLAN only."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QPointF, Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from pfsense_checker import port_vlans as pv  # noqa: E402
from pfsense_checker import site_canvas as sc  # noqa: E402
from pfsense_checker.topology_site import Device, Link, PortComponent, SiteTopology  # noqa: E402

TRUNK = {"opt5": pv.PortVlans(tagged=["630", "662", "710"]), "sfp1": pv.PortVlans(tagged=["630", "710"])}


def _view(monkeypatch, links=None) -> sc.SiteTopologyView:  # noqa: ANN001
    QApplication.instance() or QApplication([])
    monkeypatch.setattr(pv, "for_device", lambda d: pv.DeviceVlans(ports=TRUNK))
    site = SiteTopology(devices=[
        Device(name="fw", kind="pfsense", x=0, y=0, components=[PortComponent(name="OPT5")]),
        Device(name="sw", kind="mikrotik", model="CRS109-8G-1S-2HnD", role="access-switch", x=0, y=300,
               components=[PortComponent(name="sfp1", media="ether")]),
    ], links=list(links or []))
    view = sc.SiteTopologyView()
    view.render_site(site)
    return view


class _Press:
    def __init__(self, pos: QPointF, scene: QPointF, shift: bool = False) -> None:
        self._pos, self._scene, self._shift = pos, scene, shift
        self.accepted = False

    def button(self):  # noqa: ANN201
        return Qt.MouseButton.LeftButton

    def pos(self) -> QPointF:
        return self._pos

    def scenePos(self) -> QPointF:  # noqa: N802
        return self._scene

    def modifiers(self):  # noqa: ANN201
        return Qt.KeyboardModifier.ShiftModifier if self._shift else Qt.KeyboardModifier.NoModifier

    def accept(self) -> None:
        self.accepted = True


def _press(port: sc.PortItem, vid: str, shift: bool = False) -> None:
    centre = port.stripe_rect(vid).center()
    port.mousePressEvent(_Press(centre, port.mapToScene(centre), shift))


def test_first_click_picks_the_stripe_second_drags_it(monkeypatch) -> None:
    view = _view(monkeypatch)
    fw = view._chassis["fw"].port_items["OPT5"]  # noqa: SLF001
    sw = view._chassis["sw"].port_items["sfp1"]  # noqa: SLF001
    assert fw.vid_at(fw.stripe_rect("662").center()) == "662"
    _press(fw, "710")
    assert fw.selected_vid == "710" and view._wire_from is None  # noqa: SLF001 - picked, not dragging
    _press(fw, "710")
    assert view._wire_from == ("fw", "OPT5") and view._wire_vid == "710"  # noqa: SLF001
    view._complete_port_link("sw", "sfp1")  # noqa: SLF001 - dropped on the switch port
    [link] = view._site.links  # noqa: SLF001
    assert (link.kind, link.vlans) == (sc.VLAN_LINK_KIND, ["710"])
    assert fw.selected_vid == "" or view._chassis["fw"].port_items["OPT5"].selected_vid == ""  # noqa: SLF001
    # The cable runs from the 710 stripe on one port to the 710 stripe on the other.
    item = view._links[0]  # noqa: SLF001
    fw2 = view._chassis["fw"].port_items["OPT5"]  # noqa: SLF001
    sw2 = view._chassis["sw"].port_items["sfp1"]  # noqa: SLF001
    path = item.path()
    start, end = path.elementAt(0), path.elementAt(path.elementCount() - 1)
    assert abs(start.x - fw2.mapToScene(fw2.stripe_rect("710").center()).x()) < 0.5
    assert abs(end.x - sw2.mapToScene(sw2.stripe_rect("710").center()).x()) < 0.5
    assert item.pen().color().name() == pv.vlan_color("710", view._palette).lower()  # noqa: SLF001
    del sw


def test_each_vlan_gets_its_own_cable_between_the_same_ports(monkeypatch) -> None:
    v710 = Link(a_device="fw", a_port="OPT5", b_device="sw", b_port="sfp1", kind=sc.VLAN_LINK_KIND, vlans=["710"])
    view = _view(monkeypatch, [v710])
    assert view._link_exists("fw", "OPT5", "sw", "sfp1", "710")  # noqa: SLF001
    assert not view._link_exists("fw", "OPT5", "sw", "sfp1", "630")  # noqa: SLF001
    assert not view._link_exists("fw", "OPT5", "sw", "sfp1")  # noqa: SLF001 - a whole-port cable is separate


def test_shift_drag_links_the_whole_port(monkeypatch) -> None:
    view = _view(monkeypatch)
    fw = view._chassis["fw"].port_items["OPT5"]  # noqa: SLF001
    _press(fw, "662", shift=True)
    assert view._wire_from == ("fw", "OPT5") and view._wire_vid == ""  # noqa: SLF001


def test_only_one_stripe_picked_at_a_time(monkeypatch) -> None:
    view = _view(monkeypatch)
    fw = view._chassis["fw"].port_items["OPT5"]  # noqa: SLF001
    sw = view._chassis["sw"].port_items["sfp1"]  # noqa: SLF001
    _press(fw, "630")
    _press(sw, "710")
    assert fw.selected_vid == "" and sw.selected_vid == "710"
    view.clear_port_vlans()
    assert sw.selected_vid == ""


def test_link_vid_only_for_vlan_cables() -> None:
    assert sc.link_vid(Link(a_device="a", b_device="b", kind="vlan", vlans=["30"])) == "30"
    assert sc.link_vid(Link(a_device="a", b_device="b", kind="trunk", vlans=["30"])) == ""
    assert sc.link_vid(Link(a_device="a", b_device="b", kind="vlan", vlans=["30", "40"])) == ""


def test_hovering_a_stripe_names_its_vlan(monkeypatch) -> None:
    view = _view(monkeypatch)
    fw = view._chassis["fw"].port_items["OPT5"]  # noqa: SLF001
    fw._vlan_names = {"662": "IV7_S2_VL662_JAP"}  # noqa: SLF001

    from PySide6.QtCore import QEvent
    from PySide6.QtWidgets import QGraphicsSceneHoverEvent

    def _Hover(pos):  # noqa: ANN001, ANN202, N802
        ev = QGraphicsSceneHoverEvent(QEvent.Type.GraphicsSceneHoverMove)
        ev.setPos(pos)
        return ev

    fw.hoverMoveEvent(_Hover(fw.stripe_rect("662").center()))
    assert fw.toolTip().startswith("VLAN 662 — IV7_S2_VL662_JAP · tagged")
    fw.hoverMoveEvent(_Hover(fw.stripe_rect("710").center()))
    assert fw.toolTip().startswith("VLAN 710 · tagged")
    fw.hoverLeaveEvent(_Hover(fw.stripe_rect("710").center()))
    assert not fw.toolTip().startswith("VLAN")


def test_vlan_cable_on_a_port_without_that_vlan_asks_first(monkeypatch) -> None:
    """Dropped on a port that carries other VLANs but not this one: no silent cable."""
    QApplication.instance() or QApplication([])
    ports = {"opt3": pv.PortVlans(tagged=["710", "800"]), "opt5": pv.PortVlans(tagged=["630", "710"]),
             "sfp1": pv.PortVlans(tagged=["630", "710"])}
    monkeypatch.setattr(pv, "for_device", lambda d: pv.DeviceVlans(ports=ports))
    site = SiteTopology(devices=[
        Device(name="fw", kind="pfsense", x=0, y=0,
               components=[PortComponent(name="OPT3"), PortComponent(name="OPT5"), PortComponent(name="LAN")]),
        Device(name="sw", kind="mikrotik", model="CRS109-8G-1S-2HnD", role="access-switch", x=0, y=300,
               components=[PortComponent(name="sfp1", media="ether")]),
    ])
    view = sc.SiteTopologyView()
    view.render_site(site)
    asked: list[tuple] = []

    def start() -> None:
        sw = view._chassis["sw"].port_items["sfp1"]  # noqa: SLF001
        view.begin_port_link(sw, sw.mapToScene(sw.stripe_rect("630").center()), vid="630")

    monkeypatch.setattr(view, "confirm_add_missing_vlan", lambda d, p, v, have: asked.append((d, p, v, have)) or False)
    start()
    view._complete_port_link("fw", "OPT3")  # noqa: SLF001 - OPT3 has 710 and 800, not 630
    assert asked == [("fw", "OPT3", "630", ["710", "800"])] and site.links == []  # refused: no cable
    start()
    view._complete_port_link("fw", "OPT5")  # noqa: SLF001 - carries 630: no question
    assert len(asked) == 1 and [(ln.b_port, ln.vlans) for ln in site.links] == [("OPT5", ["630"])]
    start()
    view._complete_port_link("fw", "LAN")  # noqa: SLF001 - a plain port takes any cable
    assert len(asked) == 1 and len(site.links) == 2
    monkeypatch.setattr(view, "confirm_add_missing_vlan", lambda d, p, v, have: True)
    start()
    view._complete_port_link("fw", "OPT3")  # noqa: SLF001 - agreed: planned on OPT3, then connected
    assert site.devices[0].planned_vlans == {"opt3": {"tagged": ["630"], "untagged": []}}
    assert ("OPT3", ["630"]) in [(ln.b_port, ln.vlans) for ln in site.links]
    assert "630" in view._chassis["fw"].port_items["OPT3"].planned  # noqa: SLF001
