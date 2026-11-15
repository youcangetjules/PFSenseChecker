"""A bridge of VLAN interfaces joins one VLAN segment of each port, drawn as lines to it."""

from __future__ import annotations

from PySide6.QtWidgets import QApplication

from pfsense_checker import port_vlans as pv
from pfsense_checker import site_canvas as sc
from pfsense_checker.topology_site import Device, PortComponent


def test_bridge_lines_end_on_the_vlan_segment(monkeypatch) -> None:
    QApplication.instance() or QApplication([])
    info = pv.DeviceVlans(
        ports={"opt3": pv.PortVlans(tagged=["710", "800"]), "opt5": pv.PortVlans(tagged=["630", "710"])},
        bridges={"bridge0 (VLAN 710)": []},
        segments={"bridge0 (VLAN 710)": [("opt3", "710"), ("opt5", "710")]},
    )
    monkeypatch.setattr(pv, "for_device", lambda _d: info)
    comps = [PortComponent(name=n) for n in ("OPT7", "OPT3", "LAN", "OPT5")]
    ch = sc.ChassisItem(Device(name="fw", kind="pfsense", components=comps), snap=False)
    a, b = ch.port_items["OPT3"], ch.port_items["OPT5"]
    # Segment ports sit together, ahead of the rest, under the bridge chip.
    order = sorted(ch.port_items, key=lambda n: ch.port_items[n].pos().x())
    assert set(order[:2]) == {"OPT3", "OPT5"}
    assert not ch._bridge_rects  # noqa: SLF001 - no box round whole ports
    [(bridge, chip, ends)] = ch.segment_links()
    assert bridge == "bridge0 (VLAN 710)"
    assert chip.bottom() <= min(e.y() for e in ends) and chip.top() >= sc.HEADER_H
    # Each line ends on the 710 stripe: first of two on OPT3, second of two on OPT5.
    sa, sb = a.stripe_rect("710").translated(a.pos()), b.stripe_rect("710").translated(b.pos())
    assert abs(ends[0].x() - sa.center().x()) < 0.5 and sa.right() <= a.pos().x() + a.w / 2 + 1
    assert abs(ends[1].x() - sb.center().x()) < 0.5 and sb.left() >= b.pos().x() + b.w / 2 - 1
    assert a.segments == [("bridge0 (VLAN 710)", "710")]
    assert "VLAN 710 segment in bridge bridge0 (VLAN 710)" in a.toolTip()
    assert not ch.is_uplink("OPT3")


def test_one_wire_per_stripe_and_the_chip_says_only() -> None:
    from PySide6.QtCore import QPointF, QRectF

    assert sc.segment_bridge_text("bridge0 (VLAN 710)") == "bridge bridge0 — only VLAN 710"
    assert sc.segment_bridge_text("BR") == "bridge BR"
    chip = QRectF(200, 50, 160, 14)
    left, under, right = QPointF(60, 71), QPointF(250, 71), QPointF(700, 71)
    wires = sc.segment_wires(chip, [left, under, right])
    assert [len(w) for w in wires] == [3, 2, 3]
    assert wires[0][0] == QPointF(200, 57) and wires[0][1] == QPointF(60, 57) and wires[0][2] == left
    assert wires[1] == [QPointF(250, 64), under]  # straight down from the chip
    assert wires[2][0] == QPointF(360, 57) and wires[2][-1] == right
    # No wire is a bar across to another stripe: each one ends on its own stripe only.
    assert {(w[-1].x(), w[-1].y()) for w in wires} == {(60, 71), (250, 71), (700, 71)}
