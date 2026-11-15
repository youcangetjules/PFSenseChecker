"""Re-arrange cable: move a cable's long run to the lane with the fewest crossings."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QPointF  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from pfsense_checker import site_canvas as sc  # noqa: E402
from pfsense_checker.topology_site import Device, Link, PortComponent, SiteTopology  # noqa: E402


def test_count_crossings() -> None:
    pts = [QPointF(0, 0), QPointF(0, 100), QPointF(300, 100), QPointF(300, 200)]
    assert sc.count_crossings(pts, [[QPointF(150, 0), QPointF(150, 300)]]) == 1
    assert sc.count_crossings(pts, [[QPointF(150, 0), QPointF(150, 90)]]) == 0  # stops short
    assert sc.count_crossings(pts, [[QPointF(-50, 50), QPointF(50, 50)]]) == 1  # crosses the first leg


def _site() -> SiteTopology:
    P = lambda *n: [PortComponent(name=x) for x in n]  # noqa: E731
    # Two cables from one box to one box below, ports in the same order top and
    # bottom: there is always a lane where they do not cross.
    return SiteTopology(devices=[
        Device(name="fw", kind="router", x=0, y=0, components=P("p1", "p2", "p3")),
        Device(name="sw", kind="router", x=-120, y=420, components=P("q1", "q2", "q3")),
    ], links=[
        Link(a_device="fw", a_port="p1", b_device="sw", b_port="q1"),
        Link(a_device="fw", a_port="p3", b_device="sw", b_port="q2"),
    ])


def test_rearrange_cable_clears_a_crossing_and_saves_the_lane(monkeypatch) -> None:
    QApplication.instance() or QApplication([])
    from pfsense_checker import port_vlans as pv

    monkeypatch.setattr(pv, "for_device", lambda d: pv.DeviceVlans())
    site = _site()
    view = sc.SiteTopologyView()
    view.render_site(site)
    links = view._links  # noqa: SLF001
    # Force a crossing: the second cable's run below the first one's turn.
    links[0].lane_offset, links[1].lane_offset = 200.0, 40.0
    for li in links:
        li.rebuild()
    view.update_hops()
    others = lambda i: [li.points for j, li in enumerate(links) if j != i]  # noqa: E731
    assert sc.count_crossings(links[0].points, others(0)) >= 1
    saved = []
    view.positions_changed.connect(lambda: saved.append(1))
    msg = view.rearrange_cable(links[0])
    assert "re-arranged" in msg and saved
    assert sc.count_crossings(links[0].points, others(0)) == 0
    assert site.links[0].lane == links[0].lane_offset  # remembered on the link
    assert Link.from_dict(site.links[0].to_dict()).lane == site.links[0].lane  # and saved with the topology
    assert "already" in view.rearrange_cable(links[0])  # nothing better left


def test_rearrange_all_and_locked(monkeypatch) -> None:
    QApplication.instance() or QApplication([])
    from pfsense_checker import port_vlans as pv

    monkeypatch.setattr(pv, "for_device", lambda d: pv.DeviceVlans())
    site = _site()
    site.links[0].lane, site.links[1].lane = 200.0, 40.0  # a saved, crossing layout
    view = sc.SiteTopologyView()
    view.render_site(site)
    assert view._links[0].lane_offset == 200.0  # noqa: SLF001 - saved lanes come back
    msg = view.rearrange_all_cables()
    assert msg.endswith("→ 0.") and "Re-arranged 2 cable(s)" in msg
    view.set_locked(True)
    assert "locked" in view.rearrange_cable(view._links[0])  # noqa: SLF001
