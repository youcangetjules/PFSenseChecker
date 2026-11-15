"""Crossing cables: a horizontal run hops over a vertical run of another cable."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QPointF  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from pfsense_checker import site_canvas as sc  # noqa: E402


class _Cable:
    def __init__(self, *pts: tuple[float, float]) -> None:
        self.points = [QPointF(*p) for p in pts]

    def segments(self):  # noqa: ANN201
        return [(i, a, b) for i, (a, b) in enumerate(zip(self.points, self.points[1:]))]


def test_find_hops_on_horizontal_runs_only() -> None:
    across = _Cable((0, 100), (0, 150), (300, 150), (300, 200))  # horizontal run at y=150
    down = _Cable((120, 0), (120, 400))  # vertical, crosses it
    touching = _Cable((300, 150), (300, 400))  # starts at the other cable's corner: no hop
    hops = sc.find_hops([across, down, touching])
    assert hops == {0: {1: [120.0]}}


def test_close_crossings_merge_into_one_hop() -> None:
    across = _Cable((0, 50), (400, 50))
    a = _Cable((100, 0), (100, 100))
    b = _Cable((105, 0), (105, 100))  # 5 px away: one hop covers both
    c = _Cable((200, 0), (200, 100))
    assert sc.find_hops([across, a, b, c]) == {0: {0: [100.0, 200.0]}}


def test_parallel_and_end_touching_runs_do_not_hop() -> None:
    a = _Cable((0, 50), (400, 50))
    b = _Cable((100, 50), (300, 50))  # overlapping, same direction
    c = _Cable((50, 50), (50, 0))  # leaves from a's run at its end point… of c
    assert sc.find_hops([a, b, c]) == {}


def test_canvas_draws_hops_where_cables_cross(monkeypatch) -> None:
    QApplication.instance() or QApplication([])
    from pfsense_checker import port_vlans as pv
    from pfsense_checker.topology_site import Device, Link, PortComponent, SiteTopology

    monkeypatch.setattr(pv, "for_device", lambda d: pv.DeviceVlans())
    ports = [PortComponent(name=n) for n in ("p1", "p2")]
    # Two cables between devices laid out so their runs cross.
    site = SiteTopology(devices=[
        Device(name="top", kind="router", x=0, y=0, components=list(ports)),
        Device(name="left", kind="router", x=-300, y=400, components=[PortComponent(name="p1")]),
        Device(name="right", kind="router", x=500, y=400, components=[PortComponent(name="p1")]),
    ], links=[
        Link(a_device="top", a_port="p1", b_device="right", b_port="p1"),
        Link(a_device="top", a_port="p2", b_device="left", b_port="p1"),
    ])
    view = sc.SiteTopologyView()
    view.render_site(site)
    links = view._links  # noqa: SLF001
    expected = sc.find_hops(links)
    assert view.update_hops() == sum(len(v) for d in expected.values() for v in d.values())
    for i, link in enumerate(links):
        assert link.hops == expected.get(i, {})
    hopped = [li for li in links if li.hops]
    if hopped:  # the path carries an arc: more elements than plain corners
        assert hopped[0].path().elementCount() > len(hopped[0].points)
    # Moving a box re-routes its cables and the hops follow.
    view._chassis["right"].setPos(-900, 400)  # noqa: SLF001
    view.update_hops()
    assert all(li.hops == sc.find_hops(links).get(i, {}) for i, li in enumerate(links))
