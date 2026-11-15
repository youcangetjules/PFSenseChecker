"""All VLANs port-to-port: one 25 px rainbow connector instead of a strand per VLAN."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from pfsense_checker import port_vlans as pv  # noqa: E402
from pfsense_checker import site_canvas as sc  # noqa: E402
from pfsense_checker.topology_site import Device, Link, PortComponent, SiteTopology  # noqa: E402

VIDS = ["600", "630", "638", "710"]


def _vlink(vid: str, a: str = "sfp7", b: str = "sfp1") -> Link:
    return Link(a_device="core", a_port=a, b_device="office", b_port=b, kind=sc.VLAN_LINK_KIND, vlans=[vid])


def test_bundle_only_when_every_vlan_on_both_ports_is_cabled() -> None:
    ports = {("core", "sfp7"): VIDS, ("office", "sfp1"): VIDS, ("core", "sfp5"): VIDS + ["662"]}
    vids = lambda d, p: ports.get((d, p), [])  # noqa: E731
    full = [_vlink(v) for v in VIDS]
    assert sc.vlan_bundles(full, vids) == {0: [0, 1, 2, 3]}
    assert sc.vlan_bundles(full[:3], vids) == {}  # one VLAN missing: separate strands
    wider = [_vlink(v, a="sfp5") for v in VIDS]  # sfp5 also carries 662
    assert sc.vlan_bundles(wider, vids) == {}
    mixed = [Link(a_device="core", a_port="sfp7", b_device="office", b_port="sfp1"), *full]
    assert sc.vlan_bundles(mixed, vids) == {1: [1, 2, 3, 4]}  # the whole-port cable stays separate


def _view(monkeypatch, links) -> sc.SiteTopologyView:  # noqa: ANN001
    QApplication.instance() or QApplication([])
    trunk = {"sfp7": pv.PortVlans(tagged=VIDS), "sfp1": pv.PortVlans(tagged=VIDS)}
    monkeypatch.setattr(pv, "for_device", lambda d: pv.DeviceVlans(ports=trunk))
    site = SiteTopology(devices=[
        Device(name="core", kind="mikrotik", model="CRS328-4C-20S-4S+", role="core-switch", x=0, y=0,
               components=[PortComponent(name="sfp7", media="ether")]),
        Device(name="office", kind="mikrotik", model="CRS109-8G-1S-2HnD", role="access-switch", x=0, y=400,
               components=[PortComponent(name="sfp1", media="ether")]),
    ], links=list(links))
    view = sc.SiteTopologyView()
    view.render_site(site)
    return view


def test_canvas_draws_one_rainbow_ribbon(monkeypatch) -> None:
    view = _view(monkeypatch, [_vlink(v) for v in VIDS])
    [item] = view._links  # noqa: SLF001 - one item, not four
    assert item.bundle == VIDS and item.bundle_links == [0, 1, 2, 3]
    assert [c.lower() for c in item.bundle_colors] == [pv.vlan_color(v, view._palette).lower() for v in VIDS]  # noqa: SLF001
    lanes = item.ribbon()
    assert len(lanes) == 4
    # Stripes sit side by side across the 25 px band on the first (vertical) run.
    xs = [ln[0].x() for ln in lanes]
    assert abs((max(xs) - min(xs)) - sc.BUNDLE_WIDTH * 3 / 4) < 0.01
    assert item.shape().boundingRect().width() >= sc.BUNDLE_WIDTH
    # Deleting it removes all four VLAN cables, and nothing else.
    view.delete_link("core", "sfp7", "office", "sfp1", indices=item.bundle_links)
    assert view._site.links == []  # noqa: SLF001


def test_deleting_one_vlan_cable_keeps_the_others(monkeypatch) -> None:
    view = _view(monkeypatch, [_vlink("600"), _vlink("630")])  # not all VLANs: strands
    assert len(view._links) == 2 and not view._links[0].bundle  # noqa: SLF001
    view.delete_link("core", "sfp7", "office", "sfp1", "600")
    assert [ln.vlans for ln in view._site.links] == [["630"]]  # noqa: SLF001


def test_ribbon_colours_blend_into_each_other() -> None:
    stops = sc.ribbon_stops(["#111111", "#222222", "#333333"])
    assert [c for _p, c in stops] == ["#111111", "#111111", "#222222", "#222222", "#333333", "#333333"]
    pos = [p for p, _c in stops]
    assert pos == sorted(pos) and pos[0] > 0 and pos[-1] < 1
    # Between one colour's solid core and the next there is room to fade.
    assert pos[2] - pos[1] > 0.1
    sharp = sc.ribbon_stops(["#111111", "#222222"], blend=0.0)
    assert sharp[1][0] == sharp[2][0] == 0.5  # no blend: the bands meet in a line


def test_ribbon_keeps_clear_of_both_boxes_and_bar_can_be_dragged(monkeypatch) -> None:
    view = _view(monkeypatch, [_vlink(v) for v in VIDS])
    [item] = view._links  # noqa: SLF001
    assert item.long_run() is None  # ports straight above each other: no bar to drag
    view._chassis["office"].setPos(-300, 400)  # noqa: SLF001 - off to the side: now it has one
    top = view._chassis["core"].sceneBoundingRect()  # noqa: SLF001
    bottom = view._chassis["office"].sceneBoundingRect()  # noqa: SLF001
    y, x0, x1 = item.long_run()
    half = sc.BUNDLE_WIDTH / 2
    assert y - half >= top.bottom() + sc.CABLE_CLEARANCE - 0.01  # the band does not touch the upper box
    assert y + half <= bottom.top() - sc.CABLE_CLEARANCE + 0.01
    saved = []
    view.positions_changed.connect(lambda: saved.append(1))
    item.move_long_run(y + 60)  # drag the bar down
    assert abs(item.long_run()[0] - (y + 60)) < 0.01
    item.move_long_run(bottom.top() + 500)  # past the lower box: stops at the limit
    assert item.long_run()[0] + half <= bottom.top() - sc.CABLE_CLEARANCE + 0.01
    view.cable_lane_changed(item)
    assert saved and all(ln.lane == item.lane_offset for ln in view._site.links)  # noqa: SLF001 - every strand
    quads = item.ribbon_quads()
    assert len(quads) == len(item.points) - 1
    from PySide6.QtCore import QPointF

    assert item.on_long_run(QPointF((x0 + x1) / 2, item.long_run()[0]))
    assert not item.on_long_run(QPointF((x0 + x1) / 2, item.long_run()[0] + 40))
