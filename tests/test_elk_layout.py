"""Auto-arrange with ELK: cable direction, graph shape, result reading, and a real run."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from pfsense_checker import elk_layout as el  # noqa: E402


def _boxes() -> dict[str, el.BoxInfo]:
    return {
        "isp": el.BoxInfo("isp", 200, 80, 0, {"eth0": 100}),
        "fw": el.BoxInfo("fw", 700, 120, 2, {"WAN": 300, "LAN": 60}, uplinks={"WAN"}),
        "core": el.BoxInfo("core", 900, 100, 3, {"sfp1": 40, "sfp2": 80, "sfp3": 120},
                           vlan_x={("sfp1", "710"): 47}),
        "ap1": el.BoxInfo("ap1", 300, 90, 4, {"ether1": 50}),
        "ap2": el.BoxInfo("ap2", 300, 90, 4, {"ether1": 50}),
    }


def _cables() -> list[el.CableInfo]:
    return [
        el.CableInfo(0, "core", "sfp1", "fw", "LAN"),  # listed switch-first: still runs fw → core
        el.CableInfo(1, "core", "sfp2", "ap1", "ether1"),
        el.CableInfo(2, "ap2", "ether1", "core", "sfp3"),
        el.CableInfo(3, "fw", "WAN", "isp", "eth0"),  # fw's WAN is an uplink: the ISP is above
        el.CableInfo(4, "core", "sfp1", "fw", "LAN", vid="710"),
    ]


def test_cables_run_upstream_to_downstream() -> None:
    graph, edge_map = el.build_graph(_boxes(), _cables())
    assert edge_map["e:0"] == (0, False)  # reversed: fw is upstream of core
    assert edge_map["e:2"] == (2, False)  # the AP hangs off the core switch
    assert edge_map["e:3"] == (3, False)  # the ISP is above the firewall's WAN
    nodes = {n["id"]: n for n in graph["children"]}
    fw_ports = {p["id"]: p for p in nodes["n:fw"]["ports"]}
    assert fw_ports["p:0:s"]["layoutOptions"]["elk.port.side"] == "SOUTH" and fw_ports["p:0:s"]["x"] == 60
    assert fw_ports["p:3:t"]["layoutOptions"]["elk.port.side"] == "NORTH" and fw_ports["p:3:t"]["x"] == 300
    core_ports = {p["id"]: p for p in nodes["n:core"]["ports"]}
    assert core_ports["p:4:t"]["x"] == 47  # a VLAN cable meets its stripe
    assert graph["layoutOptions"]["elk.algorithm"] == "layered"


def test_read_result_starts_at_origin_and_orders_points_a_to_b() -> None:
    result = {
        "children": [{"id": "n:fw", "x": -50, "y": -20}, {"id": "n:core", "x": 10, "y": 200}],
        "edges": [{"id": "e:0", "sections": [{"startPoint": {"x": 10, "y": 100},
                                              "bendPoints": [{"x": 10, "y": 150}],
                                              "endPoint": {"x": 40, "y": 200}}]}],
    }
    arr = el.read_result(result, {"e:0": (0, False)}, origin=(100, 100))
    assert arr.positions == {"fw": (100, 100), "core": (160, 320)}
    assert arr.routes[0] == [(190, 320), (160, 270), (160, 220)]  # reversed: from core (a) to fw (b)


def test_real_elk_run_layers_top_down() -> None:
    QApplication.instance() or QApplication([])
    arr = el.arrange(_boxes(), _cables(), origin=(40, 40))
    y = {n: p[1] for n, p in arr.positions.items()}
    assert y["isp"] < y["fw"] < y["core"] < y["ap1"] and y["ap2"] > y["core"]
    assert min(p[0] for p in arr.positions.values()) == 40 and min(y.values()) == 40
    for idx, pts in arr.routes.items():  # orthogonal: every step is horizontal or vertical
        for (x1, y1), (x2, y2) in zip(pts, pts[1:]):
            assert abs(x1 - x2) < 0.01 or abs(y1 - y2) < 0.01, idx


def test_canvas_auto_arrange_and_undo(monkeypatch) -> None:
    QApplication.instance() or QApplication([])
    from pfsense_checker import port_vlans as pv
    from pfsense_checker import site_canvas as sc
    from pfsense_checker.topology_site import Device, Link, PortComponent, SiteTopology

    monkeypatch.setattr(pv, "for_device", lambda d: pv.DeviceVlans())
    site = SiteTopology(devices=[
        Device(name="sw", kind="mikrotik", model="CRS109-8G-1S-2HnD", role="access-switch", x=500, y=500,
               components=[PortComponent(name="ether1", media="ether"), PortComponent(name="ether2", media="ether")]),
        Device(name="fw", kind="pfsense", x=600, y=900, components=[PortComponent(name="LAN")]),
        Device(name="ap", kind="mikrotik", model="hAP ax3", role="access-point", x=100, y=100,
               components=[PortComponent(name="ether1")]),
    ], links=[Link(a_device="sw", a_port="ether1", b_device="fw", b_port="LAN"),
              Link(a_device="ap", a_port="ether1", b_device="sw", b_port="ether2")])
    view = sc.SiteTopologyView()
    view.render_site(site)
    moved = []
    view.positions_changed.connect(lambda: moved.append(1))
    msg = view.auto_arrange()
    assert msg.startswith("Arranged 3 devices") and moved
    y = {d.name: d.y for d in site.devices}
    assert y["fw"] < y["sw"] < y["ap"]  # firewall on top, the switch, then the AP
    assert all(li.route for li in view._links)  # noqa: SLF001 - ELK's routes are drawn
    sw = view._chassis["sw"]  # noqa: SLF001
    sw.setPos(sw.pos().x() + 40, sw.pos().y())  # move one box: its cables re-route themselves
    assert all(li.route is None for li in view._links if "sw" in (li.a.device_name, li.b.device_name))  # noqa: SLF001
    assert view.undo_arrange() and (site.device("sw").x, site.device("sw").y) == (500, 500)
    assert not view.can_undo_arrange()
    view.set_locked(True)
    assert "locked" in view.auto_arrange()
