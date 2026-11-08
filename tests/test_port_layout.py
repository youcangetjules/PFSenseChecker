"""Topology chassis port layouts: one row / flat / rectangular, cells fill the box."""

from __future__ import annotations

from pfsense_checker import site_canvas as sc
from pfsense_checker.topology_site import Device


def _groups(n_copper: int, n_sfp: int = 0, n_vlan: int = 0) -> list[str]:
    return ["physical"] * n_copper + ["sfp"] * n_sfp + ["vlan"] * n_vlan


def test_row_cells_stretch_to_fill_the_box() -> None:
    groups = _groups(8, 1, 4)
    w, h, cell, places = sc.plan_ports(groups, sc.SFP_W, layout=sc.LAYOUT_ROW, user_w=960)
    assert w == 960
    assert cell > sc.SFP_W  # wider than the old fixed cell
    assert len({y for _, y in places}) == 1
    right = max(x for x, _ in places) + cell
    assert abs(right - (960 - sc.CHASSIS_PAD)) < 0.5  # last cell ends at the right padding
    # a group gap separates copper from SFP
    assert places[8][0] - (places[7][0] + cell) > sc.PORT_GAP


def test_row_grows_the_box_when_cells_would_be_too_narrow() -> None:
    w, _h, cell, _ = sc.plan_ports(_groups(40), sc.RJ45_W, layout=sc.LAYOUT_ROW, user_w=300)
    assert cell == sc.RJ45_W and w > 300


def test_flat_is_two_rows_switch_style() -> None:
    w, h, cell, places = sc.plan_ports(_groups(8), sc.RJ45_W, layout=sc.LAYOUT_FLAT, user_w=600)
    ys = sorted({y for _, y in places})
    assert len(ys) == 2
    assert places[0][0] == places[1][0] and places[0][1] < places[1][1]  # 1 over 2
    assert places[2][0] > places[0][0]


def test_rect_fits_width_and_balances_rows() -> None:
    w, h, cell, places = sc.plan_ports(_groups(16), sc.RJ45_W, layout=sc.LAYOUT_RECT, user_w=960)
    rows = {}
    for _x, y in places:
        rows[y] = rows.get(y, 0) + 1
    assert w == 960
    assert sorted(rows.values()) == [8, 8]
    narrow = sc.plan_ports(_groups(16), sc.RJ45_W, layout=sc.LAYOUT_RECT, user_w=400)
    assert narrow[1] > h  # narrower box → more rows → taller


def test_unknown_layout_falls_back_to_row_and_empty_is_safe() -> None:
    assert sc.plan_ports(_groups(3), 20, layout="bogus")[3] == sc.plan_ports(_groups(3), 20)[3]
    w, h, _cell, places = sc.plan_ports([], 20, user_w=500)
    assert places == [] and w == 500 and h > 0


def test_port_layout_is_saved_with_the_device() -> None:
    d = Device(name="sw", port_layout="flat")
    back = Device.from_dict(d.to_dict())
    assert back.port_layout == "flat"
    assert Device.from_dict({"name": "old"}).port_layout == ""


def test_front_panel_order_copper_sfp_combo_sfpplus() -> None:
    from PySide6.QtWidgets import QApplication

    from pfsense_checker.topology_site import PortComponent

    QApplication.instance() or QApplication([])
    names = ["sfp-sfpplus2", "combo2", "sfp10", "ether1", "sfp-sfpplus1", "sfp2", "combo1", "sfp1"]
    comps = [PortComponent(name=n, media="ether") for n in names]
    comps.append(PortComponent(name="CRS109-W-1", media="cap"))  # CAPsMAN interface on the controller
    dev = Device(name="sw", kind="mikrotik", model="CRS328-4C-20S-4S+", role="core-switch", components=comps)
    ch = sc.ChassisItem(dev, snap=False)
    order = sorted(ch.port_items, key=lambda n: ch.port_items[n].pos().x())
    assert order == ["ether1", "sfp1", "sfp2", "sfp10", "combo1", "combo2", "sfp-sfpplus1", "sfp-sfpplus2"]
    assert "CRS109-W-1" not in ch.port_items
    assert [sc.cage_rank(PortComponent(name=n)) for n in ("ether1", "sfp1", "combo1", "sfp-sfpplus1", "qsfp28-1-1")] \
        == [0, 1, 2, 3, 5]


def test_scan_aliases_and_ignored_devices_are_not_drawn() -> None:
    from pfsense_checker.topology_site import PortComponent, SiteTopology

    fw = Device(name="guardian", kind="pfsense", components=[
        PortComponent(name="LAN", address="100.48.64.1/24"), PortComponent(name="OPT18", address="222.10.50.1/24")])
    lan_alias = Device(name="host-100-48-64-1", kind="pfsense", mgmt_ip="100.48.64.1")  # same box, other address
    ignored = Device(name="host-9-9-9-9", kind="pfsense", mgmt_ip="9.9.9.9", ignored=True)
    lone = Device(name="host-10-0-0-1", kind="router", mgmt_ip="10.0.0.1")  # nobody else owns this address
    site = SiteTopology(devices=[fw, lan_alias, ignored, lone])
    assert [d.name for d in sc.drawn_devices(site)] == ["guardian", "host-10-0-0-1"]
