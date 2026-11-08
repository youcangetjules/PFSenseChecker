"""Topology chassis: one row, typed ports, pfSense names, port-exact cables;
and dragging a loaded config onto Config Check."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from pfsense_checker import site_canvas as sc  # noqa: E402
from pfsense_checker.topology_site import Device, Link, PortComponent, SiteTopology  # noqa: E402

DOT = "·"


def _app():
    return QApplication.instance() or QApplication([])


def _pf() -> Device:
    return Device(
        name="fw", kind="pfsense", model="pfSense", x=0, y=0,
        components=[
            PortComponent(name="OPT18", media=f"mce1.630 {DOT} 1_IV2_VL630_MCE1_LAN {DOT} vlan", address="222.10.50.1/24"),
            PortComponent(name="WAN", media=f"igb3 {DOT} 0_S2_P3_1G_E_WAN3_last_line"),
            PortComponent(name="OPT4", media=f"igb2 {DOT} OPT4 {DOT} disabled"),
            PortComponent(name="OPT22", media=f"bridge0 {DOT} 2_BR0_1G_LB {DOT} bridge"),
            PortComponent(name="OPT8", media=f"ovpnc1 {DOT} 3_EVL0_EXVPNAN {DOT} openvpn"),
            PortComponent(name="mce1.630", media=f"tag 630 {DOT} mce1 {DOT} IV2-S4-VLAN630-LAN"),
        ],
    )


def test_port_classes_and_pfsense_names() -> None:
    dev = _pf()
    by = {c.name: c for c in dev.components}
    assert sc.port_class(by["OPT18"]) == ("vlan", False)
    assert sc.port_class(by["mce1.630"]) == ("vlan", False)
    assert sc.port_class(by["WAN"]) == ("physical", False)
    assert sc.port_class(by["OPT4"]) == ("physical", True)
    assert sc.port_class(by["OPT22"]) == ("bridge", False)
    assert sc.port_class(by["OPT8"]) == ("virtual", False)
    assert sc.port_display(dev, by["OPT18"]) == ("1_IV2_VL630_MCE1_LAN", "222.10.50.1")
    assert sc.port_display(dev, by["WAN"]) == ("0_S2_P3_1G_E_WAN3_last_line", f"WAN {DOT} igb3")
    assert sc.port_display(dev, by["mce1.630"]) == ("IV2-S4-VLAN630-LAN", "mce1.630")
    assert sc.port_display(dev, by["OPT4"]) == ("OPT4", "")  # description is just the id
    mt = Device(name="sw", kind="mikrotik", components=[PortComponent(name="sfp5", media="ether")])
    assert sc.port_display(mt, mt.components[0]) == ("sfp5", "")


def test_router_is_one_row_grouped_by_type() -> None:
    _app()
    ch = sc.ChassisItem(_pf())
    items = ch.port_items
    assert items["WAN"].pos().y() + items["WAN"].h <= sc.HEADER_H  # the uplink sits in the title bar
    rest = [i for n, i in items.items() if not ch.is_uplink(n)]
    ys = {round(i.pos().y()) for i in rest}
    assert len(ys) == 1  # one row
    order = sorted(rest, key=lambda i: i.pos().x())
    classes = [i.port_cls for i in order]
    assert classes == sorted(classes, key=lambda c: sc._CLASS_ORDER[c])  # grouped physical → … → virtual
    # VLAN interfaces and bridges are not ports: they colour / wrap the ports instead.
    assert "OPT18" not in items and "mce1.630" not in items and "OPT22" not in items
    assert items["OPT4"].disabled
    assert len({round(i.w) for i in order}) == 1 and order[0].w >= sc.NIC_W  # one shared cell width
    assert ch.boundingRect().width() > ch.boundingRect().height()  # one horizontal row (3 real ports left)


def test_cable_enters_lower_device_from_the_top() -> None:
    _app()
    up = _pf()
    down = Device(name="sw", kind="mikrotik", x=0, y=300,
                  components=[PortComponent(name="sfp5", media="ether"), PortComponent(name="sfp6", media="ether")])
    site = SiteTopology(devices=[up, down], links=[Link(a_device="sw", a_port="sfp5", b_device="fw", b_port="WAN")])
    view = sc.SiteTopologyView()
    view.render_site(site)
    link = view._links[0]
    path = link.path()
    start, end = path.elementAt(0), path.elementAt(path.elementCount() - 1)
    sw_port = view._chassis["sw"].port_items["sfp5"]
    fw_port = view._chassis["fw"].port_items["WAN"]
    assert abs(start.y - sw_port.mapToScene(0, 0).y()) < 0.5  # leaves the top of sfp5 (device below)
    # WAN is an uplink: its cable leaves the top of the port and goes round the box.
    assert abs(end.y - fw_port.mapToScene(0, 0).y()) < 0.5
    fw_bottom = view._chassis["fw"].sceneBoundingRect().bottom()
    sw_top = view._chassis["sw"].sceneBoundingRect().top()
    fw_top = view._chassis["fw"].sceneBoundingRect().top()
    runs = [path.elementAt(i).y for i in range(1, path.elementCount() - 1)]
    assert runs[-1] < fw_top and runs[-2] < fw_top  # climbs out above the firewall…
    assert all(fw_bottom <= y <= sw_top for y in runs[:-2])  # …after crossing the gap


def test_drag_loaded_config_onto_config_check(tmp_path, monkeypatch) -> None:
    _app()
    from PySide6.QtCore import QPointF, Qt
    from PySide6.QtGui import QDropEvent
    from PySide6.QtWidgets import QListWidgetItem

    from pfsense_checker import gui, net_discovery
    from pfsense_checker.home_screen import LoadedConfigList

    cfg = tmp_path / "host.rsc"
    cfg.write_text("/system identity\nset name=X\n", encoding="utf-8")
    lst = LoadedConfigList()
    item = QListWidgetItem("host — mikrotik")
    item.setData(Qt.ItemDataRole.UserRole, str(cfg))
    lst.addItem(item)
    mime = lst.mimeData([item])
    assert [u.toLocalFile() for u in mime.urls()] == [str(cfg).replace("\\", "/")]

    monkeypatch.setattr(net_discovery, "discover", lambda cidr, **k: [])
    monkeypatch.setattr(gui.MainWindow, "_collector_endpoint_for_status", lambda self: ("", ""))
    window = gui.MainWindow()
    got: list = []
    monkeypatch.setattr(window, "_on_files_dropped", lambda paths: got.extend(paths))
    event = QDropEvent(QPointF(10, 10), Qt.DropAction.CopyAction, mime,
                       Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)
    window.dropEvent(event)
    assert [str(p) for p in got] == [str(cfg)]
    window.close()
