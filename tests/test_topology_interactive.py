"""Topology page: draw a cable port → port with the mouse, delete it, lock."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QPoint, Qt  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402


def _app():
    return QApplication.instance() or QApplication([])


def _site():
    from pfsense_checker.topology_site import Device, PortComponent, SiteTopology

    a = Device(name="sw1", kind="mikrotik", x=40, y=40,
               components=[PortComponent(name="sfp-sfpplus1"), PortComponent(name="ether2")])
    b = Device(name="fw1", kind="pfsense", x=520, y=40,
               components=[PortComponent(name="mce1"), PortComponent(name="igb0")])
    return SiteTopology(devices=[a, b])


def _port(view, device: str, port: str):
    from pfsense_checker.site_canvas import PortItem

    return next(i for i in view.scene().items()
                if isinstance(i, PortItem) and i.device_name == device and i.port_name == port)


def _view_point(view, item) -> QPoint:
    return view.mapFromScene(item.mapToScene(item.boundingRect().center()))


def _drag(view, src, dst) -> None:
    start, end = _view_point(view, src), _view_point(view, dst)
    QTest.mousePress(view.viewport(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, start)
    QTest.mouseMove(view.viewport(), (start + end) / 2)
    QTest.mouseMove(view.viewport(), end)
    QTest.mouseRelease(view.viewport(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, end)
    QApplication.processEvents()


def test_draw_and_delete_cable_with_the_mouse() -> None:
    _app()
    from pfsense_checker.site_canvas import SiteTopologyView

    view = SiteTopologyView()
    view.resize(1000, 500)
    view.show()
    site = _site()
    view.render_site(site)
    QApplication.processEvents()
    changed: list[str] = []
    view.links_changed.connect(lambda: changed.append("links"))

    _drag(view, _port(view, "sw1", "sfp-sfpplus1"), _port(view, "fw1", "mce1"))
    assert [(l.a_device, l.a_port, l.b_device, l.b_port) for l in site.links] == [
        ("sw1", "sfp-sfpplus1", "fw1", "mce1")
    ]
    assert changed == ["links"]

    # Same pair again (either direction) does not duplicate.
    _drag(view, _port(view, "fw1", "mce1"), _port(view, "sw1", "sfp-sfpplus1"))
    assert len(site.links) == 1

    assert view.delete_link("fw1", "mce1", "sw1", "sfp-sfpplus1") is True
    assert site.links == []

    view.set_locked(True)
    _drag(view, _port(view, "sw1", "ether2"), _port(view, "fw1", "igb0"))
    assert site.links == []  # locked: no cable


def test_topology_page_is_interactive_and_shares_edits() -> None:
    _app()
    from pfsense_checker.home_screen import HomeScreen

    home = HomeScreen()
    site = _site()
    home.set_sites(live=site, topology=site, mode="live")
    home.show_section("topology")
    view = home.topo_preview
    assert not view._locked and not home.topo_lock.isChecked()
    emitted: list[bool] = []
    home.site_changed.connect(lambda: emitted.append(True))
    view.resize(1000, 500)
    view.show()
    view.render_site(site)
    QApplication.processEvents()
    _drag(view, _port(view, "sw1", "ether2"), _port(view, "fw1", "igb0"))
    assert len(site.links) == 1 and emitted
    home.topo_lock.setChecked(True)
    assert view._locked
