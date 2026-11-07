"""Dragging a chassis must not re-render the site mid-drag (BUG-046).

Login to Routers answers positions_changed by rebuilding every chassis. When
that fired on every pixel of a drag, the box under the mouse was destroyed and
recreated, and it jumped elsewhere.
"""

from __future__ import annotations

from PySide6.QtCore import QEvent, QPoint, QPointF, Qt
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import QApplication


def _mouse(view, kind, pos: QPoint, buttons) -> None:  # noqa: ANN001
    button = Qt.MouseButton.LeftButton if kind != QEvent.Type.MouseMove else Qt.MouseButton.NoButton
    ev = QMouseEvent(kind, QPointF(pos), QPointF(view.viewport().mapToGlobal(pos)), button, buttons,
                     Qt.KeyboardModifier.NoModifier)
    QApplication.sendEvent(view.viewport(), ev)
    QApplication.processEvents()


def test_drag_announces_once_on_release_and_keeps_the_box() -> None:
    from pfsense_checker.site_canvas import SiteTopologyView
    from pfsense_checker.topology_site import Device, SiteTopology

    QApplication.instance() or QApplication([])
    site = SiteTopology(name="t")
    site.devices.append(Device(name="sw1", kind="mikrotik", model="CRS109-8G-1S-2HnD",
                               ports=["ether1", "ether2"], x=100.0, y=100.0))
    view = SiteTopologyView()
    view.resize(900, 600)
    view.render_site(site)
    view.set_locked(False)
    view.show()
    QApplication.processEvents()

    announced: list[int] = []

    def rerender() -> None:  # what Login to Routers does with the signal
        announced.append(1)
        view.render_site(site)

    view.positions_changed.connect(rerender)
    chassis = next(i for i in view.scene().items() if type(i).__name__ == "ChassisItem")
    start = view.mapFromScene(chassis.mapToScene(QPointF(40, 10)))  # on the title bar
    _mouse(view, QEvent.Type.MouseButtonPress, start, Qt.MouseButton.LeftButton)
    for step in range(1, 11):
        _mouse(view, QEvent.Type.MouseMove, start + QPoint(step * 20, step * 10), Qt.MouseButton.LeftButton)
        assert announced == [], "site was re-rendered during the drag"
        assert chassis.scene() is view.scene(), "the dragged box was destroyed mid-drag"
    end = start + QPoint(200, 100)
    _mouse(view, QEvent.Type.MouseButtonRelease, end, Qt.MouseButton.NoButton)
    assert announced == [1]
    dev = site.device("sw1")
    assert abs(dev.x - 300) <= 20 and abs(dev.y - 200) <= 20  # moved with the mouse (grid snap)
    # a plain click (no movement) announces nothing
    fresh = next(i for i in view.scene().items() if type(i).__name__ == "ChassisItem")
    p = view.mapFromScene(fresh.mapToScene(QPointF(40, 10)))
    _mouse(view, QEvent.Type.MouseButtonPress, p, Qt.MouseButton.LeftButton)
    _mouse(view, QEvent.Type.MouseButtonRelease, p, Qt.MouseButton.NoButton)
    assert announced == [1]
    view.close()
