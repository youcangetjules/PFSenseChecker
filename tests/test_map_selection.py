"""Picking a device on the map selects it in Devices (and back); the selected
chassis is 1px thicker and pulses."""

from __future__ import annotations

from PySide6.QtWidgets import QApplication

from pfsense_checker import net_discovery as nd


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _site():  # noqa: ANN202
    from pfsense_checker.topology_site import Device, SiteTopology

    site = SiteTopology(subnets=["222.10.50.0/24"])
    for n, x in ((5, 0.0), (10, 0.0)):
        dev = Device(name=f"host-222-10-50-{n}", kind="mikrotik", model="CRS109-8G-1S-2HnD",
                     mgmt_ip=f"222.10.50.{n}", ports=["ether1"], x=x, y=n * 30.0)
        ssh = dev.ensure_ssh()
        ssh.host, ssh.username, ssh.last_status = f"222.10.50.{n}", "admin", "ok"
        site.add_or_update_device(dev)
    return site


def test_map_and_device_list_follow_each_other(monkeypatch) -> None:
    from pfsense_checker import session_screen

    _app()
    monkeypatch.setattr(nd, "discover", lambda cidr, **k: [])
    monkeypatch.setattr(nd, "default_gateways", lambda: set())
    screen = session_screen.SessionScreen()
    screen.set_site(_site())
    screen.show()
    QApplication.processEvents()
    view = screen.map_view

    # map → list
    view._chassis["host-222-10-50-10"].setSelected(True)  # noqa: SLF001 - as a click does
    QApplication.processEvents()
    row = screen._exactly_one_selected_row()  # noqa: SLF001
    assert row is not None
    assert screen._device_for_row(row).name == "host-222-10-50-10"  # noqa: SLF001

    # list → map
    other = screen._row_for_device_name("host-222-10-50-5")  # noqa: SLF001
    screen.table.selectRow(other)
    QApplication.processEvents()
    assert view.selected_device() == "host-222-10-50-5"
    assert not view._chassis["host-222-10-50-10"].isSelected()  # noqa: SLF001
    screen.close()


def test_selected_chassis_is_thicker_and_pulses() -> None:
    from pfsense_checker import site_canvas as sc

    _app()
    view = sc.SiteTopologyView()
    view.render_site(_site())
    view.show()
    QApplication.processEvents()
    seen: list[str] = []
    view.device_selected.connect(seen.append)
    assert not view._pulse_timer.isActive()  # noqa: SLF001
    view.select_device("host-222-10-50-5")
    assert seen == []  # selecting from the list does not echo back
    assert view._pulse_timer.isActive()  # noqa: SLF001
    ch = view._chassis["host-222-10-50-5"]  # noqa: SLF001
    values = set()
    for _ in range(12):
        view._pulse_t0 -= 0.13  # noqa: SLF001 - step the clock
        view._pulse_tick()  # noqa: SLF001
        values.add(round(ch.pulse, 2))
    assert len(values) > 3 and min(values) >= 0.0 and max(values) <= 1.0
    assert sc.SELECTED_BORDER == sc.BORDER + 1
    # a click on the map does emit
    view._chassis["host-222-10-50-10"].setSelected(True)  # noqa: SLF001
    ch.setSelected(False)
    QApplication.processEvents()
    assert seen[-1] == "host-222-10-50-10"
    view.scene().clearSelection()
    QApplication.processEvents()
    assert not view._pulse_timer.isActive()  # noqa: SLF001
    assert ch.pulse == 1.0
    view.close()
