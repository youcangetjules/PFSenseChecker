"""Load config dialog: load from device is first and the default."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def _dialog(kind: str):
    from PySide6.QtWidgets import QApplication

    from pfsense_checker.session_screen import _LoadConfigChooserDialog
    from pfsense_checker.topology_site import Device

    QApplication.instance() or QApplication([])
    return _LoadConfigChooserDialog(Device(name="host-222-10-50-5", kind=kind))


def _order(dlg) -> list[str]:  # noqa: ANN001
    lay = dlg.layout()
    out = []
    for i in range(lay.count()):
        w = lay.itemAt(i).widget()
        if w is dlg.radio_device:
            out.append("device")
        elif w is dlg.radio_file:
            out.append("file")
    return out


def test_device_pull_is_on_top_and_default() -> None:
    for kind in ("mikrotik", "pfsense", "opnsense"):
        dlg = _dialog(kind)
        assert _order(dlg) == ["device", "file"]
        assert dlg.radio_device.isChecked()
        assert not dlg.path_edit.isEnabled()  # file row idle until chosen


def test_unsupported_kind_falls_back_to_file() -> None:
    dlg = _dialog("router")
    assert _order(dlg) == ["device", "file"]
    assert not dlg.radio_device.isEnabled()
    assert dlg.radio_file.isChecked()
    assert dlg.path_edit.isEnabled()


def test_connected_status_is_green_and_semibold() -> None:
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import QApplication

    from pfsense_checker import session_screen
    from pfsense_checker.ssh_session import status_label

    QApplication.instance() or QApplication([])
    assert status_label("ok") == ("connected", "#2e7d32")
    screen = session_screen.SessionScreen()
    screen.table.setRowCount(2)
    screen._set_status_cell(0, "ok")
    screen._set_status_cell(1, "never")
    ok = screen.table.item(0, session_screen.COL_STATUS)
    idle = screen.table.item(1, session_screen.COL_STATUS)
    assert ok.text() == "● connected"
    assert ok.foreground().color().name() == "#2e7d32"
    assert ok.font().weight() == QFont.Weight.DemiBold
    assert idle.font().weight() != QFont.Weight.DemiBold


def test_config_button_states() -> None:
    from PySide6.QtWidgets import QApplication

    from pfsense_checker import session_screen as ss

    QApplication.instance() or QApplication([])
    screen = ss.SessionScreen()
    screen.table.setRowCount(1)
    screen._set_config_button(0, False, loading=True)
    btn = screen.table.cellWidget(0, ss.COL_CONFIG)
    assert btn.text() == "Loading…" and not btn.isEnabled()
    assert "#1565c0" in btn.styleSheet()  # blue while loading
    screen._set_config_button(0, True)
    btn = screen.table.cellWidget(0, ss.COL_CONFIG)
    assert btn.text() == "Config Loaded" and btn.isEnabled()
    assert "#2e7d32" in btn.styleSheet()  # green when loaded
    screen._set_config_button(0, False)
    assert screen.table.cellWidget(0, ss.COL_CONFIG).text() == "Load Config"


def test_tool_buttons_colours_and_hazard_stripes() -> None:
    from PySide6.QtWidgets import QApplication

    from pfsense_checker import login_screen as ls

    QApplication.instance() or QApplication([])
    btn = ls.HazardButton("Check Config")
    btn.setFixedSize(*ls.TOOL_BTN_SIZE)
    img = btn.grab().toImage()
    colours = {img.pixelColor(x, 3).name() for x in range(4, 196)}
    assert ls.HazardButton.YELLOW in colours and ls.HazardButton.BLACK in colours  # striped
    assert "#c62828" in ls.BEACON_BTN_STYLE  # red
    assert "#2e7d32" in ls.COLLECTOR_BTN_STYLE  # green


def test_login_cancel_says_quit_app() -> None:
    from PySide6.QtWidgets import QApplication

    from pfsense_checker.login_screen import LoginDialog

    QApplication.instance() or QApplication([])
    d = LoginDialog()
    try:
        assert d.cancel_btn.text() == "Cancel/Quit App"
        # Down in the status bar now: same height as Login, narrower (operator's call).
        assert d.cancel_btn.height() == d.submit.height() and d.cancel_btn.width() < d.submit.width()
    finally:
        d.reject()
