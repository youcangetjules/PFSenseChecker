"""Beacon Creator tab: syntax check shades cells green / red.

Kept apart from test_beacon_config_check: it creates a QApplication, which
test_busy (sorted between them) expects not to exist yet.
"""

from __future__ import annotations


def test_creator_tab_shades_cells(monkeypatch) -> None:
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    QApplication.instance() or QApplication([])
    from pfsense_checker import field_shading, gui, net_discovery

    monkeypatch.setattr(net_discovery, "discover", lambda cidr, **k: [])
    monkeypatch.setattr(gui.MainWindow, "_collector_endpoint_for_status", lambda self: ("", ""))
    w = gui.MainWindow()
    w._ensure_workspace()
    w.bc_collector.setText("http://10.0.0.5:8787")
    w._bc_add_ping_row("10.0.0.300", "10.0.0.0/24", "lan")
    bad = w._bc_check_syntax()
    assert [(c.field, c.row, c.key) for c in bad] == [("ping_targets", 1, "host")]
    red = w.bc_ping_table.item(1, 0).background().color().name()
    green = w.bc_ping_table.item(1, 1).background().color().name()
    assert (red, green) == (field_shading.BAD_BG, field_shading.GOOD_BG)
    assert field_shading.GOOD_BG in w.bc_collector.styleSheet()
    w.bc_ping_table.item(1, 0).setText("10.0.0.30")  # live re-check after the first check
    assert w.bc_ping_table.item(1, 0).background().color().name() == field_shading.GOOD_BG
    w.close()
