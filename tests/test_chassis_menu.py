"""Chassis topology context-menu actions."""

from __future__ import annotations

from pfsense_checker.chassis_actions import CHASSIS_MENU_ITEMS, chassis_detail_commands


def test_chassis_menu_has_requested_actions() -> None:
    labels = [label for _aid, label in CHASSIS_MENU_ITEMS]
    assert "Pull Config" in labels
    assert "Show more: OS" in labels
    assert "Show more: hardware" in labels
    assert "Show more: uptime" in labels
    assert "Show more: alerts (SNMP)" in labels


def test_detail_commands_pfsense_vs_mikrotik() -> None:
    os_cmds = chassis_detail_commands("pfsense", "os")
    assert any("uname" in c for c in os_cmds)
    mt = chassis_detail_commands("mikrotik", "hardware")
    assert any("routerboard" in c for c in mt)
    up = chassis_detail_commands("opnsense", "uptime")
    assert any("uptime" in c for c in up)


def test_site_canvas_has_context_menu_handler() -> None:
    from pathlib import Path

    text = Path("pfsense_checker/site_canvas.py").read_text(encoding="utf-8")
    assert "def contextMenuEvent" in text
    assert "_popup_chassis_menu" in text
    assert "RightButton" in text
