"""Wireshark bridge scaffold: probe, Lua notes, stub script."""

from __future__ import annotations

import pytest

from pfsense_checker import wireshark_bridge as w


def test_probe_without_and_with_binary(tmp_path) -> None:
    assert not w.WiresharkBridge().probe().available
    exe = tmp_path / "tshark.exe"
    exe.write_bytes(b"")
    status = w.WiresharkBridge(w.WiresharkBridgeConfig(tshark_exe=exe)).probe()
    assert status.available and str(exe) in status.message


def test_lua_notes_and_stub() -> None:
    bridge = w.WiresharkBridge()
    notes = bridge.list_lua_modules()
    assert notes and all(n.title and n.summary for n in notes)
    info = bridge.draft_plugin_info()
    assert set(info) == {"version", "description", "author", "repository"}
    lua = bridge.render_stub_lua()
    assert "set_plugin_info(my_info)" in lua and info["version"] in lua and "Listener" in lua


def test_run_script_not_wired_yet(tmp_path) -> None:
    with pytest.raises(NotImplementedError):
        w.WiresharkBridge().run_script(tmp_path / "x.lua")
