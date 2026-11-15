"""Will it work? right-click: Wireless → controller options, Bandwidth → which ports."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pfsense_checker import config_analysis as ca  # noqa: E402
from tests.test_config_analysis import MANAGER_RSC, _cap_rsc, _rsc  # noqa: E402


def _window(monkeypatch, result, peers):  # noqa: ANN001, ANN202
    from PySide6.QtWidgets import QApplication

    from pfsense_checker import gui

    QApplication.instance() or QApplication([])
    win = gui.MainWindow()
    win._result = result  # noqa: SLF001
    monkeypatch.setattr(win, "_peer_results", lambda current: list(peers))
    monkeypatch.setattr(win, "_known_devices", lambda: {})
    win._wiw_no_exec = True  # noqa: SLF001 - build the dialogs, do not block on them
    return win


def test_wireless_rows_offer_the_controller_options(monkeypatch, tmp_path) -> None:
    cap = _rsc(tmp_path, "cap", _cap_rsc("yes", "630,710"))
    mgr = _rsc(tmp_path, "mgr", MANAGER_RSC)
    win = _window(monkeypatch, cap, [mgr])
    ids = [a[0] for a in win.wiw_actions("Wireless", None)]
    assert ids == ["check_controller", "use_controller"]
    assert win.wiw_actions("DHCP", None) == []
    loaded = []
    monkeypatch.setattr(win, "load_path", lambda p: loaded.append(p))
    monkeypatch.setattr(win, "_goto_tab", lambda name: loaded.append(name))
    win.wiw_do("check_controller", "Wireless", None)
    assert loaded == [mgr.path, "Will it work?"]  # opens the controller's own list
    win.wiw_do("use_controller", "Wireless", None)
    title, body, _copy = win._wiw_last_dialog  # noqa: SLF001
    assert "controller data" in title and "Its SSIDs, security and VLANs were used" in body
    assert "Repair steps" in body
    win.close()


def test_controller_not_loaded_says_so(monkeypatch, tmp_path) -> None:
    cap = _rsc(tmp_path, "cap", _cap_rsc("yes", "630,710"))
    win = _window(monkeypatch, cap, [])
    win.wiw_do("use_controller", "Wireless", None)
    assert "is not loaded" in win._wiw_last_dialog[1]  # noqa: SLF001
    win.close()


def test_bandwidth_row_shows_its_ports(monkeypatch, tmp_path) -> None:
    rsc = _rsc(tmp_path, "sw", "/interface ethernet\nset [ find default-name=ether5 ] advertise=10M-baseT-full\n"
               "/interface bridge\nadd name=BR\n/interface bridge port\nadd bridge=BR interface=ether5 pvid=630\n")
    win = _window(monkeypatch, rsc, [])
    check = ca.Check(ca.WARN, "Port speeds", "1 port(s) only auto-negotiate up to 100 Mbps: ether5.", "Advertise 1G")
    assert win.wiw_actions("Bandwidth (estimate)", check) == [("show_ports", "Show which port(s)", True)]
    none = ca.Check(ca.INFO, "Note", "Estimates from the config only.")
    assert win.wiw_actions("Bandwidth (estimate)", none)[0][2] is False
    win.wiw_do("show_ports", "Bandwidth (estimate)", check)
    title, body, _copy = win._wiw_last_dialog  # noqa: SLF001
    assert title == "Ports — Port speeds" and "ether5" in body and "10M-baseT-full" in body and "630" in body
    win.close()


SWITCH = """# model = CRS109-8G-1S-2HnD
/interface bridge
add name=BR vlan-filtering=no
/interface ethernet
set [ find default-name=ether3 ] comment="Mavenir E72 (VL630)"
set [ find default-name=sfp1 ] comment=">> Uplink"
/interface vlan
add interface=BR name=V2-VL630-LAN vlan-id=630
/interface list
add name=WAN
add name=LAN
/interface wireless security-profiles
set [ find default=yes ] supplicant-identity=MikroTik
/interface bridge port
add bridge=BR interface=ether3 pvid=630
add bridge=BR interface=sfp1
/interface bridge vlan
add bridge=BR tagged=BR,sfp1 untagged=ether3 vlan-ids=630
/interface ethernet switch
set 0 drop-if-invalid-or-src-port-not-member-of-vlan-on-ports=ether3,sfp1
/ip address
add address=222.10.50.10/24 interface=V2-VL630-LAN
"""


def test_mikrotik_logical_map_has_only_real_ports(tmp_path) -> None:
    from pfsense_checker import firewall_topology as ft

    r = _rsc(tmp_path, "sw", SWITCH)
    names = {i.name for i in r.interfaces}
    assert not names & {"WAN", "LAN", "all", "none", "default", "switch1"}  # lists, profiles, the switch chip
    g = ft.build_config_topology(r)
    assert set(g.layers["phys"]) == {"ether3", "sfp1"}  # the bridge and the VLAN interface are not ports
    assert g.layers["bridge"] == ["br"] and g.layers["vlan"] == ["v2-vl630-lan"]
    subs = {g.boxes[("port", n)].title: g.boxes[("port", n)].subtitle for n in g.layers["port"]}
    assert subs["Mavenir E72 (VL630)"] == "ether3 · VLAN 630 (access)"
    assert subs[">> Uplink"].startswith("sfp1 · trunk 630")


def test_logical_map_right_click(monkeypatch, tmp_path) -> None:
    from pfsense_checker.viz import map_menu_for

    assert [a for a, _l in map_menu_for("phys")] == ["details", "find", "copy"]
    assert map_menu_for("vlan")[0][1].startswith("Show VLAN details") and map_menu_for("nope") == []
    r = _rsc(tmp_path, "sw", SWITCH)
    win = _window(monkeypatch, r, [])
    title, body = win.logical_node_details("port", "ether3", "Mavenir E72 (VL630)")
    assert title == "Port — Mavenir E72 (VL630)" and "630" in body and "BR" in body
    title, body = win.logical_node_details("vlan", "v2-vl630-lan", "VLAN 630")
    assert title.startswith("VLAN") and "sfp1" in body and "ether3" in body and "222.10.50.10" in body
    title, body = win.logical_node_details("bridge", "br", "BR")
    assert "ether3, sfp1" in body
    win.close()
