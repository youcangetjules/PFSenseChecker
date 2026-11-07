"""WLANs tied to VLANs (CAPsMAN and local), on the CAP's bridge; right-click;
ports clear of the title bar."""

from __future__ import annotations

from PySide6.QtCore import QEvent, QPoint, QPointF, Qt
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import QApplication

from pfsense_checker import port_vlans as pv
from pfsense_checker.checker import check_file

CONTROLLER = """\
# 2026-11-07 by RouterOS 7.22.3
# model = CRS328-24P-4S+
/caps-man datapath
add bridge=BR name=DP-LAN vlan-id=630 vlan-mode=use-tag
add bridge=BR name=DP-IOT vlan-id=710 vlan-mode=use-tag
/caps-man configuration
add datapath=DP-LAN mode=ap name=CFG-LAN ssid=Home-LAN
add datapath=DP-IOT mode=ap name=CFG-IOT ssid=Home-IOT
/caps-man interface
add configuration=CFG-LAN master-interface=none name=CAP-1 radio-name=AABBCCDDEE01
add configuration=CFG-IOT master-interface=CAP-1 name=CAP-1-1 radio-name=AABBCCDDEE02
/system identity
set name=CORE
"""

CAP = """\
# 2026-11-07 by RouterOS 7.22.3
# model = CRS109-8G-1S-2HnD
/interface bridge
add name=OfficeBR
/interface bridge port
add bridge=OfficeBR interface=ether1 pvid=630
/interface wireless
set [ find default-name=wlan1 ] radio-name=AABBCCDDEE01 ssid=MikroTik vlan-mode=no-tag
/interface wireless cap
set bridge=OfficeBR enabled=yes interfaces=wlan1
"""

LOCAL_AP = """\
# 2026-11-07 by RouterOS 7.22.3
/interface wireless
set [ find default-name=wlan1 ] ssid=Guest vlan-id=800 vlan-mode=use-tag
"""


def _info(tmp_path, name: str, text: str) -> pv.DeviceVlans:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return pv.from_result(check_file(p))


def test_capsman_gives_cap_wlans_their_ssid_vlans_and_bridge(tmp_path) -> None:
    ctrl = _info(tmp_path, "core.rsc", CONTROLLER)
    cap = _info(tmp_path, "cap.rsc", CAP)
    assert [c.vid for c in ctrl.capsman] == ["630", "710"]
    assert ctrl.port("CAP-1").ssid == "Home-LAN"
    assert cap.bridge_of("wlan1") == "OfficeBR"  # the CAP puts its radio on its bridge
    assert cap.port("wlan1") is None  # local config says no-tag: needs the controller
    pv.link_capsman([("core", ctrl, ["CAP-1", "CAP-1-1"]), ("cap", cap, ["ether1", "wlan1", "wlan10"])])
    w1 = cap.port("wlan1")
    assert w1.untagged == ["630"] and w1.ssid == "Home-LAN" and "CAPsMAN on CORE" in w1.via
    virt = cap.port("wlan10")
    assert virt.untagged == ["710"] and virt.ssid == "Home-IOT" and "virtual AP" in virt.via
    assert cap.bridge_of("wlan10") == "OfficeBR"  # the virtual AP joins the bridge too


def test_local_ssid_vlan(tmp_path) -> None:
    info = _info(tmp_path, "ap.rsc", LOCAL_AP)
    port = info.port("wlan1")
    assert port.untagged == ["800"] and port.ssid == "Guest"


def test_wifi_tooltip_names_ssid_and_source() -> None:
    from pfsense_checker import site_canvas as sc

    tip = sc.port_vlan_tip(pv.PortVlans(untagged=["630"], ssid="Home-LAN", via="CAPsMAN on CORE"),
                           {"630": "LAN"})
    assert tip[0] == "SSID 'Home-LAN' → VLAN 630 (LAN)" and tip[1] == "Set by CAPsMAN on CORE"


def _view():  # noqa: ANN202
    from pfsense_checker import site_canvas as sc
    from pfsense_checker.topology_site import Device, SiteTopology

    QApplication.instance() or QApplication([])
    site = SiteTopology(name="t")
    site.devices.append(Device(name="sw", kind="mikrotik", model="CRS109-8G-1S-2HnD",
                               ports=["ether1", "ether2"], x=0.0, y=0.0))
    view = sc.SiteTopologyView()
    view.resize(900, 500)
    view.render_site(site)
    view.show()
    QApplication.processEvents()
    return view


def _send(view, kind, pos: QPoint, button, buttons) -> None:  # noqa: ANN001
    ev = QMouseEvent(kind, QPointF(pos), QPointF(view.viewport().mapToGlobal(pos)), button, buttons,
                     Qt.KeyboardModifier.NoModifier)
    QApplication.sendEvent(view.viewport(), ev)
    QApplication.processEvents()


def test_right_drag_on_empty_space_does_not_rubber_band() -> None:
    view = _view()
    empty = QPoint(850, 450)
    assert view.itemAt(empty) is None
    _send(view, QEvent.Type.MouseButtonPress, empty, Qt.MouseButton.RightButton, Qt.MouseButton.RightButton)
    for i in range(1, 5):
        _send(view, QEvent.Type.MouseMove, empty - QPoint(i * 30, i * 20), Qt.MouseButton.NoButton,
              Qt.MouseButton.RightButton)
        assert view.rubberBandRect().isNull()
    _send(view, QEvent.Type.MouseButtonRelease, empty, Qt.MouseButton.RightButton, Qt.MouseButton.NoButton)
    # left-drag still selects with a rubber band
    _send(view, QEvent.Type.MouseButtonPress, empty, Qt.MouseButton.LeftButton, Qt.MouseButton.LeftButton)
    _send(view, QEvent.Type.MouseMove, empty - QPoint(60, 40), Qt.MouseButton.NoButton, Qt.MouseButton.LeftButton)
    assert not view.rubberBandRect().isNull()
    view.close()


def test_ports_sit_below_the_title_bar() -> None:
    from pfsense_checker import site_canvas as sc

    view = _view()
    ch = view._chassis["sw"]  # noqa: SLF001
    tops = {round(p.pos().y()) for p in ch.port_items.values()}
    assert min(tops) >= sc.HEADER_H + sc.PORTS_GAP_BELOW_TITLE
    view.close()
