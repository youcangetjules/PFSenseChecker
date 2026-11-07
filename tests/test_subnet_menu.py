"""Subnets panel right-click (Scan / Alter / Remove) and live subnets."""

from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pfsense_checker import net_discovery as nd  # noqa: E402
from pfsense_checker import subnet_health  # noqa: E402


def _app():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def test_subnet_from_parts_normalises_to_the_network() -> None:
    from pfsense_checker.session_screen import subnet_from_parts, subnet_usable_hosts

    assert subnet_from_parts("222.10.50.77", 24) == "222.10.50.0/24"
    assert subnet_from_parts("10.1.2.3", 22) == "10.1.0.0/22"
    assert subnet_usable_hosts("10.1.0.0/22") == 1022
    assert subnet_usable_hosts("10.0.0.0/31") == 2
    with pytest.raises(ValueError):
        subnet_from_parts("not-an-ip", 24)


def test_alter_dialog_validates() -> None:
    _app()
    from PySide6.QtWidgets import QDialogButtonBox

    from pfsense_checker.session_screen import _AlterSubnetDialog

    dlg = _AlterSubnetDialog("222.10.50.0/24", ["222.10.50.0/24", "100.48.62.0/24"])
    ok = dlg.buttons.button(QDialogButtonBox.StandardButton.Ok)
    dlg.prefix.setValue(23)
    assert dlg.new_cidr == "222.10.50.0/23" and ok.isEnabled()
    dlg.address.setText("100.48.62.9")
    dlg.prefix.setValue(24)
    assert not ok.isEnabled()  # already listed
    dlg.address.setText("999.1.1.1")
    assert not ok.isEnabled()
    dlg.address.setText("172.28.0.0")
    dlg.prefix.setValue(16)
    assert ok.isEnabled() and "not be swept" in dlg.result_label.text()


def _screen(monkeypatch, subnets: list[str]):
    from pfsense_checker import session_screen
    from pfsense_checker.topology_site import SiteTopology

    _app()
    swept: list[str] = []

    def fake_discover(cidr, **kwargs):  # noqa: ANN001
        swept.append(cidr)
        return []

    monkeypatch.setattr(nd, "discover", fake_discover)
    monkeypatch.setattr(nd, "default_gateways", lambda: set())
    screen = session_screen.SessionScreen()
    screen.set_site(SiteTopology(subnets=list(subnets)))
    return screen, swept


def _drain(screen) -> None:  # noqa: ANN001
    from PySide6.QtWidgets import QApplication

    for _ in range(50):
        worker = screen._discovery_worker
        if worker is not None:
            worker.wait(5000)
        QApplication.processEvents()
        if screen._discovery_worker is None and not screen._discovery_queue:
            return


def test_alter_replaces_in_place_and_sweeps_the_new_subnet(monkeypatch) -> None:
    screen, swept = _screen(monkeypatch, ["10.0.0.0/24", "222.10.50.0/24", "10.9.0.0/24"])
    _drain(screen)
    swept.clear()
    screen._replace_subnet("222.10.50.0/24", "222.10.50.0/23")
    _drain(screen)
    assert screen._site.subnets == ["10.0.0.0/24", "222.10.50.0/23", "10.9.0.0/24"]
    assert swept == ["222.10.50.0/23"]
    assert "222.10.50.0/24" not in screen._seen_state
    assert screen.subnet_table.item(1, 0).text() == "222.10.50.0/23"


def test_remove_and_scan_this_subnet(monkeypatch) -> None:
    screen, swept = _screen(monkeypatch, ["10.0.0.0/24", "10.9.0.0/24"])
    _drain(screen)
    swept.clear()
    screen._start_discovery(["10.9.0.0/24"], rescan=True)  # "Scan this subnet"
    _drain(screen)
    assert swept == ["10.9.0.0/24"]
    screen._remove_subnet("10.0.0.0/24")
    assert screen._site.subnets == ["10.9.0.0/24"]
    assert screen.subnet_table.rowCount() == 1


def test_windows_adapter_discovery_parses_powershell(monkeypatch) -> None:
    payload = {
        "ips": [
            {"InterfaceIndex": 7, "InterfaceAlias": "LAN", "IPAddress": "222.10.50.25", "PrefixLength": 24},
            {"InterfaceIndex": 9, "InterfaceAlias": "vEthernet (Default Switch)", "IPAddress": "172.24.32.1", "PrefixLength": 20},
        ],
        "ads": [
            {"ifIndex": 7, "Name": "LAN", "MacAddress": "AA-BB-CC-DD-EE-FF", "LinkSpeed": "1 Gbps",
             "FullDuplex": True, "PhysicalMediaType": "802.3", "InterfaceDescription": "Intel Ethernet"},
            {"ifIndex": 9, "Name": "vEthernet (Default Switch)", "LinkSpeed": "10 Gbps",
             "InterfaceDescription": "Hyper-V Virtual Ethernet Adapter"},
        ],
        "mtu": [{"InterfaceIndex": 7, "NlMtu": 1500}],
        "gw": [{"InterfaceIndex": 7, "NextHop": "222.10.50.1"}],
    }
    monkeypatch.setattr(subnet_health.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        subnet_health.winproc,
        "run",
        lambda *a, **k: SimpleNamespace(stdout=json.dumps(payload), returncode=0),
    )
    rows = subnet_health.discover_local_subnets(force_refresh=True)
    lan = next(r for r in rows if r.ip == "222.10.50.25")
    assert (lan.cidr, lan.gateway, lan.link_type, lan.duplex, lan.mtu) == (
        "222.10.50.0/24", "222.10.50.1", "wired", "full", 1500,
    )
    assert lan.mac == "aa:bb:cc:dd:ee:ff"
    hv = next(r for r in rows if r.ip == "172.24.32.1")
    assert hv.link_type == "virtual"
    text = subnet_health.describe_local_adapter("222.10.50.0/24")
    assert "speed 1 Gbps" in text and "MTU 1500" in text
    assert "reached by routing" in subnet_health.describe_local_adapter("100.48.64.0/24")


def test_ignore_device_greys_out_and_is_saved(monkeypatch) -> None:
    from PySide6.QtWidgets import QCheckBox

    from pfsense_checker import session_screen
    from pfsense_checker.topology_site import Device, SiteTopology

    _app()
    monkeypatch.setattr(nd, "discover", lambda cidr, **k: [])
    monkeypatch.setattr(nd, "default_gateways", lambda: set())
    site = SiteTopology(subnets=["222.10.50.0/24"])
    for n in (1, 5):
        dev = Device(name=f"host-222-10-50-{n}", kind="mikrotik", mgmt_ip=f"222.10.50.{n}")
        ssh = dev.ensure_ssh()
        ssh.host, ssh.last_status = f"222.10.50.{n}", "ok"
        site.add_or_update_device(dev)
    screen = session_screen.SessionScreen()
    screen.set_site(site)
    _drain(screen)
    assert len(screen._connected_devices_in_subnet("222.10.50.0/24")) == 2

    gw = screen._site.device("host-222-10-50-1")
    screen._set_device_ignored(gw, True)
    row = next(r for r in range(screen.table.rowCount())
               if screen.table.item(r, session_screen.COL_DEVICE).text() == gw.name)
    box = screen.table.cellWidget(row, session_screen.COL_INCLUDE).findChild(QCheckBox)
    assert not box.isChecked() and not box.isEnabled()
    assert screen.table.item(row, session_screen.COL_STATUS).text() == "● ignored"
    assert gw.name not in screen._included_device_names()
    assert [d.name for d in screen._connected_devices_in_subnet("222.10.50.0/24")] == [
        "host-222-10-50-5"
    ]
    # Saved with the site and restored.
    again = SiteTopology.from_dict(screen._site.to_dict())
    assert again.device(gw.name).ignored is True
    # A later sweep that sees it does not touch it.
    seen = [nd.SeenDevice(ip="222.10.50.1", role="firewall", vendor="pfSense")]
    assert screen._add_seen_to_site(seen) is False
    assert gw.kind == "mikrotik"

    screen._set_device_ignored(gw, False)
    assert len(screen._connected_devices_in_subnet("222.10.50.0/24")) == 2
