"""Device library + Add Device: models load, ports expand, user files override."""

from __future__ import annotations

import json

import pytest

from pfsense_checker import device_library as dl


def test_builtin_libraries_load_cleanly() -> None:
    lib = dl.load_library([dl.BUILTIN_DIR])
    assert not lib.errors and len(lib.files) >= 9
    assert {"MikroTik", "Netgate (pfSense)", "Juniper", "Linksys", "Generic"} <= set(lib.vendors())
    crs = lib.get("MikroTik", "CRS328-4C-20S-4S+RM")
    names = [p.name for p in crs.ports]
    assert names[:4] == ["combo1", "combo2", "combo3", "combo4"] and names[-1] == "sfp-sfpplus4"
    assert len(names) == 28 and crs.summary() == "4× 1G · combo · 20× 1G · sfp · 4× 10G · sfp+"
    for vendor in lib.vendors():
        for spec in lib.models_of(vendor):
            assert spec.ports, f"{vendor} {spec.model} has no ports"


def test_expand_ports_and_duplicates() -> None:
    ports = dl.expand_ports([{"name": "ge-0/0/{n}", "count": 2, "start": 6, "media": "1G · sfp"}])
    assert [p.name for p in ports] == ["ge-0/0/6", "ge-0/0/7"]
    with pytest.raises(ValueError, match="duplicate"):
        dl.expand_ports([{"name": "eth{n}", "count": 2}, {"name": "eth1"}])


def test_user_library_adds_and_overrides(tmp_path) -> None:
    builtin = tmp_path / "b"
    user = tmp_path / "u"
    builtin.mkdir()
    user.mkdir()
    (builtin / "v.json").write_text(json.dumps({"vendor": "Acme", "kind": "router", "models": [
        {"model": "R1", "ports": [{"name": "eth{n}", "count": 2}]}]}), encoding="utf-8")
    (user / "mine.json").write_text(json.dumps({"vendor": "Acme", "kind": "router", "models": [
        {"model": "R1", "ports": [{"name": "eth{n}", "count": 4}]},
        {"model": "R2", "ports": [{"name": "wan"}]}]}), encoding="utf-8")
    (user / "broken.json").write_text("{not json", encoding="utf-8")
    lib = dl.load_library([builtin, user])
    assert len(lib.get("Acme", "R1").ports) == 4  # user file wins
    assert lib.get("Acme", "R2") is not None
    assert lib.errors and lib.errors[0].startswith("broken.json")


def test_make_device_and_unique_names() -> None:
    lib = dl.load_library([dl.BUILTIN_DIR])
    spec = lib.get("Juniper", "SRX300")
    dev = dl.make_device(spec, "edge", mgmt_ip="10.0.0.1")
    assert dev.kind == "juniper" and dev.model == "SRX300" and dev.role == "egress"
    assert dev.ports[0] == "ge-0/0/0" and len(dev.components) == 8
    assert dev.components[7].media == "1G · sfp"
    assert dev.mgmt_ip == "10.0.0.1" and dev.ssh is not None
    assert dl.unique_name({"edge", "edge-2"}, "edge") == "edge-3"
    assert dl.unique_name(set(), "") == "device"


def test_dialog_validates_and_builds_device() -> None:
    from PySide6.QtWidgets import QApplication

    from pfsense_checker.add_device_dialog import AddDeviceDialog

    QApplication.instance() or QApplication([])
    dlg = AddDeviceDialog({"taken"}, library=dl.load_library([dl.BUILTIN_DIR]))
    dlg.vendor.setCurrentText("MikroTik")
    dlg.model.setCurrentText("hAP ax3")
    assert dlg.name.text() == "hAP-ax3" and "wifi1" in dlg.ports.toPlainText()
    dlg.name.setText("taken")
    dlg._accept()  # noqa: SLF001
    assert dlg.device() is None and "already" in dlg.error.text()
    dlg.name.setText("office-ap")
    dlg.ip.setText("not-an-ip")
    dlg._accept()  # noqa: SLF001
    assert dlg.device() is None and "not an IP" in dlg.error.text()
    dlg.ip.setText("192.168.1.2")
    dlg._accept()  # noqa: SLF001
    dev = dlg.device()
    assert dev.name == "office-ap" and dev.model == "hAP ax3" and dev.mgmt_ip == "192.168.1.2"


def test_topology_add_device_button(monkeypatch) -> None:
    from PySide6.QtWidgets import QApplication, QDialog

    from pfsense_checker import add_device_dialog
    from pfsense_checker.home_screen import HomeScreen
    from pfsense_checker.topology_site import SiteTopology

    QApplication.instance() or QApplication([])
    lib = dl.load_library([dl.BUILTIN_DIR])

    class _Auto(add_device_dialog.AddDeviceDialog):
        def exec(self) -> int:  # noqa: D102
            self.vendor.setCurrentText("Netgate (pfSense)")
            self.model.setCurrentText("Netgate 4200")
            self._accept()
            return QDialog.DialogCode.Accepted

    monkeypatch.setattr(add_device_dialog, "AddDeviceDialog", lambda names, parent=None: _Auto(names, parent, lib))
    home = HomeScreen()
    home._ensure_page("topology")  # noqa: SLF001
    site = SiteTopology(name="t")
    home.set_sites(live=site)
    home._topology_add_device()  # noqa: SLF001
    assert [d.model for d in site.devices] == ["Netgate 4200"]
    assert site.devices[0].x is not None
    assert home.topo_preview.selected_device() == site.devices[0].name
