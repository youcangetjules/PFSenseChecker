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


# --- The full library: endpoints as well as network gear -------------------- #


def _ports(lib: dl.Library, vendor: str, model: str) -> list[tuple[str, str]]:
    spec = lib.get(vendor, model)
    assert spec is not None, f"{vendor} {model} is not in the library"
    return [(p.name, p.media) for p in spec.ports]


def test_library_covers_endpoints_and_every_model_is_usable() -> None:
    from pfsense_checker.topology_site import DEVICE_KINDS, DEVICE_ROLES
    from pfsense_checker.viz import DEVICE_KIND_COLORS

    lib = dl.load_library([dl.BUILTIN_DIR])
    assert not lib.errors and lib.count() >= 700 and len(lib.vendors()) >= 55
    assert lib.categories() == list(dl.CATEGORIES)  # every category has models, in the fixed order
    for vendor in lib.vendors():
        for spec in lib.models_of(vendor):
            where = f"{vendor} {spec.model}"
            assert spec.ports, f"{where} has no ports"
            assert spec.kind in DEVICE_KINDS, f"{where}: kind {spec.kind!r} is not a NetCheck device kind"
            assert spec.kind in DEVICE_KIND_COLORS, f"{where}: kind {spec.kind!r} has no colour"
            assert spec.role in DEVICE_ROLES, f"{where}: role {spec.role!r} is not a NetCheck role"
            assert spec.category in dl.CATEGORIES, f"{where}: category {spec.category!r}"
    # What was asked for is there.
    for vendor, model in (
        ("Dell", "PowerEdge R730"), ("HP / HPE", "ProLiant DL380 Gen10"), ("Dell", "Precision 5820 Tower"),
        ("Dell", "OptiPlex 9010 USFF"), ("Dell", "U2722DE"), ("Denon", "AVR-X2800H"), ("Sky", "Sky Q box (1TB / 2TB)"),
        ("Tasmota (ESP8266 / ESP32)", "Sonoff Basic R3"), ("WiZ", "A60 bulb"), ("Juniper", "EX2300-24T"),
        ("Sony", "PlayStation 5"), ("Microsoft", "Xbox Series X"), ("USR IOT (PUSR)", "USR-TCP232-410S"),
        ("Moxa", "NPort 5150"), ("Waveshare", "RS485 TO ETH (B)"),
    ):
        assert lib.get(vendor, model) is not None, f"{vendor} {model}"


def test_port_layouts_of_some_models() -> None:
    lib = dl.load_library([dl.BUILTIN_DIR])
    assert _ports(lib, "Dell", "PowerEdge R730") == [
        ("NIC1", "1G · copper"), ("NIC2", "1G · copper"), ("NIC3", "1G · copper"), ("NIC4", "1G · copper"),
        ("iDRAC", "copper · management")]
    assert _ports(lib, "HP / HPE", "ProLiant MicroServer Gen8") == [
        ("NIC 1", "1G · copper"), ("NIC 2", "1G · copper"), ("iLO", "copper · management")]
    assert _ports(lib, "Dell", "OptiPlex 9010 USFF") == [("LAN", "1G · copper")]
    assert _ports(lib, "Lenovo", "ThinkStation P620") == [("LAN", "10G · copper")]
    names = [n for n, _m in _ports(lib, "Juniper", "EX3400-48P")]
    assert names[0] == "ge-0/0/0" and names[47] == "ge-0/0/47" and names[48:] == [
        "xe-0/2/0", "xe-0/2/1", "xe-0/2/2", "xe-0/2/3", "et-0/1/0", "et-0/1/1", "me0"]
    srx = _ports(lib, "Juniper", "SRX340")
    assert srx[7] == ("ge-0/0/7", "1G · copper") and srx[8] == ("ge-0/0/8", "1G · sfp") and srx[-1][0] == "fxp0"
    assert _ports(lib, "Denon", "AVR-X2800H") == [("LAN", "100M · copper"), ("wlan", "wlan · 2.4 + 5 GHz")]
    assert _ports(lib, "WiZ", "A60 bulb") == [("wlan", "wlan · 2.4 GHz")]  # 2.4 GHz only
    assert _ports(lib, "Tasmota (ESP8266 / ESP32)", "Olimex ESP32-POE")[0] == ("eth0", "100M · copper · PoE")
    assert _ports(lib, "USR IOT (PUSR)", "USR-TCP232-410S") == [
        ("ETH", "100M · copper"), ("RS232", "serial · RS-232"), ("RS485", "serial · RS-485")]
    assert _ports(lib, "Moxa", "NPort 5450")[1:] == [(f"P{i}", "serial · RS-232/422/485") for i in range(1, 5)]
    assert _ports(lib, "Dell", "U2722DE")[0] == ("RJ45", "1G · copper")
    assert _ports(lib, "Sony", "PlayStation 5") == [("LAN", "1G · copper"), ("wlan", "wlan · 2.4 + 5 GHz")]
    assert _ports(lib, "Nintendo", "Switch") == [("wlan", "wlan · 2.4 + 5 GHz")]  # no wired port without a dock
    # The models that were there before are still there, unchanged.
    assert lib.get("MikroTik", "CRS328-4C-20S-4S+RM").summary() == "4× 1G · combo · 20× 1G · sfp · 4× 10G · sfp+"
    assert len(lib.get("Juniper", "SRX300").ports) == 8


def test_categories_search_and_order() -> None:
    lib = dl.load_library([dl.BUILTIN_DIR])
    cat = dl.category_of
    assert cat("mikrotik", "access-switch", "Switch + Wi-Fi") == "Switches"  # role first
    assert cat("pfsense", "firewall") == "Firewalls & routers" and cat("server", "server") == "Servers"
    assert cat("sff", "sff") == "Desktops & mini PCs" and cat("iot", "iot") == "Smart home & IoT"
    assert cat("host", "host", "Phone / tablet") == "Laptops, phones & tablets"
    assert cat("cisco", "", "Access point") == "Wi-Fi" and cat("other") == "Other"
    assert cat("switch", "access-switch", "Switch", explicit="Lab gear") == "Lab gear"  # a file's own word wins

    assert lib.get("Dell", "PowerEdge R730").category == "Servers"
    assert lib.get("Dell", "PowerSwitch N1524").category == "Switches"  # per-model kind inside a server file
    assert lib.get("Sky", "Sky Glass").category == "Monitors & TVs"
    assert lib.get("TP-Link", "Kasa smart plug (HS100 / HS110 / KP115)").category == "Smart home & IoT"

    serial = lib.vendors("Serial / RS485 converters")
    assert {"Moxa", "USR IOT (PUSR)", "Waveshare", "Generic"} <= set(serial) and "Dell" not in serial
    assert [s.model for s in lib.models_of("Dell", "Monitors & TVs")][:2] == ["Monitor (HDMI + DisplayPort)", "P2422HE"]
    assert lib.vendors(search="optiplex 9010") == ["Dell"]
    assert [s.model for s in lib.models_of("Dell", search="optiplex 9010")] == [
        "OptiPlex 9010 SFF", "OptiPlex 9010 Tower", "OptiPlex 9010 USFF"]
    assert "Denon" in lib.vendors(search="av receiver") and lib.vendors(search="no-such-thing") == []
    # Numbers sort as numbers: R230 before R620, G2 before G10.
    servers = [s.model for s in lib.models_of("Dell", "Servers")]
    assert servers.index("PowerEdge R230") < servers.index("PowerEdge R620") < servers.index("PowerEdge T30")


def test_new_kinds_make_devices_with_a_type() -> None:
    from pfsense_checker import device_identity

    lib = dl.load_library([dl.BUILTIN_DIR])
    dev = dl.make_device(lib.get("Denon", "AVR-X2800H"), "lounge-avr")
    assert (dev.kind, dev.role) == ("av-receiver", "av-receiver") and [c.name for c in dev.components] == ["LAN", "wlan"]
    assert device_identity.device_type(dev) == "AV receiver"
    rs485 = dl.make_device(lib.get("Waveshare", "RS485 TO ETH (B)"), "inverter-link", mgmt_ip="222.20.20.60")
    assert rs485.kind == "serial-converter" and device_identity.device_type(rs485) == "Serial converter"
    assert device_identity.device_type(dl.make_device(lib.get("Dell", "PowerEdge R730"), "r730")) == "Server"
    assert device_identity.device_type(dl.make_device(lib.get("Dell", "PowerSwitch N1524"), "sw")) == "Switch"


def test_dialog_category_and_search_narrow_the_lists() -> None:
    from PySide6.QtWidgets import QApplication

    from pfsense_checker.add_device_dialog import ALL_CATEGORIES, AddDeviceDialog

    QApplication.instance() or QApplication([])
    lib = dl.load_library([dl.BUILTIN_DIR])
    dlg = AddDeviceDialog(set(), library=lib)
    assert dlg.category.itemText(0) == ALL_CATEGORIES and dlg.category.count() == len(dl.CATEGORIES) + 1
    assert dlg.vendor.count() == len(lib.vendors())

    dlg.category.setCurrentText("Game consoles")
    makers = [dlg.vendor.itemText(i) for i in range(dlg.vendor.count())]
    assert makers == ["Generic", "Meta", "Microsoft", "Nintendo", "Sony", "Valve"]
    dlg.vendor.setCurrentText("Sony")
    models = [dlg.model.itemText(i) for i in range(dlg.model.count())]
    assert "PlayStation 5" in models and "Bravia TV (LAN + Wi-Fi)" not in models  # the TV is not a console
    assert dlg.details.text().startswith("Game consoles · Game console")

    dlg.category.setCurrentIndex(0)
    assert dlg.vendor.currentText() == "Sony"  # widening the filter keeps the choice
    dlg.search.setText("rs485")
    assert "Sony" not in [dlg.vendor.itemText(i) for i in range(dlg.vendor.count())]
    dlg.vendor.setCurrentText("Waveshare")
    dlg.model.setCurrentText("RS485 TO POE ETH (B)")
    dlg.name.setText("meter-link")
    dlg._accept()  # noqa: SLF001
    dev = dlg.device()
    assert dev is not None and dev.kind == "serial-converter" and dev.ports == ["ETH", "RS485"]

    dlg2 = AddDeviceDialog(set(), library=lib)
    dlg2.search.setText("no-such-thing")
    assert dlg2.vendor.count() == 0 and not dlg2.add_btn.isEnabled()
    assert "Nothing in the library matches" in dlg2.details.text()
    dlg2.search.clear()
    assert dlg2.add_btn.isEnabled() and dlg2.vendor.count() == len(lib.vendors())
