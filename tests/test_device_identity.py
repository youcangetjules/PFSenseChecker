"""Topology chassis: device type, model, OS and logo lookup from configs."""

from __future__ import annotations

from pfsense_checker import device_identity as di
from pfsense_checker.topology_site import Device

RSC = """# 2026-11-07 17:02:47 by RouterOS 7.22.3
# software id = XXXX-XXXX
#
# model = CRS109-8G-1S-2HnD
/interface bridge
add name=br1
/system identity
set name="CRS109-1(Office)"
"""

XML = """<?xml version="1.0"?>
<pfsense>
\t<version>24.6</version>
\t<system><hostname>guardian</hostname></system>
</pfsense>
"""


def test_identity_from_mikrotik_and_pfsense(tmp_path) -> None:
    rsc = tmp_path / "sw.rsc"
    rsc.write_text(RSC, encoding="utf-8")
    xml = tmp_path / "fw.xml"
    xml.write_text(XML, encoding="utf-8")
    mt = di.identity_from_config(rsc)
    assert (mt.vendor, mt.model, mt.os_version, mt.hostname) == (
        "mikrotik", "CRS109-8G-1S-2HnD", "RouterOS 7.22.3", "CRS109-1(Office)")
    pf = di.identity_from_config(xml)
    assert (pf.vendor, pf.os_version, pf.hostname) == ("pfsense", "config v24.6", "guardian")


def test_type_line(tmp_path, monkeypatch) -> None:
    rsc = tmp_path / "sw.rsc"
    rsc.write_text(RSC, encoding="utf-8")
    dev = Device(name="host-222-10-50-10", kind="mikrotik", config_file=str(rsc))
    assert di.type_line(dev) == ("Switch + Wi-Fi · MikroTik CRS109-8G-1S-2HnD · RouterOS 7.22.3 · "
                                 "identity CRS109-1(Office)")
    assert di.device_type(Device(name="x", kind="mikrotik", model="CRS328-4C-20S-4S+")) == di.TYPE_SWITCH
    assert di.device_type(Device(name="x", kind="mikrotik", model="CCR2004-1G-12S+2XS")) == di.TYPE_ROUTER
    assert di.device_type(Device(name="x", kind="pfsense")) == di.TYPE_FIREWALL


def test_logo_from_assets_folder(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(di, "LOGO_DIR", tmp_path)
    assert di.logo_path("mikrotik") is None
    (tmp_path / "mikrotik.png").write_bytes(b"x")
    assert di.logo_path("mikrotik") == tmp_path / "mikrotik.png"


def test_logo_aliases_case_and_format(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(di, "LOGO_DIR", tmp_path)
    (tmp_path / "FortiGate.PNG").write_bytes(b"x")
    (tmp_path / "hpe.webp").write_bytes(b"x")
    (tmp_path / "netgear.jpg").write_bytes(b"x")
    (tmp_path / "netgear.svg").write_text("<svg/>", encoding="utf-8")
    assert di.logo_path("fortinet").name == "FortiGate.PNG"
    assert di.logo_path("juniper").name == "hpe.webp"  # HPE owns Juniper
    assert di.logo_path("netgear-managed").suffix == ".svg"  # kind → vendor, SVG preferred
    assert di.logo_path("cisco") is None


def test_new_vendor_kinds_from_model() -> None:
    from pfsense_checker.topology_site import DEVICE_KINDS, kind_for_model

    assert kind_for_model("FortiGate 60F") == "fortinet"
    assert kind_for_model("FG-100F") == "fortinet"
    assert kind_for_model("Cisco Catalyst 9200") == "cisco"
    assert kind_for_model("CRS328-24P-4S+") == "mikrotik"
    assert {"fortinet", "cisco"} <= set(DEVICE_KINDS)
    assert di.identity_for(Device(name="x", kind="netgear-managed")).vendor_name == "Netgear"


def test_linksys_devices_and_logo(tmp_path, monkeypatch) -> None:
    from pfsense_checker.topology_site import DEVICE_KINDS, kind_for_model

    for model in ("Linksys Velop MX4200", "EA8300", "MR9600", "LGS308P", "WRT3200ACM"):
        assert kind_for_model(model) == "linksys", model
    assert kind_for_model("GS108E") != "linksys"
    assert "linksys" in DEVICE_KINDS
    monkeypatch.setattr(di, "LOGO_DIR", tmp_path)
    (tmp_path / "Linksys.JPG").write_bytes(b"x")
    assert di.logo_path("linksys").name == "Linksys.JPG"
    assert di.identity_for(Device(name="x", kind="linksys")).vendor_name == "Linksys"
    assert Device(name="ap1", kind="linksys").chassis_title() == "Linksys · ap1"
