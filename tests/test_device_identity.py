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
