"""Physical Layout workbook import: VLAN cards, named gear, helpers."""

from __future__ import annotations

import pytest

from pfsense_checker import excel_layout as x


def test_helpers() -> None:
    assert x._slug(" Core / Switch #1 ") == "Core-Switch-1"  # noqa: SLF001
    assert x._slug("!!!") == "device"  # noqa: SLF001
    assert x._infer_role_kind("Mikrotik CRS328-24P") == ("core-switch", "switch")  # noqa: SLF001
    assert x._infer_role_kind("pfSense box") == ("firewall", "pfsense")  # noqa: SLF001
    assert x._infer_role_kind("TalkTalk router") == ("isp", "isp")  # noqa: SLF001
    assert x._infer_role_kind("toaster") == ("other", "other")  # noqa: SLF001


def test_vlan_cards_from_label_clusters() -> None:
    cells = [
        (2, 2, "IF"), (2, 3, "1_IV2_VL630_LAN"),
        (3, 2, "NW"), (3, 3, "222.10.50.0/24"),
        (4, 2, "S-IP/GW"), (4, 3, "222.10.50.1"),
        (5, 2, "DHCP"), (5, 4, "222.10.50.64-193"),
        (9, 9, "IF"),  # a label with nothing to its right is skipped
    ]
    cards = x._parse_vlan_cards(cells)  # noqa: SLF001
    assert len(cards) == 1
    card = cards[0]
    assert card["if_label"] == "1_IV2_VL630_LAN" and card["subnet"] == "222.10.50.0/24"
    assert card["s_ip"] == "222.10.50.1" and card["dhcp_pool"] == "222.10.50.64-193"


def test_import_workbook(tmp_path) -> None:
    openpyxl = pytest.importorskip("openpyxl")
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Physical Layout"
    ws["B2"], ws["C2"] = "Firewall 1 SECPOL: S1", "PFSense Netgate 6100"
    ws["B6"], ws["C6"] = "IF", "1_IV2_VL630_LAN"
    ws["B7"], ws["C7"] = "NW", "222.10.50.0/24"
    ws["B8"], ws["C8"] = "S-IP", "222.10.50.1"
    path = tmp_path / "layout.xlsx"
    wb.save(path)
    site = x.import_physical_layout_xlsx(path)
    assert site.name == "Imported — layout"
    fw = [d for d in site.devices if d.kind == "pfsense"]
    assert fw and fw[0].secpol == "S1"
    vlan = next(v for v in site.vlans if v.id == "630")
    assert vlan.subnet == "222.10.50.0/24" and vlan.s_ip == "222.10.50.1"
    summary = x.import_physical_layout_summary(site)
    assert "VLAN cards" in summary and summary.startswith(f"{len(site.devices)} devices")
