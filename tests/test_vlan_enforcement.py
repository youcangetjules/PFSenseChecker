"""How a MikroTik bridge enforces VLANs: bridge filtering, switch chip, or nothing."""

from __future__ import annotations

from pfsense_checker import vlan_enforcement as v


def _raw(**sections):  # noqa: ANN003, ANN202
    return {k.replace("_", " "): rows for k, rows in sections.items()}


def test_hw_filtering_models() -> None:
    assert v.hw_vlan_filtering("CRS328-24P-4S+")
    assert v.hw_vlan_filtering("rb5009ug+s+in")
    assert not v.hw_vlan_filtering("CRS109-8G-1S-2HnD")
    assert not v.hw_vlan_filtering("")


def test_bridge_mode() -> None:
    raw = _raw(interface_bridge=[{"name": "BR", "vlan-filtering": "yes"}],
               interface_bridge_vlan=[{"bridge": "BR", "vlan-ids": "10,20"},
                                      {"bridge": "BR", "vlan-ids": "30", "disabled": "yes"}])
    e = v.bridge_enforcement(raw, "BR", "CRS328-24P-4S+")
    assert e.mode == v.MODE_BRIDGE and e.enforced and e.hw_filtering
    assert e.bridge_vlans == {"10", "20"}
    assert e.carries("10") == "yes" and e.carries("30") == "missing"
    assert "offloads" in e.describe()


def test_switch_chip_mode_and_unchecked_ports() -> None:
    raw = _raw(
        interface_bridge=[{"name": "BR", "vlan-filtering": "no"}],
        interface_bridge_port=[{"bridge": "BR", "interface": "ether1"}, {"bridge": "BR", "interface": "ether2"},
                               {"bridge": "BR", "interface": "wlan1"}],
        interface_ethernet_switch=[{"drop-if-invalid-or-src-port-not-member-of-vlan-on-ports": "ether1"}],
        interface_ethernet_switch_vlan=[{"vlan-id": "630", "ports": "ether1,sfp1,switch1-cpu"},
                                        {"vlan-id": "662", "ports": "ether2,sfp1"}],
    )
    e = v.bridge_enforcement(raw, "BR", "CRS109-8G-1S-2HnD")
    assert e.mode == v.MODE_SWITCH_CHIP and e.enforced
    assert e.chip_vlans == {"630", "662"} and e.cpu_vlans == {"630"}
    assert e.carries("630") == "yes" and e.carries("662") == "missing"  # 662 has no CPU port
    assert e.unchecked_ports == ["ether2"]  # wlan is not a switch port
    assert "right design" in e.describe()


def test_unenforced_and_remedies() -> None:
    raw = _raw(interface_bridge=[{"name": "BR"}],
               interface_bridge_vlan=[{"bridge": "BR", "vlan-ids": "10"}])
    old = v.bridge_enforcement(raw, "BR", "CRS109-8G-1S-2HnD")
    assert old.mode == v.MODE_NONE and not old.enforced and old.carries("10") == "unenforced"
    assert "switch chip" in old.remedy("CRS109-1") and "as CRS109-1 does" in old.remedy("CRS109-1")
    new = v.bridge_enforcement(raw, "BR", "CRS328-24P-4S+")
    assert new.remedy().startswith("Set vlan-filtering=yes on BR")


def test_device_bridges_skips_disabled() -> None:
    raw = _raw(interface_bridge=[{"name": "A"}, {"name": "B", "disabled": "yes"}, {"name": ""}])
    assert [e.bridge for e in v.device_bridges(raw)] == ["A"]
