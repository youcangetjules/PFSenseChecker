"""Name Parser: coded port names decoded with a settable scheme."""

from __future__ import annotations

from pfsense_checker import name_parser as n


def test_default_scheme_decodes_examples() -> None:
    s = n.default_scheme()
    assert n.readable("0_S3_P0_1G_F_LB_5820_direct", s) == (
        "Physical port · Slot 3 · Port 0 · 1 Gbps · Fiber · LB 5820 direct")
    assert n.readable("0_S2_P3_1G_E_WAN3_last_line", s).endswith("Ethernet · WAN3 last line")
    assert n.readable("1_IV2_VL630_MCE1_LAN", s) == "VLAN interface · IV2 · VLAN 630 · MCE1 LAN"
    # single-letter media codes are not read inside the label
    assert n.readable("2_BR0_1G_LB_CRS_F_MCN_E", s) == "Bridge · Bridge 0 · 1 Gbps · LB CRS F MCN E"
    assert n.readable("SLOT0_PORT0_150MB_FIB_BKUP_DHCP", s).startswith("Slot 0 · Port 0 · 150 Mbps · Fiber")
    for plain in ("OPT4", "host-100-48-62-1", "V2-S4-VL630-LAN", "wan"):
        assert n.readable(plain, s) == ""


def test_readable_in_subject() -> None:
    s = n.default_scheme()
    assert n.readable_in("opt6 (0_S3_P0_1G_F_LB_5820_direct) 100.48.62.0/24", s).startswith("Physical port")
    assert n.readable_in("Default route", s) == ""


def test_scheme_is_settable_and_saved(tmp_path) -> None:
    s = n.default_scheme()
    s.type_codes["9"] = "MACVLAN"
    s.rules.append(n.TokenRule(r"N(\d+)S(\d+)\w*", "Node {1} slot {2}", "Node"))
    path = tmp_path / "np.json"
    n.save_scheme(s, path)
    back = n.load_scheme(path)
    assert back.type_codes["9"] == "MACVLAN"
    assert n.readable("9_0_N1S5MACVLANAVL801", back) == "MACVLAN · 0 · Node 1 slot 5"
    dashed = n.NameScheme("-", {"V2": "VLAN two"}, [n.TokenRule(r"VL(\d+)", "VLAN {1}", "VLAN")])
    assert n.readable("V2-S4-VL630-LAN", dashed) == "VLAN two · S4 · VLAN 630 · LAN"


def test_rule_errors() -> None:
    assert n.rule_error(n.TokenRule(r"S(\d+", "x")).startswith("Pattern does not compile")
    assert "group" in n.rule_error(n.TokenRule(r"S\d+", "Slot {1}"))
    assert n.rule_error(n.TokenRule(r"S(\d+)", "Slot {1}")) == ""


def test_interface_kind() -> None:
    s = n.default_scheme()
    assert n.interface_kind("opt18 (1_IV2_VL630_MCE1_LAN) 222.10.50.0/24", s) == "vlan"
    assert n.interface_kind("opt22 (2_BR0_1G_LB_CRS_F_MCN_E) 222.20.20.0/24", s) == "bridge"
    assert n.interface_kind("opt6 (0_S3_P0_1G_F_LB_5820_direct)", s) == ""
    assert n.interface_kind("bridge CRS109-1-Master-Bridge", s) == "bridge"
