"""Internet | external VLANs | gateway groups | NIC | port name | VLANs. The port name outranks OPT15."""

from pfsense_checker.firewall_topology import build_config_topology, is_hardware_port, tree_order
from pfsense_checker.models import BridgeInfo, CheckResult, InterfaceInfo, VlanInfo, VpnEndpoint


def _iface(name: str, device: str, descr: str, **kwargs) -> InterfaceInfo:
    return InterfaceInfo(name=name, device=device, descr=descr, enabled=True, **kwargs)


def _links(graph) -> set[tuple[str, str, str, str]]:
    return {(e.src_layer, e.src_id, e.dst_layer, e.dst_id) for e in graph.edges}


def test_assigned_names_are_not_physical_ports() -> None:
    assert is_hardware_port("ixl1")
    assert is_hardware_port("igb0")
    assert not is_hardware_port("opt15")
    assert not is_hardware_port("OPT11")
    assert not is_hardware_port("igb0.10")
    assert not is_hardware_port("lagg0")


def test_nic_feeds_its_port_name_and_the_port_name_feeds_its_vlans() -> None:
    result = CheckResult()
    result.interfaces = [
        _iface("opt1", "igb0", "UPLINK", kind="physical"),
        _iface("opt2", "igb0.10", "CAMERAS", kind="vlan", ipaddr="10.10.10.1", subnet="24"),
        _iface("opt3", "igb0.20", "GUEST", kind="vlan"),
        _iface("opt15", "igb0.30", "WAREHOUSE", kind="vlan"),
    ]
    result.vlans = [
        VlanInfo(tag="10", if_parent="igb0", vlanif="igb0.10", descr="CAMERAS"),
        VlanInfo(tag="20", if_parent="igb0", vlanif="igb0.20", descr="GUEST"),
        VlanInfo(tag="30", if_parent="igb0", vlanif="igb0.30", descr="WAREHOUSE"),
    ]
    graph = build_config_topology(result)
    assert graph.layers["phys"] == ["igb0"]
    assert graph.layers["port"] == ["opt1"]
    links = _links(graph)
    assert ("phys", "igb0", "port", "opt1") in links
    for vlanif in ("igb0.10", "igb0.20", "igb0.30"):
        assert ("port", "opt1", "vlan", vlanif) in links
        assert ("phys", "igb0", "vlan", vlanif) not in links

    vlan = graph.boxes[("vlan", "igb0.30")]
    assert vlan.title == "WAREHOUSE"
    assert "on igb0" in vlan.subtitle
    assert "OPT15" in vlan.subtitle
    assert ("port", "opt15") not in graph.boxes


def test_unassigned_nic_feeds_its_vlans_directly() -> None:
    result = CheckResult()
    result.interfaces = [
        _iface("opt16", "ixl2.1628", "DOORS", kind="vlan"),
        _iface("opt17", "ixl2.1629", "LOCKS", kind="vlan"),
    ]
    result.vlans = [
        VlanInfo(tag="1628", if_parent="ixl2", vlanif="ixl2.1628"),
        VlanInfo(tag="1629", if_parent="ixl2", vlanif="ixl2.1629"),
    ]
    graph = build_config_topology(result)
    assert graph.layers["phys"] == ["ixl2"]
    links = _links(graph)
    assert ("phys", "ixl2", "vlan", "ixl2.1628") in links
    assert ("phys", "ixl2", "vlan", "ixl2.1629") in links
    assert graph.boxes[("vlan", "ixl2.1628")].title == "DOORS"


def test_vlan_parent_given_as_an_opt_hangs_off_that_port_name() -> None:
    result = CheckResult()
    result.interfaces = [
        _iface("opt11", "ixl2", "TRUNK", kind="physical"),
        _iface("opt16", "ixl2.1628", "DOORS", kind="vlan"),
    ]
    result.vlans = [VlanInfo(tag="1628", if_parent="opt11", vlanif="ixl2.1628")]
    graph = build_config_topology(result)
    assert graph.layers["phys"] == ["ixl2"]
    links = _links(graph)
    assert ("phys", "ixl2", "port", "opt11") in links
    assert ("port", "opt11", "vlan", "ixl2.1628") in links


def _guardian_like() -> CheckResult:
    """Three WANs; em0 + mce0 in a failover group carrying three EVL tunnels."""
    result = CheckResult()
    result.interfaces = [
        _iface("wan", "igb3", "0_S2_P3_E_1G_last_line", kind="physical", ipaddr="dhcp"),
        _iface("opt1", "em0", "0_S0_P0_F_1G_Secondary", kind="physical", ipaddr="dhcp"),
        _iface("opt2", "mce0", "0_S1_P0_F_1G_fib_main", kind="physical", ipaddr="dhcp"),
        _iface("lan", "igb1", "LAN", kind="physical", ipaddr="192.168.1.1", subnet="24"),
        _iface("opt8", "ovpnc1", "3_EVL1_EXVPNAN", kind="openvpn"),
        _iface("opt9", "ovpnc2", "3_EVL2_EXVPNJP", kind="openvpn"),
        _iface("opt10", "ovpnc3", "3_EVL3_EXVPNMO", kind="openvpn"),
        _iface("opt3", "igb0", "MCN", kind="physical", ipaddr="10.0.0.1", subnet="24"),
        _iface("opt13", "igb0.710", "VL710_BM1", kind="vlan"),
        _iface("opt15", "igb0.800", "VL800", kind="vlan"),
        _iface("opt22", "bridge0", "BR1", kind="bridge"),
    ]
    result.vlans = [
        VlanInfo(tag="710", if_parent="igb0", vlanif="igb0.710", assigned_as="opt13"),
        VlanInfo(tag="800", if_parent="igb0", vlanif="igb0.800", assigned_as="opt15"),
    ]
    result.bridges = [BridgeInfo(bridgeif="bridge0", members=["opt13"], assigned_as="opt22")]
    result.gateways = [
        {"name": "WAN_DHCP", "interface": "wan"},
        {"name": "BKUP_DHCP", "interface": "opt1"},
        {"name": "MAIN_DHCP", "interface": "opt2"},
    ]
    result.gateway_groups = [{"name": "FailoverGW", "descr": "", "members": ["BKUP_DHCP", "MAIN_DHCP"]}]
    result.vpn = [
        VpnEndpoint(kind="openvpn-client", name=f"EX-VPN-{n}", interface="Failover_GW_Group", vpnid=str(i))
        for i, n in ((1, "AN"), (2, "JP"), (3, "MO"))
    ]
    return result


def test_grouped_wans_reach_internet_only_through_their_group() -> None:
    graph = build_config_topology(_guardian_like())
    links = _links(graph)
    assert ("gw", "failovergw", "ext", "internet") in links
    assert ("phys", "igb3", "ext", "internet") not in links
    for nic in ("em0", "mce0"):
        assert ("phys", nic, "ext", "internet") not in links
    assert ("phys", "igb1", "ext", "internet") not in links
    assert graph.boxes[("ext", "internet")].title == "Internet"
    assert not any(e.src_layer == "port" and e.dst_id == "internet" for e in graph.edges)


def test_ungrouped_wan_port_sits_left_of_its_nic_and_feeds_internet() -> None:
    graph = build_config_topology(_guardian_like())
    links = _links(graph)
    assert ("phys", "igb3", "gw", "wan") in links
    assert ("gw", "wan", "ext", "internet") in links
    assert ("port", "wan") not in graph.boxes
    assert graph.boxes[("gw", "wan")].kind == "wanport"
    rows = tree_order(graph).rows
    assert rows["gw"]["failovergw"] < rows["gw"]["wan"]
    assert rows["gw"]["wan"] == rows["phys"]["igb3"]


def test_evl_tunnels_are_external_vlans_behind_their_gateway_group() -> None:
    graph = build_config_topology(_guardian_like())
    links = _links(graph)
    group = graph.boxes[("gw", "failovergw")]
    assert "em0 + mce0" in group.subtitle
    assert "Failover_GW_Group" in group.subtitle
    assert ("phys", "em0", "gw", "failovergw") in links
    assert ("phys", "mce0", "gw", "failovergw") in links
    assert ("phys", "igb3", "gw", "failovergw") not in links
    for tunnel in ("opt8", "opt9", "opt10"):
        box = graph.boxes[("ext", tunnel)]
        assert box.title.startswith("3_EVL")
        assert box.subtitle.startswith("external")
        assert "VLAN" not in box.subtitle.replace("external", "")
        assert ("gw", "failovergw", "ext", tunnel) in links
        assert not any(e.dst_id == tunnel and e.src_layer == "phys" for e in graph.edges)


def test_evl_named_vlan_is_external_and_hangs_off_the_nic() -> None:
    result = CheckResult()
    result.interfaces = [
        _iface("wan", "em0", "WAN", kind="physical", ipaddr="dhcp"),
        _iface("opt4", "em0.30", "3_EVL4_CARRIER", kind="vlan"),
    ]
    result.vlans = [VlanInfo(tag="30", if_parent="em0", vlanif="em0.30", assigned_as="opt4")]
    graph = build_config_topology(result)
    assert ("vlan", "em0.30") not in graph.boxes
    assert graph.boxes[("ext", "em0.30")].subtitle.startswith("external VLAN 30")
    assert ("phys", "em0", "ext", "em0.30") in _links(graph)


def test_tunnels_sit_above_internet_and_internet_spans_what_feeds_it() -> None:
    graph = build_config_topology(_guardian_like())
    layout = tree_order(graph)
    rows = layout.rows
    top = rows["ext"]["internet"]
    span = layout.spans[("ext", "internet")]
    for tunnel in ("opt8", "opt9", "opt10"):
        assert rows["ext"][tunnel] < top
    group = rows["gw"]["failovergw"]
    assert rows["phys"]["em0"] == group
    assert rows["phys"]["mce0"] == group + 1
    for row in (group, rows["phys"]["igb3"]):
        assert top <= row < top + span


def test_tree_order_keeps_each_nics_children_together() -> None:
    result = CheckResult()
    result.interfaces = [
        _iface("opt1", "igb0", "A_UPLINK", kind="physical"),
        _iface("opt2", "igb1", "B_UPLINK", kind="physical"),
        _iface("opt3", "igb1.10", "AAA_ON_B", kind="vlan"),
        _iface("opt4", "igb0.10", "ZZZ_ON_A", kind="vlan"),
    ]
    result.vlans = [
        VlanInfo(tag="10", if_parent="igb0", vlanif="igb0.10"),
        VlanInfo(tag="10", if_parent="igb1", vlanif="igb1.10"),
    ]
    rows = tree_order(build_config_topology(result)).rows
    assert rows["phys"] == {"igb0": 0, "igb1": 1}
    assert rows["port"] == {"opt1": 0, "opt2": 1}
    assert rows["vlan"] == {"igb0.10": 0, "igb1.10": 1}


def test_tree_order_starts_each_nic_level_with_its_first_child() -> None:
    result = CheckResult()
    result.interfaces = [
        _iface("opt1", "igb0", "UPLINK", kind="physical"),
        _iface("opt2", "igb0.10", "A", kind="vlan"),
        _iface("opt3", "igb0.20", "B", kind="vlan"),
        _iface("opt4", "igb0.30", "C", kind="vlan"),
        _iface("opt5", "igb1.40", "D", kind="vlan"),
    ]
    result.vlans = [
        VlanInfo(tag="10", if_parent="igb0", vlanif="igb0.10"),
        VlanInfo(tag="20", if_parent="igb0", vlanif="igb0.20"),
        VlanInfo(tag="30", if_parent="igb0", vlanif="igb0.30"),
        VlanInfo(tag="40", if_parent="igb1", vlanif="igb1.40"),
    ]
    rows = tree_order(build_config_topology(result)).rows
    assert rows["vlan"]["igb0.10"] == 0
    assert rows["vlan"]["igb0.30"] == 2
    # igb1 starts below igb0's three VLANs, level with its own VLAN.
    assert rows["phys"]["igb1"] == rows["vlan"]["igb1.40"] == 3
