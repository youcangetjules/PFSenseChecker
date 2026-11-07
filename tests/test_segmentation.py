from pfsense_checker.models import BridgeInfo, CheckResult, InterfaceInfo, RuleInfo
from pfsense_checker.segmentation import BLOCKED, LIMITED, OPEN, analyse_segmentation


def _iface(name, device, ip, descr=""):
    return InterfaceInfo(name=name, device=device, enabled=True, ipaddr=ip, subnet="24", descr=descr)


def _rule(index, iface, source="any", destination="any", **kw):
    return RuleInfo(index=index, kind="filter", type=kw.pop("type", "pass"), interface=iface,
                    source=source, destination=destination, **kw)


def _result(rules, **kw):
    return CheckResult(
        interfaces=[
            _iface("wan", "igb3", "dhcp"),
            _iface("lan", "igb1", "10.0.1.1", "LAN"),
            _iface("opt1", "igb0.10", "10.0.10.1", "IOT"),
            _iface("opt2", "igb0.20", "10.0.20.1", "MGMT"),
        ],
        filter_rules=rules,
        **kw,
    )


def test_no_rules_is_fully_separated_and_wan_is_not_a_zone():
    seg = analyse_segmentation(_result([]))
    assert [z.name for z in seg.zones] == ["lan", "opt1", "opt2"]
    assert seg.count(BLOCKED) == seg.pairs == 6
    assert seg.score == 100


def test_pass_any_opens_every_pair_from_that_interface():
    seg = analyse_segmentation(_result([_rule(0, "lan", "lan")]))
    assert seg.reach[("lan", "opt1")].level == OPEN
    assert seg.reach[("lan", "opt1")].rules == [1]
    assert seg.reach[("opt1", "lan")].level == BLOCKED
    assert seg.summaries["lan"].open_to == ["opt1", "opt2"]


def test_block_rule_above_pass_any_keeps_subnet_out():
    rules = [
        _rule(0, "opt1", destination="opt2", type="block"),
        _rule(1, "opt1", destination="10.0.1.5", protocol="tcp", dst_port="443"),
        _rule(2, "opt1", destination="lan", type="block"),
        _rule(3, "opt1"),
    ]
    seg = analyse_segmentation(_result(rules))
    assert seg.reach[("opt1", "opt2")].level == BLOCKED
    lan = seg.reach[("opt1", "lan")]
    assert lan.level == LIMITED
    assert lan.services == ["tcp 443 (some hosts)"]


def test_alias_and_negation():
    rules = [_rule(0, "opt1", destination="INSIDE", destination_not=True)]
    aliases = [{"name": "INSIDE", "type": "network", "address": "10.0.0.0/16", "descr": ""}]
    seg = analyse_segmentation(_result(rules, aliases=aliases))
    assert seg.reach[("opt1", "lan")].level == BLOCKED


def test_gateway_rule_reaches_locals_unless_negation_disabled():
    rules = [_rule(0, "opt1", gateway="FailoverGW")]
    assert analyse_segmentation(_result(rules)).reach[("opt1", "lan")].level == OPEN
    off = _result(rules, firewall_options={"disablenegate": "1"})
    assert analyse_segmentation(off).reach[("opt1", "lan")].level == BLOCKED


def test_floating_quick_block_wins_over_interface_pass():
    rules = [
        _rule(0, "opt1"),
        _rule(1, "opt1,opt2", destination="lan", type="block", floating=True, quick=True),
    ]
    seg = analyse_segmentation(_result(rules))
    assert seg.reach[("opt1", "lan")].level == BLOCKED
    assert seg.reach[("opt1", "opt2")].level == OPEN


def test_bridge_reported_as_layer2_join():
    result = _result([], bridges=[BridgeInfo(bridgeif="bridge0", members=["opt1", "opt2"])],
                     firewall_options={"net.link.bridge.pfil_member": "0",
                                       "net.link.bridge.pfil_bridge": "1"})
    seg = analyse_segmentation(result)
    assert "IOT, MGMT" in seg.layer2[0]
    assert "bridge interface" in seg.layer2[0]
