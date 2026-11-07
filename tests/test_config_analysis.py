"""Deep 'Will it work?' analysis — DHCP, upstream dependencies, degraded state."""

from __future__ import annotations

from pathlib import Path

from pfsense_checker import config_analysis as ca
from pfsense_checker.checker import check_file
from pfsense_checker.ssh_session import extract_firewall_config_xml

PF_XML = """<?xml version="1.0"?>
<pfsense>
  <version>24.6</version>
  <system><hostname>guardian</hostname><domain>lab</domain></system>
  <interfaces>
    <lan><enable/><if>em1</if><descr>LAN</descr><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
    <opt1><enable/><if>em1.600</if><descr>MAN</descr><ipaddr>10.6.0.1</ipaddr><subnet>24</subnet></opt1>
    <opt2><enable/><if>em1.662</if><descr>JAP</descr><ipaddr>10.80.0.1</ipaddr><subnet>24</subnet></opt2>
    <opt3><if>em2</if><descr>SPARE</descr></opt3>
    <opt4><enable/><if>em3</if><descr>LAB</descr><ipaddr>10.9.0.1</ipaddr><subnet>24</subnet></opt4>
  </interfaces>
  <vlans>
    <vlan><if>em1</if><tag>600</tag><vlanif>em1.600</vlanif></vlan>
    <vlan><if>em1</if><tag>662</tag><vlanif>em1.662</vlanif></vlan>
  </vlans>
  <dhcpd>
    <lan><enable/><range><from>10.0.0.100</from><to>10.0.0.199</to></range>
      <staticmap><mac>aa:bb:cc:00:00:01</mac><ipaddr>10.0.0.150</ipaddr></staticmap>
    </lan>
    <opt1><range><from>10.6.0.100</from><to>10.6.0.199</to></range></opt1>
    <opt3><enable/><range><from>10.0.0.150</from><to>10.0.0.160</to></range></opt3>
    <opt4><enable/><range><from>10.9.0.1</from><to>10.9.0.5</to></range><gateway>192.168.1.1</gateway></opt4>
  </dhcpd>
  <unbound><enable/><active_interface>all</active_interface></unbound>
</pfsense>
"""

RSC = """# by RouterOS 7.22.3
/interface bridge
add name=bridge1 vlan-filtering=yes
/interface vlan
add interface=bridge1 name=V600 vlan-id=600
add interface=bridge1 name=V662 vlan-id=662
add interface=bridge1 name=V10 vlan-id=10
/interface bridge port
add bridge=bridge1 interface=ether2
/interface bridge vlan
add bridge=bridge1 tagged=bridge1 vlan-ids=600,662,10
/ip address
add address=10.6.0.5/24 interface=V600
add address=10.70.0.5/24 interface=V662
add address=10.0.0.5/24 interface=V10
add address=10.50.0.1/24 interface=ether2
/ip pool
add name=p-lab ranges=10.50.0.100-10.50.0.199
/ip dhcp-server
add address-pool=p-lab interface=ether2 name=dhcp-on-port
/ip dhcp-relay
add dhcp-server=10.6.0.1 disabled=no interface=V600 name=REL600
add dhcp-server=10.70.0.1 disabled=no interface=V662 name=REL662
add dhcp-server=10.0.0.1 disabled=no interface=V10 name=REL10
/ip firewall filter
add action=accept chain=input connection-state=established,related
add action=drop chain=input in-interface=V10 protocol=udp dst-port=67 comment="no dhcp here"
/system identity
set name=SW1
"""


def _load(tmp_path: Path):
    pf = tmp_path / "guardian.xml"
    pf.write_text(PF_XML, encoding="utf-8")
    mt = tmp_path / "sw1.rsc"
    mt.write_text(RSC, encoding="utf-8")
    return check_file(pf), check_file(mt)


def _msgs(area: ca.AreaVerdict, status: str) -> list[str]:
    return [f"{c.subject}: {c.message}" for c in area.checks if c.status == status]


def test_pfsense_scope_checks(tmp_path) -> None:
    pf, _ = _load(tmp_path)
    dhcp = ca.analyse(pf).area("DHCP")
    fails = "\n".join(_msgs(dhcp, ca.FAIL))
    warns = "\n".join(_msgs(dhcp, ca.WARN))
    assert "includes the interface address 10.9.0.1" in fails  # opt4 range
    assert "gateway 192.168.1.1, outside 10.9.0.0/24" in fails
    assert "interface is disabled" in warns  # opt3 scope on a disabled interface
    assert "Static mapping 10.0.0.150" in warns and "inside the dynamic pool" in warns
    assert "only 5 address" in warns  # opt4 pool
    assert "overlaps opt3" in warns  # opt3 not live, so a warning not a failure
    passes = "\n".join(_msgs(dhcp, ca.PASS))
    assert "resolver listens there" in passes
    assert dhcp.status == ca.FAILS
    assert not dhcp.dependencies  # a pfSense serving locally needs nobody else


def test_relays_alone_are_degraded(tmp_path) -> None:
    _, mt = _load(tmp_path)
    analysis = ca.analyse(mt, [], {"10.6.0.1": "host-gw"})
    dhcp = analysis.area("DHCP")
    assert analysis.degraded and dhcp.coverage == 0
    assert {d.address for d in dhcp.missing} == {"10.6.0.1", "10.70.0.1", "10.0.0.1"}
    assert next(d for d in dhcp.missing if d.address == "10.6.0.1").known_as == "host-gw"
    # Local failures still show even while degraded.
    fails = "\n".join(_msgs(dhcp, ca.FAIL))
    assert "port of bridge bridge1" in fails  # dhcp-server bound to a bridge port
    assert "no dhcp here" in fails  # input rule drops UDP 67 on V10
    text = ca.report_text(analysis)
    assert "Assessment coverage 0 %" in text and "degraded" in text


def test_relays_resolved_against_loaded_pfsense(tmp_path) -> None:
    pf, mt = _load(tmp_path)
    analysis = ca.analyse(mt, [pf])
    dhcp = analysis.area("DHCP")
    fails = "\n".join(_msgs(dhcp, ca.FAIL))
    warns = "\n".join(_msgs(dhcp, ca.WARN))
    # VL600: server owns 10.6.0.1 but its scope is disabled.
    assert "DHCP is disabled on guardian opt1" in fails
    # VL662: same VLAN id, different subnet; nobody owns 10.70.0.1.
    assert "VLAN 662 is 10.70.0.0/24 here but 10.80.0.0/24 on guardian" in fails
    # Relay target on the relay's own subnet.
    assert "same subnet (10.6.0.0/24)" in warns
    assert {d.address for d in dhcp.missing} == {"10.70.0.1"}
    assert round(dhcp.coverage * 100) == 67
    assert dhcp.status == ca.FAILS


def test_findings_include_degraded_notice(tmp_path) -> None:
    _, mt = _load(tmp_path)
    findings = ca.findings_from(ca.analyse(mt))
    texts = [f.message for f in findings]
    assert any("Analysis degraded: config for DHCP server (relay target) 10.6.0.1" in t for t in texts)
    assert {f.category for f in findings} >= {"DHCP", "Reachability"}


def test_device_without_dhcp_is_not_configured(tmp_path) -> None:
    rsc = tmp_path / "plain.rsc"
    rsc.write_text("/ip address\nadd address=10.1.1.1/24 interface=ether1\n", encoding="utf-8")
    dhcp = ca.analyse(check_file(rsc)).area("DHCP")
    assert dhcp.status == ca.ABSENT


def test_text_after_closing_tag_is_ignored_with_warning(tmp_path) -> None:
    junk = PF_XML + "\n\nWe trust you have received the usual lecture\nPassword:\n"
    path = tmp_path / "pulled.xml"
    path.write_text(junk, encoding="utf-8")
    result = check_file(path)
    assert result.valid_xml and result.hostname == "guardian"
    assert any("after </pfsense> were ignored" in f.message for f in result.findings)


def test_pull_extractor_cuts_sudo_tail() -> None:
    noisy = "Password:\n" + PF_XML + "\nWe trust you have received the usual lecture\n"
    cleaned = extract_firewall_config_xml(noisy)
    assert cleaned.startswith("<?xml") and cleaned.rstrip().endswith("</pfsense>")


# ---------------------------------------------------------------- Wireless

AP_RSC = """/interface bridge
add name=br1
/interface wireless security-profiles
set [ find default=yes ] mode=none name=default
add name=wep mode=static-keys-required
/interface wireless
set [ find default-name=wlan1 ] mode=ap-bridge ssid=Guest security-profile=default country=no_country_set wps-mode=push-button
set [ find default-name=wlan2 ] mode=ap-bridge ssid=Old security-profile=wep country=etsi
/interface bridge port
add bridge=br1 interface=wlan1
/system identity
set name=AP1
"""

MANAGER_RSC = """/interface bridge
add name=core
/ip address
add address=10.1.0.5/24 interface=core
/caps-man manager
set enabled=yes
/caps-man channel
add band=2ghz-b/g/n frequency=2412 name=CH1
add band=2ghz-b/g/n frequency=2432 name=CH5
/caps-man security
add authentication-types=wpa2-psk encryption=aes-ccm name=SEC
/caps-man datapath
add bridge=core local-forwarding=yes name=DP vlan-id=630 vlan-mode=use-tag
/caps-man configuration
add channel=CH1 country="united kingdom" datapath=DP name=CFG1 security=SEC ssid=Office
add channel=CH5 country="united kingdom" datapath=DP name=CFG2 security=NOPE ssid=Office2
/caps-man provisioning
add action=create-enabled master-configuration=CFG1
/system identity
set name=MGR
"""


def _cap_rsc(filtering: str, vlans: str) -> str:
    return f"""/interface bridge
add name=capbr vlan-filtering={filtering}
/interface bridge vlan
add bridge=capbr tagged=ether1,capbr vlan-ids={vlans}
/interface wireless cap
set bridge=capbr caps-man-addresses=10.1.0.5 enabled=yes interfaces=wlan1
/interface wireless
set [ find default-name=wlan1 ] mode=station ssid=x
/system identity
set name=CAP1
"""


def _rsc(tmp_path: Path, name: str, text: str):
    path = tmp_path / f"{name}.rsc"
    path.write_text(text, encoding="utf-8")
    return check_file(path)


def test_local_access_point_security(tmp_path) -> None:
    w = ca.analyse(_rsc(tmp_path, "ap", AP_RSC)).area("Wireless")
    fails = "\n".join(_msgs(w, ca.FAIL))
    warns = "\n".join(_msgs(w, ca.WARN))
    assert "radio wlan1: No encryption" in fails
    assert "radio wlan2: WEP" in fails
    assert "radio wlan2: Not in a bridge" in fails
    assert "No country set" in warns and "WPS is on" in warns
    assert w.status == ca.FAILS


def test_cap_alone_is_degraded_then_resolved(tmp_path) -> None:
    cap = _rsc(tmp_path, "cap", _cap_rsc("yes", "630"))
    mgr = _rsc(tmp_path, "mgr", MANAGER_RSC)
    alone = ca.analyse(cap).area("Wireless")
    assert alone.status == ca.DEGRADED
    assert alone.missing[0].role == "CAPsMAN manager" and alone.missing[0].address == "10.1.0.5"
    assert any("Managed by CAPsMAN" in m for m in _msgs(alone, ca.INFO))  # local station mode ignored
    resolved = ca.analyse(cap, [mgr]).area("Wireless")
    assert not resolved.missing
    assert any("VLAN 630 is carried on capbr" in m for m in _msgs(resolved, ca.PASS))


def test_cap_bridge_missing_ssid_vlan_fails(tmp_path) -> None:
    cap = _rsc(tmp_path, "cap", _cap_rsc("yes", "10"))
    mgr = _rsc(tmp_path, "mgr", MANAGER_RSC)
    w = ca.analyse(mgr, [cap]).area("Wireless")
    fails = "\n".join(_msgs(w, ca.FAIL))
    assert "tags VLAN 630, but bridge capbr on CAP1 has no VLAN 630" in fails
    assert "Security 'NOPE' not found" in fails
    assert any("channels overlap (2412/2432 MHz)" in m for m in _msgs(w, ca.WARN))
    assert w.dependencies[0].resolved_by == "CAP1"


def test_unfiltered_cap_bridge_passes_tags_but_warns(tmp_path) -> None:
    cap = _rsc(tmp_path, "cap", _cap_rsc("no", "10"))
    mgr = _rsc(tmp_path, "mgr", MANAGER_RSC)
    w = ca.analyse(cap, [mgr]).area("Wireless")
    assert any("VLAN filtering is off" in m for m in _msgs(w, ca.PASS))
    assert any("VLAN hopping" in m for m in _msgs(w, ca.WARN))


def test_manager_alone_needs_its_caps(tmp_path) -> None:
    w = ca.analyse(_rsc(tmp_path, "mgr", MANAGER_RSC)).area("Wireless")
    assert w.missing and w.missing[0].role == "CAP access points"


# ---------------------------------------------------------------- Bandwidth

PF_BW_XML = """<?xml version="1.0"?>
<pfsense>
  <system><hostname>edge</hostname></system>
  <interfaces>
    <wan><enable/><if>igb0</if><descr>WAN1_1G_main</descr><ipaddr>dhcp</ipaddr></wan>
    <opt1><enable/><if>em0</if><descr>WAN2_150m_backup</descr><ipaddr>dhcp</ipaddr></opt1>
    <lan><enable/><if>ix1</if><descr>LAN_trunk</descr><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
    <opt2><enable/><if>ix1.630</if><descr>VL630</descr><ipaddr>10.63.0.1</ipaddr><subnet>24</subnet></opt2>
    <opt3><enable/><if>ix1.662</if><descr>VL662</descr><ipaddr>10.80.0.1</ipaddr><subnet>24</subnet></opt3>
  </interfaces>
  <vlans>
    <vlan><if>ix1</if><tag>630</tag><vlanif>ix1.630</vlanif></vlan>
    <vlan><if>ix1</if><tag>662</tag><vlanif>ix1.662</vlanif></vlan>
  </vlans>
  <gateways>
    <gateway_item><name>GW1</name><interface>wan</interface><gateway>dynamic</gateway></gateway_item>
    <gateway_item><name>GW2</name><interface>opt1</interface><gateway>dynamic</gateway></gateway_item>
    <gateway_group><name>Failover</name><item>GW1|1|address</item><item>GW2|2|address</item></gateway_group>
    <defaultgw4>Failover</defaultgw4>
  </gateways>
</pfsense>
"""

SW_RSC = """/interface bridge
add name=br vlan-filtering=yes
/interface ethernet
set [ find default-name=ether1 ] advertise=10M-baseT-half,10M-baseT-full
set [ find default-name=ether2 ] advertise=10M-baseT-full,100M-baseT-full,1G-baseT-full
set [ find default-name=sfp-sfpplus1 ] auto-negotiation=no speed=10G-baseSR-LR
/interface vlan
add interface=br name=V630 vlan-id=630
add interface=br name=V662 vlan-id=662
/interface bridge vlan
add bridge=br tagged=br,sfp-sfpplus1 untagged=ether1,ether2 vlan-ids=630
add bridge=br tagged=br,sfp-sfpplus1 vlan-ids=662
/ip address
add address=10.63.0.5/24 interface=V630
add address=10.70.0.5/24 interface=V662
/system identity
set name=SW
"""


def test_rate_helpers() -> None:
    assert ca._rate_from_text("0_S1_P0_1G_F_WAN1_main") == 1000
    assert ca._rate_from_text("0_S0_P0_150m_E_WAN2") == 150
    assert ca._rate_from_text("SLOT0_PORT0_150MB_FIB") == 150
    assert ca._rate_from_text("LAN_trunk") is None
    assert ca._ros_rate("10M-baseT-half,100M-baseT-full,1G-baseT-full") == 1000
    assert ca._ros_rate("10G-baseSR-LR") == 10000
    assert ca._wifi_estimate("2ghz-b/g/n", "20mhz") == (144.0, 72)
    assert ca._wifi_estimate("5ghz-a/n/ac", "80mhz") == (866.0, 433)
    assert ca._wifi_estimate("2ghz-b/g", "20mhz") == (54.0, 27)


def test_pfsense_internet_failover(tmp_path) -> None:
    pf = tmp_path / "edge.xml"
    pf.write_text(PF_BW_XML, encoding="utf-8")
    w = ca.analyse(check_file(pf)).area("Bandwidth (estimate)")
    inet = next(c.message for c in w.checks if c.subject == "Internet")
    assert "1 Gbps via WAN1_1G_main" in inet and "fails over to 150 Mbps via WAN2_150m_backup" in inet
    lan = next(c.message for c in w.checks if c.subject.startswith("lan "))
    assert "10 Gbps (ix NIC, shared by 3 networks on ix1)" in lan and "≈ 1 Gbps per client" in lan


def test_switch_vlan_estimates_and_dependencies(tmp_path) -> None:
    sw_path = tmp_path / "sw.rsc"
    sw_path.write_text(SW_RSC, encoding="utf-8")
    pf_path = tmp_path / "edge.xml"
    pf_path.write_text(PF_BW_XML, encoding="utf-8")
    sw, pf = check_file(sw_path), check_file(pf_path)

    alone = ca.analyse(sw).area("Bandwidth (estimate)")
    assert alone.status == ca.DEGRADED
    assert {d.address for d in alone.missing} == {"VLAN 630 gateway (10.63.0.0/24)", "VLAN 662 gateway (10.70.0.0/24)"}
    assert any("ether1" in m and "only 10 Mbps" in m for m in _msgs(alone, ca.WARN))

    joined = ca.analyse(sw, [pf]).area("Bandwidth (estimate)")
    v630 = next(c.message for c in joined.checks if c.subject.startswith("VLAN 630"))
    assert "uplink assumed sfp-sfpplus1 10 Gbps" in v630 and "onward via edge ix1" in v630
    assert "Per wired client ≈ 1 Gbps" in v630
    v662 = next(c for c in joined.checks if c.subject.startswith("VLAN 662"))
    assert v662.status == ca.WARN and "uses 10.80.0.0/24, not 10.70.0.0/24" in v662.message


# ---------------------------------------------------------------- Reachability

PF_REACH_XML = PF_BW_XML.replace(
    "</gateways>",
    "</gateways>\n  <nat><outbound><mode>automatic</mode></outbound></nat>\n"
    "  <filter>\n"
    "    <rule><type>pass</type><interface>lan</interface><source><network>lan</network></source>"
    "<destination><any/></destination></rule>\n"
    "    <rule><type>block</type><interface>opt2</interface><source><network>opt2</network></source>"
    "<destination><any/></destination><descr>quarantine</descr></rule>\n"
    "    <rule><type>pass</type><interface>opt2</interface><source><network>opt2</network></source>"
    "<destination><any/></destination></rule>\n"
    "  </filter>\n"
    "  <unbound><enable/></unbound>",
)

SW_REACH_RSC = SW_RSC.replace(
    "add bridge=br tagged=br,sfp-sfpplus1 vlan-ids=662",
    "add bridge=br tagged=sfp-sfpplus1 vlan-ids=662",
) + "/ip route\nadd dst-address=0.0.0.0/0 gateway=10.63.0.1\n/ip dhcp-relay\nadd dhcp-server=10.80.0.1 interface=V662 name=R662\n"


def test_pfsense_reachability(tmp_path) -> None:
    pf = tmp_path / "edge.xml"
    pf.write_text(PF_REACH_XML, encoding="utf-8")
    r = ca.analyse(check_file(pf)).area("Reachability")
    passes = "\n".join(_msgs(r, ca.PASS))
    fails = "\n".join(_msgs(r, ca.FAIL))
    assert "Default via Failover (GW1, GW2 usable)" in passes
    assert "passes lan net to any" in passes
    assert "quarantine" in fails and "blocks this network before any pass rule" in fails  # opt2
    assert "opt3 (VL662) 10.80.0.0/24: No firewall rule lets this network out" in fails
    assert "Mode automatic" in passes
    assert not any("public" in m for m in _msgs(r, ca.WARN))  # 10.x is private


def test_mikrotik_reachability(tmp_path) -> None:
    sw_path = tmp_path / "sw.rsc"
    sw_path.write_text(SW_REACH_RSC, encoding="utf-8")
    pf_path = tmp_path / "edge.xml"
    pf_path.write_text(PF_REACH_XML, encoding="utf-8")
    sw, pf = check_file(sw_path), check_file(pf_path)
    alone = ca.analyse(sw).area("Reachability")
    fails = "\n".join(_msgs(alone, ca.FAIL))
    assert "V662" in fails and "not a tagged member of VLAN 662" in fails
    assert alone.missing and alone.missing[0].role == "Default gateway"
    dhcp_fails = "\n".join(_msgs(ca.analyse(sw).area("DHCP"), ca.FAIL))
    assert "The relay never sees a request" in dhcp_fails
    joined = ca.analyse(sw, [pf]).area("Reachability")
    assert any("Default via 10.63.0.1 = edge VL630" in m for m in _msgs(joined, ca.PASS))
    assert any("VLAN 662 is 10.70.0.0/24 here but 10.80.0.0/24 on edge" in m for m in _msgs(joined, ca.FAIL))


def test_public_address_space_warning(tmp_path) -> None:
    rsc = tmp_path / "pub.rsc"
    rsc.write_text("/ip address\nadd address=222.10.50.5/24 interface=ether1\n", encoding="utf-8")
    r = ca.analyse(check_file(rsc)).area("Reachability")
    assert any("public (Internet-routable) address space: 222.10.50.0/24" in m for m in _msgs(r, ca.WARN))
