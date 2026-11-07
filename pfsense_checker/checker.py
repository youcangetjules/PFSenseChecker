"""Comprehensive pfSense config.xml parsing and validation.

Parses a pfSense (or OPNsense) ``config.xml`` backup, builds a full inventory
of interfaces (including bridges, VLANs, LAGGs, VPN and other virtual
interfaces), packages and their services, firewall/NAT rules, VPN endpoints,
DHCP, DNS, certificates and more, then runs a battery of correctness and
best-practice checks.
"""

from __future__ import annotations

import re
from pathlib import Path
from xml.etree import ElementTree as ET

from pfsense_checker.models import (
    BridgeInfo,
    CheckResult,
    Finding,
    InterfaceInfo,
    LaggInfo,
    PackageInfo,
    RuleInfo,
    ServiceInfo,
    Severity,
    VlanInfo,
    VpnEndpoint,
)

# Tags that must appear at most once under their parent (known restore breakers).
# Deliberately excludes intentionally repeated siblings (dnsserver, user, rule…).
UNIQUE_SIBLING_TAGS = frozenset(
    {
        "sshdata",
        "rrddata",
        "version",
        "lastchange",
        "theme",
        "timezone",
        "language",
        "hostname",
        "domain",
    }
)

# Top-level sections commonly present in a valid backup.
EXPECTED_TOP_SECTIONS = ("version", "system", "interfaces")

# Reserved logical interface names (physical assignments). opt* are dynamic.
CORE_IFACE_NAMES = frozenset({"wan", "lan"})

# Values that indicate a dynamically-obtained address rather than a static one.
DYNAMIC_ADDRS = frozenset({"dhcp", "pppoe", "pptp", "l2tp", "dhcp6"})


# --------------------------------------------------------------------------- #
# XML helpers
# --------------------------------------------------------------------------- #

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _child_path(parent: str, name: str) -> str:
    return f"{parent}/{name}" if parent else name


def _text(el: ET.Element | None) -> str:
    if el is None or el.text is None:
        return ""
    return el.text.strip()


def _find(parent: ET.Element | None, name: str) -> ET.Element | None:
    if parent is None:
        return None
    name_l = name.lower()
    for child in parent:
        if _local(child.tag).lower() == name_l:
            return child
    return None


def _find_text(parent: ET.Element | None, name: str) -> str:
    return _text(_find(parent, name))


def _find_all(parent: ET.Element | None, name: str) -> list[ET.Element]:
    if parent is None:
        return []
    name_l = name.lower()
    return [c for c in parent if _local(c.tag).lower() == name_l]


def _has_flag(parent: ET.Element | None, name: str) -> bool:
    """A pfSense presence/boolean flag: tag exists and isn't an explicit off."""
    el = _find(parent, name)
    if el is None:
        return False
    val = _text(el).lower()
    return val not in {"false", "off", "0", "no", "disabled"}


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def check_file(path: Path | str) -> CheckResult:
    """Run all checks against a pfSense config.xml or MikroTik RouterOS export."""
    path = Path(path)

    # Sniff format: XML (pfSense/OPNsense) vs RouterOS export (.rsc text).
    if _is_routeros_file(path):
        from pfsense_checker.mikrotik import parse_routeros

        try:
            text = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            result = CheckResult(path=path, source_type="mikrotik")
            result.findings.append(
                Finding(Severity.ERROR, "File", f"Cannot read file: {exc}")
            )
            return result
        return parse_routeros(text, path)

    result = CheckResult(path=path, source_status="ok")

    root = _load_root(path, result)
    if root is None:
        result.source_status = "error"
        return result

    result.valid_xml = True
    result.root_tag = _local(root.tag)
    if result.root_tag.lower() not in {"pfsense", "opnsense"}:
        result.findings.append(
            Finding(
                Severity.WARNING,
                "Structure",
                f"Root element is <{result.root_tag}>, expected <pfsense>",
            )
        )

    result.top_sections = [_local(c.tag).lower() for c in root]

    # Structural integrity
    _check_duplicate_siblings(root, "", result)
    _check_structure(root, result)

    # Inventory + section checks
    _check_system(root, result)
    _collect_interfaces(root, result)
    _collect_bridges(root, result)
    _collect_vlans(root, result)
    _collect_laggs(root, result)
    _cross_check_interfaces(result)
    _check_interface_findings(result)
    _check_filter(root, result)
    _check_nat(root, result)
    _collect_vpn(root, result)
    _check_dhcp(root, result)
    _check_dns(root, result)
    _check_gateways(root, result)
    _check_vpn_bindings(result)
    _check_static_routes(root, result)
    _check_virtual_ips(root, result)
    _check_aliases(root, result)
    _check_certs(root, result)
    _check_users(root, result)
    _collect_packages(root, result)
    _collect_services(root, result)
    _check_segmentation(result)

    from pfsense_checker.attack_surface import apply_posture, assess_pfsense

    assess_pfsense(root, result)
    _build_summary(result)
    apply_posture(result)
    return result


def _is_routeros_file(path: Path) -> bool:
    """Decide whether a file is a MikroTik RouterOS export rather than pfSense XML."""
    if not path.is_file():
        return False
    suffix = path.suffix.lower()
    if suffix in {".xml"}:
        return False
    try:
        head = path.read_text(encoding="utf-8-sig", errors="replace")[:4096]
    except OSError:
        return False
    stripped = head.lstrip()
    if stripped.startswith("<"):
        return False
    if suffix in {".rsc", ".routeros"}:
        return True
    from pfsense_checker.mikrotik import looks_like_routeros

    return looks_like_routeros(head)


def _load_root(path: Path, result: CheckResult) -> ET.Element | None:
    if not path.is_file():
        result.findings.append(
            Finding(Severity.ERROR, "File", f"File not found: {path}")
        )
        return None
    try:
        raw = path.read_bytes()
    except OSError as exc:
        result.findings.append(
            Finding(Severity.ERROR, "File", f"Cannot read file: {exc}")
        )
        return None

    if not raw.strip():
        result.findings.append(Finding(Severity.ERROR, "File", "File is empty"))
        return None

    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        result.findings.append(
            Finding(
                Severity.WARNING,
                "Encoding",
                "UTF-16 BOM detected; pfSense expects UTF-8",
            )
        )
    elif raw.startswith(b"\xef\xbb\xbf"):
        result.findings.append(
            Finding(Severity.INFO, "Encoding", "UTF-8 BOM present (usually fine)")
        )

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
            result.findings.append(
                Finding(
                    Severity.WARNING,
                    "Encoding",
                    "File is not valid UTF-8; decoded as Latin-1 for analysis",
                )
            )
        except Exception as exc:  # noqa: BLE001
            result.findings.append(
                Finding(Severity.ERROR, "Encoding", f"Cannot decode file: {exc}")
            )
            return None

    if "\x00" in text:
        result.findings.append(
            Finding(Severity.ERROR, "Encoding", "Null byte(s) present — invalid XML")
        )

    try:
        return ET.fromstring(text)
    except ET.ParseError as exc:
        result.findings.append(
            Finding(
                Severity.ERROR,
                "XML",
                f"XML parse error: {exc}",
                line=getattr(exc, "position", (None, None))[0],
            )
        )
        return None


# --------------------------------------------------------------------------- #
# Structural checks
# --------------------------------------------------------------------------- #

def _check_duplicate_siblings(
    element: ET.Element, path: str, result: CheckResult
) -> None:
    counts: dict[str, list[ET.Element]] = {}
    for child in element:
        counts.setdefault(_local(child.tag).lower(), []).append(child)

    for name, siblings in counts.items():
        if len(siblings) > 1 and name in UNIQUE_SIBLING_TAGS:
            result.findings.append(
                Finding(
                    Severity.ERROR,
                    "Structure",
                    f"Duplicate <{name}> ({len(siblings)} occurrences) — "
                    "pfSense fails to parse configs with repeated unique tags "
                    "(classic sshdata / rrddata restore breaker)",
                    path=_child_path(path, name),
                )
            )
        for child in siblings:
            _check_duplicate_siblings(
                child, _child_path(path, _local(child.tag).lower()), result
            )


def _check_structure(root: ET.Element, result: CheckResult) -> None:
    children = {_local(c.tag).lower() for c in root}
    for section in EXPECTED_TOP_SECTIONS:
        if section not in children:
            result.findings.append(
                Finding(
                    Severity.WARNING,
                    "Structure",
                    f"Missing expected top-level <{section}> section",
                    path=section,
                )
            )


# --------------------------------------------------------------------------- #
# System
# --------------------------------------------------------------------------- #

def _check_system(root: ET.Element, result: CheckResult) -> None:
    system = _find(root, "system")
    result.version = _find_text(root, "version")
    if system is None:
        result.findings.append(
            Finding(Severity.ERROR, "System", "No <system> section", path="system")
        )
        return

    result.hostname = _find_text(system, "hostname")
    result.domain = _find_text(system, "domain")
    if _find(system, "disablenegate") is not None:
        result.firewall_options["disablenegate"] = "1"
    for item in _find_all(_find(root, "sysctl"), "item"):
        tunable = _find_text(item, "tunable")
        if tunable:
            result.firewall_options[tunable] = _find_text(item, "value")
    if not result.hostname:
        result.findings.append(
            Finding(Severity.WARNING, "System", "No hostname configured", path="system")
        )
    if not _find_text(system, "timezone"):
        result.findings.append(
            Finding(Severity.INFO, "System", "Timezone not set", path="system/timezone")
        )

    webgui = _find(system, "webgui")
    if webgui is not None:
        protocol = _find_text(webgui, "protocol").lower()
        if protocol == "http":
            result.findings.append(
                Finding(
                    Severity.WARNING,
                    "Security",
                    "WebGUI protocol is HTTP (prefer HTTPS)",
                    path="system/webgui/protocol",
                )
            )
    if not _has_flag(system, "enablesshd"):
        result.findings.append(
            Finding(Severity.INFO, "System", "SSH daemon not enabled", path="system")
        )


# --------------------------------------------------------------------------- #
# Interfaces + virtual interfaces
# --------------------------------------------------------------------------- #

def _collect_interfaces(root: ET.Element, result: CheckResult) -> None:
    interfaces = _find(root, "interfaces")
    if interfaces is None:
        result.findings.append(
            Finding(
                Severity.WARNING, "Interfaces", "No <interfaces> section", path="interfaces"
            )
        )
        return

    for child in interfaces:
        name = _local(child.tag).lower()
        info = InterfaceInfo(
            name=name,
            descr=_find_text(child, "descr"),
            device=_find_text(child, "if"),
            enabled=_has_flag(child, "enable"),
            ipaddr=_find_text(child, "ipaddr"),
            subnet=_find_text(child, "subnet"),
            ipaddrv6=_find_text(child, "ipaddrv6"),
            subnetv6=_find_text(child, "subnetv6"),
            media=_find_text(child, "media"),
        )
        info.kind = _classify_device(info.device)
        info.raw = {
            _local(c.tag).lower(): _text(c) for c in child if _text(c)
        }
        result.interfaces.append(info)

    names = {i.name for i in result.interfaces}
    for core in CORE_IFACE_NAMES:
        if core not in names:
            result.findings.append(
                Finding(
                    Severity.WARNING,
                    "Interfaces",
                    f"No {core.upper()} interface defined",
                    path="interfaces",
                )
            )


def _check_interface_findings(result: CheckResult) -> None:
    """Per-interface checks, run after bridge/LAGG membership is resolved."""
    for info in result.interfaces:
        ipl = info.ipaddr.lower()
        if not info.enabled:
            result.findings.append(
                Finding(
                    Severity.INFO,
                    "Interfaces",
                    f"{info.name.upper()} is present but disabled",
                    path=f"interfaces/{info.name}",
                )
            )
        # Bridge/LAGG member ports intentionally carry no IP (the bridge does).
        if (
            info.enabled
            and not info.ipaddr
            and not info.ipaddrv6
            and not info.bridge_member
            and info.kind not in {"lagg"}
        ):
            result.findings.append(
                Finding(
                    Severity.WARNING,
                    "Interfaces",
                    f"{info.name.upper()} is enabled but has no IPv4/IPv6 address "
                    "(fine if it is a switch/bridge/transit port)",
                    path=f"interfaces/{info.name}",
                )
            )
        if info.enabled and not info.device:
            result.findings.append(
                Finding(
                    Severity.ERROR,
                    "Interfaces",
                    f"{info.name.upper()} is enabled but has no <if> device assignment",
                    path=f"interfaces/{info.name}",
                )
            )
        if ipl in DYNAMIC_ADDRS:
            result.findings.append(
                Finding(
                    Severity.INFO,
                    "Interfaces",
                    f"{info.name.upper()} uses {ipl.upper()}",
                    path=f"interfaces/{info.name}",
                )
            )


def _classify_device(device: str) -> str:
    d = device.lower()
    if not d:
        return "physical"
    if d.startswith("bridge"):
        return "bridge"
    if d.startswith("lagg"):
        return "lagg"
    if d.startswith("ovpn") or d.startswith("openvpn"):
        return "openvpn"
    if d.startswith("ipsec") or d.startswith("enc"):
        return "ipsec"
    if d.startswith("gif"):
        return "gif"
    if d.startswith("gre"):
        return "gre"
    if d.startswith("pppoe") or d.startswith("ppp") or d.startswith("l2tp"):
        return "ppp"
    if "." in d or "vlan" in d or "_vlan" in d:
        return "vlan"
    return "physical"


def _collect_bridges(root: ET.Element, result: CheckResult) -> None:
    bridges = _find(root, "bridges")
    if bridges is None:
        return
    for i, b in enumerate(_find_all(bridges, "bridged")):
        members = [
            m.strip()
            for m in _find_text(b, "members").split(",")
            if m.strip()
        ]
        info = BridgeInfo(
            bridgeif=_find_text(b, "bridgeif"),
            members=members,
            descr=_find_text(b, "descr"),
            stp_enabled=_has_flag(b, "enablestp"),
        )
        result.bridges.append(info)
        if not info.bridgeif:
            result.findings.append(
                Finding(
                    Severity.WARNING,
                    "Bridges",
                    f"Bridge #{i + 1} has no bridgeif name",
                    path=f"bridges/bridged[{i}]",
                )
            )
        if not members:
            result.findings.append(
                Finding(
                    Severity.WARNING,
                    "Bridges",
                    f"Bridge {info.bridgeif or f'#{i + 1}'} has no members",
                    path=f"bridges/bridged[{i}]",
                )
            )
        elif len(members) == 1:
            result.findings.append(
                Finding(
                    Severity.INFO,
                    "Bridges",
                    f"Bridge {info.bridgeif} has only one member ({members[0]})",
                    path=f"bridges/bridged[{i}]",
                )
            )


def _collect_vlans(root: ET.Element, result: CheckResult) -> None:
    vlans = _find(root, "vlans")
    if vlans is None:
        return
    for v in _find_all(vlans, "vlan"):
        result.vlans.append(
            VlanInfo(
                tag=_find_text(v, "tag"),
                if_parent=_find_text(v, "if"),
                vlanif=_find_text(v, "vlanif"),
                descr=_find_text(v, "descr"),
            )
        )


def _collect_laggs(root: ET.Element, result: CheckResult) -> None:
    laggs = _find(root, "laggs")
    if laggs is None:
        return
    for lg in _find_all(laggs, "lagg"):
        members = [
            m.strip() for m in _find_text(lg, "members").split(",") if m.strip()
        ]
        result.laggs.append(
            LaggInfo(
                laggif=_find_text(lg, "laggif"),
                members=members,
                proto=_find_text(lg, "proto"),
                descr=_find_text(lg, "descr"),
            )
        )


def _cross_check_interfaces(result: CheckResult) -> None:
    """Link virtual interface devices to their logical assignments and flag gaps."""
    device_to_iface = {i.device.lower(): i for i in result.interfaces if i.device}

    # Bridges: mark membership + assignment
    for bridge in result.bridges:
        assigned = device_to_iface.get(bridge.bridgeif.lower())
        if assigned is not None:
            bridge.assigned_as = assigned.name
            assigned.kind = "bridge"
        for member in bridge.members:
            mi = device_to_iface.get(member.lower())
            if mi is not None:
                mi.bridge_member = True
                mi.bridge_of = bridge.bridgeif
        if not assigned:
            result.findings.append(
                Finding(
                    Severity.INFO,
                    "Bridges",
                    f"Bridge {bridge.bridgeif} is not assigned to a logical interface",
                    path="bridges",
                )
            )

    # LAGGs assignment
    for lagg in result.laggs:
        assigned = device_to_iface.get(lagg.laggif.lower())
        if assigned is not None:
            lagg.assigned_as = assigned.name
        if lagg.proto and lagg.proto.lower() not in {
            "none",
            "lacp",
            "failover",
            "loadbalance",
            "roundrobin",
        }:
            result.findings.append(
                Finding(
                    Severity.WARNING,
                    "LAGG",
                    f"LAGG {lagg.laggif} has unusual proto '{lagg.proto}'",
                    path="laggs",
                )
            )
        if not lagg.members:
            result.findings.append(
                Finding(
                    Severity.WARNING,
                    "LAGG",
                    f"LAGG {lagg.laggif} has no members",
                    path="laggs",
                )
            )

    # VLAN parent existence
    for vlan in result.vlans:
        assigned = device_to_iface.get((vlan.vlanif or "").lower())
        if assigned is not None:
            vlan.assigned_as = assigned.name


# --------------------------------------------------------------------------- #
# Firewall / NAT
# --------------------------------------------------------------------------- #

def _endpoint_text(el: ET.Element | None) -> str:
    if el is None:
        return ""
    if _find(el, "any") is not None:
        return "any"
    addr = _find_text(el, "address")
    net = _find_text(el, "network")
    port = _find_text(el, "port")
    base = addr or net or ""
    if port:
        base = f"{base}:{port}" if base else f"port {port}"
    return base or "(any)"


def _check_filter(root: ET.Element, result: CheckResult) -> None:
    filt = _find(root, "filter")
    if filt is None:
        return
    for i, rule in enumerate(_find_all(filt, "rule")):
        proto = _find_text(rule, "protocol")
        info = RuleInfo(
            index=i,
            kind="filter",
            type=_find_text(rule, "type"),
            interface=_find_text(rule, "interface"),
            descr=_find_text(rule, "descr"),
            disabled=_find(rule, "disabled") is not None,
            source=_endpoint_text(_find(rule, "source")),
            destination=_endpoint_text(_find(rule, "destination")),
            protocol=proto,
            src_port=_find_text(_find(rule, "source"), "port") if _find(rule, "source") is not None else "",
            dst_port=_find_text(_find(rule, "destination"), "port") if _find(rule, "destination") is not None else "",
            direction=_find_text(rule, "direction"),
            gateway=_find_text(rule, "gateway"),
            floating=_find(rule, "floating") is not None,
            quick=_find(rule, "quick") is not None,
            source_not=_find(_find(rule, "source"), "not") is not None,
            destination_not=_find(_find(rule, "destination"), "not") is not None,
        )
        result.filter_rules.append(info)
        if not info.interface:
            result.findings.append(
                Finding(
                    Severity.WARNING,
                    "Firewall",
                    f"Filter rule has no interface: {info.descr or f'rule #{i + 1}'}",
                    path=f"filter/rule[{i}]",
                )
            )
        if info.type.lower() not in {"pass", "block", "reject", ""}:
            result.findings.append(
                Finding(
                    Severity.WARNING,
                    "Firewall",
                    f"Unusual rule type '{info.type}' on: {info.descr or f'rule #{i + 1}'}",
                    path=f"filter/rule[{i}]",
                )
            )

    disabled = sum(1 for r in result.filter_rules if r.disabled)
    if disabled:
        result.findings.append(
            Finding(
                Severity.INFO,
                "Firewall",
                f"{disabled} of {len(result.filter_rules)} filter rule(s) disabled",
                path="filter",
            )
        )
    if not result.filter_rules:
        result.findings.append(
            Finding(
                Severity.WARNING,
                "Firewall",
                "No filter rules present — default deny may lock you out",
                path="filter",
            )
        )


def _check_nat(root: ET.Element, result: CheckResult) -> None:
    nat = _find(root, "nat")
    if nat is None:
        return
    # Inbound port forwards
    for i, rule in enumerate(_find_all(nat, "rule")):
        result.nat_rules.append(
            RuleInfo(
                index=i,
                kind="nat-port-forward",
                interface=_find_text(rule, "interface"),
                descr=_find_text(rule, "descr"),
                disabled=_find(rule, "disabled") is not None,
                destination=_find_text(rule, "target"),
            )
        )
    # 1:1
    for i, rule in enumerate(_find_all(nat, "onetoone")):
        result.nat_rules.append(
            RuleInfo(
                index=i,
                kind="nat-1:1",
                interface=_find_text(rule, "interface"),
                descr=_find_text(rule, "descr"),
                disabled=_find(rule, "disabled") is not None,
                destination=_find_text(rule, "external"),
            )
        )
    # Outbound
    outbound = _find(nat, "outbound")
    if outbound is not None:
        mode = _find_text(outbound, "mode")
        if mode:
            result.summary["nat_outbound_mode"] = mode
        for i, rule in enumerate(_find_all(outbound, "rule")):
            result.nat_rules.append(
                RuleInfo(
                    index=i,
                    kind="nat-outbound",
                    interface=_find_text(rule, "interface"),
                    descr=_find_text(rule, "descr"),
                    disabled=_find(rule, "disabled") is not None,
                )
            )
    # NPt
    for i, rule in enumerate(_find_all(nat, "npt")):
        result.nat_rules.append(
            RuleInfo(
                index=i,
                kind="nat-npt",
                interface=_find_text(rule, "interface"),
                descr=_find_text(rule, "descr"),
                disabled=_find(rule, "disabled") is not None,
            )
        )


# --------------------------------------------------------------------------- #
# VPN
# --------------------------------------------------------------------------- #

def _collect_vpn(root: ET.Element, result: CheckResult) -> None:
    openvpn = _find(root, "openvpn")
    if openvpn is not None:
        for s in _find_all(openvpn, "openvpn-server"):
            result.vpn.append(
                VpnEndpoint(
                    kind="openvpn-server",
                    name=_find_text(s, "description") or f"vpnid {_find_text(s, 'vpnid')}",
                    disabled=_find(s, "disable") is not None,
                    interface=_find_text(s, "interface"),
                    details=f"proto={_find_text(s, 'protocol')} port={_find_text(s, 'local_port')}",
                    local_address=_find_text(s, "local_port"),
                    protocol="openvpn",
                    vpnid=_find_text(s, "vpnid"),
                    networks=[
                        x.strip()
                        for x in _find_text(s, "tunnel_network").split(",")
                        if x.strip()
                    ],
                )
            )
        for c in _find_all(openvpn, "openvpn-client"):
            peer = _find_text(c, "server_addr")
            result.vpn.append(
                VpnEndpoint(
                    kind="openvpn-client",
                    name=_find_text(c, "description") or f"vpnid {_find_text(c, 'vpnid')}",
                    disabled=_find(c, "disable") is not None,
                    interface=_find_text(c, "interface"),
                    details=f"server={peer}:{_find_text(c, 'server_port')}",
                    peer=peer,
                    protocol="openvpn",
                    vpnid=_find_text(c, "vpnid"),
                    networks=[
                        x.strip()
                        for x in _find_text(c, "remote_network").split(",")
                        if x.strip()
                    ],
                )
            )

    ipsec = _find(root, "ipsec")
    if ipsec is not None:
        for p1 in _find_all(ipsec, "phase1"):
            remote = _find_text(p1, "remote-gateway")
            result.vpn.append(
                VpnEndpoint(
                    kind="ipsec-phase1",
                    name=_find_text(p1, "descr") or f"ikeid {_find_text(p1, 'ikeid')}",
                    disabled=_find(p1, "disabled") is not None,
                    interface=_find_text(p1, "interface"),
                    details=f"remote={remote}",
                    peer=remote,
                    protocol="ipsec",
                    vpnid=_find_text(p1, "ikeid"),
                )
            )
        for p2 in _find_all(ipsec, "phase2"):
            local_net = _find_text(p2, "localid") or _find_text(p2, "local")
            remote_net = _find_text(p2, "remoteid") or _find_text(p2, "remote")
            nets = [x for x in (local_net, remote_net) if x]
            result.vpn.append(
                VpnEndpoint(
                    kind="ipsec-phase2",
                    name=_find_text(p2, "descr") or f"reqid {_find_text(p2, 'reqid')}",
                    disabled=_find(p2, "disabled") is not None,
                    details=f"proto={_find_text(p2, 'protocol')}",
                    networks=nets,
                    protocol="ipsec",
                )
            )

    disabled = sum(1 for v in result.vpn if v.disabled)
    if disabled:
        result.findings.append(
            Finding(
                Severity.INFO,
                "VPN",
                f"{disabled} of {len(result.vpn)} VPN endpoint(s) disabled",
                path="openvpn/ipsec",
            )
        )


# --------------------------------------------------------------------------- #
# DHCP / DNS / routing
# --------------------------------------------------------------------------- #

def _check_dhcp(root: ET.Element, result: CheckResult) -> None:
    for section in ("dhcpd", "dhcpdv6"):
        dhcp = _find(root, section)
        if dhcp is None:
            continue
        for scope in dhcp:
            name = _local(scope.tag).lower()
            rng = _find(scope, "range")
            enabled = _has_flag(scope, "enable")
            entry = {
                "interface": name,
                "family": "v6" if section == "dhcpdv6" else "v4",
                "enabled": "yes" if enabled else "no",
                "from": _find_text(rng, "from") if rng is not None else "",
                "to": _find_text(rng, "to") if rng is not None else "",
                "staticmaps": str(len(_find_all(scope, "staticmap"))),
            }
            result.dhcp_scopes.append(entry)


def _check_dns(root: ET.Element, result: CheckResult) -> None:
    system = _find(root, "system")
    servers = [
        _text(c) for c in _find_all(system, "dnsserver") if _text(c)
    ] if system is not None else []
    result.dns["servers"] = servers
    unbound = _find(root, "unbound")
    unbound_enable = unbound is not None and _has_flag(unbound, "enable")
    result.dns["resolver"] = unbound_enable
    result.dns["unbound_enable"] = unbound_enable
    if unbound is not None:
        # Light enrichment for resiliency Unbound deep-dive (not full schema).
        active = [
            _text(c)
            for c in _find_all(unbound, "active_interface")
            if _text(c)
        ]
        outgoing = [
            _text(c)
            for c in _find_all(unbound, "outgoing_network")
            if _text(c)
        ]
        # Some builds store comma/space lists in a single node.
        if not active:
            raw = _text(_find(unbound, "active_interface"))
            if raw:
                active = [p for p in re.split(r"[\s,]+", raw) if p]
        if not outgoing:
            raw = _text(_find(unbound, "outgoing_network"))
            if raw:
                outgoing = [p for p in re.split(r"[\s,]+", raw) if p]
        result.dns["unbound_active_interface"] = active
        result.dns["unbound_outgoing_network"] = outgoing
        result.dns["unbound_has_acls"] = bool(
            _find(unbound, "acls") or _find_all(unbound, "acl")
        )
        result.dns["unbound_port"] = _text(_find(unbound, "port")) or "53"
        result.dns["unbound_system_domain_local_zone_type"] = _text(
            _find(unbound, "system_domain_local_zone_type")
        )
    else:
        result.dns["unbound_active_interface"] = []
        result.dns["unbound_outgoing_network"] = []
        result.dns["unbound_has_acls"] = False
    result.dns["forwarder"] = _find(root, "dnsmasq") is not None and _has_flag(
        _find(root, "dnsmasq"), "enable"
    )
    if not servers and not result.dns["resolver"] and not result.dns["forwarder"]:
        result.findings.append(
            Finding(
                Severity.WARNING,
                "DNS",
                "No DNS servers and neither resolver (unbound) nor forwarder (dnsmasq) enabled",
                path="system",
            )
        )
    if result.dns["resolver"] and result.dns["forwarder"]:
        result.findings.append(
            Finding(
                Severity.WARNING,
                "DNS",
                "Both DNS Resolver (unbound) and Forwarder (dnsmasq) appear enabled — "
                "they cannot both bind port 53 on the same interface",
                path="unbound/dnsmasq",
            )
        )


def _check_gateways(root: ET.Element, result: CheckResult) -> None:
    gws = _find(root, "gateways")
    if gws is None:
        return
    for gw in _find_all(gws, "gateway_item"):
        result.gateways.append(
            {
                "name": _find_text(gw, "name"),
                "interface": _find_text(gw, "interface"),
                "gateway": _find_text(gw, "gateway"),
                "ipprotocol": _find_text(gw, "ipprotocol"),
                "default": "yes" if _find(gw, "defaultgw") is not None else "no",
                "disabled": "yes" if _find(gw, "disabled") is not None else "no",
            }
        )
    for group in _find_all(gws, "gateway_group"):
        members = []
        for item in _find_all(group, "item"):
            name = _text(item).split("|", 1)[0].strip()
            if name:
                members.append(name)
        result.gateway_groups.append(
            {
                "name": _find_text(group, "name"),
                "descr": _find_text(group, "descr"),
                "members": members,
            }
        )


_VPN_BIND_KEYWORDS = {"any", "lo0", "localhost", ""}


def _check_vpn_bindings(result: CheckResult) -> None:
    """A tunnel bound to a name that is not an interface or gateway group."""
    known = {i.name.lower() for i in result.interfaces}
    known |= {str(g.get("name", "")).lower() for g in result.gateway_groups}
    for vpn in result.vpn:
        bound = (vpn.interface or "").strip()
        low = bound.lower()
        if vpn.kind not in {"openvpn-server", "openvpn-client", "ipsec-phase1"}:
            continue
        if low in _VPN_BIND_KEYWORDS or low in known or low.startswith("_vip"):
            continue
        result.findings.append(
            Finding(
                Severity.WARNING,
                "VPN",
                f"{vpn.name} is bound to '{bound}', which is not an interface or "
                "gateway group in this config. pfSense cannot pick the intended WAN "
                "for this tunnel; check which address it actually sources from.",
                path="openvpn" if vpn.protocol == "openvpn" else "ipsec",
            )
        )


def _check_segmentation(result: CheckResult) -> None:
    """Which inside subnets the rules let reach each other."""
    from pfsense_checker.segmentation import OPEN, analyse_segmentation

    seg = analyse_segmentation(result)
    if not seg.reach:
        return
    titles = {z.name: z.title for z in seg.zones}
    others = len(seg.zones) - 1
    result.findings.append(
        Finding(
            Severity.WARNING if seg.score < 60 else Severity.INFO,
            "Segmentation",
            f"Inside subnets are {seg.verdict} (score {seg.score}/100): "
            f"{seg.count(OPEN)} of {seg.pairs} subnet pairs allow any protocol, "
            f"{seg.count('limited')} allow some services.",
            path="filter",
            remediation="Give each inside interface an explicit block to RFC1918 / the other "
            "inside networks above its pass-to-any rule, then pass only the services "
            "each subnet needs.",
        )
    )
    for name, summary in seg.summaries.items():
        if not summary.open_to:
            continue
        rules = sorted({n for d in summary.open_to for n in seg.reach[(name, d)].rules})
        reach = "every other inside subnet" if len(summary.open_to) == others else (
            ", ".join(titles[d] for d in summary.open_to)
        )
        result.findings.append(
            Finding(
                Severity.WARNING,
                "Segmentation",
                f"{titles[name]} ({name.upper()}) can reach {reach} on any protocol "
                f"(filter rule {', '.join(f'#{n}' for n in rules)}).",
                path="filter",
            )
        )
    for line in seg.layer2:
        result.findings.append(Finding(Severity.INFO, "Segmentation", line, path="bridges"))


def _check_static_routes(root: ET.Element, result: CheckResult) -> None:
    sr = _find(root, "staticroutes")
    if sr is None:
        return
    for route in _find_all(sr, "route"):
        result.static_routes.append(
            {
                "network": _find_text(route, "network"),
                "gateway": _find_text(route, "gateway"),
                "descr": _find_text(route, "descr"),
                "disabled": "yes" if _find(route, "disabled") is not None else "no",
            }
        )


def _check_virtual_ips(root: ET.Element, result: CheckResult) -> None:
    vip_root = _find(root, "virtualip")
    if vip_root is None:
        return
    for vip in _find_all(vip_root, "vip"):
        result.virtual_ips.append(
            {
                "mode": _find_text(vip, "mode"),
                "interface": _find_text(vip, "interface"),
                "subnet": f"{_find_text(vip, 'subnet')}/{_find_text(vip, 'subnet_bits')}",
                "descr": _find_text(vip, "descr"),
            }
        )


def _check_aliases(root: ET.Element, result: CheckResult) -> None:
    aliases = _find(root, "aliases")
    if aliases is None:
        return
    for al in _find_all(aliases, "alias"):
        result.aliases.append(
            {
                "name": _find_text(al, "name"),
                "type": _find_text(al, "type"),
                "address": _find_text(al, "address"),
                "descr": _find_text(al, "descr"),
            }
        )


def _check_certs(root: ET.Element, result: CheckResult) -> None:
    result.certs = {
        "ca": len(_find_all(root, "ca")),
        "cert": len(_find_all(root, "cert")),
        "crl": len(_find_all(root, "crl")),
    }


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #

def _check_users(root: ET.Element, result: CheckResult) -> None:
    system = _find(root, "system")
    if system is None:
        return
    users = _find_all(system, "user")
    names: list[str] = []
    for user in users:
        name = _find_text(user, "name")
        if name:
            names.append(name)
        if name == "admin":
            has_hash = bool(
                _find_text(user, "bcrypt-hash") or _find_text(user, "password")
            )
            if not has_hash:
                result.findings.append(
                    Finding(
                        Severity.INFO,
                        "Users",
                        "Admin user has no password hash in backup "
                        "(normal for some exports)",
                        path="system/user",
                    )
                )
    result.summary["users"] = names


# --------------------------------------------------------------------------- #
# Packages + services
# --------------------------------------------------------------------------- #

def _collect_packages(root: ET.Element, result: CheckResult) -> None:
    installed = _find(root, "installedpackages")
    if installed is None:
        return

    for pkg in _find_all(installed, "package"):
        info = PackageInfo(
            name=_find_text(pkg, "name"),
            version=_find_text(pkg, "version"),
            descr=_find_text(pkg, "descr"),
            internal_name=_find_text(pkg, "internal_name"),
            config_file=_find_text(pkg, "configurationfile"),
        )
        info.enabled, info.notes = _infer_package_enabled(installed, info)
        result.packages.append(info)

    # Record which config sub-sections exist under installedpackages
    result.package_config_keys = sorted(
        {
            _local(c.tag).lower()
            for c in installed
            if _local(c.tag).lower() != "package"
        }
    )

    disabled = [p for p in result.packages if p.enabled is False]
    if disabled:
        result.findings.append(
            Finding(
                Severity.INFO,
                "Packages",
                f"{len(disabled)} package(s) appear disabled: "
                + ", ".join(p.name for p in disabled),
                path="installedpackages",
            )
        )


def _infer_package_enabled(
    installed: ET.Element, info: PackageInfo
) -> tuple[bool | None, str]:
    """Best-effort detection of whether a package's service is enabled.

    pfSense has no universal per-package ``disabled`` flag; each package stores
    its own state in its own config sub-section. We look at the common patterns
    (``<enable>`` / ``<enabled>`` presence, ``on``/``off`` values) inside a
    config block whose tag matches the package name.
    """
    key = (info.internal_name or info.name).lower().replace(" ", "")
    config_block = None
    for child in installed:
        tag = _local(child.tag).lower()
        if tag == "package":
            continue
        if tag == key or tag.startswith(key) or key.startswith(tag):
            config_block = child
            break

    if config_block is None:
        return None, "no dedicated config block found"

    # Look for a config/enable style toggle within the block (possibly nested).
    for path in ("config", "general", "settings", ""):
        node = _find(config_block, path) if path else config_block
        if node is None:
            continue
        for flag in ("enable", "enabled", "active"):
            el = _find(node, flag)
            if el is not None:
                val = _text(el).lower()
                enabled = val not in {"", "off", "false", "0", "no", "disabled"}
                # Empty presence tag usually means enabled in pfSense.
                if val == "":
                    enabled = True
                return enabled, f"{flag}={val or '(present)'}"
    return None, "state not determinable from config block"


def _collect_services(root: ET.Element, result: CheckResult) -> None:
    installed = _find(root, "installedpackages")
    if installed is None:
        return
    # <service> can be repeated directly under installedpackages
    for svc in _find_all(installed, "service"):
        info = ServiceInfo(
            name=_find_text(svc, "name"),
            rcfile=_find_text(svc, "rcfile"),
            executable=_find_text(svc, "executable"),
            description=_find_text(svc, "description"),
        )
        # 'stopped'/'disabled' style flags if present
        if _find(svc, "stopped") is not None:
            info.enabled = False
        elif _has_flag(svc, "enabled"):
            info.enabled = True
        result.services.append(info)


# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

def _build_summary(result: CheckResult) -> None:
    s = result.summary
    s["root"] = result.root_tag
    s["version"] = result.version
    s["hostname"] = result.hostname
    s["domain"] = result.domain
    s["interfaces"] = [i.name for i in result.interfaces]
    s["interfaces_total"] = len(result.interfaces)
    s["interfaces_enabled"] = sum(1 for i in result.interfaces if i.enabled)
    s["interfaces_disabled"] = sum(1 for i in result.interfaces if not i.enabled)
    s["bridges"] = len(result.bridges)
    s["vlans"] = len(result.vlans)
    s["laggs"] = len(result.laggs)
    s["filter_rules"] = len(result.filter_rules)
    s["nat_rules"] = len(result.nat_rules)
    s["vpn"] = len(result.vpn)
    s["packages"] = len(result.packages)
    s["packages_disabled"] = sum(1 for p in result.packages if p.enabled is False)
    s["services"] = len(result.services)
    s["gateways"] = len(result.gateways)
    s["dhcp_scopes"] = len(result.dhcp_scopes)
    s["virtual_ips"] = len(result.virtual_ips)
    s["aliases"] = len(result.aliases)
    s["certs"] = result.certs
    s["users"] = result.summary.get("users", [])

    if result.version:
        result.findings.insert(
            0,
            Finding(
                Severity.INFO,
                "System",
                f"Config version {result.version} · "
                f"{s['interfaces_total']} interfaces "
                f"({s['interfaces_enabled']} up / {s['interfaces_disabled']} down) · "
                f"{s['bridges']} bridges · {s['vlans']} VLANs · {s['laggs']} LAGGs · "
                f"{s['packages']} packages",
                path="version",
            ),
        )
