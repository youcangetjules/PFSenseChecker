"""MikroTik RouterOS export (.rsc) parser producing a CheckResult inventory."""

from __future__ import annotations

import re
from pathlib import Path

from pfsense_checker.models import (
    BridgeInfo,
    CheckResult,
    Finding,
    InterfaceInfo,
    LaggInfo,
    RuleInfo,
    Severity,
    VlanInfo,
    VpnEndpoint,
)

# key=value with optional quoted value; tolerates [ find ... ] selectors.
_PAIR_RE = re.compile(r'([A-Za-z0-9_.\-]+)=("(?:[^"\\]|\\.)*"|\S+)')

# Interface kinds keyed by the RouterOS section under /interface.
_TUNNEL_SECTIONS = {
    "wireguard": "wireguard",
    "ovpn-server": "openvpn",
    "ovpn-client": "openvpn",
    "eoip": "gre",
    "gre": "gre",
    "ipip": "gif",
    "pppoe-client": "ppp",
    "pppoe-server": "ppp",
    "l2tp-client": "ppp",
    "l2tp-server": "ppp",
    "sstp-client": "ppp",
    "pptp-client": "ppp",
    "6to4": "gif",
    "vrrp": "other",
}


def looks_like_routeros(text: str) -> bool:
    head = text.lstrip()
    if "RouterOS" in text[:400]:
        return True
    # Section markers or command lines are the strongest signal.
    if re.search(r"^\s*/(interface|ip|system|routing|ipv6|user)\b", text, re.M):
        return True
    if head.startswith("/") or head.startswith("# "):
        # a bare export often starts with a comment then a "/section"
        return bool(re.search(r"^\s*/\S", text, re.M))
    return False


def _parse_pairs(line: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _PAIR_RE.finditer(line):
        key = m.group(1)
        val = m.group(2)
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        out[key] = val
    return out


def _logical_lines(text: str) -> list[str]:
    """Join RouterOS backslash line-continuations into single logical lines.

    RouterOS wraps exports mid-token (e.g. ``name=\\`` / ``    W1-CFG1``), so
    continuation lines are joined with their leading indent removed and no
    separator inserted.
    """
    raw = text.replace("\r\n", "\n").split("\n")
    joined: list[str] = []
    buf = ""
    for line in raw:
        stripped = line.rstrip()
        if buf:
            stripped = stripped.lstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1]
            continue
        buf += stripped
        joined.append(buf)
        buf = ""
    if buf:
        joined.append(buf)
    return joined


def _kind_for_section(section: str) -> str:
    last = section.rsplit(" ", 1)[-1]
    if last == "ethernet":
        return "physical"
    if last == "bridge":
        return "bridge"
    if last == "vlan":
        return "vlan"
    if last in ("bonding",):
        return "lagg"
    return _TUNNEL_SECTIONS.get(last, "other")


# Sections whose full key/value pairs are kept in result.summary["raw"].
RAW_SECTIONS = frozenset(
    {
        "ip address",
        "ip pool",
        "ip dhcp-server",
        "ip dhcp-server network",
        "ip dhcp-server lease",
        "ip dhcp-relay",
        "ip dhcp-client",
        "ip firewall filter",
        "ip dns",
        "ip route",
        "interface bridge",
        "interface bridge port",
        "interface bridge vlan",
        "interface vlan",
        "interface list member",
        "interface wireless",
        "interface wireless security-profiles",
        "interface wifi",
        "interface wifi security",
        "interface wifi configuration",
        "interface wifi datapath",
        "interface wifi cap",
        "interface wifi capsman",
        "interface wireless cap",
        "caps-man manager",
        "caps-man manager interface",
        "caps-man configuration",
        "caps-man security",
        "caps-man datapath",
        "caps-man channel",
        "caps-man interface",
        "caps-man provisioning",
        "interface ethernet",
        # CRS1xx/2xx switch-chip VLANs (vlan_enforcement.py)
        "interface ethernet switch",
        "interface ethernet switch vlan",
        "interface ethernet switch egress-vlan-tag",
        "interface ethernet switch ingress-vlan-translation",
        "interface bonding",
        "queue simple",
        "queue tree",
        # What the device itself offers on the network (security_holes.py).
        "ip service",
        "ip ssh",
        "ip proxy",
        "ip socks",
        "ip upnp",
        "ip cloud",
        "ip neighbor discovery-settings",
        "snmp",
        "tool mac-server",
        "tool mac-server mac-winbox",
    }
)


def _is_interface_section(section: str) -> bool:
    """True for sections whose rows are interfaces (``/interface eoip``, ``/interface veth``…).

    Not interfaces: interface lists (all, none, dynamic, static, WAN, LAN…), and
    every sub-section — ``/interface ethernet switch`` (the switch chip),
    ``/interface wireless security-profiles``, ``/interface bridge port`` and
    the like. Those used to show up as ports on the maps and in the counts.
    """
    words = section.split()
    return len(words) == 2 and words[0] == "interface" and words[1] != "list"


def parse_routeros(text: str, path: Path | str | None = None) -> CheckResult:
    result = CheckResult(
        path=Path(path) if path else None,
        source_type="mikrotik",
        valid_xml=True,  # not XML, but "parsed OK" semantically
        root_tag="routeros",
        source_status="ok",
    )

    ifaces: dict[str, InterfaceInfo] = {}

    def ensure_iface(name: str, kind: str = "physical") -> InterfaceInfo:
        key = name.lower()
        if key not in ifaces:
            ifaces[key] = InterfaceInfo(name=name, device=name, kind=kind, enabled=True)
        return ifaces[key]

    # Export header metadata lives in comments / the console banner.
    m = re.search(r"by RouterOS (\S+)", text) or re.search(
        r"MikroTik RouterOS (\S+)", text
    )
    if m:
        result.version = m.group(1)

    section = ""
    users: list[str] = []
    dns_servers: list[str] = []
    pools: dict[str, dict[str, str]] = {}
    dhcp_networks: list[dict[str, str]] = []

    for line in _logical_lines(text):
        s = line.strip()
        if not s:
            continue
        if s.startswith("#"):
            mm = re.match(r"#\s*model\s*=\s*(\S+)", s)
            if mm:
                result.summary["model"] = mm.group(1)
            mm = re.match(r"#\s*serial number\s*=\s*(\S+)", s)
            if mm:
                result.summary["serial"] = mm.group(1)
            continue
        if s.startswith("/"):
            section = s[1:].strip()
            continue

        parts = s.split(None, 1)
        verb = parts[0]
        rest = parts[1] if len(parts) > 1 else ""
        pairs = _parse_pairs(rest)

        if verb not in ("add", "set"):
            continue

        if section in RAW_SECTIONS:
            # Keep every key for the deep analysis (config_analysis.py); the
            # typed model above drops some (connection-state, local-address…).
            raw = dict(pairs)
            raw["_verb"] = verb
            # "set telnet disabled=no": the row is named by a bare first word, not a key.
            first = rest.split(None, 1)[0] if rest.strip() else ""
            if verb == "set" and first and "=" not in first and not first.startswith("["):
                raw["_name"] = first
            result.summary.setdefault("raw", {}).setdefault(section, []).append(raw)
        elif section == "snmp community" and pairs.get("name", "").strip('"').lower() == "public" \
                and str(pairs.get("disabled", "no")).lower() != "yes":
            # Only the fact is kept. Community names are passwords and stay out of the summary.
            result.summary["snmp_public_community"] = True

        _dispatch(
            section,
            pairs,
            result,
            ensure_iface,
            users,
            dns_servers,
            pools,
            dhcp_networks,
        )

    result.interfaces = list(ifaces.values())
    result.ip_pools = list(pools.values())
    _resolve_dhcp_pools(result, pools, dhcp_networks)
    _derive_gateways_from_routes(result)
    _cross_link(result)
    _finalize(result, users, dns_servers)
    return result


def _dispatch(  # noqa: ANN001
    section,
    pairs,
    result,
    ensure_iface,
    users,
    dns_servers,
    pools,
    dhcp_networks,
):
    name = pairs.get("name") or pairs.get("default-name") or ""
    disabled = pairs.get("disabled", "no").lower() in ("yes", "true")

    if section == "interface bridge":
        if name:
            iface = ensure_iface(name, "bridge")
            iface.enabled = not disabled
            proto = pairs.get("protocol-mode", "").lower() or "none"
            result.bridges.append(
                BridgeInfo(
                    bridgeif=name,
                    descr=pairs.get("comment", ""),
                    stp_enabled=proto in ("rstp", "stp", "mstp"),
                )
            )
            result.summary.setdefault("bridge_protocol_mode", {})[name] = proto
            result.summary.setdefault("bridge_vlan_filtering", {})[name] = (
                pairs.get("vlan-filtering", "no").lower() in ("yes", "true")
            )

    elif section == "interface bridge port":
        bridge = pairs.get("bridge", "")
        iface = pairs.get("interface", "")
        for b in result.bridges:
            if b.bridgeif == bridge and iface:
                b.members.append(iface)
        if iface:
            result.summary.setdefault("bridge_ports", []).append(
                {
                    "bridge": bridge,
                    "interface": iface,
                    "pvid": pairs.get("pvid", ""),
                    "comment": pairs.get("comment", ""),
                    "frame_types": pairs.get("frame-types", ""),
                }
            )

    elif section == "interface bridge vlan":
        result.summary.setdefault("bridge_vlans", []).append(
            {
                "bridge": pairs.get("bridge", ""),
                "vlan_ids": pairs.get("vlan-ids", ""),
                "tagged": pairs.get("tagged", ""),
                "untagged": pairs.get("untagged", ""),
                "comment": pairs.get("comment", ""),
            }
        )

    elif section == "interface ethernet":
        if name:
            iface = ensure_iface(name, "physical")
            iface.enabled = not disabled
            if pairs.get("comment"):
                iface.descr = pairs["comment"]

    elif section == "interface vlan":
        if name:
            iface = ensure_iface(name, "vlan")
            iface.enabled = not disabled
            result.vlans.append(
                VlanInfo(
                    tag=pairs.get("vlan-id", ""),
                    if_parent=pairs.get("interface", ""),
                    vlanif=name,
                    descr=pairs.get("comment", ""),
                )
            )

    elif section == "interface bonding":
        if name:
            iface = ensure_iface(name, "lagg")
            iface.enabled = not disabled
            slaves = [m.strip() for m in pairs.get("slaves", "").split(",") if m.strip()]
            result.laggs.append(
                LaggInfo(
                    laggif=name,
                    members=slaves,
                    proto=pairs.get("mode", ""),
                    descr=pairs.get("comment", ""),
                )
            )

    elif section == "interface wireless":
        if name:
            iface = ensure_iface(name, "wireless")
            iface.enabled = not disabled
            result.summary.setdefault("wireless_ifaces", []).append(
                {
                    "name": name,
                    "ssid": pairs.get("ssid", ""),
                    "mode": pairs.get("mode", ""),
                    "disabled": "yes" if disabled else "no",
                }
            )

    elif section in ("interface wireless cap", "interface wifi cap"):
        cap = result.summary.setdefault("wireless_cap", {})
        if pairs.get("enabled"):
            cap["enabled"] = pairs["enabled"].lower() in ("yes", "true")
        if pairs.get("bridge"):
            cap["bridge"] = pairs["bridge"]
        if pairs.get("caps-man-addresses"):
            cap["addresses"] = [
                x.strip()
                for x in pairs["caps-man-addresses"].split(",")
                if x.strip()
            ]
        if pairs.get("interfaces") or pairs.get("slaves-static"):
            cap["interfaces"] = [
                x.strip()
                for x in (pairs.get("interfaces", "")).split(",")
                if x.strip()
            ]

    elif section == "caps-man manager":
        if pairs.get("enabled"):
            result.summary["capsman_manager_enabled"] = (
                pairs["enabled"].lower() in ("yes", "true")
            )

    elif section == "caps-man datapath":
        if name:
            result.summary.setdefault("capsman_datapaths", []).append(
                {
                    "name": name,
                    "bridge": pairs.get("bridge", ""),
                    "local_forwarding": pairs.get("local-forwarding", ""),
                    "client_to_client": pairs.get("client-to-client-forwarding", ""),
                    "vlan_id": pairs.get("vlan-id", ""),
                    "vlan_mode": pairs.get("vlan-mode", ""),
                }
            )

    elif section == "caps-man configuration":
        if name:
            # RouterOS shortens datapath overrides to ".key=value" in exports.
            def _ov(key: str) -> str:
                return (
                    pairs.get(f".{key}")
                    or pairs.get(f"datapath.{key}")
                    or ""
                )

            result.summary.setdefault("capsman_configs", []).append(
                {
                    "name": name,
                    "ssid": pairs.get("ssid", ""),
                    "datapath": pairs.get("datapath", ""),
                    "ov_bridge": _ov("bridge"),
                    "ov_local_forwarding": _ov("local-forwarding"),
                    "ov_client_to_client": _ov("client-to-client-forwarding"),
                    "ov_vlan_id": _ov("vlan-id"),
                    "ov_vlan_mode": _ov("vlan-mode"),
                }
            )

    elif section == "caps-man interface":
        if name:
            result.summary.setdefault("capsman_interfaces", []).append(
                {
                    "name": name,
                    "disabled": "yes" if disabled else "no",
                    "configuration": pairs.get("configuration", ""),
                    "master": pairs.get("master-interface", ""),
                    "radio_mac": pairs.get("radio-mac", ""),
                }
            )

    elif section == "caps-man provisioning":
        result.summary.setdefault("capsman_provisioning", []).append(
            {
                "action": pairs.get("action", ""),
                "master_configuration": pairs.get("master-configuration", ""),
                "name_prefix": pairs.get("name-prefix", ""),
            }
        )

    elif section.startswith("interface "):
        # tunnels / vpn / wireguard / pppoe etc.
        kind = _kind_for_section(section)
        last = section.rsplit(" ", 1)[-1]
        if name and kind != "other":
            iface = ensure_iface(name, kind)
            iface.enabled = not disabled
            if kind in ("openvpn", "wireguard", "ppp", "gre", "gif"):
                peer = (
                    pairs.get("connect-to")
                    or pairs.get("remote-address")
                    or pairs.get("endpoint-address")
                    or ""
                )
                nets = [
                    x.strip()
                    for x in pairs.get("allowed-address", "").split(",")
                    if x.strip()
                ]
                result.vpn.append(
                    VpnEndpoint(
                        kind=f"mikrotik-{last}",
                        name=name,
                        disabled=disabled,
                        interface=name,
                        details=pairs.get("comment", ""),
                        peer=peer,
                        local_address=pairs.get("local-address", ""),
                        networks=nets,
                        protocol=kind,
                    )
                )
        elif name and _is_interface_section(section):
            ensure_iface(name, "other").enabled = not disabled

    elif section in ("ip address", "ipv6 address"):
        addr = pairs.get("address", "")
        iface_name = pairs.get("interface", "")
        if iface_name and addr:
            iface = ensure_iface(iface_name)
            ip, _, cidr = addr.partition("/")
            if section == "ip address":
                iface.ipaddr = ip
                iface.subnet = cidr
            else:
                iface.ipaddrv6 = ip
                iface.subnetv6 = cidr

    elif section == "ip dhcp-client":
        iface_name = pairs.get("interface", "")
        if iface_name:
            ensure_iface(iface_name).ipaddr = "dhcp"

    elif section == "ip pool":
        if name:
            ranges = pairs.get("ranges", "")
            # ranges like 10.0.0.100-10.0.0.200
            from_ip, to_ip = "", ""
            if "-" in ranges:
                from_ip, _, to_ip = ranges.partition("-")
            pools[name] = {
                "name": name,
                "ranges": ranges,
                "from": from_ip.strip(),
                "to": to_ip.strip(),
            }

    elif section == "ip dhcp-server":
        result.dhcp_scopes.append(
            {
                "interface": pairs.get("interface", ""),
                "family": "v4",
                "enabled": "no" if disabled else "yes",
                "from": pairs.get("address-pool", ""),
                "to": "",
                "pool": pairs.get("address-pool", ""),
                "name": name,
                "staticmaps": "",
                "network": "",
            }
        )

    elif section == "ip dhcp-server network":
        dhcp_networks.append(
            {
                "address": pairs.get("address", ""),
                "gateway": pairs.get("gateway", ""),
                "dns": pairs.get("dns-server", ""),
                "comment": pairs.get("comment", ""),
            }
        )

    elif section == "ip firewall filter":
        chain = pairs.get("chain", "")
        result.filter_rules.append(
            RuleInfo(
                index=len(result.filter_rules),
                kind="filter",
                type=pairs.get("action", ""),
                interface=pairs.get("in-interface", ""),
                out_interface=pairs.get("out-interface", ""),
                chain=chain,
                protocol=pairs.get("protocol", ""),
                src_port=pairs.get("src-port", ""),
                dst_port=pairs.get("dst-port", ""),
                descr=pairs.get("comment", ""),
                disabled=disabled,
                source=pairs.get("src-address", ""),
                destination=pairs.get("dst-address", ""),
            )
        )

    elif section == "ip firewall nat":
        action = pairs.get("action", "nat")
        result.nat_rules.append(
            RuleInfo(
                index=len(result.nat_rules),
                kind=f"nat-{action}",
                type=action,
                interface=pairs.get("in-interface", ""),
                out_interface=pairs.get("out-interface", ""),
                chain=pairs.get("chain", ""),
                protocol=pairs.get("protocol", ""),
                dst_port=pairs.get("dst-port", ""),
                descr=pairs.get("comment", ""),
                disabled=disabled,
                source=pairs.get("src-address", ""),
                destination=pairs.get("to-addresses", "") or pairs.get("dst-address", ""),
                direction="out" if action in ("masquerade", "src-nat") else "in",
            )
        )

    elif section == "system identity":
        if pairs.get("name"):
            result.hostname = pairs["name"]

    elif section == "system package" or section == "system resource":
        if pairs.get("version") and not result.version:
            result.version = pairs["version"]

    elif section == "ip dns":
        if pairs.get("servers"):
            dns_servers.extend(
                x.strip() for x in pairs["servers"].split(",") if x.strip()
            )

    elif section == "system ntp client servers":
        if pairs.get("address"):
            result.summary.setdefault("ntp_servers", []).append(pairs["address"])

    elif section == "ip dhcp-relay":
        result.summary.setdefault("dhcp_relays", []).append(
            {
                "name": name,
                "interface": pairs.get("interface", ""),
                "dhcp_server": pairs.get("dhcp-server", ""),
                "disabled": "yes" if disabled else "no",
            }
        )

    elif section == "user" or section == "user group":
        if section == "user" and name:
            users.append(name)

    elif section == "routing bgp connection" or section == "ip route":
        if section == "ip route":
            network = pairs.get("dst-address", "")
            gateway = pairs.get("gateway", "")
            result.static_routes.append(
                {
                    "network": network,
                    "gateway": gateway,
                    "descr": pairs.get("comment", ""),
                    "disabled": "yes" if disabled else "no",
                    "distance": pairs.get("distance", ""),
                    "routing-table": pairs.get("routing-table", ""),
                }
            )

    elif section in ("ip ipsec peer", "ip ipsec identity"):
        peer = pairs.get("address", "") or pairs.get("remote-address", "")
        result.vpn.append(
            VpnEndpoint(
                kind="mikrotik-ipsec",
                name=name or peer or "peer",
                disabled=disabled,
                details=pairs.get("comment", ""),
                peer=peer,
                protocol="ipsec",
            )
        )

    elif section == "ip ipsec policy":
        src = pairs.get("src-address", "")
        dst = pairs.get("dst-address", "")
        nets = [x for x in (src, dst) if x]
        result.vpn.append(
            VpnEndpoint(
                kind="mikrotik-ipsec-policy",
                name=name or f"{src}->{dst}",
                disabled=disabled,
                details=pairs.get("comment", ""),
                networks=nets,
                peer=pairs.get("sa-dst-address", ""),
                protocol="ipsec",
            )
        )


def _resolve_dhcp_pools(
    result: CheckResult,
    pools: dict[str, dict[str, str]],
    dhcp_networks: list[dict[str, str]],
) -> None:
    """Fill DHCP scope from/to from named pools and attach network if unique."""
    for scope in result.dhcp_scopes:
        pool_name = scope.get("pool") or scope.get("from") or ""
        pool = pools.get(pool_name)
        if pool:
            scope["from"] = pool.get("from", "")
            scope["to"] = pool.get("to", "")
            scope["pool"] = pool_name
        if len(dhcp_networks) == 1:
            scope["network"] = dhcp_networks[0].get("address", "")
            if not scope.get("gateway"):
                scope["gateway"] = dhcp_networks[0].get("gateway", "")
        elif dhcp_networks:
            # Best-effort: match by comment / leave network blank
            scope["network"] = ""


def _derive_gateways_from_routes(result: CheckResult) -> None:
    """Synthesise gateway entries from default routes for correlation."""
    for route in result.static_routes:
        if route.get("disabled") == "yes":
            continue
        network = (route.get("network") or "").strip()
        gateway = (route.get("gateway") or "").strip()
        if network in ("0.0.0.0/0", "::/0", "0.0.0.0", "default") and gateway:
            # Gateway may be "ether1" or an IP or "IP%iface"
            gw_ip, _, via = gateway.partition("%")
            result.gateways.append(
                {
                    "name": f"route-default-{gw_ip or gateway}",
                    "interface": via or "",
                    "gateway": gw_ip or gateway,
                    "ipprotocol": "inet6" if ":" in (gw_ip or gateway) else "inet",
                    "default": "yes",
                    "disabled": "no",
                }
            )


def _cross_link(result: CheckResult) -> None:
    dev_map = {i.device.lower(): i for i in result.interfaces}
    for bridge in result.bridges:
        assigned = dev_map.get(bridge.bridgeif.lower())
        if assigned:
            bridge.assigned_as = assigned.name
        for m in bridge.members:
            mi = dev_map.get(m.lower())
            if mi:
                mi.bridge_member = True
                mi.bridge_of = bridge.bridgeif
    for lg in result.laggs:
        assigned = dev_map.get(lg.laggif.lower())
        if assigned:
            lg.assigned_as = assigned.name
    for v in result.vlans:
        assigned = dev_map.get((v.vlanif or "").lower())
        if assigned:
            v.assigned_as = assigned.name


def _finalize(result: CheckResult, users: list[str], dns_servers: list[str]) -> None:
    result.dns["servers"] = dns_servers
    result.summary["users"] = users

    if not result.interfaces:
        result.findings.append(
            Finding(Severity.WARNING, "Interfaces", "No interfaces found in export")
        )
    if not result.hostname:
        result.findings.append(
            Finding(Severity.INFO, "System", "No system identity (hostname) set")
        )
    if not dns_servers:
        result.findings.append(
            Finding(Severity.WARNING, "DNS", "No DNS servers configured (/ip dns)")
        )
    if not result.filter_rules:
        result.findings.append(
            Finding(
                Severity.WARNING,
                "Firewall",
                "No /ip firewall filter rules — device may be unprotected",
            )
        )
    else:
        has_drop_input = any(
            r.type.lower() in ("drop", "reject")
            and ("input" in r.interface.lower() or True)
            for r in result.filter_rules
        )
        if not has_drop_input:
            result.findings.append(
                Finding(
                    Severity.INFO,
                    "Firewall",
                    "No explicit drop/reject rule detected in filter chain",
                )
            )
    for iface in result.interfaces:
        if iface.enabled and not iface.ipaddr and not iface.ipaddrv6 \
                and not iface.bridge_member and iface.kind not in ("lagg", "physical"):
            result.findings.append(
                Finding(
                    Severity.INFO,
                    "Interfaces",
                    f"{iface.name} enabled without an IP (transit/bridge port?)",
                    path=f"interface/{iface.name}",
                )
            )
        if iface.ipaddr.lower() == "dhcp":
            result.findings.append(
                Finding(
                    Severity.INFO, "Interfaces", f"{iface.name} uses DHCP",
                    path=f"interface/{iface.name}",
                )
            )
    if any(r.kind == "nat-masquerade" for r in result.nat_rules):
        result.findings.append(
            Finding(Severity.INFO, "NAT", "Masquerade (srcnat) rule present")
        )

    from pfsense_checker.attack_surface import apply_posture, assess_routeros

    assess_routeros(result)
    _build_summary(result, users)
    apply_posture(result)


def _build_summary(result: CheckResult, users: list[str]) -> None:
    s = result.summary
    s["root"] = "routeros"
    s["source_type"] = "mikrotik"
    s["version"] = result.version
    s["hostname"] = result.hostname
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
    s["packages"] = 0
    s["packages_disabled"] = 0
    s["services"] = 0
    s["gateways"] = len(result.gateways)
    s["dhcp_scopes"] = len(result.dhcp_scopes)
    s["virtual_ips"] = 0
    s["aliases"] = 0
    s["certs"] = {"ca": 0, "cert": 0, "crl": 0}
    s["users"] = users

    result.findings.insert(
        0,
        Finding(
            Severity.INFO,
            "System",
            f"MikroTik RouterOS · {s['interfaces_total']} interfaces "
            f"({s['interfaces_enabled']} up / {s['interfaces_disabled']} down) · "
            f"{s['bridges']} bridges · {s['vlans']} VLANs · {s['laggs']} bonds · "
            f"{s['filter_rules']} filter rules",
            path="routeros",
        ),
    )
