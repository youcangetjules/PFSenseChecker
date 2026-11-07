"""Problems / Troubleshooting: describe a problem, ask Ollama against the config.

The operator picks a device (a loaded config), an interface on it, a problem
type and adds free-text notes. :func:`build_context` gathers the parts of the
config that matter for that interface and problem — the interface itself, its
VLAN / bridge, DHCP, routes, gateways, firewall and NAT rules, DNS, VPN — plus
NetCheck's own Will it work? checks and findings that mention the interface.
Secret fields are dropped and secret-looking blobs redacted before anything is
sent.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from pfsense_checker import ai, config_analysis, device_identity, name_parser
from pfsense_checker.checker import check_file
from pfsense_checker.models import CheckResult

WHOLE_DEVICE = ""  # interface key meaning "no single interface"
MAX_CONTEXT_CHARS = 60_000
MAX_RULES = 80
MAX_SECTION_ROWS = 60


@dataclass(frozen=True)
class Problem:
    key: str
    label: str
    focus: frozenset[str]  # config areas: dhcp, dns, route, nat, firewall, vpn, wireless, link, l2
    ask: str


def _p(key: str, label: str, focus: str, ask: str) -> Problem:
    return Problem(key, label, frozenset(focus.split()), ask)


PROBLEMS: tuple[Problem, ...] = (
    _p("no_internet", "No internet access", "route nat firewall dns l2",
       "Clients on this interface have no internet access."),
    _p("no_dhcp", "Clients get no IP address (DHCP)", "dhcp firewall l2",
       "Clients on this interface do not get an IP address from DHCP."),
    _p("no_reach", "Can't reach another subnet / VLAN", "route firewall nat l2",
       "Hosts on this interface cannot reach another subnet or VLAN (or vice versa)."),
    _p("dns", "DNS not resolving", "dns dhcp firewall",
       "Clients on this interface cannot resolve names."),
    _p("slow", "Slow / poor throughput", "link l2 route wireless",
       "Traffic through this interface is slower than expected."),
    _p("drops", "Intermittent drops", "link l2 route wireless dhcp",
       "Connections through this interface drop intermittently."),
    _p("link", "Port / link down", "link l2",
       "This port or link is down or not passing traffic."),
    _p("wifi", "Wi-Fi clients can't connect", "wireless l2 dhcp",
       "Wi-Fi clients cannot connect or get no traffic through."),
    _p("vpn", "VPN not connecting / no traffic", "vpn route firewall nat",
       "A VPN on this device does not connect, or passes no traffic."),
    _p("port_forward", "Port forward / inbound service not working", "nat firewall route",
       "An inbound service / port forward through this interface does not work."),
    _p("mgmt", "Can't manage the device (GUI / SSH)", "firewall route l2",
       "The device cannot be managed (web GUI / SSH / Winbox) from this interface."),
    _p("other", "Something else (describe below)",
       "dhcp dns route nat firewall vpn wireless link l2",
       "The operator describes the problem below."),
)
PROBLEM_BY_KEY = {p.key: p for p in PROBLEMS}

SYSTEM_PROMPT = (
    "You are a senior network engineer troubleshooting a live fault on a pfSense / OPNsense "
    "firewall or a MikroTik RouterOS device. You are given the relevant parts of the device's "
    "real configuration (secrets removed), automated checks from NetCheck, and the operator's "
    "description of the problem. Reason only from the configuration shown and say when "
    "something you would need is not in it. Answer in this order:\n"
    "1. Most likely causes, ranked, each citing the exact config lines or settings that point "
    "to it.\n"
    "2. What to check on the device to confirm (exact pfSense UI paths or RouterOS commands).\n"
    "3. The fix for each cause (exact steps or commands), and any side effects.\n"
    "Be concise. Do not invent interfaces, addresses or rules that are not in the config. "
    "Note deliberate design choices (for example VLANs enforced in the switch chip with "
    "bridge vlan-filtering off to keep hardware offload) and do not 'fix' them."
)


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

_CACHE: dict[str, tuple[float, CheckResult]] = {}


def load_result(path: str | Path) -> CheckResult:
    """check_file, cached by path and modification time."""
    p = Path(path)
    mtime = p.stat().st_mtime
    key = str(p.resolve())
    hit = _CACHE.get(key)
    if hit is not None and hit[0] == mtime:
        return hit[1]
    result = check_file(p)
    _CACHE[key] = (mtime, result)
    return result


# --------------------------------------------------------------------------- #
# Interfaces
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class IfaceChoice:
    key: str  # interface name (pfSense opt18 / RouterOS name); "" = whole device
    label: str  # shown in the combo


def _nets(iface) -> str:  # noqa: ANN001
    return ", ".join(str(n) for n in iface.networks)


def interface_choices(result: CheckResult, scheme: name_parser.NameScheme | None = None) -> list[IfaceChoice]:
    """Every interface of the device, labelled with description, addresses and VLAN."""
    scheme = scheme or name_parser.load_scheme()
    dev = config_analysis._Device(result)  # noqa: SLF001 - same package
    out = [IfaceChoice(WHOLE_DEVICE, "(whole device — no single interface)")]
    info = {i.name.lower(): i for i in result.interfaces}
    skip = _not_interfaces(result)
    for key in sorted(dev.ifaces, key=_iface_sort_key):
        if key in skip:
            continue
        iface = dev.ifaces[key]
        bits = [iface.name]
        kind = _mt_kind(result, key)
        if kind:
            bits.append(kind)
        if iface.label and iface.label != iface.name:
            bits.append(iface.label)
        pf = info.get(key)
        if pf is not None and pf.ipaddr in ("dhcp", "pppoe", "dhcp6"):
            bits.append(pf.ipaddr.upper())
        if iface.networks:
            bits.append(_nets(iface))
        if iface.vlan_id:
            bits.append(f"VLAN {iface.vlan_id}")
        if iface.bridge_port_of:
            bits.append(f"port of {iface.bridge_port_of}")
        if not iface.enabled:
            bits.append("DISABLED")
        out.append(IfaceChoice(iface.name, " · ".join(bits)))
    return out


_ROS_LIST_BUILTINS = {"all", "none", "dynamic", "static"}


def _not_interfaces(result: CheckResult) -> set[str]:
    """RouterOS names the parser lists as interfaces but are not: interface
    lists and wireless security profiles."""
    if result.source_type != "mikrotik":
        return set()
    raw = result.summary.get("raw", {})
    out = set(_ROS_LIST_BUILTINS)
    for section, key in (("interface list", "name"), ("interface list member", "list"),
                         ("interface wireless security-profiles", "name"),
                         ("interface wifi security", "name")):
        for row in raw.get(section, []):
            if row.get(key):
                out.add(str(row[key]).lower())
    return out


def _mt_kind(result: CheckResult, key: str) -> str:
    if result.source_type != "mikrotik":
        return ""
    raw = result.summary.get("raw", {})
    for section, kind in (("interface bridge", "bridge"), ("interface vlan", "VLAN interface"),
                          ("interface ethernet", "ethernet"), ("interface wireless", "wireless"),
                          ("interface wifi", "wifi"), ("interface bonding", "bond"),
                          ("interface wireguard", "WireGuard"), ("interface ovpn-server", "OpenVPN"),
                          ("interface ovpn-client", "OpenVPN")):
        for row in raw.get(section, []):
            if str(row.get("name", row.get("default-name", ""))).lower() == key:
                return kind
    if key.startswith(("ether", "sfp", "qsfp", "combo")):
        return "ethernet"
    if key.startswith("wlan"):
        return "wireless"
    return ""


def _iface_sort_key(name: str) -> tuple:
    low = name.lower()
    head = low.rstrip("0123456789")
    tail = low[len(head):]
    order = {"wan": 0, "lan": 1}.get(head, 2)
    return (order, head, int(tail) if tail else -1)


# --------------------------------------------------------------------------- #
# Context
# --------------------------------------------------------------------------- #


# Field names that hold secrets. Precise on purpose: ai.SECRET_FIELD_HINTS also
# matches "ca" inside broadcast-flood / local-address, which would hide settings
# that matter for troubleshooting.
_SECRET_PARTS = (
    "password", "passwd", "passphrase", "secret", "pre-shared", "preshared", "psk", "privatekey",
    "private-key", "private_key", "bcrypt", "md5-hash", "apikey", "api-key", "api_key", "authkey",
    "auth-key", "domainkey", "token", "community", "shared-key", "sharedkey", "sae-password",
)
_SECRET_NAMES = frozenset({"key", "tls", "prv", "sshdata", "rrddata", "hash", "pass"})


def is_secret_key(name: str) -> bool:
    low = name.lower()
    if any(part in low for part in _SECRET_PARTS):
        return True
    tokens = set(low.replace("_", "-").replace("/", "-").replace(".", "-").split("-"))
    return bool(tokens & _SECRET_NAMES)


def _clean(row: dict) -> dict[str, str]:
    """Drop secret fields and internal keys from a parsed config row."""
    out: dict[str, str] = {}
    for k, v in row.items():
        if k.startswith("_") or is_secret_key(k):
            continue
        out[k] = str(v)
    return out


def _ros_line(section: str, row: dict) -> str:
    cleaned = _clean(row)
    verb = str(row.get("_verb", "add")) or "add"
    args = " ".join(f"{k}={_q(v)}" for k, v in cleaned.items() if v != "")
    return f"/{section} {verb} {args}".rstrip()


def _q(v: str) -> str:
    return f'"{v}"' if (not v or any(c in v for c in ' ;"')) else v


def _kv(row: dict) -> str:
    return ", ".join(f"{k}={v}" for k, v in _clean(row).items() if v not in ("", None))


def _rule_line(r) -> str:  # noqa: ANN001
    bits = [f"#{r.index}", r.type or "?"]
    if r.disabled:
        bits.append("DISABLED")
    if r.floating:
        bits.append("floating")
    if r.direction and r.direction not in ("in", ""):
        bits.append(f"dir={r.direction}")
    bits.append(f"if={r.interface or '-'}")
    if r.protocol:
        bits.append(f"proto={r.protocol}")
    src = ("!" if r.source_not else "") + (r.source or "any")
    dst = ("!" if r.destination_not else "") + (r.destination or "any")
    bits.append(f"src={src}{':' + r.src_port if r.src_port else ''}")
    bits.append(f"dst={dst}{':' + r.dst_port if r.dst_port else ''}")
    if r.gateway:
        bits.append(f"gw={r.gateway}")
    if r.descr:
        bits.append(f'"{r.descr}"')
    return " ".join(bits)


def _on_iface(spec: str, names: set[str]) -> bool:
    return any(p.strip().lower() in names for p in (spec or "").split(","))


def _tokens(result: CheckResult, iface_name: str, dev) -> set[str]:  # noqa: ANN001
    """Names that identify the interface and what it sits on / carries."""
    if not iface_name:
        return set()
    names = {iface_name.lower()}
    iface = dev.ifaces.get(iface_name.lower())
    if iface is not None:
        if iface.bridge_port_of:
            names.add(iface.bridge_port_of.lower())
        if iface.vlan_id:
            names.add(iface.vlan_id)
    if result.source_type == "mikrotik":
        raw = result.summary.get("raw", {})
        for v in raw.get("interface vlan", []):
            if v.get("name", "").lower() == iface_name.lower():
                names.add(v.get("interface", "").lower())
            if v.get("interface", "").lower() == iface_name.lower():
                names.add(v.get("name", "").lower())
        for port in raw.get("interface bridge port", []):
            if port.get("bridge", "").lower() == iface_name.lower():
                names.add(port.get("interface", "").lower())
    else:
        info = next((i for i in result.interfaces if i.name.lower() == iface_name.lower()), None)
        if info is not None:
            if info.device:
                names.add(info.device.lower())
            if info.bridge_of:
                names.add(info.bridge_of.lower())
    names.discard("")
    return names


def _row_mentions(row: dict, names: set[str]) -> bool:
    for k, v in row.items():
        if k.startswith("_"):
            continue
        for part in str(v).replace(",", " ").split():
            if part.lower() in names:
                return True
    return False


_MT_FOCUS: dict[str, tuple[str, ...]] = {
    "dhcp": ("ip dhcp-server", "ip dhcp-server network", "ip dhcp-server lease", "ip dhcp-relay",
             "ip pool", "ip dhcp-client"),
    "dns": ("ip dns", "ip dns static", "ip dhcp-server network"),
    "route": ("ip route", "ip address", "ip dhcp-client", "interface list member", "routing rule",
              "ip route rule"),
    "nat": ("ip firewall nat",),
    "firewall": ("ip firewall filter", "ip firewall raw", "ip firewall mangle", "interface list member",
                 "ip service", "tool mac-server", "tool mac-server mac-winbox"),
    "vpn": ("interface wireguard", "interface wireguard peers", "ip ipsec peer", "ip ipsec policy",
            "interface ovpn-client", "interface l2tp-client", "interface sstp-client"),
    "wireless": ("interface wireless", "interface wireless security-profiles", "interface wireless cap",
                 "caps-man manager", "caps-man configuration", "caps-man provisioning",
                 "caps-man manager interface", "interface wifi", "interface wifi cap",
                 "interface wifi capsman", "interface wifi configuration", "interface wifi provisioning"),
    "link": ("interface ethernet", "interface bonding", "interface ethernet switch"),
    "l2": ("interface bridge", "interface bridge port", "interface bridge vlan", "interface vlan",
           "interface ethernet switch", "interface ethernet switch vlan",
           "interface ethernet switch egress-vlan-tag", "interface ethernet switch ingress-vlan-translation"),
}


def _mikrotik_sections(result: CheckResult, names: set[str], focus: frozenset[str]) -> list[str]:
    raw = result.summary.get("raw", {})
    wanted: list[str] = []
    for area in sorted(focus):
        for section in _MT_FOCUS.get(area, ()):
            if section not in wanted:
                wanted.append(section)
    lines: list[str] = []
    for section in sorted(raw):
        rows = raw[section]
        if not rows:
            continue
        in_focus = section in wanted
        if names:
            hits = [r for r in rows if _row_mentions(r, names)]
            # Small whole-device sections in focus (routes, DNS, NAT…) are kept whole.
            keep = rows if in_focus and (not hits or len(rows) <= MAX_SECTION_ROWS) else hits
        else:
            keep = rows if in_focus else []
        if not keep:
            continue
        lines.append(f"# {section}" + (" (rows that mention the interface)" if keep is not rows else ""))
        for row in keep[:MAX_SECTION_ROWS]:
            lines.append(_ros_line(section, row))
        if len(keep) > MAX_SECTION_ROWS:
            lines.append(f"# … {len(keep) - MAX_SECTION_ROWS} more rows not shown")
    return lines


# Empty pfSense tags that mean "on" by being present.
_PF_FLAGS = frozenset({
    "enable", "denyunknown", "ignorebootp", "ignoreclientuids", "staticarp", "disablepingcheck",
    "nonak", "dhcpleaseinlocaltime", "statsgraph", "dhcpinlocaltime", "disable", "blockpriv",
    "blockbogons", "spoofmac", "interfaceiplist", "logging",
})


def _pfsense_xml_block(result: CheckResult, xpath: str, max_chars: int = 4000) -> str:
    """One element of the pfSense config.xml, secrets redacted, static maps counted."""
    import xml.etree.ElementTree as ET  # noqa: N817

    path = result.path
    if path is None or not str(path).lower().endswith(".xml") or not Path(path).is_file():
        return ""
    try:
        root = ET.parse(path).getroot()  # noqa: S314 - operator's own config
    except (ET.ParseError, OSError):
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
            end = text.find("</pfsense>")
            root = ET.fromstring(text[: end + len("</pfsense>")] if end >= 0 else text)  # noqa: S314
        except (ET.ParseError, OSError):
            return ""
    el = root.find(xpath)
    if el is None:
        return ""
    maps = el.findall("staticmap")
    for m in maps:
        el.remove(m)
    lines: list[str] = []
    flags: list[str] = []

    def walk(node, prefix: str) -> None:  # noqa: ANN001
        for child in node:
            name = f"{prefix}{child.tag}"
            if len(child):
                walk(child, name + "/")
                continue
            value = (child.text or "").strip()
            if is_secret_key(child.tag):
                if value:
                    lines.append(f"{name}=[REDACTED]")
            elif value:
                lines.append(f"{name}={value}")
            elif child.tag in _PF_FLAGS:
                flags.append(name)

    walk(el, "")
    if flags:
        lines.append("flags set: " + ", ".join(flags))
    if maps:
        lines.append(f"static mappings: {len(maps)}")
    block = ai.redact_text("\n".join(lines)) if lines else "(no settings)"
    if len(block) > max_chars:
        block = block[:max_chars] + "\n<!-- … cut -->"
    return block


def _pfsense_sections(result: CheckResult, iface_name: str, names: set[str], focus: frozenset[str]) -> list[str]:
    lines: list[str] = []
    key = iface_name.lower()

    def head(text: str) -> None:
        lines.append("")
        lines.append(f"## {text}")

    if "l2" in focus or "link" in focus or names:
        vl = [v for v in result.vlans if not names or {v.vlanif.lower(), v.if_parent.lower(),
                                                        v.assigned_as.lower()} & names]
        if vl:
            head("VLANs")
            lines += [f"- {v.vlanif or '?'} tag {v.tag} on {v.if_parent}"
                      f"{' = ' + v.assigned_as if v.assigned_as else ''}{' ' + repr(v.descr) if v.descr else ''}"
                      for v in vl]
        br = [b for b in result.bridges if not names or ({b.bridgeif.lower(), b.assigned_as.lower()}
                                                           | {m.lower() for m in b.members}) & names]
        if br:
            head("Bridges")
            lines += [f"- {b.bridgeif} members={','.join(b.members)} stp={'on' if b.stp_enabled else 'off'}"
                      f"{' = ' + b.assigned_as if b.assigned_as else ''}" for b in br]
        lg = [g for g in result.laggs if not names or ({g.laggif.lower()} | {m.lower() for m in g.members}) & names]
        if lg:
            head("LAGGs")
            lines += [f"- {g.laggif} proto={g.proto} members={','.join(g.members)}" for g in lg]
    if "dhcp" in focus or "dns" in focus:
        scopes = [s for s in result.dhcp_scopes if not key or s.get("interface", "").lower() == key]
        if scopes:
            head("DHCP server scopes")
            for s in scopes:
                s = dict(s)
                s.pop("staticmaps", None)
                lines.append(f"- {_kv(s)}")
        raw_dhcp = _pfsense_xml_block(result, f"dhcpd/{key}") if key else ""
        if raw_dhcp:
            head(f"DHCP server settings for {iface_name} (config.xml, static mappings summarised)")
            lines.append(raw_dhcp)
        relay = _pfsense_xml_block(result, "dhcrelay")
        if relay:
            head("DHCP relay (config.xml)")
            lines.append(relay)
    if "route" in focus or "nat" in focus or "vpn" in focus:
        if result.gateways:
            head("Gateways")
            lines += [f"- {_kv(g)}" for g in result.gateways]
        if result.gateway_groups:
            head("Gateway groups")
            lines += [f"- {g.get('name')}: {g.get('members')}" for g in result.gateway_groups]
        if result.static_routes:
            head("Static routes")
            lines += [f"- {_kv(r)}" for r in result.static_routes]
        default_gw = result.summary.get("default_gateway")
        if default_gw:
            lines.append(f"- default gateway: {default_gw}")
    vips = [v for v in result.virtual_ips if not key or v.get("interface", "").lower() == key]
    if vips:
        head("Virtual IPs")
        lines += [f"- {_kv(v)}" for v in vips]
    if "firewall" in focus or "nat" in focus or "route" in focus or "vpn" in focus:
        rules = [r for r in result.filter_rules if not key or r.floating or _on_iface(r.interface, {key})]
        if rules:
            head(f"Firewall rules {'on ' + iface_name + ' and floating' if key else ''} (in order)")
            lines += [f"- {_rule_line(r)}" for r in rules[:MAX_RULES]]
            if len(rules) > MAX_RULES:
                lines.append(f"- … {len(rules) - MAX_RULES} more rules not shown")
        if result.firewall_options:
            head("Firewall options")
            lines.append(f"- {_kv(result.firewall_options)}")
    if "nat" in focus or "route" in focus:
        nat = [r for r in result.nat_rules if not key or _on_iface(r.interface, {key})
               or _on_iface(r.out_interface, {key}) or r.kind == "outbound"]
        mode = result.summary.get("outbound_nat_mode")
        if nat or mode:
            head("NAT")
            if mode:
                lines.append(f"- outbound NAT mode: {mode}")
            lines += [f"- {r.kind}: {_rule_line(r)}" for r in nat[:MAX_RULES]]
    if "dns" in focus and result.dns:
        head("DNS")
        lines.append(f"- {_kv(result.dns)}")
    if "vpn" in focus and result.vpn:
        head("VPN")
        for v in result.vpn:
            lines.append(f"- {v.kind} {v.name}{' DISABLED' if v.disabled else ''} if={v.interface or '-'} "
                         f"peer={v.peer or '-'} local={v.local_address or '-'} "
                         f"networks={','.join(v.networks) or '-'} {v.details}".rstrip())
    if "wireless" in focus:
        wl = [i for i in result.interfaces if i.raw.get("wireless") or "wlan" in i.device.lower()
              or "ath" in i.device.lower()]
        if wl:
            head("Wireless interfaces")
            lines += [f"- {i.summary_line()}" for i in wl]
    return lines


def _checks_for(analysis: config_analysis.Analysis, iface_terms: set[str]) -> list[str]:
    out: list[str] = []
    for area in analysis.areas:
        for c in area.checks:
            text = f"{c.subject} {c.message}".lower()
            if iface_terms and not any(t in text for t in iface_terms):
                continue
            if not iface_terms and c.status == config_analysis.PASS:
                continue
            line = f"- [{area.area}] {c.status.upper()}: {c.subject} — {c.message}"
            if c.remediation:
                line += f" (NetCheck fix: {c.remediation})"
            out.append(line)
        for dep in area.missing:
            out.append(f"- [{area.area}] NOT CHECKED: needs the config of {dep.role} {dep.address} "
                       f"({dep.needed_for})")
    return out


def _iface_terms(result: CheckResult, iface_name: str, dev) -> set[str]:  # noqa: ANN001
    if not iface_name:
        return set()
    terms = {iface_name.lower()}
    iface = dev.ifaces.get(iface_name.lower())
    if iface is not None:
        if iface.label:
            terms.add(iface.label.lower())
        for n in iface.networks:
            terms.add(str(n.network))
            terms.add(str(n.ip))
    return {t for t in terms if len(t) > 2}


def build_context(
    result: CheckResult,
    iface_name: str,
    problem: Problem | str,
    notes: str = "",
    *,
    peers: Iterable[CheckResult] = (),
    scheme: name_parser.NameScheme | None = None,
) -> str:
    """The redacted text sent to Ollama: device, interface, relevant config, checks."""
    if isinstance(problem, str):
        problem = PROBLEM_BY_KEY.get(problem, PROBLEM_BY_KEY["other"])
    scheme = scheme or name_parser.load_scheme()
    dev = config_analysis._Device(result)  # noqa: SLF001
    kind = "MikroTik RouterOS" if result.source_type == "mikrotik" else "pfSense / OPNsense"
    lines: list[str] = ["# Device"]
    ident = device_identity.Identity()
    if result.path is not None:
        try:
            ident = device_identity.identity_from_config(result.path)
        except Exception:  # noqa: BLE001
            pass
    lines.append(f"- type: {kind}")
    lines.append(f"- name: {result.hostname or result.device_name or '?'}")
    if ident.model:
        lines.append(f"- model: {ident.model}")
    if ident.os_version or result.version:
        lines.append(f"- version: {ident.os_version or result.version}")
    s = result.summary
    lines.append(f"- interfaces: {len(result.interfaces)}, VLANs: {s.get('vlans', len(result.vlans))}, "
                 f"bridges: {s.get('bridges', len(result.bridges))}")

    lines.append("")
    lines.append("# Problem")
    lines.append(f"- type: {problem.label}")
    lines.append(f"- {problem.ask}")
    if notes.strip():
        lines.append("- operator's notes:")
        lines += [f"  {ln}" for ln in notes.strip().splitlines()]

    lines.append("")
    lines.append("# Interface")
    iface = dev.ifaces.get(iface_name.lower()) if iface_name else None
    if iface is None:
        lines.append("- none selected: the whole device")
    else:
        lines.append(f"- name: {iface.name}")
        if iface.label and iface.label != iface.name:
            lines.append(f"- description: {iface.label}")
        decoded = name_parser.readable(iface.label or iface.name, scheme)
        if decoded:
            lines.append(f"- description decoded (site naming scheme): {decoded}")
        lines.append(f"- enabled: {'yes' if iface.enabled else 'NO'}")
        lines.append(f"- addresses: {_nets(iface) or 'none'}")
        if iface.vlan_id:
            lines.append(f"- VLAN id: {iface.vlan_id}")
        if iface.bridge_port_of:
            lines.append(f"- bridge port of: {iface.bridge_port_of}")
        info = next((i for i in result.interfaces if i.name.lower() == iface_name.lower()), None)
        if info is not None:
            lines.append(f"- parsed: {info.summary_line()}")
            if info.raw:
                lines.append(f"- settings: {_kv(info.raw)}")

    names = _tokens(result, iface_name, dev)
    lines.append("")
    lines.append("# Relevant configuration" + (f" (around {iface_name})" if iface_name else ""))
    if result.source_type == "mikrotik":
        lines += _mikrotik_sections(result, names, problem.focus)
    else:
        lines += _pfsense_sections(result, iface_name, names, problem.focus)

    terms = _iface_terms(result, iface_name, dev)
    try:
        analysis = config_analysis.analyse(result, [p for p in peers if p is not result])
        checks = _checks_for(analysis, terms)
    except Exception as exc:  # noqa: BLE001
        checks = [f"- (NetCheck analysis failed: {exc})"]
    if checks:
        lines.append("")
        lines.append("# NetCheck automated checks" + (" that mention this interface" if terms else ""))
        lines += checks
    fnd = [f for f in result.findings
           if not terms or any(t in f"{f.path} {f.message}".lower() for t in terms)]
    if fnd:
        lines.append("")
        lines.append("# NetCheck findings" + (" that mention this interface" if terms else ""))
        lines += [f"- {f.severity.value.upper()} | {f.category} | {f.path or '-'} | {f.message}"
                  for f in fnd[:60]]

    text = ai.redact_text("\n".join(lines))
    if len(text) > MAX_CONTEXT_CHARS:
        text = text[:MAX_CONTEXT_CHARS] + "\n# … context cut to fit; ask about a single interface for more detail"
    return text


def question_for(problem: Problem | str, iface_name: str) -> str:
    if isinstance(problem, str):
        problem = PROBLEM_BY_KEY.get(problem, PROBLEM_BY_KEY["other"])
    where = f"interface {iface_name}" if iface_name else "this device"
    return (f"Troubleshoot: {problem.label} on {where}. Use the configuration above and the "
            "operator's notes. Rank the likely causes, how to confirm each, and the fix.")


def context_window(context: str) -> int:
    """Ollama num_ctx large enough for the prompt plus an answer (~3 chars a token)."""
    need = len(context) // 3 + len(SYSTEM_PROMPT) // 3 + 4096
    size = 8192
    while size < need and size < 131072:
        size *= 2
    return size


def ask(
    context: str,
    problem: Problem | str,
    iface_name: str,
    *,
    model: str,
    base_url: str,
    idle_timeout: float = 300,
    think: bool = True,
    on_text=None,  # noqa: ANN001
    on_thinking=None,  # noqa: ANN001
    should_stop=None,  # noqa: ANN001
) -> str:
    """Stream the context to Ollama with the troubleshooting prompt.

    *think* False skips a thinking model's reasoning pass (much faster).
    """
    return ai.ask_ollama_stream(
        context,
        question_for(problem, iface_name),
        model=model,
        base_url=base_url,
        system=SYSTEM_PROMPT,
        num_ctx=context_window(context),
        idle_timeout=idle_timeout,
        think=None if think else False,
        on_text=on_text,
        on_thinking=on_thinking,
        should_stop=should_stop,
    )
