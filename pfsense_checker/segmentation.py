"""How well the inside subnets are kept apart by the firewall rules.

Each routed inside interface with a static IPv4 network is a zone. For every
ordered pair of zones the rules on the source interface are evaluated in
pfSense order: floating quick rules, the interface's own rules, then floating
rules without quick, first match wins, default deny. The answer is one of

- ``open``: any protocol to the whole destination subnet
- ``limited``: only the listed protocols / ports, or only some hosts
- ``blocked``: nothing reaches it

Rules that send traffic to a gateway still reach local subnets, because
pfSense adds bypass rules for directly connected networks, unless "Disable
negation rules" is set. Aliases of host / network type are expanded. URL
tables (pfBlockerNG feeds) are treated as outside addresses.

Layer 2 joins (bridges) and overlapping subnets are reported separately; a
bridge puts its members on one segment no matter what the rules say.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from pfsense_checker.firewall_topology import is_tunnel_device, is_wan
from pfsense_checker.models import CheckResult, InterfaceInfo, RuleInfo

OPEN = "open"
LIMITED = "limited"
BLOCKED = "blocked"

_FULL = 2
_PART = 1
_NONE = 0

Network = ipaddress.IPv4Network


@dataclass(frozen=True)
class Zone:
    name: str  # lan / opt15
    title: str  # port name (description)
    device: str
    network: Network


@dataclass
class Reach:
    level: str = BLOCKED
    services: list[str] = field(default_factory=list)
    rules: list[int] = field(default_factory=list)  # 1-based position in <filter>
    note: str = ""


@dataclass
class ZoneSummary:
    zone: Zone
    open_to: list[str] = field(default_factory=list)
    limited_to: list[str] = field(default_factory=list)

    @property
    def grade(self) -> str:
        if self.open_to:
            return OPEN
        if self.limited_to:
            return LIMITED
        return BLOCKED


@dataclass
class Segmentation:
    zones: list[Zone] = field(default_factory=list)
    reach: dict[tuple[str, str], Reach] = field(default_factory=dict)
    summaries: dict[str, ZoneSummary] = field(default_factory=dict)
    layer2: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def pairs(self) -> int:
        return len(self.reach)

    def count(self, level: str) -> int:
        return sum(1 for r in self.reach.values() if r.level == level)

    @property
    def score(self) -> int:
        """0 (flat network) .. 100 (every pair blocked). Limited pairs count half."""
        if not self.reach:
            return 100
        closed = self.count(BLOCKED) + 0.5 * self.count(LIMITED)
        return round(100 * closed / self.pairs)

    @property
    def verdict(self) -> str:
        if not self.reach:
            return "fewer than two routed inside subnets"
        score = self.score
        if score >= 90:
            return "well separated"
        if score >= 60:
            return "partly separated"
        if score >= 25:
            return "weakly separated"
        return "flat: subnets reach each other freely"


def _network(iface: InterfaceInfo) -> Network | None:
    try:
        bits = int(iface.subnet)
        return ipaddress.ip_network(f"{iface.ipaddr}/{bits}", strict=False)
    except (TypeError, ValueError):
        return None


def inside_zones(result: CheckResult) -> list[Zone]:
    zones = []
    for iface in result.interfaces:
        if not iface.enabled or is_wan(iface) or is_tunnel_device(iface.device):
            continue
        net = _network(iface)
        if net is None or net.version != 4:
            continue
        zones.append(Zone(iface.name, iface.descr or iface.name.upper(), iface.device, net))
    return zones


def _alias_networks(result: CheckResult) -> dict[str, list[Network]]:
    raw = {a.get("name", ""): a for a in result.aliases if a.get("name")}
    resolved: dict[str, list[Network]] = {}

    def expand(name: str, depth: int = 0) -> list[Network]:
        if name in resolved:
            return resolved[name]
        alias = raw.get(name)
        nets: list[Network] = []
        if alias and depth < 8 and alias.get("type", "").lower() in {"host", "network"}:
            for token in alias.get("address", "").split():
                if token in raw:
                    nets.extend(expand(token, depth + 1))
                    continue
                try:
                    nets.append(ipaddress.ip_network(token, strict=False))
                except ValueError:
                    continue
        resolved[name] = [n for n in nets if n.version == 4]
        return resolved[name]

    for name in raw:
        expand(name)
    return resolved


def _strip_port(text: str, port: str) -> str:
    text = (text or "").strip()
    if port and text == f"port {port}":
        return "any"
    if port and text.endswith(f":{port}"):
        return text[: -len(port) - 1]
    return text


class _Matcher:
    def __init__(self, result: CheckResult, zones: list[Zone]) -> None:
        self.zones = {z.name: z for z in zones}
        self.aliases = _alias_networks(result)
        self.alias_names = {a.get("name", "") for a in result.aliases}

    def match(self, text: str, zone: Zone, negate: bool) -> int:
        hit = self._match(text.strip(), zone)
        if negate:
            return {_FULL: _NONE, _NONE: _FULL}.get(hit, _PART)
        return hit

    def _match(self, text: str, zone: Zone) -> int:
        low = text.lower()
        if low in {"any", "(any)", ""}:
            return _FULL
        if low == zone.name:
            return _FULL
        if low in self.zones or low.endswith("ip") or low == "(self)":
            return _NONE
        if text in self.alias_names:
            return self._cover(self.aliases.get(text, []), zone.network)
        try:
            return self._cover([ipaddress.ip_network(text, strict=False)], zone.network)
        except ValueError:
            return _NONE

    @staticmethod
    def _cover(nets: list[Network], target: Network) -> int:
        best = _NONE
        for net in nets:
            if net.version != 4:
                continue
            if target.subnet_of(net):
                return _FULL
            if net.subnet_of(target) or net.overlaps(target):
                best = _PART
        return best


def _service(rule: RuleInfo) -> str | None:
    proto = (rule.protocol or "").strip().lower()
    port = (rule.dst_port or "").strip()
    if not proto or proto == "any":
        return f"any proto port {port}" if port else None
    return f"{proto} {port}" if port else proto


def _on_interface(rule: RuleInfo, name: str) -> bool:
    return name in {p.strip().lower() for p in (rule.interface or "").split(",")}


def _ordered_rules(rules: list[RuleInfo], name: str) -> list[RuleInfo]:
    mine = [
        r
        for r in rules
        if r.kind == "filter"
        and not r.disabled
        and _on_interface(r, name)
        and (r.direction or "any").lower() in {"in", "any", ""}
    ]
    quick = [r for r in mine if r.floating and r.quick]
    own = [r for r in mine if not r.floating]
    late = [r for r in mine if r.floating and not r.quick]
    return quick + own + late


def _evaluate(rules: list[RuleInfo], src: Zone, dst: Zone, m: _Matcher, bypass: bool) -> Reach:
    reach = Reach()
    blocked: set[str | None] = set()
    allowed: list[str] = []
    for rule in rules:
        action = (rule.type or "pass").lower()
        if action not in {"pass", "block", "reject"}:
            continue
        sm = m.match(_strip_port(rule.source, rule.src_port), src, rule.source_not)
        dm = m.match(_strip_port(rule.destination, rule.dst_port), dst, rule.destination_not)
        if _NONE in (sm, dm):
            continue
        service = _service(rule)
        whole = sm == _FULL and dm == _FULL
        if action == "pass":
            if rule.gateway and not bypass:
                continue
            if service in blocked:
                continue
            if whole and service is None:
                reach.level = OPEN
                reach.rules = [rule.index + 1]
                reach.services = ["any"]
                if rule.gateway:
                    reach.note = f"policy-routed to {rule.gateway}; local traffic bypasses it"
                return reach
            label = service or "any"
            if not whole:
                label += " (some hosts)"
            if label not in allowed:
                allowed.append(label)
            reach.rules.append(rule.index + 1)
        elif whole and service is None:
            break
        elif whole:
            blocked.add(service)
    if allowed:
        reach.level = LIMITED
        reach.services = allowed
    return reach


def analyse_segmentation(result: CheckResult) -> Segmentation:
    seg = Segmentation(zones=inside_zones(result))
    matcher = _Matcher(result, seg.zones)
    bypass = result.firewall_options.get("disablenegate") != "1"
    if not bypass:
        seg.notes.append(
            "Negation rules are disabled: pass rules with a gateway send inter-subnet "
            "traffic to that gateway, so they are not counted as reach."
        )
    for src in seg.zones:
        rules = _ordered_rules(result.filter_rules, src.name)
        summary = ZoneSummary(src)
        for dst in seg.zones:
            if dst.name == src.name:
                continue
            reach = _evaluate(rules, src, dst, matcher, bypass)
            seg.reach[(src.name, dst.name)] = reach
            if reach.level == OPEN:
                summary.open_to.append(dst.name)
            elif reach.level == LIMITED:
                summary.limited_to.append(dst.name)
        seg.summaries[src.name] = summary
    seg.layer2 = _layer2(result, seg.zones)
    return seg


def _layer2(result: CheckResult, zones: list[Zone]) -> list[str]:
    out = []
    by_name = {i.name: i for i in result.interfaces}
    opts = result.firewall_options
    member_filter = opts.get("net.link.bridge.pfil_member", "1") != "0"
    bridge_filter = opts.get("net.link.bridge.pfil_bridge", "0") != "0"
    for bridge in result.bridges:
        names = [
            (by_name[m].descr or m.upper()) if m in by_name else m for m in bridge.members
        ]
        host = bridge.assigned_as or bridge.bridgeif
        if member_filter and bridge_filter:
            how = "the rules on each member and on the bridge"
        elif member_filter:
            how = "the rules on each member interface"
        elif bridge_filter:
            how = f"the rules on the bridge interface ({host.upper()}) only"
        else:
            how = "nothing: bridge filtering is off"
        out.append(
            f"{bridge.bridgeif} joins {', '.join(names) or 'no members'} into one layer 2 segment; "
            f"traffic between them is filtered by {how}."
        )
    for i, a in enumerate(zones):
        for b in zones[i + 1 :]:
            if a.network.overlaps(b.network):
                out.append(
                    f"{a.title} ({a.network}) and {b.title} ({b.network}) overlap; "
                    "the firewall cannot tell them apart."
                )
    return out
