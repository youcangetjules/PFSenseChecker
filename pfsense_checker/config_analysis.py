"""Deep "Will it work?" analysis of loaded configs.

Each functional area (DHCP first; wireless, bandwidth and reachability
follow) gets a verdict built from individual checks:

* WORKS      — every check passed
* WARNINGS   — it works, with problems worth fixing
* FAILS      — at least one check shows it will not work
* DEGRADED   — the answer depends on another device whose config is not
               loaded (an upstream router, gateway or DHCP server). The
               verdict lists exactly which config to add and what could not
               be checked without it.

Analysis is cross-device: pass the other loaded configs as *peers* and a
relay on a MikroTik is followed to the pfSense scope that answers it.
Nothing here touches the network; it reads parsed configs only.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

from pfsense_checker.models import CheckResult, Finding, Severity
from pfsense_checker import vlan_enforcement

PASS, WARN, FAIL, INFO = "pass", "warn", "fail", "info"
WORKS, WARNINGS, FAILS, DEGRADED, ABSENT = (
    "works",
    "warnings",
    "fails",
    "degraded",
    "not-configured",
)
SMALL_POOL = 10  # addresses; below this a pool is easy to exhaust

VERDICT_TEXT = {
    WORKS: "Works",
    WARNINGS: "Works, with warnings",
    FAILS: "Will not work",
    DEGRADED: "Degraded — upstream config missing",
    ABSENT: "Not configured on this device",
}


@dataclass(frozen=True)
class Check:
    status: str  # pass / warn / fail / info
    subject: str  # e.g. "opt18 VL630_LAN 222.10.50.0/24"
    message: str
    remediation: str = ""


@dataclass(frozen=True)
class Dependency:
    """Another device whose config is needed to finish the analysis."""

    role: str  # "DHCP server", "DHCP failover peer", …
    address: str
    needed_for: str  # what could not be checked without it
    known_as: str = ""  # device name on Login to Routers, if known
    resolved_by: str = ""  # hostname of the loaded config that owns it

    @property
    def resolved(self) -> bool:
        return bool(self.resolved_by)


@dataclass
class AreaVerdict:
    area: str
    checks: list[Check] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    present: bool = True

    @property
    def missing(self) -> list[Dependency]:
        return [d for d in self.dependencies if not d.resolved]

    @property
    def coverage(self) -> float:
        if not self.dependencies:
            return 1.0
        return sum(1 for d in self.dependencies if d.resolved) / len(self.dependencies)

    @property
    def status(self) -> str:
        if not self.present:
            return ABSENT
        if any(c.status == FAIL for c in self.checks):
            return FAILS
        if self.missing:
            return DEGRADED
        if any(c.status == WARN for c in self.checks):
            return WARNINGS
        return WORKS

    def add(self, status: str, subject: str, message: str, remediation: str = "") -> None:
        self.checks.append(Check(status, subject, message, remediation))


@dataclass
class Analysis:
    device: str
    areas: list[AreaVerdict] = field(default_factory=list)

    @property
    def missing(self) -> list[Dependency]:
        seen: dict[str, Dependency] = {}
        for area in self.areas:
            for dep in area.missing:
                seen.setdefault(dep.address, dep)
        return list(seen.values())

    @property
    def coverage(self) -> float:
        deps = [d for a in self.areas for d in a.dependencies]
        if not deps:
            return 1.0
        return sum(1 for d in deps if d.resolved) / len(deps)

    @property
    def degraded(self) -> bool:
        return bool(self.missing)

    def area(self, name: str) -> AreaVerdict | None:
        return next((a for a in self.areas if a.area == name), None)


# --------------------------------------------------------------------------- #
# Device model: who owns which address, subnets per interface, VLAN ids
# --------------------------------------------------------------------------- #


@dataclass
class _Iface:
    name: str  # pfSense opt18 / MikroTik interface name
    label: str  # descr or name
    enabled: bool
    networks: list[ipaddress.IPv4Interface] = field(default_factory=list)
    vlan_id: str = ""
    bridge_port_of: str = ""  # MikroTik: this interface is a port of that bridge


class _Device:
    def __init__(self, result: CheckResult) -> None:
        self.result = result
        self.kind = result.source_type
        self.name = result.hostname or (result.path.stem if result.path else "this device")
        self.ifaces: dict[str, _Iface] = {}
        if self.kind == "mikrotik":
            self._load_mikrotik()
        else:
            self._load_pfsense()

    # --- pfSense ---------------------------------------------------------- #
    def _load_pfsense(self) -> None:
        vlan_tag = {v.vlanif: v.tag for v in self.result.vlans if v.vlanif}
        for i in self.result.interfaces:
            iface = _Iface(
                name=i.name,
                label=i.descr or i.name,
                enabled=i.enabled,
                vlan_id=vlan_tag.get(i.device, ""),
            )
            net = _iface_net(i.ipaddr, i.subnet)
            if net is not None:
                iface.networks.append(net)
            self.ifaces[i.name.lower()] = iface
        for vip in self.result.virtual_ips:
            owner = self.ifaces.get((vip.get("interface") or "").lower())
            net = _iface_net(vip.get("subnet", ""), vip.get("subnet_bits", ""))
            if owner is not None and net is not None:
                owner.networks.append(net)

    # --- MikroTik --------------------------------------------------------- #
    def _load_mikrotik(self) -> None:
        raw = self.result.summary.get("raw", {})
        for i in self.result.interfaces:
            self.ifaces[i.name.lower()] = _Iface(name=i.name, label=i.name, enabled=i.enabled)
        for v in raw.get("interface vlan", []):
            iface = self._get(v.get("name", ""))
            if iface is not None:
                iface.vlan_id = v.get("vlan-id", "")
        for port in raw.get("interface bridge port", []):
            iface = self._get(port.get("interface", ""))
            if iface is not None and not _disabled(port):
                iface.bridge_port_of = port.get("bridge", "")
        for addr in raw.get("ip address", []):
            if _disabled(addr):
                continue
            iface = self._get(addr.get("interface", ""))
            net = _parse_iface(addr.get("address", ""))
            if iface is not None and net is not None:
                iface.networks.append(net)

    def _get(self, name: str) -> _Iface | None:
        if not name:
            return None
        key = name.lower()
        if key not in self.ifaces:
            self.ifaces[key] = _Iface(name=name, label=name, enabled=True)
        return self.ifaces[key]

    # --- queries ---------------------------------------------------------- #
    def owner_of(self, ip: ipaddress.IPv4Address) -> _Iface | None:
        for iface in self.ifaces.values():
            if any(n.ip == ip for n in iface.networks):
                return iface
        return None

    def iface_in(self, net: ipaddress.IPv4Network) -> _Iface | None:
        for iface in self.ifaces.values():
            if any(n.network == net for n in iface.networks):
                return iface
        return None

    def vlan_subnets(self) -> dict[str, list[ipaddress.IPv4Network]]:
        out: dict[str, list[ipaddress.IPv4Network]] = {}
        for iface in self.ifaces.values():
            if iface.vlan_id:
                out.setdefault(iface.vlan_id, []).extend(n.network for n in iface.networks)
        return out


def _disabled(raw: Mapping[str, str]) -> bool:
    return str(raw.get("disabled", "no")).lower() in ("yes", "true")


def _parse_iface(text: str) -> ipaddress.IPv4Interface | None:
    try:
        net = ipaddress.ip_interface((text or "").strip())
    except ValueError:
        return None
    return net if isinstance(net, ipaddress.IPv4Interface) else None


def _iface_net(ip: str, bits: str) -> ipaddress.IPv4Interface | None:
    ip = (ip or "").strip()
    bits = (bits or "").strip()
    if not ip or not bits or ip in ("dhcp", "pppoe", "track6"):
        return None
    return _parse_iface(f"{ip}/{bits}")


def _ip(text: str) -> ipaddress.IPv4Address | None:
    try:
        addr = ipaddress.ip_address((text or "").strip())
    except ValueError:
        return None
    return addr if isinstance(addr, ipaddress.IPv4Address) else None


def _subject(iface: _Iface | None, fallback: str) -> str:
    if iface is None:
        return fallback
    nets = ", ".join(str(n.network) for n in iface.networks)
    label = iface.name if iface.label == iface.name else f"{iface.name} ({iface.label})"
    return f"{label} {nets}".strip()


# --------------------------------------------------------------------------- #
# DHCP
# --------------------------------------------------------------------------- #


def _dhcp_pfsense(dev: _Device, verdict: AreaVerdict, peers: list[_Device], known: Mapping[str, str]) -> None:
    result = dev.result
    scopes = [s for s in result.dhcp_scopes if s.get("family") == "v4"]
    relay = result.summary.get("dhcp_relay") or {}
    if not any(s.get("enabled") == "yes" for s in scopes) and not relay.get("enabled"):
        verdict.present = False
        return
    backend = result.summary.get("dhcp_backend", "isc")
    verdict.add(INFO, dev.name, f"DHCP backend: {backend.upper()}.")

    ranges: list[tuple[str, bool, ipaddress.IPv4Address, ipaddress.IPv4Address]] = []
    for scope in scopes:
        a, b = _ip(scope.get("from", "")), _ip(scope.get("to", ""))
        iface = dev.ifaces.get((scope.get("interface") or "").lower())
        live = scope.get("enabled") == "yes" and iface is not None and iface.enabled
        if a and b:
            ranges.append((scope.get("interface", ""), live, a, b))

    for scope in scopes:
        if scope.get("enabled") != "yes":
            continue
        name = scope.get("interface", "")
        iface = dev.ifaces.get(name.lower())
        subject = _subject(iface, name)
        if iface is None:
            verdict.add(FAIL, subject, "DHCP scope for an interface that does not exist.",
                        "Remove the scope or restore the interface assignment.")
            continue
        if not iface.enabled:
            verdict.add(WARN, subject, "Scope is enabled but the interface is disabled, so it never runs.",
                        "Disable the scope, or enable the interface if it should serve DHCP.")
            continue
        if not iface.networks:
            verdict.add(FAIL, subject, "Interface has no static IPv4 address; the DHCP server cannot serve it.",
                        "Give the interface a static IPv4 address.")
            continue
        net = iface.networks[0]
        a, b = _ip(scope.get("from", "")), _ip(scope.get("to", ""))
        if a is None or b is None:
            verdict.add(FAIL, subject, "Scope has no valid address range.", "Set a From / To range.")
            continue
        if a not in net.network or b not in net.network:
            verdict.add(FAIL, subject, f"Range {a}–{b} is outside {net.network}.",
                        f"Move the range inside {net.network}.")
            continue
        if a > b:
            verdict.add(FAIL, subject, f"Range start {a} is after its end {b}.", "Swap From and To.")
            continue
        if a <= net.ip <= b:
            verdict.add(FAIL, subject, f"Range {a}–{b} includes the interface address {net.ip}.",
                        "Start or end the range so it skips the interface address.")
        if a == net.network.network_address or b == net.network.broadcast_address:
            verdict.add(FAIL, subject, "Range includes the network or broadcast address.",
                        "Keep the range inside the usable hosts.")
        size = int(b) - int(a) + 1
        if size < SMALL_POOL:
            verdict.add(WARN, subject, f"Pool has only {size} address(es) ({a}–{b}); it runs out quickly.",
                        "Widen the range if more than a few clients use this network.")
        else:
            verdict.add(PASS, subject, f"Pool {a}–{b} ({size} addresses) inside {net.network}.")

        for other_if, other_live, oa, ob in ranges:
            if other_if == name or oa > b or ob < a:
                continue
            level = FAIL if other_live else WARN
            why = "both serve" if other_live else f"{other_if} is not active now, but would hand out"
            verdict.add(level, subject, f"Range overlaps {other_if} ({oa}–{ob}); {why} the same addresses.",
                        "Give each scope its own range.")

        statics = [m.split("|", 1) for m in (scope.get("staticmap_list") or "").split(";") if m]
        seen_ip: set[str] = set()
        seen_mac: set[str] = set()
        for ip_text, mac in statics:
            sip = _ip(ip_text)
            if sip is not None and sip not in net.network:
                verdict.add(FAIL, subject, f"Static mapping {sip} ({mac}) is outside {net.network}.",
                            "Fix or remove the mapping.")
            elif sip is not None and a <= sip <= b:
                verdict.add(WARN, subject, f"Static mapping {sip} ({mac}) is inside the dynamic pool; "
                            "it can be leased to another client.", "Move it outside the range.")
            if ip_text and ip_text in seen_ip:
                verdict.add(WARN, subject, f"Static IP {ip_text} is mapped twice.", "Remove the duplicate.")
            if mac and mac.lower() in seen_mac:
                verdict.add(WARN, subject, f"MAC {mac} is mapped twice.", "Remove the duplicate.")
            seen_ip.add(ip_text)
            seen_mac.add((mac or "").lower())

        gw = _ip(scope.get("gateway", ""))
        if scope.get("gateway") and gw is None and scope.get("gateway") != "none":
            verdict.add(FAIL, subject, f"Gateway option '{scope.get('gateway')}' is not an IPv4 address.",
                        "Leave it empty to hand out the interface address.")
        elif gw is not None and gw not in net.network:
            verdict.add(FAIL, subject, f"Clients are told to use gateway {gw}, outside {net.network}.",
                        "Use an address on this network, or leave it empty.")

        dns = [d for d in (scope.get("dnsservers") or "").split(",") if d]
        if dns:
            verdict.add(PASS, subject, f"Clients get DNS servers {', '.join(dns)}.")
        else:
            resolver = result.dns.get("unbound_enable") or result.dns.get("forwarder")
            active = [x.lower() for x in result.dns.get("unbound_active_interface", [])]
            if resolver and (not active or "all" in active or iface.name.lower() in active):
                verdict.add(PASS, subject, f"Clients get {net.ip} as DNS; the resolver listens there.")
            elif resolver:
                verdict.add(FAIL, subject, f"Clients get {net.ip} as DNS but the resolver does not listen on this interface.",
                            "Add the interface to the DNS Resolver's network interfaces, or set DNS servers on the scope.")
            else:
                verdict.add(FAIL, subject, f"Clients get {net.ip} as DNS but no DNS resolver or forwarder is enabled.",
                            "Enable the DNS Resolver, or set DNS servers on the scope.")

        peer_ip = _ip(scope.get("failover_peerip", ""))
        if peer_ip is not None:
            _depend(verdict, peers, known, peer_ip, "DHCP failover peer",
                    f"failover for {net.network} (both firewalls must agree on the pool)")

    if relay.get("enabled"):
        for server in (relay.get("server") or "").split(","):
            sip = _ip(server)
            if sip is not None:
                _depend(verdict, peers, known, sip, "DHCP server (relay target)",
                        f"whether {sip} answers relayed requests")


def _dhcp_mikrotik(dev: _Device, verdict: AreaVerdict, peers: list[_Device], known: Mapping[str, str]) -> None:
    raw = dev.result.summary.get("raw", {})
    servers = [s for s in raw.get("ip dhcp-server", []) if not _disabled(s)]
    relays = [r for r in raw.get("ip dhcp-relay", []) if not _disabled(r)]
    if not servers and not relays:
        verdict.present = False
        return
    pools = {p.get("name", ""): p for p in raw.get("ip pool", [])}
    networks = [
        (n, _parse_net(n.get("address", ""))) for n in raw.get("ip dhcp-server network", [])
    ]
    dns_servers = [d for d in (raw.get("ip dns", [{}])[0].get("servers", "") if raw.get("ip dns") else "").split(",") if d]

    for srv in servers:
        iface = dev.ifaces.get((srv.get("interface") or "").lower())
        subject = f"dhcp-server {srv.get('name', '?')} on {_subject(iface, srv.get('interface', '?'))}"
        if iface is None:
            verdict.add(FAIL, subject, "Bound to an interface that does not exist.", "Bind it to an existing interface.")
            continue
        if iface.bridge_port_of:
            verdict.add(FAIL, subject, f"Bound to {iface.name}, a port of bridge {iface.bridge_port_of}. "
                        "Requests arrive on the bridge, so this server never sees them.",
                        f"Bind the server to {iface.bridge_port_of} (or the VLAN interface on it).")
            continue
        relayed = bool(srv.get("relay"))
        l3_ok, why = mt_vlan_iface_state(dev, iface.name)
        if not l3_ok:
            verdict.add(FAIL, subject, f"The server never sees a request: {why}.",
                        "Add the bridge as a tagged member of the VLAN (/interface bridge vlan).")
            continue
        if not iface.networks and not relayed:
            verdict.add(FAIL, subject, "Interface has no IPv4 address.", "Add an /ip address on the interface.")
            continue
        pool_name = srv.get("address-pool", "")
        if pool_name in ("", "static-only"):
            verdict.add(INFO, subject, "No address pool: leases only for static entries.")
            continue
        pool = pools.get(pool_name)
        if pool is None:
            verdict.add(FAIL, subject, f"Address pool '{pool_name}' does not exist.", "Create the pool or fix the name.")
            continue
        pool_ranges = _pool_ranges(pool.get("ranges", ""))
        size = sum(int(b) - int(a) + 1 for a, b in pool_ranges)
        homes = [n for n in (iface.networks or []) ]
        for a, b in pool_ranges:
            net_entry = next((net for entry, net in networks if net and a in net and b in net), None)
            if net_entry is None:
                verdict.add(FAIL, subject, f"No /ip dhcp-server network covers {a}–{b}; clients get no mask, gateway or DNS.",
                            "Add a dhcp-server network with gateway and dns-server.")
                continue
            entry = next(e for e, n in networks if n == net_entry)
            if not relayed and homes and not any(net_entry == h.network for h in homes):
                verdict.add(FAIL, subject, f"Pool {a}–{b} is not on the interface subnet ({', '.join(str(h.network) for h in homes)}).",
                            "Use a pool from the interface subnet.")
            if any(h.ip >= a and h.ip <= b for h in homes):
                verdict.add(FAIL, subject, "The pool includes the router's own address.", "Exclude it from the pool.")
            if not entry.get("gateway"):
                verdict.add(WARN, subject, f"Network {net_entry} has no gateway; clients get no default route.",
                            "Set gateway= on the dhcp-server network.")
            if not entry.get("dns-server") and not dns_servers:
                verdict.add(WARN, subject, f"Network {net_entry} has no dns-server and /ip dns has no servers.",
                            "Set dns-server= on the network or servers in /ip dns.")
        if size and size < SMALL_POOL:
            verdict.add(WARN, subject, f"Pool '{pool_name}' has only {size} address(es).", "Widen the pool.")
        elif size:
            verdict.add(PASS, subject, f"Pool '{pool_name}' has {size} addresses.")
        _input_allows_dhcp(dev, iface, subject, verdict)

    for rel in relays:
        iface = dev.ifaces.get((rel.get("interface") or "").lower())
        subject = f"dhcp-relay {rel.get('name', '?')} on {_subject(iface, rel.get('interface', '?'))}"
        if iface is None:
            verdict.add(FAIL, subject, "Relay on an interface that does not exist.", "Fix the interface name.")
            continue
        if iface.bridge_port_of:
            verdict.add(FAIL, subject, f"Relay on {iface.name}, a port of bridge {iface.bridge_port_of}; "
                        "requests arrive on the bridge.", f"Run the relay on {iface.bridge_port_of} or its VLAN.")
            continue
        if not iface.networks:
            verdict.add(FAIL, subject, "Relay interface has no IPv4 address, so it cannot stamp requests (giaddr).",
                        "Add an /ip address on the interface.")
            continue
        l3_ok, why = mt_vlan_iface_state(dev, iface.name)
        if not l3_ok:
            verdict.add(FAIL, subject, f"The relay never sees a request: {why}.",
                        "Add the bridge as a tagged member of the VLAN (/interface bridge vlan).")
            continue
        _input_allows_dhcp(dev, iface, subject, verdict)
        here = iface.networks[0]
        for server in (rel.get("dhcp-server") or "").split(","):
            sip = _ip(server)
            if sip is None:
                continue
            _check_relay_target(dev, iface, here, sip, subject, verdict, peers, known)


def _check_relay_target(dev, iface, here, sip, subject, verdict, peers, known) -> None:  # noqa: ANN001
    owner_dev = next((p for p in peers if p.owner_of(sip) is not None), None)
    if owner_dev is None:
        dep = _depend(verdict, peers, known, sip, "DHCP server (relay target)",
                      f"whether {sip} hands out addresses for {here.network}")
        # Same VLAN id, different subnet on a loaded peer: a likely wiring error.
        for peer in peers:
            for vid, nets in peer.vlan_subnets().items():
                if vid and vid == iface.vlan_id and nets and all(n != here.network for n in nets):
                    verdict.add(FAIL, subject,
                                f"VLAN {vid} is {here.network} here but {', '.join(map(str, nets))} on "
                                f"{peer.name}; nothing on {peer.name} owns {sip}.",
                                "Use the same subnet for the VLAN on both devices, and point the relay "
                                "at the server's address on it.")
        return dep
    owner_iface = owner_dev.owner_of(sip)
    _depend(verdict, peers, known, sip, "DHCP server (relay target)",
            f"whether {sip} hands out addresses for {here.network}")
    if sip in here.network:
        verdict.add(WARN, subject,
                    f"Relay target {sip} is on the same subnet ({here.network}); clients' broadcasts "
                    f"already reach {owner_dev.name} directly, so every request is answered twice.",
                    "Remove the relay, or move the server off this subnet.")
    serving = owner_dev.iface_in(here.network)
    if owner_dev.kind == "mikrotik":
        raw = owner_dev.result.summary.get("raw", {})
        nets = [_parse_net(n.get("address", "")) for n in raw.get("ip dhcp-server network", [])]
        ok = any(n == here.network for n in nets)
        if ok:
            verdict.add(PASS, subject, f"{owner_dev.name} has a DHCP network for {here.network}.")
        else:
            verdict.add(FAIL, subject, f"{owner_dev.name} ({sip}) has no DHCP network for {here.network}.",
                        f"Add a dhcp-server and network for {here.network} on {owner_dev.name}.")
        return
    if serving is None:
        verdict.add(FAIL, subject, f"{owner_dev.name} ({sip}) has no interface or scope for {here.network}; "
                    "relayed requests get no answer.", f"Add a DHCP scope for {here.network} on {owner_dev.name}.")
        return
    scope = next((s for s in owner_dev.result.dhcp_scopes
                  if s.get("family") == "v4" and (s.get("interface") or "").lower() == serving.name.lower()), None)
    if scope is None or scope.get("enabled") != "yes":
        verdict.add(FAIL, subject, f"DHCP is {'disabled' if scope else 'not configured'} on {owner_dev.name} "
                    f"{_subject(serving, serving.name)}; clients on {here.network} get no address.",
                    f"Enable the DHCP server on {owner_dev.name} {serving.label}.")
        return
    verdict.add(PASS, subject, f"{owner_dev.name} serves {here.network} ({scope.get('from')}–{scope.get('to')}).")


def _depend(verdict, peers, known, ip, role, needed_for) -> Dependency:  # noqa: ANN001
    owner = next((p for p in peers if p.owner_of(ip) is not None), None)
    dep = Dependency(
        role=role,
        address=str(ip),
        needed_for=needed_for,
        known_as=known.get(str(ip), ""),
        resolved_by=owner.name if owner else "",
    )
    if all(d.address != dep.address or d.role != dep.role for d in verdict.dependencies):
        verdict.dependencies.append(dep)
    return dep


def _input_allows_dhcp(dev: _Device, iface: _Iface, subject: str, verdict: AreaVerdict) -> None:
    """Walk the input chain for a new UDP/67 packet arriving on *iface*."""
    raw = dev.result.summary.get("raw", {})
    lists: dict[str, set[str]] = {}
    for m in raw.get("interface list member", []):
        lists.setdefault(m.get("list", ""), set()).add((m.get("interface") or "").lower())
    names = {iface.name.lower()}
    for idx, rule in enumerate(raw.get("ip firewall filter", [])):
        if _disabled(rule) or rule.get("chain") != "input":
            continue
        if rule.get("protocol") not in (None, "", "udp"):
            continue
        if not _port_matches(rule.get("dst-port", ""), 67):
            continue
        state = rule.get("connection-state", "")
        if state and "new" not in state.replace("!", "").split(",") or state.startswith("!new"):
            continue
        if rule.get("src-address") not in (None, "", "0.0.0.0", "0.0.0.0/0"):
            continue
        if rule.get("dst-address"):
            continue
        in_if = (rule.get("in-interface") or "").lower()
        if in_if and not _name_matches(in_if, names):
            continue
        in_list = rule.get("in-interface-list") or ""
        if in_list:
            neg = in_list.startswith("!")
            members = lists.get(in_list.lstrip("!"), set())
            if not members and in_list.lstrip("!") not in ("all",):
                continue  # unknown list membership: cannot tell, keep walking
            member = bool(names & members) or in_list.lstrip("!") == "all"
            if member == neg:
                continue
        action = rule.get("action", "accept")
        if action in ("accept", "passthrough"):
            if action == "accept":
                verdict.add(PASS, subject, f"Input rule {idx} accepts DHCP on {iface.name}.")
                return
            continue
        if action in ("drop", "reject", "tarpit"):
            verdict.add(FAIL, subject, f"Input rule {idx} ({rule.get('comment') or action}) drops DHCP (UDP 67) "
                        f"arriving on {iface.name}.",
                        f"Accept UDP 67 on {iface.name} above that rule.")
            return
    verdict.add(PASS, subject, f"No input rule blocks DHCP on {iface.name}.")


def _name_matches(spec: str, names: set[str]) -> bool:
    neg = spec.startswith("!")
    hit = spec.lstrip("!") in names
    return hit != neg


def _port_matches(spec: str, port: int) -> bool:
    spec = (spec or "").strip()
    if not spec:
        return True
    for part in spec.split(","):
        if "-" in part:
            lo, _, hi = part.partition("-")
            if lo.isdigit() and hi.isdigit() and int(lo) <= port <= int(hi):
                return True
        elif part.isdigit() and int(part) == port:
            return True
    return False


def _parse_net(text: str) -> ipaddress.IPv4Network | None:
    try:
        net = ipaddress.ip_network((text or "").strip(), strict=False)
    except ValueError:
        return None
    return net if isinstance(net, ipaddress.IPv4Network) else None


def _pool_ranges(text: str) -> list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]]:
    out = []
    for part in (text or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            net = _parse_net(part)
            if net is not None:
                out.append((net.network_address, net.broadcast_address))
            continue
        lo, _, hi = part.partition("-")
        a, b = _ip(lo), _ip(hi or lo)
        if a and b:
            out.append((a, b))
    return out


# --------------------------------------------------------------------------- #
# Wireless
# --------------------------------------------------------------------------- #

_AP_MODES = {"ap-bridge", "bridge", "wds-slave", "ap"}


def _yes(value: str | None) -> bool:
    return str(value or "").lower() in ("yes", "true")


def _split(text: str | None) -> list[str]:
    return [x.strip() for x in str(text or "").split(",") if x.strip()]


def _security_verdict(auth: str, ciphers: str, mode: str = "dynamic-keys") -> tuple[str, str]:
    """(status, message) for a wireless security setting."""
    auth_l = auth.lower()
    if mode == "none" or (mode == "dynamic-keys" and not auth_l):
        return FAIL, "No encryption: the network is open to anyone in range."
    if mode.startswith("static-keys"):
        return FAIL, "WEP (static keys) is broken; anyone can recover the key."
    if "wpa3" in auth_l:
        return PASS, f"Security {auth} ({ciphers or 'default ciphers'})."
    if "wpa2" not in auth_l and "wpa" in auth_l:
        return WARN, f"WPA1 only ({auth}); WPA1/TKIP is broken."
    if "tkip" in ciphers.lower():
        return WARN, f"{auth} allows TKIP ({ciphers}); TKIP is broken."
    return PASS, f"Security {auth} ({ciphers or 'aes-ccm'}); WPA3 not enabled."


def _enforcement(dev: _Device, bridge: str) -> vlan_enforcement.Enforcement:
    return vlan_enforcement.bridge_enforcement(
        dev.result.summary.get("raw", {}), bridge, dev.result.summary.get("model", "")
    )


def _cap_vlan_ok(cap: _Device, bridge: str, vlan_id: str) -> str:
    """'yes' / 'no' / 'chip' (carried by the switch chip, filtering off by design) /
    'chip-missing' / 'unfiltered' (tags pass, nothing enforced) / 'unknown'."""
    raw = cap.result.summary.get("raw", {})
    if not any(b.get("name", "") == bridge for b in raw.get("interface bridge", [])):
        return "unknown"
    enf = _enforcement(cap, bridge)
    state = enf.carries(vlan_id)
    if enf.mode == vlan_enforcement.MODE_SWITCH_CHIP:
        return "chip" if state == "yes" else "chip-missing"
    if enf.mode == vlan_enforcement.MODE_BRIDGE:
        return state if state == "yes" else "no"
    return "unfiltered"


def _vlan_result(verdict: AreaVerdict, subject: str, where: str, bridge: str, cfg: dict[str, str], state: str,
                 warned: set[str]) -> None:
    vid, ssid = cfg["vlan_id"], cfg["ssid"]
    if state == "no":
        verdict.add(FAIL, subject, f"SSID '{ssid}' tags VLAN {vid}, but bridge {bridge}{where} has no VLAN {vid}: "
                    "those clients reach nothing.", f"Add VLAN {vid} to {bridge} (tagged on the uplink).")
    elif state == "yes":
        verdict.add(PASS, subject, f"SSID '{ssid}' → VLAN {vid} is carried on {bridge}{where}.")
    elif state == "chip":
        verdict.add(PASS, subject, f"SSID '{ssid}' → VLAN {vid} is carried on {bridge}{where} by the switch "
                    "chip (VLAN filtering off by design, keeping hardware offload).")
    elif state == "chip-missing":
        verdict.add(WARN, subject, f"SSID '{ssid}' tags VLAN {vid}, but the switch chip{where} has no VLAN {vid} "
                    "entry with the CPU port as a member, so those clients may not reach the uplink.",
                    f"Add VLAN {vid} to /interface ethernet switch vlan (ports incl. switch1-cpu and the uplink) "
                    "and to egress-vlan-tag.")
    elif state == "unfiltered":
        verdict.add(PASS, subject, f"SSID '{ssid}' → VLAN {vid}: tagged frames pass bridge {bridge}{where} "
                    "(VLANs are not enforced on this bridge).")
        if bridge not in warned:
            warned.add(bridge)
            verdict.add(WARN, subject, f"Nothing enforces VLANs on {bridge}{where}: VLAN filtering is off and the "
                        "switch chip has no VLAN rules, so any port can send frames into any VLAN (VLAN hopping), "
                        "including management.", "Enforce VLANs in the switch chip (keeps hardware offload) or "
                        "with vlan-filtering=yes; see Reachability for which suits this model.")


def _wireless_mikrotik(dev: _Device, verdict: AreaVerdict, peers: list[_Device], known: Mapping[str, str]) -> None:
    raw = dev.result.summary.get("raw", {})
    radios = [r for r in raw.get("interface wireless", []) if not _disabled(r)]
    cap = next(iter(raw.get("interface wireless cap", [])), {})
    cap_on = _yes(cap.get("enabled"))
    wifi_cap_on = _yes(next(iter(raw.get("interface wifi cap", [])), {}).get("enabled"))
    manager_on = _yes(next(iter(raw.get("caps-man manager", [])), {}).get("enabled"))
    wifi_radios = [r for r in raw.get("interface wifi", []) if not _disabled(r)]
    if not (radios or cap_on or manager_on or wifi_radios):
        verdict.present = False
        return
    managed = set(_split(cap.get("interfaces"))) if cap_on else set()
    if cap_on and wifi_cap_on:
        verdict.add(INFO, dev.name, "Both legacy CAP (/interface wireless cap) and wifi CAP (/interface wifi cap) "
                    "are enabled; only the one matching the installed package does anything.")

    profiles = {p.get("name", ""): p for p in raw.get("interface wireless security-profiles", [])}
    ports = {(p.get("interface") or "").lower() for p in raw.get("interface bridge port", []) if not _disabled(p)}
    for radio in radios:
        name = radio.get("name") or radio.get("default-name") or "?"
        subject = f"radio {name}"
        if name in managed:
            verdict.add(INFO, subject, "Managed by CAPsMAN: SSID, security and channel come from the manager, "
                        "not from this device's settings.")
            continue
        mode = radio.get("mode", "station")
        if mode not in _AP_MODES:
            verdict.add(INFO, subject, f"{mode} mode (a client of SSID '{radio.get('ssid', '')}'), not an access point.")
            continue
        if not radio.get("ssid"):
            verdict.add(FAIL, subject, "Access point with no SSID.", "Set ssid=.")
        prof = profiles.get(radio.get("security-profile", "default"), {})
        status, msg = _security_verdict(
            prof.get("authentication-types", ""),
            prof.get("unicast-ciphers", ""),
            prof.get("mode", "none"),
        )
        verdict.add(status, subject, msg, "Use a security profile with mode=dynamic-keys and wpa2-psk / wpa3-psk."
                    if status != PASS else "")
        if prof and prof.get("management-protection", "disabled") == "disabled":
            verdict.add(INFO, subject, "Protected management frames are off (deauthentication attacks possible).")
        if radio.get("country") in (None, "", "no_country_set"):
            verdict.add(WARN, subject, "No country set: channels and power are limited and may be illegal here.",
                        "Set country= to where the AP is installed.")
        if radio.get("wps-mode", "disabled") not in ("disabled", ""):
            verdict.add(WARN, subject, f"WPS is on ({radio.get('wps-mode')}); WPS can be abused to join the network.",
                        "Set wps-mode=disabled.")
        iface = dev.ifaces.get(name.lower())
        if name.lower() not in ports and not (iface and iface.networks):
            verdict.add(FAIL, subject, "Not in a bridge and no IP address: clients can join but reach nothing.",
                        "Add the radio to the LAN bridge (or give it an address and DHCP).")
        elif radio.get("ssid"):
            verdict.add(PASS, subject, f"SSID '{radio.get('ssid')}' is bridged / addressed.")

    if cap_on:
        subject = "CAP mode"
        bridge = cap.get("bridge", "")
        if not managed:
            verdict.add(WARN, subject, "CAP is enabled but lists no radios (interfaces=).", "Set interfaces=wlan1,…")
        addresses = _split(cap.get("caps-man-addresses"))
        discovery = _split(cap.get("discovery-interfaces"))
        managers: list[_Device] = []
        warned: set[str] = set()
        for addr in addresses:
            ip = _ip(addr)
            if ip is None:
                continue
            _depend(verdict, peers, known, ip, "CAPsMAN manager",
                    "which SSIDs, security and VLANs this access point broadcasts")
            owner = next((p for p in peers if p.owner_of(ip) is not None), None)
            if owner is not None:
                managers.append(owner)
                if not _yes(next(iter(owner.result.summary.get("raw", {}).get("caps-man manager", [])), {}).get("enabled")):
                    verdict.add(FAIL, subject, f"Manager {addr} ({owner.name}) has CAPsMAN disabled; radios stay down.",
                                f"Enable /caps-man manager on {owner.name}.")
                else:
                    verdict.add(PASS, subject, f"Manager {addr} is {owner.name}, CAPsMAN enabled.")
        if not addresses:
            where = ", ".join(discovery) or "all interfaces (broadcast)"
            found = [p for p in peers if _yes(next(iter(p.result.summary.get("raw", {}).get("caps-man manager", [])), {}).get("enabled"))]
            dep = Dependency("CAPsMAN manager", f"discovered on {where}",
                             "which SSIDs, security and VLANs this access point broadcasts",
                             resolved_by=found[0].name if found else "")
            verdict.dependencies.append(dep)
            managers.extend(found[:1])
        done: set[tuple[str, str]] = set()
        for mgr in managers:
            for cfg in _capsman_configs(mgr):
                if not _yes(cfg["local_forwarding"]) or (cfg["vlan_id"], cfg["ssid"]) in done:
                    continue
                done.add((cfg["vlan_id"], cfg["ssid"]))
                if bridge in ("", "none"):
                    verdict.add(FAIL, subject, f"SSID '{cfg['ssid']}' uses local forwarding but this CAP has no bridge.",
                                "Set bridge= in /interface wireless cap.")
                    continue
                if cfg["vlan_mode"] == "use-tag" and cfg["vlan_id"]:
                    _vlan_result(verdict, subject, " here", bridge, cfg,
                                 _cap_vlan_ok(dev, bridge, cfg["vlan_id"]), warned)

    if manager_on:
        _capsman_manager(dev, verdict, peers, known)


def _capsman_configs(mgr: _Device) -> list[dict[str, str]]:
    """Each CAPsMAN configuration with its datapath overrides merged in."""
    raw = mgr.result.summary.get("raw", {})
    paths = {d.get("name", ""): d for d in raw.get("caps-man datapath", [])}
    out = []
    for cfg in raw.get("caps-man configuration", []):
        dp = paths.get(cfg.get("datapath", ""), {})

        def pick(key: str) -> str:
            return cfg.get(f".{key}") or cfg.get(f"datapath.{key}") or dp.get(key, "")

        out.append(
            {
                "name": cfg.get("name", ""),
                "ssid": cfg.get("ssid", ""),
                "security": cfg.get("security", ""),
                "channel": cfg.get("channel", ""),
                "country": cfg.get("country", ""),
                "datapath": cfg.get("datapath", ""),
                "bridge": pick("bridge"),
                "local_forwarding": pick("local-forwarding"),
                "vlan_mode": pick("vlan-mode"),
                "vlan_id": pick("vlan-id"),
            }
        )
    return out


def _capsman_manager(dev: _Device, verdict: AreaVerdict, peers: list[_Device], known: Mapping[str, str]) -> None:
    raw = dev.result.summary.get("raw", {})
    security = {s.get("name", ""): s for s in raw.get("caps-man security", [])}
    channels = {c.get("name", ""): c for c in raw.get("caps-man channel", [])}
    bridges = {b.get("name", "") for b in raw.get("interface bridge", [])}
    configs = _capsman_configs(dev)
    if not configs:
        verdict.add(WARN, "CAPsMAN manager", "Manager enabled with no configurations: CAPs get nothing to broadcast.")
    for cfg in configs:
        subject = f"CAPsMAN {cfg['name']} (SSID '{cfg['ssid']}')"
        if not cfg["ssid"]:
            verdict.add(FAIL, subject, "No SSID.", "Set ssid=.")
        sec = security.get(cfg["security"])
        if sec is None:
            verdict.add(FAIL, subject, f"Security '{cfg['security'] or '(none)'}' not found: the SSID would be open.",
                        "Attach a security profile with wpa2-psk / wpa3-psk.")
        else:
            status, msg = _security_verdict(sec.get("authentication-types", ""), sec.get("encryption", ""))
            verdict.add(status, subject, msg, "Use wpa2-psk / wpa3-psk with aes-ccm." if status != PASS else "")
        if cfg["channel"] and cfg["channel"] not in channels:
            verdict.add(FAIL, subject, f"Channel '{cfg['channel']}' does not exist.", "Fix the channel name.")
        if not cfg["country"]:
            verdict.add(WARN, subject, "No country: CAPs use the most restrictive defaults.", "Set country=.")
        if not _yes(cfg["local_forwarding"]) and cfg["bridge"] and cfg["bridge"] not in bridges:
            verdict.add(FAIL, subject, f"Traffic is tunnelled to this manager, but bridge {cfg['bridge']} does not exist here.",
                        "Create the bridge or fix datapath bridge=.")
    provisioning = [p for p in raw.get("caps-man provisioning", []) if not _disabled(p)]
    statics = [i for i in raw.get("caps-man interface", []) if not _disabled(i)]
    names = {c["name"] for c in configs}
    for rule in provisioning:
        master = rule.get("master-configuration", "")
        if master and master not in names:
            verdict.add(FAIL, "CAPsMAN provisioning", f"Rule uses configuration '{master}', which does not exist.",
                        "Fix master-configuration=.")
    if not provisioning and not statics:
        verdict.add(WARN, "CAPsMAN provisioning", "No provisioning rules: new CAPs get no configuration.",
                    "Add /caps-man provisioning action=create-enabled.")

    used = {c["channel"] for c in configs}
    freqs = sorted({int(f) for n, ch in channels.items() if n in used for f in _split(ch.get("frequency")) if f.isdigit()})
    clean = {2412, 2437, 2462, 2484}
    overlaps = [(a, b) for i, a in enumerate(freqs) for b in freqs[i + 1:] if a < 3000 and b < 3000 and b - a < 25]
    if overlaps:
        pairs = ", ".join(f"{a}/{b} MHz" for a, b in overlaps)
        verdict.add(WARN, "CAPsMAN channels", f"2.4 GHz channels overlap ({pairs}); only 1/6/11 (2412/2437/2462) do not.",
                    "Move the radios to 2412, 2437 and 2462 MHz.")
    elif freqs:
        verdict.add(PASS, "CAPsMAN channels", f"Channels {', '.join(map(str, freqs))} MHz do not overlap.")
    if freqs and all(f < 3000 for f in freqs):
        verdict.add(INFO, "CAPsMAN channels", "2.4 GHz only: no 5 GHz SSIDs (lower throughput, more interference).")
    if any(f not in clean for f in freqs if f < 3000) and not overlaps:
        verdict.add(INFO, "CAPsMAN channels", "Channels outside 1/6/11 overlap with neighbours' networks.")

    caps = [
        p for p in peers
        if _yes(next(iter(p.result.summary.get("raw", {}).get("interface wireless cap", [])), {}).get("enabled"))
        and any(dev.owner_of(_ip(a)) is not None for a in _split(
            next(iter(p.result.summary.get("raw", {}).get("interface wireless cap", [])), {}).get("caps-man-addresses"))
            if _ip(a) is not None)
    ]
    if statics or provisioning:
        dep = Dependency(
            "CAP access points",
            f"CAPs of {dev.name}",
            "whether each access point's bridge carries the SSID VLANs (local forwarding)",
            resolved_by=", ".join(c.name for c in caps),
        )
        verdict.dependencies.append(dep)
    warned: set[str] = set()
    for cap_dev in caps:
        cap = next(iter(cap_dev.result.summary.get("raw", {}).get("interface wireless cap", [])), {})
        bridge = cap.get("bridge", "")
        seen: set[tuple[str, str]] = set()
        for cfg in configs:
            key = (cfg["vlan_id"], cfg["ssid"])
            if key in seen:
                continue
            if _yes(cfg["local_forwarding"]) and cfg["vlan_mode"] == "use-tag" and cfg["vlan_id"]:
                seen.add(key)
                _vlan_result(verdict, f"CAP {cap_dev.name}", f" on {cap_dev.name}", bridge, cfg,
                             _cap_vlan_ok(cap_dev, bridge, cfg["vlan_id"]), warned)


def _wireless_pfsense(dev: _Device, verdict: AreaVerdict) -> None:
    radios = [i for i in dev.result.interfaces
              if i.device.split("_")[0].rstrip("0123456789") in ("ath", "iwm", "iwn", "run", "mt", "rtwn", "wlan")]
    if not radios:
        verdict.present = False
        return
    for i in radios:
        verdict.add(INFO, f"{i.name} ({i.descr or i.device})",
                    "Wireless interface on pfSense: radio settings are not analysed yet.")


# --------------------------------------------------------------------------- #
# Bandwidth (estimates)
# --------------------------------------------------------------------------- #

import re as _re  # noqa: E402

_RATE_TOKEN = _re.compile(r"^(\d+(?:\.\d+)?)(g|gb|gbe|gbit|gbps|m|mb|mbit|mbps)$", _re.IGNORECASE)
_ROS_RATE = _re.compile(r"(\d+(?:\.\d+)?)([MG])-base", _re.IGNORECASE)
_PORT_DEFAULTS = (
    ("qsfp28", 100_000), ("qsfpplus", 40_000), ("sfp28", 25_000), ("sfp-sfpplus", 10_000),
    ("sfpplus", 10_000), ("combo", 1_000), ("sfp", 1_000), ("ether", 1_000),
)
_NIC_DEFAULTS = (
    ("igc", 2_500), ("igb", 1_000), ("em", 1_000), ("re", 1_000), ("bge", 1_000), ("alc", 1_000),
    ("ixl", 10_000), ("ix", 10_000), ("ice", 25_000), ("mce", 10_000), ("mlx", 10_000),
    ("cxl", 10_000), ("bnxt", 10_000), ("vmx", 10_000), ("vtnet", 10_000), ("hn", 10_000),
)
CONFIG_ONLY_NOTE = (
    "Estimates from the config only: ISP line rates (unless named in interface descriptions), "
    "firewall CPU, NAT / VPN / IDS throughput and real Wi-Fi conditions are not in a config."
)


def _fmt(mbps: float | None) -> str:
    if mbps is None:
        return "unknown"
    if mbps >= 1000:
        g = mbps / 1000
        return f"{g:g} Gbps" if g == int(g) else f"{g:.1f} Gbps"
    return f"{mbps:g} Mbps"


def _rate_from_text(text: str) -> float | None:
    """'0_S1_P0_1G_F_WAN1' → 1000; '150m' → 150 (tokens split on _ - space)."""
    for token in _re.split(r"[_\-\s/]+", text or ""):
        m = _RATE_TOKEN.match(token)
        if m:
            value = float(m.group(1))
            return value * 1000 if m.group(2).lower().startswith("g") else value
    return None


def _ros_rate(text: str) -> float | None:
    rates = []
    for m in _ROS_RATE.finditer(text or ""):
        value = float(m.group(1))
        rates.append(value * 1000 if m.group(2).upper() == "G" else value)
    return max(rates) if rates else None


def _mt_port_speeds(dev: _Device) -> dict[str, tuple[float, str]]:
    """port name (lower) → (Mbps, where the number came from)."""
    out: dict[str, tuple[float, str]] = {}
    for eth in dev.result.summary.get("raw", {}).get("interface ethernet", []):
        name = (eth.get("name") or eth.get("default-name") or "").lower()
        if not name or _disabled(eth):
            continue
        auto = str(eth.get("auto-negotiation", "yes")).lower() in ("yes", "true")
        if not auto and _ros_rate(eth.get("speed", "")):
            out[name] = (_ros_rate(eth.get("speed", "")), f"fixed speed {eth.get('speed')}")
            continue
        adv = _ros_rate(eth.get("advertise", ""))
        if auto and adv:
            out[name] = (adv, f"auto-negotiation advertises up to {_fmt(adv)}")
            continue
        base = (eth.get("default-name") or name).lower()
        for prefix, mbps in _PORT_DEFAULTS:
            if base.startswith(prefix):
                out[name] = (float(mbps), "port type")
                break
    return out


def _pf_speed(dev: _Device, device: str, descr: str = "") -> tuple[float | None, str]:
    """NIC speed for a pfSense device name (em0, mce1.630 → mce1)."""
    parent = device.split(".")[0]
    for i in dev.result.interfaces:
        if i.device == parent:
            rate = _rate_from_text(i.descr)
            if rate:
                return rate, f"description '{i.descr}'"
            media = _rate_from_text((i.media or "").replace("base", " "))
            if media:
                return media, f"media {i.media}"
    rate = _rate_from_text(descr)
    if rate:
        return rate, f"description '{descr}'"
    driver = parent.rstrip("0123456789")
    for prefix, mbps in _NIC_DEFAULTS:
        if driver == prefix:
            return float(mbps), f"{driver} NIC"
    return None, "unknown NIC"


def _wifi_estimate(band: str, width: str, streams: int = 2) -> tuple[float, float]:
    """(PHY Mbps, realistic Mbps ≈ 50 % of PHY) for one radio."""
    band = (band or "").lower()
    mhz = int(_re.sub(r"\D", "", width or "20") or 20)
    if "ax" in band:
        per = {20: 143, 40: 287, 80: 600, 160: 1201}.get(mhz, 143)
    elif "ac" in band:
        per = {20: 87, 40: 200, 80: 433, 160: 867}.get(mhz, 87)
    elif band.endswith("n") or "/n" in band or "-n" in band:
        per = {20: 72, 40: 150}.get(mhz, 72)
    elif "g" in band or "a" in band:
        per, streams = 54, 1
    else:
        per, streams = 11, 1
    phy = float(per * streams)
    return phy, round(phy * 0.5)


def _pf_internet(dev: _Device) -> tuple[float | None, str]:
    """Internet capacity from the default gateway / group (tier 1, backup tier)."""
    result = dev.result
    default = result.summary.get("default_gateway_v4", "")
    gw_if = {g.get("name", ""): g.get("interface", "") for g in result.gateways}
    group = next((g for g in result.gateway_groups if g.get("name") == default), None)

    def gw_speed(name: str) -> tuple[float | None, str]:
        iface = dev.result.interfaces
        ifname = gw_if.get(name, "")
        info = next((i for i in iface if i.name == ifname), None)
        if info is None:
            return None, name
        speed, _src = _pf_speed(dev, info.device, info.descr)
        return speed, f"{info.descr or info.name}"

    if group is not None:
        tiers: dict[int, list[str]] = {}
        for member, tier in (group.get("tiers") or {m: 1 for m in group.get("members", [])}).items():
            tiers.setdefault(int(tier), []).append(member)
        ordered = [tiers[k] for k in sorted(tiers)]
        main = [gw_speed(m) for m in ordered[0]]
        main_total = sum(s for s, _ in main if s) or None
        text = f"{_fmt(main_total)} via {', '.join(n for _, n in main)}"
        if len(ordered[0]) > 1:
            text += " (load-balanced; a single flow gets one link)"
        if len(ordered) > 1:
            backup = [gw_speed(m) for m in ordered[1]]
            text += f"; fails over to {_fmt(sum(s for s, _ in backup if s) or None)} via {', '.join(n for _, n in backup)}"
        return main_total, text
    if default:
        speed, name = gw_speed(default)
        return speed, f"{_fmt(speed)} via {name}"
    return None, "no default gateway set"


def _bandwidth_pfsense(dev: _Device, verdict: AreaVerdict) -> dict[ipaddress.IPv4Network, tuple[float | None, str]]:
    """Per inside subnet: (estimate Mbps, explanation). Also used by switches."""
    result = dev.result
    internet, inet_text = _pf_internet(dev)
    verdict.add(INFO if internet else WARN, "Internet", f"Capacity ≈ {inet_text}.",
                "" if internet else "Set a default gateway (System → Routing).")
    wan_ifaces = {g.get("interface", "") for g in result.gateways}
    shared: dict[str, list[str]] = {}
    rows = []
    for info in result.interfaces:
        iface = dev.ifaces.get(info.name.lower())
        if not info.enabled or iface is None or not iface.networks or info.name in wan_ifaces:
            continue
        if info.kind in ("openvpn", "ipsec", "gif", "gre", "ppp"):
            continue
        parent = info.device.split(".")[0]
        shared.setdefault(parent, []).append(info.descr or info.name)
        speed, src = _pf_speed(dev, info.device, info.descr)
        rows.append((info, iface, parent, speed, src))
    out: dict[ipaddress.IPv4Network, tuple[float | None, str]] = {}
    for info, iface, parent, speed, src in rows:
        net = iface.networks[0].network
        peers_on_nic = len(shared.get(parent, []))
        share = f", shared by {peers_on_nic} networks on {parent}" if peers_on_nic > 1 else ""
        est = min(x for x in (speed, internet) if x) if (speed or internet) else None
        msg = (f"LAN side {_fmt(speed)} ({src}{share}); to the Internet ≈ {_fmt(est)} per client, "
               f"less when others are busy.")
        verdict.add(INFO, f"{info.name} ({info.descr or info.name}) {net}", msg)
        out[net] = (est, f"{dev.name} {parent} {_fmt(speed)}{share}; Internet {inet_text}")
    shaper = result.summary.get("shaper_queues")
    if shaper:
        verdict.add(INFO, "Traffic shaping", f"Shaper / limiters configured: {shaper}.")
    verdict.add(INFO, "Note", CONFIG_ONLY_NOTE)
    return out


def _bandwidth_mikrotik(dev: _Device, verdict: AreaVerdict, peers: list[_Device], known: Mapping[str, str]) -> None:
    raw = dev.result.summary.get("raw", {})
    speeds = _mt_port_speeds(dev)
    bridges = {(b.get("name") or "").lower() for b in raw.get("interface bridge", [])}
    pvid: dict[str, list[str]] = {}
    for port in raw.get("interface bridge port", []):
        if not _disabled(port) and port.get("pvid"):
            pvid.setdefault(port["pvid"], []).append((port.get("interface") or "").lower())

    slow = sorted(n for n, (s, src) in speeds.items() if s <= 100 and "advertises" in src)
    if slow:
        ten = [n for n in slow if speeds[n][0] <= 10]
        verdict.add(WARN, "Port speeds", f"{len(slow)} port(s) only auto-negotiate up to 100 Mbps: {', '.join(slow)}"
                    + (f"; {', '.join(ten)} only 10 Mbps" if ten else "") + ".",
                    "Add 1G-baseT-full (and faster) to advertise= on those ports.")

    radios = _radio_rates(dev, peers)
    vlans: dict[str, dict[str, set[str]]] = {}
    for entry in raw.get("interface bridge vlan", []):
        if _disabled(entry):
            continue
        for vid in _split(entry.get("vlan-ids")):
            slot = vlans.setdefault(vid, {"tagged": set(), "untagged": set()})
            for p in _split(entry.get("tagged")):
                slot["tagged"].add(p.lower())
            for p in _split(entry.get("untagged")):
                slot["untagged"].add(p.lower())
    for vid, members in pvid.items():
        vlans.setdefault(vid, {"tagged": set(), "untagged": set()})["untagged"].update(members)
    vlans.pop("1", None)  # default VLAN: not a user network here
    if not vlans:
        verdict.add(INFO, "Switching", "No VLAN table: all ports share one network.")

    trunk_load: dict[str, int] = {}
    for members in vlans.values():
        for p in members["tagged"]:
            trunk_load[p] = trunk_load.get(p, 0) + 1

    for vid in sorted(vlans, key=lambda v: int(v) if v.isdigit() else 0):
        members = vlans[vid]
        access = [p for p in members["untagged"] if p in speeds]
        trunks = [p for p in members["tagged"] if p in speeds and p not in bridges]
        wifi = [p for p in members["tagged"] | members["untagged"] if p in radios]
        net = next((n.network for i in dev.ifaces.values() if i.vlan_id == vid for n in i.networks), None)
        subject = f"VLAN {vid}" + (f" ({net})" if net else "")
        parts = []
        if access:
            best = max(speeds[p][0] for p in access)
            capped = [p for p in access if speeds[p][0] < best]
            parts.append(f"wired clients up to {_fmt(best)} on {len(access)} port(s)"
                         + (f" ({', '.join(sorted(capped))} slower)" if capped else ""))
        uplink = max(trunks, key=lambda p: speeds[p][0]) if trunks else None
        if uplink:
            parts.append(f"uplink assumed {uplink} {_fmt(speeds[uplink][0])} (fastest trunk), "
                         f"shared by {trunk_load.get(uplink, 1)} VLAN(s)")
        for w in wifi:
            phy, real = radios[w]
            parts.append(f"wireless {w}: ≈ {_fmt(real)} shared by its clients (PHY {_fmt(phy)})")
        gw_dev, gw_row, mismatch = _gateway_for_vlan(vid, net, peers)
        candidates = [speeds[uplink][0]] if uplink else []
        if access:
            candidates.append(max(speeds[p][0] for p in access))
        if mismatch is not None:
            verdict.add(WARN, subject, "; ".join(parts) + f". The router for VLAN {vid} ({gw_dev.name}) uses "
                        f"{mismatch}, not {net}: clients here have no working gateway, so no Internet capacity "
                        "applies (see DHCP).", f"Use the same subnet for VLAN {vid} on both devices.")
        elif gw_row is not None:
            est, how = gw_row
            if est:
                candidates.append(est)
            parts.append(f"onward via {how}")
            verdict.add(INFO, subject, "; ".join(parts) + f". Per wired client ≈ {_fmt(min(candidates))} to the Internet.")
        else:
            label = f"Gateway for VLAN {vid}"
            dep = Dependency(label, f"VLAN {vid} gateway" + (f" ({net})" if net else ""),
                             f"Internet capacity for VLAN {vid} beyond this switch")
            if all(d.address != dep.address for d in verdict.dependencies):
                verdict.dependencies.append(dep)
            verdict.add(INFO, subject, "; ".join(parts) + (f". Up to {_fmt(min(candidates))} as far as the uplink; "
                        "beyond that needs the gateway's config." if candidates else "."))
    verdict.add(INFO, "Note", CONFIG_ONLY_NOTE)


def _gateway_for_vlan(vid: str, net, peers: list[_Device]):  # noqa: ANN001
    """(peer, row, mismatch) for the loaded pfSense that routes VLAN *vid*.

    A subnet match wins. A tag-only match whose subnet differs from this
    switch's is returned as *mismatch* (that network): clients there have no
    working gateway.
    """
    tag_hit = None
    for peer in peers:
        if peer.kind == "mikrotik":
            continue
        rows = _bandwidth_pfsense(peer, AreaVerdict("scratch"))
        for iface in peer.ifaces.values():
            if not iface.networks:
                continue
            gw_net = iface.networks[0].network
            if net is not None and any(n.network == net for n in iface.networks):
                return peer, rows.get(gw_net), None
            if iface.vlan_id == vid and tag_hit is None:
                tag_hit = (peer, rows.get(gw_net), gw_net)
    if tag_hit is None:
        return None, None, None
    peer, row, gw_net = tag_hit
    if net is not None and gw_net != net:
        return peer, None, gw_net
    return peer, row, None


def _radio_rates(dev: _Device, peers: list[_Device]) -> dict[str, tuple[float, float]]:
    """Wireless interface → (PHY, realistic) Mbps; CAPsMAN channels win when loaded."""
    raw = dev.result.summary.get("raw", {})
    out: dict[str, tuple[float, float]] = {}
    cap = next(iter(raw.get("interface wireless cap", [])), {})
    managed = set(_split(cap.get("interfaces"))) if _yes(cap.get("enabled")) else set()
    manager_channel = None
    if managed:
        for addr in _split(cap.get("caps-man-addresses")):
            ip = _ip(addr)
            owner = next((p for p in peers if ip is not None and p.owner_of(ip) is not None), None)
            if owner is not None:
                chans = owner.result.summary.get("raw", {}).get("caps-man channel", [])
                if chans:
                    manager_channel = chans[0]
    for radio in raw.get("interface wireless", []):
        if _disabled(radio):
            continue
        name = (radio.get("name") or radio.get("default-name") or "").lower()
        if name in managed and manager_channel is not None:
            out[name] = _wifi_estimate(manager_channel.get("band", ""),
                                       manager_channel.get("control-channel-width", "20mhz"))
        else:
            out[name] = _wifi_estimate(radio.get("band", ""), radio.get("channel-width", "20mhz"))
    return out


# --------------------------------------------------------------------------- #
# Reachability
# --------------------------------------------------------------------------- #


def _is_internal_range(net: ipaddress.IPv4Network) -> bool:
    """RFC 1918, shared (100.64/10) or other non-global space."""
    return not net.is_global


def mt_vlan_iface_state(dev: _Device, name: str) -> tuple[bool, str]:
    """Can a MikroTik VLAN interface on a bridge pass traffic at all?

    With vlan-filtering=yes the bridge itself must be a tagged member of the
    VLAN, or the router's own address on that VLAN is cut off.
    """
    raw = dev.result.summary.get("raw", {})
    vlan = next((v for v in raw.get("interface vlan", []) if (v.get("name") or "").lower() == name.lower()), None)
    if vlan is None:
        return True, ""
    parent = vlan.get("interface", "")
    vid = vlan.get("vlan-id", "")
    if parent.lower() not in dev.ifaces:
        return False, f"its parent interface {parent} does not exist"
    bridge = next((b for b in raw.get("interface bridge", []) if (b.get("name") or "") == parent), None)
    if bridge is None:
        return True, ""
    if not _yes(bridge.get("vlan-filtering")):
        enf = _enforcement(dev, parent)
        if enf.mode == vlan_enforcement.MODE_SWITCH_CHIP and vid not in enf.cpu_vlans:
            return False, (f"the switch chip enforces VLANs on {parent} and VLAN {vid} has no switch VLAN entry "
                           "with the CPU port (switch1-cpu) as a member")
        return True, ""
    for entry in raw.get("interface bridge vlan", []):
        if _disabled(entry) or vid not in _split(entry.get("vlan-ids")):
            continue
        if parent in _split(entry.get("tagged")):
            return True, ""
        return False, (f"bridge {parent} filters VLANs and is not a tagged member of VLAN {vid}, "
                       "so this interface can neither send nor receive")
    return False, f"bridge {parent} filters VLANs and has no VLAN {vid} entry"


def _overlaps(dev: _Device, verdict: AreaVerdict) -> None:
    nets = [(i, n.network) for i in dev.ifaces.values() if i.enabled for n in i.networks]
    for idx, (a_if, a) in enumerate(nets):
        for b_if, b in nets[idx + 1:]:
            if a_if is not b_if and a.overlaps(b):
                verdict.add(FAIL, f"{a_if.name} / {b_if.name}",
                            f"{a} and {b} overlap: traffic for the shared addresses goes to one interface only.",
                            "Give each interface its own subnet.")


def _public_space(dev: _Device, verdict: AreaVerdict, skip: set[str]) -> None:
    flagged = sorted({str(n.network) for i in dev.ifaces.values() if i.enabled and i.name not in skip
                      for n in i.networks if not _is_internal_range(n.network)})
    if flagged:
        verdict.add(WARN, "Addressing", f"Internal networks use public (Internet-routable) address space: "
                    f"{', '.join(flagged)}. Clients cannot reach the real owners of those addresses, and "
                    "replies or leaks can go to them.",
                    "Renumber into private space (10/8, 172.16/12, 192.168/16) or 100.64/10.")


def _reach_pfsense(dev: _Device, verdict: AreaVerdict) -> None:
    result = dev.result
    default = result.summary.get("default_gateway_v4", "")
    gws = {g.get("name", ""): g for g in result.gateways}
    group = next((g for g in result.gateway_groups if g.get("name") == default), None)
    if not default:
        verdict.add(FAIL, "Default route", "No default IPv4 gateway: nothing reaches the Internet.",
                    "Set a default gateway (System → Routing).")
    else:
        members = group.get("members", []) if group else [default]
        live = []
        for m in members:
            gw = gws.get(m)
            iface = dev.ifaces.get((gw or {}).get("interface", "").lower()) if gw else None
            if gw is None:
                verdict.add(FAIL, "Default route", f"Gateway {m} does not exist.", "Fix the gateway group.")
            elif gw.get("disabled") == "yes" or iface is None or not iface.enabled:
                verdict.add(WARN, "Default route", f"Gateway {m} is disabled or its interface is down.")
            else:
                live.append(m)
        if live:
            verdict.add(PASS, "Default route", f"Default via {default} ({', '.join(live)} usable).")
        else:
            verdict.add(FAIL, "Default route", f"No usable gateway in {default}.", "Enable a WAN gateway.")

    mode = result.summary.get("outbound_nat_mode", "automatic")
    outbound = [r for r in result.nat_rules if r.kind.startswith("outbound") and not r.disabled]
    wan_ifaces = {g.get("interface", "") for g in result.gateways}
    inside = [i for i in dev.ifaces.values() if i.enabled and i.networks and i.name not in wan_ifaces
              and not i.name.startswith(("ovpn", "ipsec"))]
    for iface in inside:
        net = iface.networks[0].network
        subject = _subject(iface, iface.name)
        if mode in ("automatic", "hybrid"):
            nat_ok = True
        elif mode == "disabled":
            nat_ok = _is_internal_range(net) is False
        else:
            nat_ok = any(r.source in ("any", str(net)) or str(net) in r.source for r in outbound)
        if not nat_ok:
            verdict.add(FAIL, subject, f"Outbound NAT is {mode} and no rule translates {net}.",
                        "Add an outbound NAT rule for this network (or use automatic).")
        verdict_rule = _first_internet_rule(result, iface.name)
        if verdict_rule is None:
            verdict.add(FAIL, subject, "No firewall rule lets this network out; pfSense blocks it by default.",
                        f"Add a pass rule on {iface.label} from {iface.name} net to any.")
        else:
            action, rule = verdict_rule
            if action == "pass":
                via = f" via {rule.gateway}" if rule.gateway else ""
                verdict.add(PASS, subject, f"Rule {rule.index} passes {iface.name} net to any{via}.")
            else:
                verdict.add(FAIL, subject, f"Rule {rule.index} ({rule.descr or action}) blocks this network "
                            "before any pass rule.", "Move or remove the block rule.")
    if mode in ("automatic", "hybrid"):
        verdict.add(PASS, "Outbound NAT", f"Mode {mode}: every internal interface network is translated.")
    resolver = result.dns.get("unbound_enable") or result.dns.get("forwarder")
    verdict.add(PASS if resolver else WARN, "DNS",
                "DNS resolver / forwarder enabled." if resolver else "No DNS resolver or forwarder enabled.",
                "" if resolver else "Enable the DNS Resolver or hand out other DNS servers.")
    _overlaps(dev, verdict)
    _public_space(dev, verdict, wan_ifaces)


def _first_internet_rule(result: CheckResult, ifname: str):  # noqa: ANN202
    """First rule on *ifname* that decides traffic from its net to the Internet."""
    srcs = {"any", ifname, f"{ifname}ip", f"{ifname}net"}
    for rule in sorted(result.filter_rules, key=lambda r: (not r.floating, r.index)):
        if rule.disabled or ifname not in rule.interface.split(","):
            continue
        if rule.floating and not rule.quick:
            continue
        if rule.source_not or rule.source not in srcs:
            continue
        if rule.dst_port or rule.protocol not in ("", "any", "tcp/udp"):
            continue
        if rule.destination not in ("any", "") or rule.destination_not:
            continue
        action = rule.type or "pass"
        if action in ("pass", "block", "reject"):
            return ("pass" if action == "pass" else action), rule
    return None


def _vlan_enforcement_checks(dev: _Device, verdict: AreaVerdict, peers: list[_Device]) -> None:
    """Judge VLAN filtering by how this bridge really enforces VLANs."""
    raw = dev.result.summary.get("raw", {})
    model = dev.result.summary.get("model", "")
    chip_peer = next((p.name for p in peers if p.kind == "mikrotik" and p is not dev and any(
        e.mode == vlan_enforcement.MODE_SWITCH_CHIP
        for e in vlan_enforcement.device_bridges(p.result.summary.get("raw", {}), p.result.summary.get("model", ""))
    )), "")
    for enf in vlan_enforcement.device_bridges(raw, model):
        subject = f"bridge {enf.bridge}"
        if enf.mode == vlan_enforcement.MODE_BRIDGE:
            if enf.hw_filtering:
                verdict.add(PASS, subject, f"VLANs enforced by {enf.describe()}.")
            else:
                verdict.add(INFO, subject, f"VLANs enforced by {enf.describe()}. Switch-chip VLAN rules with "
                            "vlan-filtering=no would keep hardware offload, if throughput matters here.")
            continue
        if enf.mode == vlan_enforcement.MODE_SWITCH_CHIP:
            verdict.add(PASS, subject, f"VLANs {', '.join(sorted(enf.chip_vlans, key=int))} enforced by "
                        f"{enf.describe()}.")
            ignored = sorted(enf.bridge_vlans - enf.chip_vlans, key=lambda v: int(v) if v.isdigit() else 0)
            if ignored:
                verdict.add(WARN, subject, f"VLAN(s) {', '.join(ignored)} are in the bridge VLAN table but not in the "
                            "switch chip. With vlan-filtering=no the bridge table is ignored, so they are not "
                            "carried as configured.", "Add them to /interface ethernet switch vlan and "
                            "egress-vlan-tag, or remove them from the bridge VLAN table if unused.")
            if enf.unchecked_ports:
                verdict.add(WARN, subject, f"Port(s) {', '.join(enf.unchecked_ports)} are not in "
                            "drop-if-invalid-or-src-port-not-member-of-vlan-on-ports, so frames they send for "
                            "VLANs they are not members of are not dropped (VLAN hopping).",
                            "Add them to that list under /interface ethernet switch.")
            continue
        if enf.bridge_vlans:
            verdict.add(WARN, subject, f"VLAN table lists {', '.join(sorted(enf.bridge_vlans, key=lambda v: int(v) if v.isdigit() else 0))}, "
                        "but nothing enforces it (vlan-filtering=no and no switch-chip VLAN rules). Tagged frames pass between any ports "
                        "(VLAN hopping).", enf.remedy(chip_peer))


def _reach_mikrotik(dev: _Device, verdict: AreaVerdict, peers: list[_Device], known: Mapping[str, str]) -> None:
    raw = dev.result.summary.get("raw", {})
    _vlan_enforcement_checks(dev, verdict, peers)
    for iface in dev.ifaces.values():
        if not iface.networks:
            continue
        ok, why = mt_vlan_iface_state(dev, iface.name)
        subject = _subject(iface, iface.name)
        if not ok:
            fix = ("Add VLAN to /interface ethernet switch vlan with switch1-cpu as a member."
                   if "switch chip" in why else "Add the bridge as a tagged member of the VLAN (/interface bridge vlan).")
            verdict.add(FAIL, subject, f"This device's address here is unreachable: {why}.", fix)

    routes = [r for r in raw.get("ip route", []) if not _disabled(r) and r.get("dst-address") in ("0.0.0.0/0", None)]
    if not routes:
        verdict.add(WARN, "Default route", "No default route: this device cannot reach other networks "
                    "(fine for a pure switch, but management from other subnets fails).",
                    "Add /ip route dst-address=0.0.0.0/0 gateway=<router>.")
    for route in routes:
        gw = _ip(route.get("gateway", ""))
        if gw is None:
            verdict.add(INFO, "Default route", f"Default via {route.get('gateway')} (not an address).")
            continue
        on_link = next((i for i in dev.ifaces.values() for n in i.networks if gw in n.network), None)
        if on_link is None:
            verdict.add(FAIL, "Default route", f"Gateway {gw} is not on any connected network.",
                        "Use a gateway address on one of this device's subnets.")
            continue
        ok, why = mt_vlan_iface_state(dev, on_link.name)
        if not ok:
            verdict.add(FAIL, "Default route", f"Gateway {gw} is reached via {on_link.name}, but {why}.")
            continue
        owner = next((p for p in peers if p.owner_of(gw) is not None), None)
        _depend(verdict, peers, known, gw, "Default gateway", "whether the gateway routes this device's traffic")
        if owner is not None:
            o_if = owner.owner_of(gw)
            if not o_if.enabled:
                verdict.add(FAIL, "Default route", f"Gateway {gw} is {owner.name} {o_if.label}, which is disabled.")
            else:
                verdict.add(PASS, "Default route", f"Default via {gw} = {owner.name} {o_if.label} on {on_link.name}.")
        else:
            verdict.add(PASS, "Default route", f"Default via {gw} on {on_link.name} (on-link).")
    # Each addressed VLAN: does the loaded router agree on the subnet?
    for iface in dev.ifaces.values():
        if not iface.vlan_id or not iface.networks:
            continue
        net = iface.networks[0].network
        for peer in peers:
            same_tag = [i for i in peer.ifaces.values() if i.vlan_id == iface.vlan_id and i.networks]
            if same_tag and all(n.network != net for i in same_tag for n in i.networks):
                theirs = ", ".join(str(n.network) for i in same_tag for n in i.networks)
                verdict.add(FAIL, _subject(iface, iface.name),
                            f"VLAN {iface.vlan_id} is {net} here but {theirs} on {peer.name}: devices on it "
                            "cannot reach their router.", "Use one subnet per VLAN on every device.")
    _overlaps(dev, verdict)
    _public_space(dev, verdict, set())


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #


def analyse(
    result: CheckResult,
    peers: Iterable[CheckResult] = (),
    known_devices: Mapping[str, str] | None = None,
) -> Analysis:
    """Analyse *result* (with other loaded configs as *peers*).

    *known_devices* maps IP → device name for devices NetCheck knows about
    (Login to Routers) whose config may not be loaded.
    """
    dev = _Device(result)
    peer_devs = [_Device(p) for p in peers if p is not result and p.valid_xml]
    known = dict(known_devices or {})
    analysis = Analysis(device=dev.name)
    dhcp = AreaVerdict("DHCP")
    if dev.kind == "mikrotik":
        _dhcp_mikrotik(dev, dhcp, peer_devs, known)
    else:
        _dhcp_pfsense(dev, dhcp, peer_devs, known)
    analysis.areas.append(dhcp)
    wireless = AreaVerdict("Wireless")
    if dev.kind == "mikrotik":
        _wireless_mikrotik(dev, wireless, peer_devs, known)
    else:
        _wireless_pfsense(dev, wireless)
    analysis.areas.append(wireless)
    bandwidth = AreaVerdict("Bandwidth (estimate)")
    if dev.kind == "mikrotik":
        _bandwidth_mikrotik(dev, bandwidth, peer_devs, known)
    else:
        _bandwidth_pfsense(dev, bandwidth)
    analysis.areas.append(bandwidth)
    reach = AreaVerdict("Reachability")
    if dev.kind == "mikrotik":
        _reach_mikrotik(dev, reach, peer_devs, known)
    else:
        _reach_pfsense(dev, reach)
    analysis.areas.append(reach)
    return analysis


def findings_from(analysis: Analysis) -> list[Finding]:
    """Findings for the Findings list: failures, warnings, missing upstream."""
    out: list[Finding] = []
    for area in analysis.areas:
        for check in area.checks:
            if check.status not in (FAIL, WARN):
                continue
            out.append(
                Finding(
                    Severity.ERROR if check.status == FAIL else Severity.WARNING,
                    area.area,
                    f"{check.subject}: {check.message}",
                    remediation=check.remediation,
                )
            )
        for dep in area.missing:
            who = f" ({dep.known_as})" if dep.known_as else ""
            out.append(
                Finding(
                    Severity.WARNING,
                    area.area,
                    f"Analysis degraded: config for {dep.role} {dep.address}{who} is not loaded — "
                    f"cannot check {dep.needed_for}.",
                    remediation="Load that device's config (Login to Routers → Load Config).",
                )
            )
    return out


def report_text(analysis: Analysis) -> str:
    """Plain-text 'Will it work?' report (dashboard / export)."""
    lines = [f"Will it work? — {analysis.device}"]
    if analysis.degraded:
        lines.append(
            f"Assessment coverage {round(analysis.coverage * 100)} %: "
            f"{len(analysis.missing)} upstream config(s) missing — checking is degraded until they are loaded."
        )
        for dep in analysis.missing:
            who = f" — known as {dep.known_as}" if dep.known_as else ""
            lines.append(f"  • add config for {dep.role} {dep.address}{who} (needed for {dep.needed_for})")
    for area in analysis.areas:
        lines.append("")
        lines.append(f"{area.area}: {VERDICT_TEXT[area.status]}")
        marks = {PASS: "✓", WARN: "!", FAIL: "✗", INFO: "·"}
        for c in area.checks:
            lines.append(f"  {marks[c.status]} {c.subject}: {c.message}")
            if c.remediation and c.status in (FAIL, WARN):
                lines.append(f"      → {c.remediation}")
    return "\n".join(lines)


__all__: Sequence[str] = (
    "Analysis",
    "AreaVerdict",
    "Check",
    "Dependency",
    "analyse",
    "findings_from",
    "report_text",
)
