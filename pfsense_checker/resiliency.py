"""Cross-device resiliency analysis for Topology Builder sites.

Loads every topology-attached config into a SiteSnapshot, then correlates
physical links / VLANs / bridges / VPN / egress with parsed device inventories
to find end-to-end and single-failure issues.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pfsense_checker.checker import check_file
from pfsense_checker.models import CheckResult, Severity
from pfsense_checker.topology_site import CONFIG_SOURCE_MIKROTIK_REST, Device, SiteTopology


@dataclass
class ResiliencyFinding:
    severity: Severity
    category: str
    message: str
    devices: list[str] = field(default_factory=list)
    vlan: str = ""
    path: list[str] = field(default_factory=list)  # device names along an affected path
    evidence: str = ""
    impact: str = ""
    remediation: str = ""
    certainty: str = "known"  # known | unknown | likely

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "category": self.category,
            "message": self.message,
            "devices": list(self.devices),
            "vlan": self.vlan,
            "path": list(self.path),
            "evidence": self.evidence,
            "impact": self.impact,
            "remediation": self.remediation,
            "certainty": self.certainty,
        }


@dataclass
class DeviceSnapshot:
    device: Device
    result: CheckResult | None = None
    status: str = "missing"  # ok | missing | error | stale | backup-only
    error: str = ""

    @property
    def name(self) -> str:
        return self.device.name


@dataclass
class SiteSnapshot:
    site: SiteTopology
    devices: dict[str, DeviceSnapshot] = field(default_factory=dict)
    analyzed_at: str = ""
    incomplete: bool = False

    def result_for(self, name: str) -> CheckResult | None:
        snap = self.devices.get(name)
        return snap.result if snap else None


@dataclass
class ResiliencyReport:
    findings: list[ResiliencyFinding] = field(default_factory=list)
    snapshot: SiteSnapshot | None = None
    summary: dict[str, Any] = field(default_factory=dict)
    # Optional Ollama narratives keyed by deep-dive category (Loops, RST, …).
    deep_dive_notes: dict[str, str] = field(default_factory=dict)

    @property
    def error_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.INFO)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "incomplete": bool(self.snapshot and self.snapshot.incomplete),
            "deep_dive_notes": dict(self.deep_dive_notes),
        }


# Deep-dive sections shown in the Resiliency UI (false positives OK).
DEEP_DIVE_CATEGORIES: tuple[str, ...] = (
    "Loops",
    "RST",
    "Unbound",
    "NAT",
    "Firewall",
)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_site_snapshot(site: SiteTopology) -> SiteSnapshot:
    """Parse every attached analyzable config into a SiteSnapshot."""
    snap = SiteSnapshot(site=site, analyzed_at=_now())
    for dev in site.devices:
        src = dev.ensure_config_source()
        ds = DeviceSnapshot(device=dev)
        if src is None or (not src.path and not src.backup_artifact):
            ds.status = "missing"
            ds.error = "No config attached"
            snap.devices[dev.name] = ds
            continue
        if src.backup_artifact and not src.path:
            ds.status = "backup-only"
            ds.error = (
                "Binary .backup attached; collect a live RouterOS REST export to analyze"
            )
            snap.incomplete = True
            snap.devices[dev.name] = ds
            continue
        path = Path(src.path)
        if not path.is_file():
            ds.status = "error"
            ds.error = f"Config file not found: {path}"
            snap.incomplete = True
            snap.devices[dev.name] = ds
            continue
        try:
            result = check_file(path)
            result.device_name = dev.name
            result.collected_at = src.last_collected_at or ""
            if src.last_status == "error":
                result.source_status = "stale"
                ds.status = "stale"
                snap.incomplete = True
            elif src.source_type == CONFIG_SOURCE_MIKROTIK_REST and not src.last_collected_at:
                result.source_status = "unknown"
                ds.status = "ok"
            else:
                result.source_status = src.last_status or "ok"
                ds.status = "ok" if result.valid_xml else "error"
            ds.result = result
            if not result.valid_xml:
                ds.status = "error"
                ds.error = "Parse failed"
                snap.incomplete = True
        except Exception as exc:  # noqa: BLE001
            ds.status = "error"
            ds.error = str(exc)
            snap.incomplete = True
        snap.devices[dev.name] = ds
    return snap


def analyze_site(site: SiteTopology, *, snapshot: SiteSnapshot | None = None) -> ResiliencyReport:
    """Run layered resiliency checks against a site + attached configs."""
    snap = snapshot or load_site_snapshot(site)
    findings: list[ResiliencyFinding] = []

    findings.extend(_check_source_health(snap))
    findings.extend(_check_l1_l2(snap))
    findings.extend(_check_l3_dhcp(snap))
    findings.extend(_check_firewall_nat_vpn(snap))
    findings.extend(_check_resilience(snap))
    findings.extend(_check_consistency(snap))
    findings.extend(_check_wireless(snap))
    # Deep-dive sections (aggressive heuristics; false positives OK).
    findings.extend(_check_loops(snap))
    findings.extend(_check_rst(snap))
    findings.extend(_check_unbound(snap))
    findings.extend(_check_nat_deep(snap))
    findings.extend(_check_firewall_deep(snap))

    # Structural site issues (kept separate category)
    for msg in site.validate():
        findings.append(
            ResiliencyFinding(
                severity=Severity.WARNING,
                category="Topology",
                message=msg,
                impact="Site map may be incomplete or inconsistent",
                remediation="Fix the Topology Builder entry that this message refers to",
            )
        )

    report = ResiliencyReport(findings=findings, snapshot=snap)
    report.summary = {
        "devices": len(site.devices),
        "with_config": sum(
            1 for d in snap.devices.values() if d.status in ("ok", "stale")
        ),
        "missing_config": sum(1 for d in snap.devices.values() if d.status == "missing"),
        "errors": report.error_count,
        "warnings": report.warning_count,
        "info": report.info_count,
        "incomplete": snap.incomplete,
        "analyzed_at": snap.analyzed_at,
    }
    return report


# --------------------------------------------------------------------------- #
# Source health
# --------------------------------------------------------------------------- #

def _check_source_health(snap: SiteSnapshot) -> list[ResiliencyFinding]:
    out: list[ResiliencyFinding] = []
    host_map: dict[str, list[str]] = {}
    for name, ds in snap.devices.items():
        if ds.status == "missing":
            # Only flag network roles that normally have configs
            role = (ds.device.role or ds.device.kind or "").lower()
            if any(
                k in role
                for k in (
                    "firewall",
                    "router",
                    "mikrotik",
                    "pfsense",
                    "opnsense",
                    "egress",
                    "core-switch",
                    "juniper",
                    "ubiquiti",
                )
            ) or ds.device.kind in ("pfsense", "opnsense", "mikrotik", "juniper", "ubiquiti"):
                out.append(
                    ResiliencyFinding(
                        severity=Severity.WARNING,
                        category="Source",
                        message=f"{name} has no attached analyzable config",
                        devices=[name],
                        impact="Cross-device checks cannot include this device",
                        remediation="Attach a pfSense XML, MikroTik .rsc, or collect via REST",
                    )
                )
        elif ds.status == "backup-only":
            out.append(
                ResiliencyFinding(
                    severity=Severity.WARNING,
                    category="Source",
                    message=(
                        f"{name}: .backup is restore evidence only — "
                        "live REST export required for analysis"
                    ),
                    devices=[name],
                    evidence=ds.device.config_source.backup_artifact
                    if ds.device.config_source
                    else "",
                    impact="Device excluded from path/DHCP/firewall correlation",
                    remediation="Configure REST endpoint/credentials and Collect export",
                )
            )
        elif ds.status == "error":
            out.append(
                ResiliencyFinding(
                    severity=Severity.ERROR,
                    category="Source",
                    message=f"{name}: failed to load config — {ds.error}",
                    devices=[name],
                    impact="Analysis is incomplete for this device",
                    remediation="Fix the config path or re-collect the REST export",
                )
            )
        elif ds.status == "stale":
            out.append(
                ResiliencyFinding(
                    severity=Severity.WARNING,
                    category="Source",
                    message=f"{name}: using stale/last-known export after a collection error",
                    devices=[name],
                    evidence=ds.error or (
                        ds.device.config_source.last_error
                        if ds.device.config_source
                        else ""
                    ),
                    impact="Findings may not reflect the live router",
                    remediation="Re-run Collect for this device",
                    certainty="unknown",
                )
            )
        if ds.result and ds.result.hostname:
            host_map.setdefault(ds.result.hostname.lower(), []).append(name)

    for host, names in host_map.items():
        if len(names) > 1:
            out.append(
                ResiliencyFinding(
                    severity=Severity.WARNING,
                    category="Source",
                    message=f"Hostname '{host}' appears on multiple devices: {', '.join(names)}",
                    devices=names,
                    impact="Auto-matching and correlation may attach the wrong config",
                    remediation="Rename devices or attach configs explicitly",
                )
            )
    return out


# --------------------------------------------------------------------------- #
# L1 / L2
# --------------------------------------------------------------------------- #

def _iface_names(result: CheckResult) -> set[str]:
    names: set[str] = set()
    for i in result.interfaces:
        if i.name:
            names.add(i.name.lower())
        if i.device:
            names.add(i.device.lower())
    for v in result.vlans:
        if v.vlanif:
            names.add(v.vlanif.lower())
    for b in result.bridges:
        if b.bridgeif:
            names.add(b.bridgeif.lower())
        for m in b.members:
            names.add(m.lower())
    for lg in result.laggs:
        if lg.laggif:
            names.add(lg.laggif.lower())
        for m in lg.members:
            names.add(m.lower())
    return names


def _vlan_tags(result: CheckResult) -> set[str]:
    tags = {v.tag for v in result.vlans if v.tag}
    # MikroTik bridge VLAN table entries count as carrying the VLAN at L2
    for row in result.summary.get("bridge_vlans", []) or []:
        for vid in str(row.get("vlan_ids", "")).split(","):
            if vid.strip():
                tags.add(vid.strip())
    return tags


def _check_l1_l2(snap: SiteSnapshot) -> list[ResiliencyFinding]:
    out: list[ResiliencyFinding] = []
    site = snap.site

    for i, link in enumerate(site.links):
        for side, port in (
            (link.a_device, link.a_port),
            (link.b_device, link.b_port),
        ):
            if not side or not port:
                continue
            ds = snap.devices.get(side)
            if not ds or not ds.result:
                continue
            names = _iface_names(ds.result)
            # Also accept declared topology ports when config has no matching name
            declared = {p.lower() for p in ds.device.ports}
            if port.lower() not in names and port.lower() not in declared:
                out.append(
                    ResiliencyFinding(
                        severity=Severity.WARNING,
                        category="L1/L2",
                        message=(
                            f"Link {i + 1}: port {side}:{port} not found in "
                            f"attached config or device port list"
                        ),
                        devices=[side],
                        path=[link.a_device, link.b_device],
                        evidence=f"config interfaces={sorted(names)[:12]}",
                        impact="Cable endpoint may be wrong or config incomplete",
                        remediation="Correct the link port or enrich the device from config",
                        certainty="likely",
                    )
                )
            else:
                # Disabled interface?
                for iface in ds.result.interfaces:
                    if iface.name.lower() == port.lower() or iface.device.lower() == port.lower():
                        if not iface.enabled:
                            out.append(
                                ResiliencyFinding(
                                    severity=Severity.ERROR,
                                    category="L1/L2",
                                    message=f"{side}:{port} is DISABLED but used by a site link",
                                    devices=[side],
                                    path=[link.a_device, link.b_device],
                                    impact="Link will not carry traffic",
                                    remediation=f"Enable {port} on {side} or rewire the link",
                                )
                            )

        # VLAN continuity on trunks
        if link.kind in ("trunk", "access", "copper", "fiber", "sfp", "lag") and (
            link.vlans or link.native_vlan
        ):
            for side in (link.a_device, link.b_device):
                ds = snap.devices.get(side)
                if not ds or not ds.result:
                    continue
                tags = _vlan_tags(ds.result)
                if not tags:
                    continue  # switches without VLAN inventory — skip
                missing = [v for v in link.vlans if v not in tags]
                if missing and ds.device.kind in (
                    "mikrotik",
                    "pfsense",
                    "opnsense",
                    "juniper",
                    "ubiquiti",
                ):
                    out.append(
                        ResiliencyFinding(
                            severity=Severity.WARNING,
                            category="L1/L2",
                            message=(
                                f"{side} config lacks VLAN(s) {', '.join(missing)} "
                                f"declared on link to "
                                f"{link.b_device if side == link.a_device else link.a_device}"
                            ),
                            devices=[side],
                            vlan=",".join(missing),
                            path=[link.a_device, link.b_device],
                            impact="Tagged frames may be dropped at this hop",
                            remediation="Add matching VLAN interfaces or bridge VLANs on the device",
                            certainty="likely",
                        )
                    )

    # Native VLAN disagreement between adjacent trunk ends sharing the same VLAN set
    for link in site.links:
        if link.kind != "trunk":
            continue
        # Compare against site VLAN native expectations only when both ends have configs
        # with VLAN defs — native is a link property; flag empty native on trunk
        if link.vlans and not link.native_vlan:
            out.append(
                ResiliencyFinding(
                    severity=Severity.INFO,
                    category="L1/L2",
                    message=(
                        f"Trunk {link.a_device}↔{link.b_device} has tagged VLANs "
                        "but no native/PVID set"
                    ),
                    devices=[link.a_device, link.b_device],
                    path=[link.a_device, link.b_device],
                    impact="Untagged frames may land on an unexpected VLAN",
                    remediation="Set native_vlan on the trunk link",
                )
            )

    # Bridge / LAGG membership notes
    for name, ds in snap.devices.items():
        if not ds.result:
            continue
        for lg in ds.result.laggs:
            if len(lg.members) < 2:
                out.append(
                    ResiliencyFinding(
                        severity=Severity.WARNING,
                        category="L1/L2",
                        message=f"{name}: LAGG/bond {lg.laggif} has fewer than 2 members",
                        devices=[name],
                        evidence=f"members={lg.members}",
                        impact="No link aggregation redundancy",
                        remediation="Add a second member port or remove the unused bond",
                    )
                )
    return out


# --------------------------------------------------------------------------- #
# L3 / DHCP
# --------------------------------------------------------------------------- #

def _parse_network(ip: str, cidr: str) -> ipaddress._BaseNetwork | None:
    if not ip or ip.lower() in {"dhcp", "pppoe", "pptp", "l2tp", "dhcp6"}:
        return None
    try:
        if "/" in ip:
            return ipaddress.ip_network(ip, strict=False)
        if cidr:
            return ipaddress.ip_network(f"{ip}/{cidr}", strict=False)
        return None
    except ValueError:
        return None


def _iface_networks(result: CheckResult) -> list[tuple[str, ipaddress._BaseNetwork]]:
    nets: list[tuple[str, ipaddress._BaseNetwork]] = []
    for iface in result.interfaces:
        net = _parse_network(iface.ipaddr, iface.subnet)
        if net:
            nets.append((iface.name, net))
    return nets


def _check_l3_dhcp(snap: SiteSnapshot) -> list[ResiliencyFinding]:
    out: list[ResiliencyFinding] = []
    # Collect all interface networks across devices
    all_nets: list[tuple[str, str, ipaddress._BaseNetwork]] = []
    for name, ds in snap.devices.items():
        if not ds.result:
            continue
        for ifname, net in _iface_networks(ds.result):
            all_nets.append((name, ifname, net))

    # Duplicate / overlapping identical networks on different devices (OK if intentional
    # for point-to-point; flag same subnet with different hosts as INFO/WARN)
    by_net: dict[str, list[tuple[str, str]]] = {}
    for name, ifname, net in all_nets:
        by_net.setdefault(str(net), []).append((name, ifname))
    for net_s, owners in by_net.items():
        devices = sorted({o[0] for o in owners})
        if len(devices) > 1:
            # Same L3 subnet claimed by multiple routers — may be OK for CARP/VRRP
            out.append(
                ResiliencyFinding(
                    severity=Severity.INFO,
                    category="L3/DHCP",
                    message=f"Subnet {net_s} configured on multiple devices: {', '.join(devices)}",
                    devices=devices,
                    evidence="; ".join(f"{d}:{i}" for d, i in owners),
                    impact="Confirm this is intentional (HA/VIP) and not a clash",
                    remediation="Use CARP/VRRP or unique subnets per device",
                    certainty="unknown",
                )
            )

    # Overlapping but non-equal networks
    for i in range(len(all_nets)):
        for j in range(i + 1, len(all_nets)):
            n1, i1, net1 = all_nets[i]
            n2, i2, net2 = all_nets[j]
            if n1 == n2:
                continue
            if net1.version != net2.version:
                continue
            if net1.overlaps(net2) and net1 != net2:
                out.append(
                    ResiliencyFinding(
                        severity=Severity.ERROR,
                        category="L3/DHCP",
                        message=(
                            f"Overlapping subnets: {n1}:{i1} ({net1}) overlaps "
                            f"{n2}:{i2} ({net2})"
                        ),
                        devices=[n1, n2],
                        impact="Routing ambiguity / asymmetric reachability",
                        remediation="Resize or renumber one of the overlapping prefixes",
                    )
                )

    # Connected-subnet check across links: if both ends have IPs, they should share a subnet
    for link in snap.site.links:
        a = snap.result_for(link.a_device)
        b = snap.result_for(link.b_device)
        if not a or not b or not link.a_port or not link.b_port:
            continue
        a_nets = [
            net
            for name, net in _iface_networks(a)
            if name.lower() == link.a_port.lower()
        ]
        b_nets = [
            net
            for name, net in _iface_networks(b)
            if name.lower() == link.b_port.lower()
        ]
        if a_nets and b_nets:
            if not any(an.overlaps(bn) for an in a_nets for bn in b_nets):
                out.append(
                    ResiliencyFinding(
                        severity=Severity.ERROR,
                        category="L3/DHCP",
                        message=(
                            f"Link {link.a_device}:{link.a_port} ↔ "
                            f"{link.b_device}:{link.b_port} has incompatible addresses"
                        ),
                        devices=[link.a_device, link.b_device],
                        path=[link.a_device, link.b_device],
                        evidence=f"{a_nets} vs {b_nets}",
                        impact="Direct L3 adjacency will not work",
                        remediation="Put both sides in the same subnet or use L2-only ports",
                    )
                )

    # Default route / gateway presence on firewalls/egress
    for name, ds in snap.devices.items():
        if not ds.result:
            continue
        role = (ds.device.role or "").lower()
        if role not in ("firewall", "egress", "router") and ds.device.kind not in (
            "pfsense",
            "opnsense",
        ):
            continue
        defaults = [
            g
            for g in ds.result.gateways
            if g.get("default") == "yes" and g.get("disabled") != "yes"
        ]
        route_defaults = [
            r
            for r in ds.result.static_routes
            if r.get("network") in ("0.0.0.0/0", "::/0", "default")
            and r.get("disabled") != "yes"
        ]
        if not defaults and not route_defaults:
            out.append(
                ResiliencyFinding(
                    severity=Severity.WARNING,
                    category="L3/DHCP",
                    message=f"{name}: no default gateway / default route found",
                    devices=[name],
                    impact="Device may not reach the Internet / upstream",
                    remediation="Configure a default gateway or static 0.0.0.0/0 route",
                )
            )

    # DHCP scopes
    dhcp_by_net: dict[str, list[str]] = {}
    for name, ds in snap.devices.items():
        if not ds.result:
            continue
        for scope in ds.result.dhcp_scopes:
            if scope.get("enabled") == "no":
                continue
            network = scope.get("network") or ""
            iface = scope.get("interface") or ""
            # Validate pool inside interface subnet when possible
            from_ip, to_ip = scope.get("from", ""), scope.get("to", "")
            iface_net = None
            for ifname, net in _iface_networks(ds.result):
                if ifname.lower() == iface.lower():
                    iface_net = net
                    break
            if iface_net and from_ip and to_ip:
                try:
                    a = ipaddress.ip_address(from_ip)
                    b = ipaddress.ip_address(to_ip)
                    if a not in iface_net or b not in iface_net:
                        out.append(
                            ResiliencyFinding(
                                severity=Severity.ERROR,
                                category="L3/DHCP",
                                message=(
                                    f"{name}: DHCP pool {from_ip}-{to_ip} is outside "
                                    f"interface {iface} subnet {iface_net}"
                                ),
                                devices=[name],
                                evidence=f"interface={iface}",
                                impact="Clients may receive unusable leases",
                                remediation="Move the pool inside the interface subnet",
                            )
                        )
                except ValueError:
                    pass
            key = network or f"{name}:{iface}"
            dhcp_by_net.setdefault(key, []).append(name)

    for key, owners in dhcp_by_net.items():
        if len(set(owners)) > 1:
            out.append(
                ResiliencyFinding(
                    severity=Severity.WARNING,
                    category="L3/DHCP",
                    message=f"Multiple active DHCP servers for '{key}': {', '.join(sorted(set(owners)))}",
                    devices=sorted(set(owners)),
                    impact="Clients may get conflicting leases",
                    remediation="Keep a single authoritative DHCP server (or coordinated HA)",
                )
            )

    # Site VLAN subnet vs device gateway
    for vlan in snap.site.vlans:
        if not vlan.subnet or not vlan.gateway:
            continue
        try:
            vnet = ipaddress.ip_network(vlan.subnet, strict=False)
        except ValueError:
            continue
        gw_dev = snap.site.device(vlan.gateway)
        if gw_dev is None:
            # gateway may be an IP
            continue
        ds = snap.devices.get(gw_dev.name)
        if not ds or not ds.result:
            continue
        nets = _iface_networks(ds.result)
        if nets and not any(vnet.overlaps(n) or n.subnet_of(vnet) or vnet.subnet_of(n) for _, n in nets):
            # Also accept exact network match via site s_ip
            out.append(
                ResiliencyFinding(
                    severity=Severity.WARNING,
                    category="L3/DHCP",
                    message=(
                        f"VLAN {vlan.id} ({vlan.subnet}) gateway device '{gw_dev.name}' "
                        "has no overlapping interface address in its config"
                    ),
                    devices=[gw_dev.name],
                    vlan=vlan.id,
                    impact="Clients on this VLAN may have no working gateway",
                    remediation="Assign the VLAN interface/IP on the gateway device",
                    certainty="likely",
                )
            )
    return out


# --------------------------------------------------------------------------- #
# Firewall / NAT / VPN
# --------------------------------------------------------------------------- #

def _check_firewall_nat_vpn(snap: SiteSnapshot) -> list[ResiliencyFinding]:
    out: list[ResiliencyFinding] = []
    for name, ds in snap.devices.items():
        if not ds.result:
            continue
        role = (ds.device.role or "").lower()
        is_edge = role in ("firewall", "egress", "router") or ds.device.kind in (
            "pfsense",
            "opnsense",
            "mikrotik",
        )
        if is_edge and not ds.result.filter_rules:
            out.append(
                ResiliencyFinding(
                    severity=Severity.WARNING,
                    category="Firewall/NAT",
                    message=f"{name}: no filter rules present",
                    devices=[name],
                    impact="Device may be wide open or locked down unpredictably",
                    remediation="Add an explicit default-deny with required allow rules",
                    certainty="unknown",
                )
            )
        if is_edge and role in ("firewall", "egress") and not ds.result.nat_rules:
            # Only warn if device has a WAN-like interface
            has_wan = any(
                i.name.lower() in ("wan", "pppoe", "lte")
                or "wan" in (i.descr or "").lower()
                for i in ds.result.interfaces
            )
            if has_wan:
                out.append(
                    ResiliencyFinding(
                        severity=Severity.INFO,
                        category="Firewall/NAT",
                        message=f"{name}: WAN-like interface present but no NAT rules found",
                        devices=[name],
                        impact="Outbound Internet may fail without NAT or public addressing",
                        remediation="Confirm NAT outbound / masquerade if using private RFC1918 WANs",
                        certainty="unknown",
                    )
                )

    # Site VPN agreements vs device VPN endpoints
    for vpn in snap.site.vpn:
        for side in (vpn.a_device, vpn.b_device):
            if not side:
                continue
            ds = snap.devices.get(side)
            if not ds or not ds.result:
                continue
            if not ds.result.vpn:
                out.append(
                    ResiliencyFinding(
                        severity=Severity.WARNING,
                        category="VPN",
                        message=(
                            f"Site VPN '{vpn.name}' lists {side}, but that device's "
                            "config has no VPN endpoints"
                        ),
                        devices=[side],
                        path=[vpn.a_device, vpn.b_device],
                        impact="Declared VPN path may not be configured",
                        remediation="Configure the tunnel on the device or remove the site VPN entry",
                        certainty="likely",
                    )
                )
            else:
                # Peer matching when both sides known
                peers = { (v.peer or "").lower() for v in ds.result.vpn if v.peer }
                other = vpn.b_device if side == vpn.a_device else vpn.a_device
                other_ds = snap.devices.get(other) if other else None
                if other_ds and other_ds.result:
                    other_ips = set()
                    for iface in other_ds.result.interfaces:
                        if iface.ipaddr and iface.ipaddr.lower() not in {
                            "dhcp",
                            "pppoe",
                        }:
                            other_ips.add(iface.ipaddr.lower())
                    if peers and other_ips and peers.isdisjoint(other_ips):
                        # Also compare hostname — soft
                        out.append(
                            ResiliencyFinding(
                                severity=Severity.INFO,
                                category="VPN",
                                message=(
                                    f"VPN on {side}: configured peers {sorted(peers)} "
                                    f"do not obviously match {other} interface IPs "
                                    f"{sorted(other_ips)}"
                                ),
                                devices=[side, other],
                                path=[vpn.a_device, vpn.b_device],
                                impact="Tunnel may fail to establish",
                                remediation="Align peer addresses with the remote WAN/public IP",
                                certainty="unknown",
                            )
                        )

        # Routed networks declared on site VPN but missing from device routes
        for net in vpn.networks:
            for side in (vpn.a_device, vpn.b_device):
                if not side:
                    continue
                ds = snap.devices.get(side)
                if not ds or not ds.result:
                    continue
                route_nets = {
                    (r.get("network") or "").strip() for r in ds.result.static_routes
                }
                vpn_nets = set()
                for v in ds.result.vpn:
                    vpn_nets.update(v.networks)
                if net and net not in route_nets and net not in vpn_nets:
                    out.append(
                        ResiliencyFinding(
                            severity=Severity.WARNING,
                            category="VPN",
                            message=(
                                f"{side}: site VPN '{vpn.name}' includes network {net}, "
                                "but it is not present in routes or VPN selectors"
                            ),
                            devices=[side],
                            evidence=f"vpn={vpn.name}",
                            impact="Traffic to that network may not traverse the tunnel",
                            remediation="Add a route or VPN network selector for that prefix",
                            certainty="likely",
                        )
                    )
    return out


# --------------------------------------------------------------------------- #
# Resilience / SPOF
# --------------------------------------------------------------------------- #

def _adjacency(site: SiteTopology) -> dict[str, set[str]]:
    adj: dict[str, set[str]] = {d.name: set() for d in site.devices}
    for link in site.links:
        if link.a_device and link.b_device:
            adj.setdefault(link.a_device, set()).add(link.b_device)
            adj.setdefault(link.b_device, set()).add(link.a_device)
    for vpn in site.vpn:
        if vpn.a_device and vpn.b_device:
            adj.setdefault(vpn.a_device, set()).add(vpn.b_device)
            adj.setdefault(vpn.b_device, set()).add(vpn.a_device)
    return adj


def _reachable(adj: dict[str, set[str]], start: str, blocked: set[str] | None = None) -> set[str]:
    blocked = blocked or set()
    if start in blocked:
        return set()
    seen = {start}
    stack = [start]
    while stack:
        cur = stack.pop()
        for nxt in adj.get(cur, ()):
            if nxt in seen or nxt in blocked:
                continue
            seen.add(nxt)
            stack.append(nxt)
    return seen


def _check_resilience(snap: SiteSnapshot) -> list[ResiliencyFinding]:
    out: list[ResiliencyFinding] = []
    site = snap.site
    if len(site.devices) < 2:
        return out

    adj = _adjacency(site)
    egress_devices = [
        e.device for e in site.egress if e.device
    ] or [
        d.name
        for d in site.devices
        if (d.role or "").lower() in ("egress", "firewall")
        or d.kind in ("pfsense", "opnsense")
    ]
    access = [
        d.name
        for d in site.devices
        if (d.role or "").lower() in ("access-switch", "workstation", "desktop", "sff", "host")
        or d.kind in ("workstation", "desktop", "sff", "host")
    ]
    # Fallback: treat leaf-ish devices (degree 1) as access
    if not access:
        access = [n for n, peers in adj.items() if len(peers) == 1]

    # Single points of failure: device whose removal disconnects access from egress
    for candidate in list(adj.keys()):
        if candidate in egress_devices and len(egress_devices) == 1:
            out.append(
                ResiliencyFinding(
                    severity=Severity.WARNING,
                    category="Resilience",
                    message=f"Single egress/firewall device: {candidate}",
                    devices=[candidate],
                    impact="Site Internet/VPN egress fails if this device is down",
                    remediation="Add a backup egress path with independent upstream",
                )
            )
            continue
        blocked = {candidate}
        for src in access:
            if src == candidate:
                continue
            reach = _reachable(adj, src, blocked)
            if egress_devices and not any(e in reach for e in egress_devices if e != candidate):
                # Only report if without failure they could reach
                if any(e in _reachable(adj, src) for e in egress_devices):
                    out.append(
                        ResiliencyFinding(
                            severity=Severity.ERROR,
                            category="Resilience",
                            message=(
                                f"Single point of failure: losing {candidate} isolates "
                                f"{src} from egress"
                            ),
                            devices=[candidate, src],
                            path=[src, candidate],
                            impact="No alternate physical/VPN path to Internet egress",
                            remediation="Add a redundant uplink or secondary core path",
                        )
                    )
                    break

    # Link cut: each physical link removal
    for link in site.links:
        # Build adj without this link
        adj2: dict[str, set[str]] = {d.name: set() for d in site.devices}
        for other in site.links:
            if other is link:
                continue
            if other.a_device and other.b_device:
                adj2[other.a_device].add(other.b_device)
                adj2[other.b_device].add(other.a_device)
        for vpn in site.vpn:
            if vpn.a_device and vpn.b_device:
                adj2.setdefault(vpn.a_device, set()).add(vpn.b_device)
                adj2.setdefault(vpn.b_device, set()).add(vpn.a_device)
        for src in access:
            if not egress_devices:
                break
            before = any(e in _reachable(adj, src) for e in egress_devices)
            after = any(e in _reachable(adj2, src) for e in egress_devices)
            if before and not after:
                out.append(
                    ResiliencyFinding(
                        severity=Severity.ERROR,
                        category="Resilience",
                        message=(
                            f"Critical link {link.a_device}:{link.a_port or '?'} ↔ "
                            f"{link.b_device}:{link.b_port or '?'} — cutting it isolates {src}"
                        ),
                        devices=[link.a_device, link.b_device, src],
                        path=[link.a_device, link.b_device],
                        impact="No redundant path for this access device",
                        remediation="Add a parallel trunk or secondary uplink",
                    )
                )
                break

    # Shared upstream among multiple egress paths
    if len(site.egress) >= 2:
        upstreams = [e.upstream for e in site.egress if e.upstream]
        if len(upstreams) >= 2 and len(set(upstreams)) == 1:
            out.append(
                ResiliencyFinding(
                    severity=Severity.WARNING,
                    category="Resilience",
                    message=(
                        f"All egress paths share upstream '{upstreams[0]}' — "
                        "not an independent failure domain"
                    ),
                    devices=[e.device for e in site.egress if e.device],
                    impact="ISP/upstream outage takes down every WAN path",
                    remediation="Use diverse upstream providers or circuits where possible",
                )
            )

    # Priority-tagged devices without a lower-priority peer
    by_role: dict[str, list[Device]] = {}
    for d in site.devices:
        if d.priority != "":
            by_role.setdefault((d.role or d.kind or "device").lower(), []).append(d)
    for role, group in by_role.items():
        if len(group) == 1 and group[0].priority in ("0", "1"):
            out.append(
                ResiliencyFinding(
                    severity=Severity.INFO,
                    category="Resilience",
                    message=(
                        f"{group[0].name} is marked priority={group[0].priority} "
                        f"for role '{role}' but has no peer with another priority"
                    ),
                    devices=[group[0].name],
                    impact="Failover priority is unused without a standby device",
                    remediation="Add a reserve/backup device or clear the priority field",
                )
            )
    return out


# --------------------------------------------------------------------------- #
# Cross-device consistency / anomaly detection
# --------------------------------------------------------------------------- #

_VL_COMMENT_RE = re.compile(r"\bVL(\d{1,4})\b", re.I)


def _vl_in_comment(comment: str) -> str:
    """Extract a 'VL<id>' tag from a port comment, e.g. 'KVM1 (VL646)' -> 646."""
    m = _VL_COMMENT_RE.search(comment or "")
    return m.group(1) if m else ""


def _check_consistency(snap: SiteSnapshot) -> list[ResiliencyFinding]:
    """Detailed anomaly detection across every device with a parsed config."""
    out: list[ResiliencyFinding] = []
    loaded = {n: ds for n, ds in snap.devices.items() if ds.result}
    if len(loaded) < 2:
        return out

    # ---- Duplicate interface IPs (true address clash) ----
    ip_owners: dict[str, list[str]] = {}
    for name, ds in loaded.items():
        for iface in ds.result.interfaces:
            ip = (iface.ipaddr or "").strip().lower()
            if ip and ip not in ("dhcp", "pppoe", "pptp", "l2tp"):
                ip_owners.setdefault(ip, []).append(f"{name}:{iface.name}")
    for ip, owners in sorted(ip_owners.items()):
        devs = sorted({o.split(":", 1)[0] for o in owners})
        if len(devs) > 1:
            out.append(
                ResiliencyFinding(
                    severity=Severity.ERROR,
                    category="Anomaly",
                    message=f"Duplicate IP address {ip} on: {', '.join(owners)}",
                    devices=devs,
                    impact="Address conflict — ARP flapping and unreachable hosts",
                    remediation="Renumber one of the interfaces (unless CARP/VRRP VIP)",
                )
            )

    # ---- VLAN name drift: same VLAN id, different names across devices ----
    auto_name = re.compile(r"^\S+\.\d+$")  # pfSense-style parent.tag — not drift
    vlan_names: dict[str, dict[str, set[str]]] = {}
    for name, ds in loaded.items():
        for v in ds.result.vlans:
            if v.tag:
                label = v.vlanif or v.descr
                if label and not auto_name.match(label):
                    vlan_names.setdefault(v.tag, {}).setdefault(label, set()).add(name)
    for tag, names in sorted(vlan_names.items()):
        if len(names) > 1:
            detail = "; ".join(
                f"'{label}' on {', '.join(sorted(devs))}" for label, devs in sorted(names.items())
            )
            out.append(
                ResiliencyFinding(
                    severity=Severity.WARNING,
                    category="Anomaly",
                    message=f"VLAN {tag} is named inconsistently across devices",
                    devices=sorted({d for devs in names.values() for d in devs}),
                    vlan=tag,
                    evidence=detail,
                    impact="Naming drift hides configuration mistakes during changes",
                    remediation="Adopt one interface-naming convention for this VLAN",
                )
            )

    # ---- VLAN coverage: id carried by most devices but missing on some ----
    vlan_carriers: dict[str, set[str]] = {}
    switchy = {
        n
        for n, ds in loaded.items()
        if ds.result.vlans or ds.device.kind in ("mikrotik", "switch")
    }
    for name, ds in loaded.items():
        for v in ds.result.vlans:
            if v.tag:
                vlan_carriers.setdefault(v.tag, set()).add(name)
        for row in ds.result.summary.get("bridge_vlans", []) or []:
            for vid in str(row.get("vlan_ids", "")).split(","):
                if vid.strip():
                    vlan_carriers.setdefault(vid.strip(), set()).add(name)
    for tag, carriers in sorted(vlan_carriers.items()):
        missing = sorted(switchy - carriers)
        if carriers and missing and len(carriers) >= max(2, len(switchy) - 1):
            out.append(
                ResiliencyFinding(
                    severity=Severity.WARNING,
                    category="Anomaly",
                    message=(
                        f"VLAN {tag} exists on {', '.join(sorted(carriers))} "
                        f"but not on {', '.join(missing)}"
                    ),
                    devices=missing,
                    vlan=tag,
                    impact="Tagged traffic for this VLAN dies at the missing device",
                    remediation="Add the VLAN (or confirm it is intentionally absent)",
                    certainty="likely",
                )
            )

    # ---- Bridge-port PVID vs port-comment VL tag (MikroTik) ----
    for name, ds in loaded.items():
        iface_comment = {
            i.name.lower(): i.descr for i in ds.result.interfaces if i.descr
        }
        for row in ds.result.summary.get("bridge_ports", []) or []:
            port = str(row.get("interface", ""))
            pvid = str(row.get("pvid", "")).strip()
            comment = str(row.get("comment", "")) or iface_comment.get(port.lower(), "")
            tagged_vl = _vl_in_comment(comment)
            if pvid and tagged_vl and pvid != tagged_vl:
                out.append(
                    ResiliencyFinding(
                        severity=Severity.WARNING,
                        category="Anomaly",
                        message=(
                            f"{name}:{port} comment says VL{tagged_vl} "
                            f"but bridge PVID is {pvid}"
                        ),
                        devices=[name],
                        vlan=pvid,
                        evidence=f"comment='{comment.strip()}' pvid={pvid}",
                        impact="Untagged device is on a different VLAN than documented",
                        remediation="Fix the PVID or update the port comment",
                    )
                )

    # ---- DNS server consistency ----
    dns_sets: dict[str, tuple[str, ...]] = {}
    for name, ds in loaded.items():
        servers = tuple(sorted(ds.result.dns.get("servers", []) or []))
        if servers:
            dns_sets[name] = servers
    if len(set(dns_sets.values())) > 1:
        detail = "; ".join(f"{n}={', '.join(v)}" for n, v in sorted(dns_sets.items()))
        out.append(
            ResiliencyFinding(
                severity=Severity.INFO,
                category="Consistency",
                message="Devices use different DNS server sets",
                devices=sorted(dns_sets),
                evidence=detail,
                impact="Inconsistent resolution / split-horizon surprises",
                remediation="Standardise resolvers (or document per-device intent)",
                certainty="unknown",
            )
        )

    # ---- DNS/NTP/gateway targets should live on a known site subnet ----
    site_nets: list[ipaddress._BaseNetwork] = []
    owned_ips: set[str] = set()
    for name, ds in loaded.items():
        for _ifname, net in _iface_networks(ds.result):
            site_nets.append(net)
        for iface in ds.result.interfaces:
            ip = (iface.ipaddr or "").strip()
            if ip and ip.lower() not in ("dhcp", "pppoe"):
                owned_ips.add(ip)

    def _on_site(ip_s: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_s)
        except ValueError:
            return False
        return any(ip in net for net in site_nets)

    for name, ds in loaded.items():
        for server in ds.result.dns.get("servers", []) or []:
            try:
                ip = ipaddress.ip_address(server)
            except ValueError:
                continue
            if ip.is_private and not _on_site(server) and server not in owned_ips:
                out.append(
                    ResiliencyFinding(
                        severity=Severity.WARNING,
                        category="Anomaly",
                        message=(
                            f"{name}: DNS server {server} is private but not on any "
                            "known site subnet"
                        ),
                        devices=[name],
                        evidence=f"site subnets={sorted(str(n) for n in set(site_nets))[:10]}",
                        impact="Lookups may time out (stale resolver from an old design?)",
                        remediation="Point DNS at a reachable resolver",
                        certainty="likely",
                    )
                )

    # ---- Default gateway must be owned by a site device ----
    for name, ds in loaded.items():
        for gw in ds.result.gateways:
            if gw.get("default") != "yes" or gw.get("disabled") == "yes":
                continue
            gw_ip = (gw.get("gateway") or "").strip()
            if not gw_ip:
                continue
            try:
                ipaddress.ip_address(gw_ip)
            except ValueError:
                continue
            if gw_ip not in owned_ips:
                sev = Severity.WARNING if _on_site(gw_ip) else Severity.INFO
                out.append(
                    ResiliencyFinding(
                        severity=sev,
                        category="Consistency",
                        message=(
                            f"{name}: default gateway {gw_ip} is not an interface "
                            "address on any imported device"
                        ),
                        devices=[name],
                        impact="Gateway may be a missing device or a stale address",
                        remediation="Import the gateway device's config or fix the route",
                        certainty="unknown",
                    )
                )

    # ---- DHCP relay targets must exist ----
    for name, ds in loaded.items():
        for relay in ds.result.summary.get("dhcp_relays", []) or []:
            if relay.get("disabled") == "yes":
                continue
            target_ip = (relay.get("dhcp_server") or "").strip()
            if target_ip and target_ip not in owned_ips:
                out.append(
                    ResiliencyFinding(
                        severity=Severity.WARNING,
                        category="Anomaly",
                        message=(
                            f"{name}: DHCP relay {relay.get('name') or relay.get('interface')} "
                            f"forwards to {target_ip}, which no imported device owns"
                        ),
                        devices=[name],
                        evidence=f"interface={relay.get('interface')}",
                        impact="Clients on that VLAN may never get a lease",
                        remediation="Point the relay at the real DHCP server or import its config",
                        certainty="likely",
                    )
                )

    # ---- NTP consistency ----
    ntp_sets: dict[str, tuple[str, ...]] = {}
    for name, ds in loaded.items():
        servers = tuple(sorted(ds.result.summary.get("ntp_servers", []) or []))
        if servers:
            ntp_sets[name] = servers
    if len(ntp_sets) >= 2 and len(set(ntp_sets.values())) > 1:
        detail = "; ".join(f"{n}={', '.join(v)}" for n, v in sorted(ntp_sets.items()))
        out.append(
            ResiliencyFinding(
                severity=Severity.INFO,
                category="Consistency",
                message="Devices use different NTP server sets",
                devices=sorted(ntp_sets),
                evidence=detail,
                impact="Clock drift complicates log correlation",
                remediation="Standardise NTP sources",
                certainty="unknown",
            )
        )
    missing_ntp = [
        n
        for n, ds in loaded.items()
        if ds.device.kind == "mikrotik" and n not in ntp_sets
    ]
    if ntp_sets and missing_ntp:
        out.append(
            ResiliencyFinding(
                severity=Severity.INFO,
                category="Consistency",
                message=f"No NTP servers configured on: {', '.join(sorted(missing_ntp))}",
                devices=sorted(missing_ntp),
                impact="Unsynchronised clocks skew logs and certificates",
                remediation="Enable the NTP client with the site-standard servers",
            )
        )

    # ---- Software version drift within a vendor ----
    versions: dict[str, dict[str, list[str]]] = {}
    for name, ds in loaded.items():
        if ds.result.version:
            versions.setdefault(ds.result.source_type, {}).setdefault(
                ds.result.version, []
            ).append(name)
    for vendor, by_ver in versions.items():
        if len(by_ver) > 1:
            detail = "; ".join(
                f"{ver}: {', '.join(sorted(names))}" for ver, names in sorted(by_ver.items())
            )
            out.append(
                ResiliencyFinding(
                    severity=Severity.INFO,
                    category="Consistency",
                    message=f"Mixed {vendor} software versions across the site",
                    devices=sorted(n for names in by_ver.values() for n in names),
                    evidence=detail,
                    impact="Behaviour/feature drift between devices",
                    remediation="Upgrade to a common tested release",
                    certainty="unknown",
                )
            )

    return out


# --------------------------------------------------------------------------- #
# Wireless / CAPsMAN path analysis
# --------------------------------------------------------------------------- #

def _check_wireless(snap: SiteSnapshot) -> list[ResiliencyFinding]:
    """Diagnose the CAPsMAN WLAN path: 'wireline works, Wi-Fi is marginal' class.

    Wired clients ride the switch chip; Wi-Fi clients ride the software bridge
    plus the CAPsMAN datapath. These checks compare the two paths.
    """
    out: list[ResiliencyFinding] = []
    loaded = {n: ds for n, ds in snap.devices.items() if ds.result}
    if not loaded:
        return out

    # Interface IPs across the site → find the CAPsMAN manager device by IP.
    ip_owner: dict[str, str] = {}
    for name, ds in loaded.items():
        for iface in ds.result.interfaces:
            ip = (iface.ipaddr or "").strip()
            if ip and ip.lower() not in ("dhcp", "pppoe"):
                ip_owner.setdefault(ip, name)

    managers = {
        n: ds
        for n, ds in loaded.items()
        if ds.result.summary.get("capsman_configs")
        or ds.result.summary.get("capsman_manager_enabled")
    }
    caps = {
        n: ds
        for n, ds in loaded.items()
        if (ds.result.summary.get("wireless_cap") or {}).get("enabled")
    }

    # ---- Manager-side checks ----
    for mname, ds in managers.items():
        s = ds.result.summary
        datapaths = {d["name"]: d for d in s.get("capsman_datapaths", [])}
        manager_bridges = {b.bridgeif for b in ds.result.bridges}

        for cfg in s.get("capsman_configs", []):
            dp = datapaths.get(cfg.get("datapath", ""), {})
            eff_local = (cfg.get("ov_local_forwarding") or dp.get("local_forwarding") or "").lower()
            eff_bridge = cfg.get("ov_bridge") or dp.get("bridge") or ""
            vlan_id = cfg.get("ov_vlan_id") or dp.get("vlan_id") or ""
            ssid = cfg.get("ssid") or cfg.get("name")

            # local-forwarding=yes bridges frames on the CAP — a bridge name
            # that only exists on the manager cannot work there.
            if eff_local == "yes" and eff_bridge and eff_bridge in manager_bridges:
                cap_has_bridge = any(
                    eff_bridge in {b.bridgeif for b in cds.result.bridges}
                    for cn, cds in caps.items()
                    if cn != mname
                )
                if not cap_has_bridge:
                    out.append(
                        ResiliencyFinding(
                            severity=Severity.ERROR,
                            category="Wireless",
                            message=(
                                f"{mname}: CAPsMAN config '{cfg['name']}' (SSID {ssid}) uses "
                                f"local-forwarding but overrides bridge to '{eff_bridge}', "
                                "which only exists on the manager — CAPs cannot bridge into it"
                            ),
                            devices=[mname],
                            vlan=vlan_id,
                            evidence=f"datapath={cfg.get('datapath')} local-forwarding={eff_local}",
                            impact=(
                                "Wi-Fi clients on this SSID get an inconsistent L2 path "
                                "(classic 'wireline fine, WLAN marginal' symptom)"
                            ),
                            remediation=(
                                "With local-forwarding=yes drop the manager bridge override; "
                                "let each CAP use its own bridge (set in /interface wireless cap)"
                            ),
                        )
                    )

            # Datapath vs configuration override conflicts
            for label, dp_key, ov_key in (
                ("client-to-client-forwarding", "client_to_client", "ov_client_to_client"),
                ("local-forwarding", "local_forwarding", "ov_local_forwarding"),
                ("vlan-id", "vlan_id", "ov_vlan_id"),
            ):
                dp_val = (dp.get(dp_key) or "").lower()
                ov_val = (cfg.get(ov_key) or "").lower()
                if dp_val and ov_val and dp_val != ov_val:
                    out.append(
                        ResiliencyFinding(
                            severity=Severity.WARNING,
                            category="Wireless",
                            message=(
                                f"{mname}: CAPsMAN config '{cfg['name']}' overrides "
                                f"{label}={ov_val} while datapath "
                                f"'{cfg.get('datapath')}' says {dp_val}"
                            ),
                            devices=[mname],
                            vlan=vlan_id,
                            evidence=f"SSID {ssid}",
                            impact="Effective wireless behaviour differs from the documented datapath",
                            remediation="Align the datapath and configuration override",
                        )
                    )

        # Disabled radios on the manager silently kill Wi-Fi on that AP
        disabled_radios = [
            r["name"]
            for r in s.get("capsman_interfaces", [])
            if r.get("disabled") == "yes" and (r.get("master") in ("", "none"))
        ]
        if disabled_radios:
            out.append(
                ResiliencyFinding(
                    severity=Severity.ERROR,
                    category="Wireless",
                    message=(
                        f"{mname}: CAPsMAN radio(s) disabled on the manager: "
                        f"{', '.join(disabled_radios)}"
                    ),
                    devices=[mname],
                    evidence=f"{len(caps)} CAP device(s) point at this manager",
                    impact="APs whose radio entry is disabled provide no Wi-Fi at all",
                    remediation="Enable the /caps-man interface entries (or remove dead APs)",
                )
            )
        disabled_slaves = [
            r["name"]
            for r in s.get("capsman_interfaces", [])
            if r.get("disabled") == "yes" and r.get("master") not in ("", "none")
        ]
        if disabled_slaves:
            out.append(
                ResiliencyFinding(
                    severity=Severity.WARNING,
                    category="Wireless",
                    message=(
                        f"{mname}: CAPsMAN virtual AP(s) disabled: "
                        f"{', '.join(disabled_slaves)}"
                    ),
                    devices=[mname],
                    impact="Secondary SSIDs (e.g. IOT) absent on those APs",
                    remediation="Enable the slave interfaces or update provisioning",
                )
            )

    # ---- CAP-side checks ----
    manager_uses_tagging = any(
        (d.get("vlan_mode") or "").lower() == "use-tag"
        for ds in managers.values()
        for d in ds.result.summary.get("capsman_datapaths", [])
    )
    for cname, ds in caps.items():
        s = ds.result.summary
        cap = s.get("wireless_cap") or {}
        vf_map = s.get("bridge_vlan_filtering", {}) or {}
        cap_bridge = cap.get("bridge", "")

        # Manager address must be owned by an imported device
        for addr in cap.get("addresses", []) or []:
            owner = ip_owner.get(addr)
            if owner is None:
                out.append(
                    ResiliencyFinding(
                        severity=Severity.WARNING,
                        category="Wireless",
                        message=(
                            f"{cname}: CAP points at CAPsMAN manager {addr}, "
                            "which no imported device owns"
                        ),
                        devices=[cname],
                        impact="CAP may never provision; radio stays unmanaged",
                        remediation="Import the manager's config or fix caps-man-addresses",
                        certainty="likely",
                    )
                )
            else:
                mds = loaded.get(owner)
                if mds and mds.result.summary.get("capsman_manager_enabled") is False:
                    out.append(
                        ResiliencyFinding(
                            severity=Severity.ERROR,
                            category="Wireless",
                            message=(
                                f"{cname}: CAP manager {owner} ({addr}) has "
                                "CAPsMAN disabled"
                            ),
                            devices=[cname, owner],
                            impact="CAP cannot provision — no Wi-Fi from this AP",
                            remediation=f"Enable /caps-man manager on {owner}",
                        )
                    )

        # Wi-Fi frames are VLAN-tagged onto the CAP bridge; without
        # vlan-filtering the bridge VLAN table is ignored.
        wlan_tagged_vlans: list[str] = []
        for row in s.get("bridge_vlans", []) or []:
            tagged = {p.strip().lower() for p in str(row.get("tagged", "")).split(",")}
            if any(t.startswith("wlan") for t in tagged):
                wlan_tagged_vlans.extend(
                    v.strip() for v in str(row.get("vlan_ids", "")).split(",") if v.strip()
                )
        if (
            cap_bridge
            and wlan_tagged_vlans
            and manager_uses_tagging
            and vf_map.get(cap_bridge) is False
        ):
            out.append(
                ResiliencyFinding(
                    severity=Severity.ERROR,
                    category="Wireless",
                    message=(
                        f"{cname}: bridge '{cap_bridge}' tags wlan on VLAN(s) "
                        f"{', '.join(sorted(set(wlan_tagged_vlans)))} but has "
                        "vlan-filtering=no"
                    ),
                    devices=[cname],
                    vlan=",".join(sorted(set(wlan_tagged_vlans))),
                    evidence="CAPsMAN datapath uses vlan-mode=use-tag",
                    impact=(
                        "Wired ports work via the switch chip, but Wi-Fi VLAN "
                        "tagging is not enforced on the software bridge — "
                        "intermittent DHCP/ARP for wireless clients"
                    ),
                    remediation=(
                        f"Set vlan-filtering=yes on '{cap_bridge}' "
                        "(keep wlan tagged on the VLAN and sfp uplink tagged)"
                    ),
                )
            )

        # wlan interfaces tagged in bridge VLANs but not handed to CAPsMAN
        cap_ifaces = {i.lower() for i in cap.get("interfaces", []) or []}
        wlan_in_vlans: set[str] = set()
        for row in s.get("bridge_vlans", []) or []:
            for p in str(row.get("tagged", "")).split(","):
                p = p.strip().lower()
                if p.startswith("wlan"):
                    wlan_in_vlans.add(p)
        orphan_wlans = sorted(wlan_in_vlans - cap_ifaces) if cap_ifaces else []
        if orphan_wlans:
            out.append(
                ResiliencyFinding(
                    severity=Severity.WARNING,
                    category="Wireless",
                    message=(
                        f"{cname}: {', '.join(orphan_wlans)} referenced in bridge "
                        "VLANs but not listed in the CAP interfaces"
                    ),
                    devices=[cname],
                    evidence=f"cap interfaces={sorted(cap_ifaces)}",
                    impact="That SSID/VLAN path exists on paper but no radio serves it",
                    remediation="Add the wlan to /interface wireless cap interfaces, or remove it",
                    certainty="likely",
                )
            )

    return out


# --------------------------------------------------------------------------- #
# Deep-dive: Loops / RST / Unbound / NAT / Firewall (FP OK)
# --------------------------------------------------------------------------- #


def _undirected_cycles(adj: dict[str, set[str]]) -> list[list[str]]:
    """Return simple undirected cycles (device-name rings). Cap for noise."""
    cycles: list[list[str]] = []
    seen_rings: set[frozenset[str]] = set()
    nodes = sorted(adj)

    def dfs(start: str, node: str, parent: str | None, path: list[str]) -> None:
        if len(cycles) >= 25 or len(path) > 12:
            return
        for nbr in sorted(adj.get(node, ())):
            if nbr == parent:
                continue
            if nbr == start and len(path) >= 3:
                ring = frozenset(path)
                if ring not in seen_rings:
                    seen_rings.add(ring)
                    cycles.append(list(path) + [start])
                continue
            if nbr in path:
                continue
            if nbr < start:
                # Only start cycles from the lexicographically smallest node
                # once we leave the start — reduces duplicate directions.
                continue
            dfs(start, nbr, node, path + [nbr])

    for start in nodes:
        dfs(start, start, None, [start])
    return cycles


def _check_loops(snap: SiteSnapshot) -> list[ResiliencyFinding]:
    """Aggressive L2/topology loop heuristics."""
    out: list[ResiliencyFinding] = []
    site = snap.site
    adj = _adjacency(site)
    # Multi-edge pairs (parallel links)
    pair_counts: dict[frozenset[str], int] = {}
    for link in site.links:
        a, b = (link.a_device or "").strip(), (link.b_device or "").strip()
        if not a or not b or a == b:
            continue
        key = frozenset((a, b))
        pair_counts[key] = pair_counts.get(key, 0) + 1
    for pair, count in pair_counts.items():
        if count < 2:
            continue
        devices = sorted(pair)
        out.append(
            ResiliencyFinding(
                severity=Severity.WARNING,
                category="Loops",
                message=(
                    f"Parallel links ({count}) between {devices[0]} and {devices[1]} "
                    "— possible L2 loop if STP is not blocking"
                ),
                devices=devices,
                path=devices,
                impact="Broadcast storms / MAC flapping if both links forward",
                remediation="Confirm RSTP/MSTP is active or use LAGG instead of parallel trunks",
                certainty="low",
                evidence=f"link_count={count}",
            )
        )

    for cycle in _undirected_cycles(adj):
        if len(cycle) < 4:  # start…start
            continue
        nodes = cycle[:-1]
        out.append(
            ResiliencyFinding(
                severity=Severity.WARNING,
                category="Loops",
                message=f"Topology cycle detected: {' → '.join(nodes)}",
                devices=list(nodes),
                path=list(nodes),
                impact="Redundant L2/L3 path may loop without proper blocking/routing",
                remediation="Verify spanning tree or routed design on this ring",
                certainty="low",
                evidence=f"cycle_len={len(nodes)}",
            )
        )

    # Same VLAN on multiple links between same pair
    vlan_pairs: dict[tuple[frozenset[str], str], int] = {}
    for link in site.links:
        a, b = (link.a_device or "").strip(), (link.b_device or "").strip()
        if not a or not b:
            continue
        pair = frozenset((a, b))
        for vid in link.vlans or []:
            key = (pair, str(vid))
            vlan_pairs[key] = vlan_pairs.get(key, 0) + 1
    for (pair, vid), count in vlan_pairs.items():
        if count < 2:
            continue
        devices = sorted(pair)
        out.append(
            ResiliencyFinding(
                severity=Severity.INFO,
                category="Loops",
                message=(
                    f"VLAN {vid} appears on {count} parallel links between "
                    f"{devices[0]} and {devices[1]}"
                ),
                devices=devices,
                vlan=str(vid),
                impact="Duplicate VLAN paths increase loop risk",
                remediation="Prune VLAN from one link or rely on STP",
                certainty="low",
            )
        )
    return out


def _bridge_protocol_mode(ds: DeviceSnapshot, bridgeif: str) -> str:
    if not ds.result:
        return ""
    modes = ds.result.summary.get("bridge_protocol_mode") or {}
    if isinstance(modes, dict) and bridgeif in modes:
        return str(modes[bridgeif] or "").lower()
    for b in ds.result.bridges:
        if b.bridgeif == bridgeif:
            return "rstp" if b.stp_enabled else "none"
    return ""


def _check_rst(snap: SiteSnapshot) -> list[ResiliencyFinding]:
    """STP/RSTP health heuristics (config inventory, not live BPDUs)."""
    out: list[ResiliencyFinding] = []
    has_loops = bool(_undirected_cycles(_adjacency(snap.site)))
    modes_seen: dict[str, list[str]] = {}  # mode -> devices

    for name, ds in snap.devices.items():
        if not ds.result:
            continue
        for br in ds.result.bridges:
            members = br.members or []
            multi = len(members) >= 2
            mode = _bridge_protocol_mode(ds, br.bridgeif) or (
                "stp" if br.stp_enabled else "none"
            )
            modes_seen.setdefault(mode or "none", []).append(f"{name}/{br.bridgeif}")
            if (multi or has_loops) and not br.stp_enabled:
                out.append(
                    ResiliencyFinding(
                        severity=Severity.WARNING,
                        category="RST",
                        message=(
                            f"{name}: bridge {br.bridgeif} has STP/RSTP disabled "
                            f"({len(members)} member(s))"
                        ),
                        devices=[name],
                        impact="No spanning-tree blocking — loops can flood the domain",
                        remediation="Enable RSTP/MSTP on the bridge (protocol-mode=rstp)",
                        certainty="low",
                        evidence=f"members={','.join(members[:8])} mode={mode}",
                    )
                )
            if mode == "stp" and multi:
                out.append(
                    ResiliencyFinding(
                        severity=Severity.INFO,
                        category="RST",
                        message=(
                            f"{name}: bridge {br.bridgeif} uses classic STP "
                            "(prefer RSTP/MSTP for faster convergence)"
                        ),
                        devices=[name],
                        impact="Slow reconvergence after topology changes",
                        remediation="Switch protocol-mode to rstp or mstp",
                        certainty="low",
                    )
                )

    active_modes = {m: devs for m, devs in modes_seen.items() if m and m != "none"}
    if len(active_modes) > 1:
        detail = "; ".join(f"{m}: {', '.join(v[:4])}" for m, v in sorted(active_modes.items()))
        devices = sorted(
            {
                d.split("/", 1)[0]
                for vals in active_modes.values()
                for d in vals
            }
        )
        out.append(
            ResiliencyFinding(
                severity=Severity.WARNING,
                category="RST",
                message="Mixed STP protocol modes across the site",
                devices=devices[:12],
                impact="Inconsistent spanning-tree behaviour / unexpected blocking",
                remediation="Standardise on RSTP or MSTP site-wide",
                certainty="low",
                evidence=detail,
            )
        )
    return out


def _check_unbound(snap: SiteSnapshot) -> list[ResiliencyFinding]:
    out: list[ResiliencyFinding] = []
    dns_sets: dict[str, tuple[str, ...]] = {}
    for name, ds in snap.devices.items():
        if not ds.result:
            continue
        dns = ds.result.dns or {}
        servers = tuple(str(s) for s in (dns.get("servers") or []) if s)
        if servers:
            dns_sets[name] = servers
        resolver = bool(dns.get("resolver") or dns.get("unbound_enable"))
        forwarder = bool(dns.get("forwarder"))
        if resolver and forwarder:
            out.append(
                ResiliencyFinding(
                    severity=Severity.WARNING,
                    category="Unbound",
                    message=(
                        f"{name}: Unbound resolver and dnsmasq forwarder both enabled"
                    ),
                    devices=[name],
                    impact="Port 53 bind conflict / unpredictable DNS answers",
                    remediation="Disable one of Unbound or dnsmasq",
                    certainty="likely",
                )
            )
        if not resolver and not forwarder and not servers:
            role = (ds.device.role or "").lower()
            if role in ("firewall", "egress", "router") or ds.device.kind in (
                "pfsense",
                "opnsense",
            ):
                out.append(
                    ResiliencyFinding(
                        severity=Severity.WARNING,
                        category="Unbound",
                        message=f"{name}: no DNS resolver/forwarder and no system DNS servers",
                        devices=[name],
                        impact="Clients/firewall may fail name resolution",
                        remediation="Enable Unbound or set system DNS servers",
                        certainty="low",
                    )
                )
        if resolver:
            active = dns.get("unbound_active_interface") or []
            if isinstance(active, list) and not active:
                out.append(
                    ResiliencyFinding(
                        severity=Severity.INFO,
                        category="Unbound",
                        message=(
                            f"{name}: Unbound enabled but no active_interface list "
                            "parsed (may listen on all or defaults)"
                        ),
                        devices=[name],
                        impact="Unexpected listen scope / exposure",
                        remediation="Set explicit Unbound Network Interfaces",
                        certainty="low",
                    )
                )
            if not dns.get("unbound_has_acls"):
                out.append(
                    ResiliencyFinding(
                        severity=Severity.INFO,
                        category="Unbound",
                        message=f"{name}: Unbound has no access-lists parsed",
                        devices=[name],
                        impact="Open recursion risk if reachable from untrusted nets",
                        remediation="Add Unbound ACLs for trusted networks only",
                        certainty="low",
                    )
                )
    if len(set(dns_sets.values())) > 1:
        detail = "; ".join(
            f"{n}={','.join(v)}" for n, v in sorted(dns_sets.items())
        )
        out.append(
            ResiliencyFinding(
                severity=Severity.INFO,
                category="Unbound",
                message="Site devices advertise different DNS server sets",
                devices=sorted(dns_sets),
                impact="Inconsistent resolution / hard-to-debug client behaviour",
                remediation="Align system DNS / Unbound upstream across the site",
                certainty="low",
                evidence=detail[:500],
            )
        )
    return out


def _mgmt_ips(snap: SiteSnapshot) -> set[str]:
    ips: set[str] = set()
    for ds in snap.devices.values():
        if ds.device.mgmt_ip:
            ips.add(ds.device.mgmt_ip.strip())
        if not ds.result:
            continue
        for iface in ds.result.interfaces:
            ip = (iface.ipaddr or "").strip()
            if ip and ip not in ("dhcp", "pppoe"):
                ips.add(ip.split("/")[0])
    return ips


def _check_nat_deep(snap: SiteSnapshot) -> list[ResiliencyFinding]:
    out: list[ResiliencyFinding] = []
    known_ips = _mgmt_ips(snap)
    for name, ds in snap.devices.items():
        if not ds.result:
            continue
        role = (ds.device.role or "").lower()
        is_edge = role in ("firewall", "egress", "router") or ds.device.kind in (
            "pfsense",
            "opnsense",
            "mikrotik",
        )
        nat_rules = list(ds.result.nat_rules or [])
        has_wan = any(
            i.name.lower() in ("wan", "pppoe", "lte")
            or "wan" in (i.descr or "").lower()
            for i in ds.result.interfaces
        )
        if is_edge and has_wan and not nat_rules:
            out.append(
                ResiliencyFinding(
                    severity=Severity.INFO,
                    category="NAT",
                    message=f"{name}: WAN-like interface present but no NAT rules",
                    devices=[name],
                    impact="Outbound internet or inbound services may fail",
                    remediation="Add outbound NAT / port forwards as required",
                    certainty="low",
                )
            )
        # Port-forward overlaps (same interface + dst port)
        seen_fw: dict[tuple[str, str], list[str]] = {}
        masq_ifaces: dict[str, int] = {}
        for rule in nat_rules:
            kind = (rule.kind or "").lower()
            iface = (rule.interface or rule.out_interface or "").lower()
            if "masquerade" in kind or kind.endswith("srcnat"):
                masq_ifaces[iface or "?"] = masq_ifaces.get(iface or "?", 0) + 1
            if rule.disabled:
                descr = (rule.descr or "").lower()
                if any(x in descr for x in ("wan", "critical", "prod", "vpn", "mail")):
                    out.append(
                        ResiliencyFinding(
                            severity=Severity.INFO,
                            category="NAT",
                            message=(
                                f"{name}: disabled NAT rule looks important "
                                f"({rule.descr or rule.kind})"
                            ),
                            devices=[name],
                            impact="Service may be unintentionally offline",
                            remediation="Re-enable or remove obsolete NAT rule",
                            certainty="low",
                        )
                    )
            if "port-forward" in kind or kind in ("nat-dstnat", "nat-netmap"):
                port = (rule.dst_port or rule.destination or "").strip()
                key = (iface, port)
                seen_fw.setdefault(key, []).append(rule.descr or str(rule.index))
                # Forward target host unknown
                target = (rule.destination or "").strip()
                host = target.split("/")[0].split(":")[0]
                if host and re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                    if host not in known_ips and not any(
                        host.startswith(p)
                        for p in ("10.", "192.168.", "172.")
                    ):
                        pass  # public VIP — skip
                    elif host not in known_ips:
                        out.append(
                            ResiliencyFinding(
                                severity=Severity.INFO,
                                category="NAT",
                                message=(
                                    f"{name}: port-forward target {host} not seen "
                                    "on site mgmt/interface IPs"
                                ),
                                devices=[name],
                                impact="Forward may point at a missing host",
                                remediation="Verify target host address / DHCP reservation",
                                certainty="low",
                                evidence=f"rule={rule.descr or rule.index}",
                            )
                        )
        for (iface, port), names in seen_fw.items():
            if len(names) < 2 or not port:
                continue
            out.append(
                ResiliencyFinding(
                    severity=Severity.WARNING,
                    category="NAT",
                    message=(
                        f"{name}: overlapping port-forwards on {iface or 'any'} "
                        f"port {port} ({len(names)} rules)"
                    ),
                    devices=[name],
                    impact="Ambiguous inbound mapping",
                    remediation="Deduplicate or differentiate external ports",
                    certainty="low",
                    evidence="; ".join(names[:6]),
                )
            )
        for iface, count in masq_ifaces.items():
            if count >= 2:
                out.append(
                    ResiliencyFinding(
                        severity=Severity.INFO,
                        category="NAT",
                        message=(
                            f"{name}: multiple masquerade/srcnat rules on {iface} "
                            f"({count})"
                        ),
                        devices=[name],
                        impact="Harder to reason about outbound source NAT",
                        remediation="Consolidate outbound NAT policy",
                        certainty="low",
                    )
                )
    return out


def _is_any_endpoint(text: str) -> bool:
    t = (text or "").strip().lower()
    return t in ("", "any", "*", "0.0.0.0/0", "::/0", "all")


def _check_firewall_deep(snap: SiteSnapshot) -> list[ResiliencyFinding]:
    out: list[ResiliencyFinding] = []
    for name, ds in snap.devices.items():
        if not ds.result:
            continue
        role = (ds.device.role or "").lower()
        is_edge = role in ("firewall", "egress", "router") or ds.device.kind in (
            "pfsense",
            "opnsense",
            "mikrotik",
        )
        rules = [r for r in (ds.result.filter_rules or []) if not r.disabled]
        disabled = [r for r in (ds.result.filter_rules or []) if r.disabled]
        ifaces = {i.name.lower() for i in ds.result.interfaces if i.name}
        ifaces |= {
            (i.descr or "").lower() for i in ds.result.interfaces if i.descr
        }

        if is_edge and not rules and not ds.result.filter_rules:
            out.append(
                ResiliencyFinding(
                    severity=Severity.WARNING,
                    category="Firewall",
                    message=f"{name}: no filter rules present",
                    devices=[name],
                    impact="Device may be wide open or locked down unpredictably",
                    remediation="Add explicit allow rules and a default deny",
                    certainty="unknown",
                )
            )

        fingerprints: dict[tuple[str, str, str, str, str], int] = {}
        for rule in rules:
            action = (rule.type or "").lower()
            src, dst = rule.source or "", rule.destination or ""
            if action in ("pass", "accept", "allow") and _is_any_endpoint(src) and _is_any_endpoint(dst):
                proto = (rule.protocol or "any").lower()
                if proto in ("", "any", "*"):
                    out.append(
                        ResiliencyFinding(
                            severity=Severity.WARNING,
                            category="Firewall",
                            message=(
                                f"{name}: broad pass any-any"
                                + (f" ({rule.descr})" if rule.descr else "")
                            ),
                            devices=[name],
                            impact="Permissive rule may expose the network",
                            remediation="Narrow source/destination/protocol",
                            certainty="low",
                            evidence=f"iface={rule.interface} index={rule.index}",
                        )
                    )
            rif = (rule.interface or "").strip()
            if rif and rif.lower() not in ("any", "*", "all", ""):
                # Loose match — interface labels often differ from device names
                token = rif.lower().split("(")[0].strip()
                if token and token not in ifaces and not any(
                    token in x or x in token for x in ifaces
                ):
                    out.append(
                        ResiliencyFinding(
                            severity=Severity.INFO,
                            category="Firewall",
                            message=(
                                f"{name}: filter rule references interface "
                                f"'{rif}' not found in inventory"
                            ),
                            devices=[name],
                            impact="Rule may never match or targets wrong NIC",
                            remediation="Fix interface assignment on the rule",
                            certainty="low",
                            evidence=f"descr={rule.descr or rule.index}",
                        )
                    )
            fp = (
                action,
                (rule.interface or "").lower(),
                src.lower(),
                dst.lower(),
                (rule.protocol or "").lower(),
            )
            fingerprints[fp] = fingerprints.get(fp, 0) + 1

        for fp, count in fingerprints.items():
            if count < 2:
                continue
            out.append(
                ResiliencyFinding(
                    severity=Severity.INFO,
                    category="Firewall",
                    message=f"{name}: duplicate filter rule pattern ×{count}",
                    devices=[name],
                    impact="Clutter / possible unintentional double-match",
                    remediation="Remove duplicate rules",
                    certainty="low",
                    evidence=str(fp),
                )
            )

        for rule in disabled[:8]:
            descr = (rule.descr or "").lower()
            if any(x in descr for x in ("allow", "mgmt", "admin", "vpn", "prod")):
                out.append(
                    ResiliencyFinding(
                        severity=Severity.INFO,
                        category="Firewall",
                        message=(
                            f"{name}: disabled filter looks important "
                            f"({rule.descr or rule.index})"
                        ),
                        devices=[name],
                        impact="Access path may be unintentionally closed",
                        remediation="Confirm whether the rule should be enabled",
                        certainty="low",
                    )
                )
    return out


def build_deep_dive_evidence(report: ResiliencyReport, category: str) -> str:
    """Compact evidence pack for one deep-dive section (Ollama / UI)."""
    lines = [
        f"Deep-dive category: {category}",
        f"Site devices: {report.summary.get('devices', 0)}",
        f"With config: {report.summary.get('with_config', 0)}",
        "",
        "Deterministic findings in this category:",
    ]
    matched = [f for f in report.findings if f.category == category]
    if not matched:
        lines.append("(none yet)")
    for f in matched[:40]:
        lines.append(
            f"- {f.severity.value}: {f.message} "
            f"[{','.join(f.devices) or '-'}] rem={f.remediation}"
        )
    snap = report.snapshot
    if snap is not None:
        lines.append("")
        lines.append("Inventory hints:")
        lines.append(f"- topology links: {len(snap.site.links)}")
        for name, ds in list(snap.devices.items())[:20]:
            if not ds.result:
                continue
            r = ds.result
            bridges = ", ".join(
                f"{b.bridgeif}:stp={b.stp_enabled}" for b in r.bridges[:4]
            )
            lines.append(
                f"- {name}: filters={len(r.filter_rules)} nat={len(r.nat_rules)} "
                f"dns_resolver={bool((r.dns or {}).get('resolver'))} "
                f"bridges=[{bridges}]"
            )
    return "\n".join(lines)


def parse_ollama_deep_dive(
    category: str, reply: str, *, devices_hint: list[str] | None = None
) -> tuple[list[ResiliencyFinding], str]:
    """Best-effort parse of Ollama text into findings + narrative note."""
    text = (reply or "").strip()
    findings: list[ResiliencyFinding] = []
    if not text:
        return findings, ""
    for raw in text.splitlines():
        line = raw.strip().lstrip("-•* ").strip()
        if not line or line.lower().startswith(("here ", "based ", "note:")):
            continue
        if len(line) < 12:
            continue
        # Skip markdown headers
        if line.startswith("#"):
            continue
        sev = Severity.INFO
        low = line.lower()
        if any(x in low for x in ("critical", "severe", "must ")):
            sev = Severity.WARNING
        if any(x in low for x in ("outage", "storm", "wide open", "exploit")):
            sev = Severity.WARNING
        findings.append(
            ResiliencyFinding(
                severity=sev,
                category=category,
                message=line[:300],
                devices=list(devices_hint or [])[:8],
                impact="AI-suggested issue (verify before acting)",
                remediation="Review evidence and confirm on the device",
                certainty="ai",
                evidence="ollama deep-dive",
            )
        )
        if len(findings) >= 12:
            break
    return findings, text[:4000]


def enrich_report_with_ollama(
    report: ResiliencyReport,
    *,
    model: str,
    base_url: str,
    api_key: str = "",
    categories: tuple[str, ...] | None = None,
) -> ResiliencyReport:
    """Synchronously enrich *report* via Ollama (call from a worker thread)."""
    from pfsense_checker import ai

    cats = categories or DEEP_DIVE_CATEGORIES
    for category in cats:
        evidence = build_deep_dive_evidence(report, category)
        question = (
            f"Deep-dive the '{category}' section for this network site. "
            "List concrete additional risks as short bullet lines "
            "(one issue per line). False positives are acceptable. "
            "Do not invent device names that are not in the evidence."
        )
        try:
            reply = ai.ask_ollama(
                evidence,
                question,
                model=model,
                base_url=base_url,
                api_key=api_key,
                temperature=0.2,
                timeout=120,
            )
        except Exception as exc:  # noqa: BLE001
            report.deep_dive_notes[category] = f"(Ollama error: {exc})"
            continue
        extra, note = parse_ollama_deep_dive(category, reply)
        report.deep_dive_notes[category] = note or "(no narrative)"
        report.findings.extend(extra)
    # Refresh counts in summary
    report.summary["errors"] = report.error_count
    report.summary["warnings"] = report.warning_count
    report.summary["info"] = report.info_count
    report.summary["ollama_deep_dive"] = True
    return report


def build_ai_context(report: ResiliencyReport) -> str:
    """Redacted site-level summary for the AI Advisor (no secrets / raw config)."""
    s = report.summary
    lines = [
        "Site resiliency analysis summary:",
        f"- devices: {s.get('devices', 0)} "
        f"({s.get('with_config', 0)} with config, {s.get('missing_config', 0)} missing)",
        f"- result: {s.get('errors', 0)} errors, {s.get('warnings', 0)} warnings, "
        f"{s.get('info', 0)} info",
        f"- incomplete: {s.get('incomplete', False)}",
        "",
        "Findings (severity | category | devices | message | remediation):",
    ]
    for f in report.findings:
        lines.append(
            f"- {f.severity.value.upper()} | {f.category} | "
            f"{','.join(f.devices) or '-'} | {f.message} | {f.remediation}"
        )
    if report.deep_dive_notes:
        lines.append("")
        lines.append("Ollama deep-dive notes:")
        for cat, note in report.deep_dive_notes.items():
            lines.append(f"## {cat}")
            lines.append(note[:1500])
    return "\n".join(lines)
