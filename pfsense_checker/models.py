"""Shared models for pfSense config analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    severity: Severity
    category: str
    message: str
    path: str = ""
    line: int | None = None
    remediation: str = ""

    def label(self) -> str:
        parts: list[str] = [f"[{self.severity.value.upper()}]"]
        if self.category:
            parts.append(f"[{self.category}]")
        loc = ""
        if self.path:
            loc = self.path
            if self.line is not None:
                loc += f", line {self.line}"
            parts.append(f"({loc})")
        parts.append(self.message)
        return " ".join(parts)


@dataclass
class InterfaceInfo:
    name: str
    descr: str = ""
    device: str = ""
    enabled: bool = False
    ipaddr: str = ""
    subnet: str = ""
    ipaddrv6: str = ""
    subnetv6: str = ""
    media: str = ""
    bridge_member: bool = False
    bridge_of: str = ""
    kind: str = "physical"  # physical, vlan, bridge, lagg, openvpn, ipsec, gif, gre, ppp, other
    raw: dict[str, str] = field(default_factory=dict)

    def summary_line(self) -> str:
        state = "enabled" if self.enabled else "DISABLED"
        addr = self.ipaddr or "(none)"
        if self.subnet and self.ipaddr not in {"dhcp", "pppoe", ""}:
            addr = f"{self.ipaddr}/{self.subnet}"
        bits = [
            self.name.upper(),
            state,
            f"if={self.device or '?'}",
            f"ip={addr}",
            f"kind={self.kind}",
        ]
        if self.descr:
            bits.append(f'"{self.descr}"')
        if self.bridge_of:
            bits.append(f"bridge-member-of={self.bridge_of}")
        return " | ".join(bits)


@dataclass
class BridgeInfo:
    bridgeif: str
    members: list[str] = field(default_factory=list)
    descr: str = ""
    stp_enabled: bool = False
    assigned_as: str = ""  # logical iface that uses this bridge device


@dataclass
class VlanInfo:
    tag: str
    if_parent: str
    vlanif: str = ""
    descr: str = ""
    assigned_as: str = ""


@dataclass
class LaggInfo:
    laggif: str
    members: list[str] = field(default_factory=list)
    proto: str = ""
    descr: str = ""
    assigned_as: str = ""


@dataclass
class PackageInfo:
    name: str
    version: str = ""
    descr: str = ""
    internal_name: str = ""
    config_file: str = ""
    enabled: bool | None = None  # None = unknown / n/a
    notes: str = ""


@dataclass
class ServiceInfo:
    name: str
    rcfile: str = ""
    executable: str = ""
    description: str = ""
    enabled: bool | None = None
    source: str = "installedpackages/service"


@dataclass
class RuleInfo:
    index: int
    kind: str  # filter / nat / outbound / onetoone / npt
    type: str = ""  # action / pass|block|reject|drop|…
    interface: str = ""
    descr: str = ""
    disabled: bool = False
    source: str = ""
    destination: str = ""
    # Extra fields for cross-device correlation (optional / best-effort)
    chain: str = ""
    protocol: str = ""
    src_port: str = ""
    dst_port: str = ""
    out_interface: str = ""
    direction: str = ""  # in / out / both / ""


@dataclass
class VpnEndpoint:
    kind: str  # openvpn-server / openvpn-client / ipsec-p1 / ipsec-p2
    name: str
    disabled: bool = False
    interface: str = ""
    details: str = ""
    peer: str = ""  # remote endpoint address / hostname
    local_address: str = ""
    networks: list[str] = field(default_factory=list)  # routed / interesting traffic
    protocol: str = ""  # wireguard / openvpn / ipsec / …


@dataclass
class CheckResult:
    path: Path | None = None
    source_type: str = "pfsense"  # pfsense | mikrotik
    valid_xml: bool = False
    root_tag: str = ""
    version: str = ""
    hostname: str = ""
    domain: str = ""
    findings: list[Finding] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    # Provenance for combined analysis
    device_name: str = ""  # topology device this result was loaded for
    collected_at: str = ""
    source_status: str = ""  # ok | stale | error | missing | unknown

    interfaces: list[InterfaceInfo] = field(default_factory=list)
    bridges: list[BridgeInfo] = field(default_factory=list)
    vlans: list[VlanInfo] = field(default_factory=list)
    laggs: list[LaggInfo] = field(default_factory=list)
    packages: list[PackageInfo] = field(default_factory=list)
    services: list[ServiceInfo] = field(default_factory=list)
    filter_rules: list[RuleInfo] = field(default_factory=list)
    nat_rules: list[RuleInfo] = field(default_factory=list)
    vpn: list[VpnEndpoint] = field(default_factory=list)
    gateways: list[dict[str, str]] = field(default_factory=list)
    static_routes: list[dict[str, str]] = field(default_factory=list)
    virtual_ips: list[dict[str, str]] = field(default_factory=list)
    aliases: list[dict[str, str]] = field(default_factory=list)
    dhcp_scopes: list[dict[str, str]] = field(default_factory=list)
    ip_pools: list[dict[str, str]] = field(default_factory=list)
    dns: dict[str, Any] = field(default_factory=dict)
    certs: dict[str, int] = field(default_factory=dict)
    top_sections: list[str] = field(default_factory=list)
    package_config_keys: list[str] = field(default_factory=list)

    @property
    def error_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.INFO)

    @property
    def ok(self) -> bool:
        return self.valid_xml and self.error_count == 0
