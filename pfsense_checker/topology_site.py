"""Site topology builder: devices, links, VLANs, bridges, VPN, and egress.

Captures how physical gear is wired (e.g. CRS109 → CRS328 → pfSense) plus
logical overlays: VLAN trunks, bridges, VPN agreements, and egress routers.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CONFIG_SOURCE_LOCAL = "local_file"
CONFIG_SOURCE_MIKROTIK_REST = "mikrotik_rest"

DEVICE_KINDS = [
    "pfsense",
    "opnsense",
    "mikrotik",
    "juniper",
    "fortinet",
    "cisco",
    "linksys",
    "ubiquiti",
    "netgear-managed",
    "netgear-unmanaged",
    "switch",
    "router",
    "access-point",
    "server",
    "workstation",
    "desktop",
    "sff",
    "kvm",
    "nas",
    "tv",
    "video-box",
    "game-console",
    "host",
    "isp",
    "egress",
    "other",
]

# Vendor / model pickers (editable free-text still OK).
DEVICE_MODELS = [
    "",
    # --- MikroTik ---
    "CRS109-8G-1S-2HnD",
    "CRS112-8G-4S",
    "CRS125-24G-1S",
    "CRS309-1G-8S+",
    "CRS317-1G-16S+",
    "CRS326-24G-2S+",
    "CRS326-24G-2S+RM",
    "CRS328-24P-4S+",
    "CRS328-24P-4S+RM",
    "CRS328-4C-20S-4S+",
    "CCR2004",
    "CCR2116",
    "hEX",
    "hAP ac³",
    "RB4011",
    "RB5009",
    # --- Juniper SRX3xx ---
    "SRX300",
    "SRX320",
    "SRX340",
    "SRX345",
    "SRX380",
    # --- Ubiquiti EdgeRouter ---
    "EdgeRouter X",
    "EdgeRouter X SFP",
    "EdgeRouter 4",
    "EdgeRouter 6P",
    "EdgeRouter 12",
    "EdgeRouter Infinity",
    # --- HPE / Aruba / ProCurve ---
    "Aruba 2530-24G",
    "Aruba 2530-48G",
    "Aruba 2930F-24G-4SFP+",
    "Aruba 2930F-48G-4SFP+",
    "Aruba 6100-24G",
    "HPE OfficeConnect 1820-24G",
    "HPE OfficeConnect 1920S-24G",
    "ProCurve 2810-24G",
    # --- Netgear managed ---
    "GS108Ev3 (managed)",
    "GS116Ev2 (managed)",
    "GS324T (managed)",
    "GS724T (managed)",
    "GS748T (managed)",
    "M4250-26G (managed)",
    "XS708T (managed)",
    # --- Netgear unmanaged ---
    "GS105 (unmanaged)",
    "GS108 (unmanaged)",
    "GS116 (unmanaged)",
    "GS308 (unmanaged)",
    "JGS524 (unmanaged)",
    "GS908 (unmanaged)",
    # --- Computers ---
    "Workstation",
    "Desktop PC",
    "Dell Optiplex SFF",
    "HP EliteDesk SFF",
    "Lenovo ThinkCentre SFF",
    "Intel NUC",
    "Custom Tower",
    # --- KVM ---
    "KVM Switch 4-port",
    "KVM Switch 8-port",
    "KVM Switch 16-port",
    "IP KVM",
    "Aten KVM",
    "Trendnet KVM",
    # --- NAS / storage ---
    "Synology DS920+",
    "Synology DS1821+",
    "QNAP TS-464",
    "QNAP TS-873A",
    "TrueNAS Mini",
    "TrueNAS Core/Scale",
    "Buffalo LinkStation",
    "USB NAS / DIY",
    # --- TVs ---
    "Smart TV",
    "Samsung Smart TV",
    "LG OLED TV",
    "Sony Bravia TV",
    "Hisense TV",
    "TCL TV",
    # --- Video boxes / streamboxes ---
    "Apple TV",
    "Amazon Fire TV Stick",
    "Amazon Fire TV Cube",
    "Roku Ultra",
    "Chromecast / Google TV",
    "NVIDIA Shield TV",
    "Android TV Box",
    "Sky Q / Set-top",
    # --- Game consoles ---
    "PlayStation 5",
    "PlayStation 4",
    "Xbox Series X",
    "Xbox Series S",
    "Xbox One",
    "Nintendo Switch",
    "Steam Deck (docked)",
    # --- Firewalls / other ---
    "pfSense",
    "OPNsense",
    "other",
]

# Default copper / SFP port counts derived from common models.
_MODEL_PORT_LAYOUT: dict[str, tuple[list[str], list[str]]] = {
    # copper_names_or_count_hint, sfp_names
    "CRS109": ([str(i) for i in range(1, 9)], ["sfp1"]),
    "CRS112": ([str(i) for i in range(1, 9)], [f"sfp{i}" for i in range(1, 5)]),
    "CRS125": ([str(i) for i in range(1, 25)], ["sfp1"]),
    "CRS309": ([str(i) for i in range(1, 9)], [f"sfp{i}" for i in range(1, 9)]),
    "CRS317": ([], [f"sfp{i}" for i in range(1, 17)]),
    "CRS326": ([str(i) for i in range(1, 25)], ["sfp1", "sfp2"]),
    "CRS328-24P": ([str(i) for i in range(1, 25)], ["sfp1", "sfp2", "sfp3", "sfp4"]),
    "CRS328-4C": (
        [str(i) for i in range(1, 5)],
        [f"sfp{i}" for i in range(1, 21)] + ["sfpplus1", "sfpplus2", "sfpplus3", "sfpplus4"],
    ),
    "SRX300": (["ge-0/0/0", "ge-0/0/1", "ge-0/0/2", "ge-0/0/3", "ge-0/0/4", "ge-0/0/5", "ge-0/0/6", "ge-0/0/7"], []),
    "SRX320": (["ge-0/0/0", "ge-0/0/1", "ge-0/0/2", "ge-0/0/3", "ge-0/0/4", "ge-0/0/5", "ge-0/0/6", "ge-0/0/7"], []),
    "SRX340": ([f"ge-0/0/{i}" for i in range(0, 16)], []),
    "SRX345": ([f"ge-0/0/{i}" for i in range(0, 16)], ["xe-0/0/16", "xe-0/0/17"]),
    "SRX380": ([f"ge-0/0/{i}" for i in range(0, 16)], [f"xe-0/0/{i}" for i in range(16, 20)]),
    "EdgeRouter 4": (["eth0", "eth1", "eth2", "eth3"], []),
    "EdgeRouter 6P": (["eth0", "eth1", "eth2", "eth3", "eth4", "eth5"], []),
    "EdgeRouter X": (["eth0", "eth1", "eth2", "eth3", "eth4"], []),
    "EdgeRouter X SFP": (["eth0", "eth1", "eth2", "eth3", "eth4"], ["sfp0"]),
    "EdgeRouter 12": ([f"eth{i}" for i in range(0, 10)], ["sfp0", "sfp1"]),
    # --- HPE / Aruba / ProCurve ---
    "Aruba 2530-24G": ([str(i) for i in range(1, 25)], ["sfp1", "sfp2"]),
    "Aruba 2530-48G": ([str(i) for i in range(1, 49)], ["sfp1", "sfp2", "sfp3", "sfp4"]),
    "Aruba 2930F-24G-4SFP+": ([str(i) for i in range(1, 25)], [f"sfpplus{i}" for i in range(1, 5)]),
    "Aruba 2930F-48G-4SFP+": ([str(i) for i in range(1, 49)], [f"sfpplus{i}" for i in range(1, 5)]),
    "Aruba 6100-24G": ([str(i) for i in range(1, 25)], [f"sfpplus{i}" for i in range(1, 5)]),
    "HPE OfficeConnect 1820-24G": ([str(i) for i in range(1, 25)], ["sfp1", "sfp2"]),
    "HPE OfficeConnect 1920S-24G": ([str(i) for i in range(1, 25)], ["sfp1", "sfp2"]),
    "ProCurve 2810-24G": ([str(i) for i in range(1, 25)], ["sfp1", "sfp2", "sfp3", "sfp4"]),
    "GS105": ([str(i) for i in range(1, 6)], []),
    "GS108": ([str(i) for i in range(1, 9)], []),
    "GS116": ([str(i) for i in range(1, 17)], []),
    "GS308": ([str(i) for i in range(1, 9)], []),
    "GS324": ([str(i) for i in range(1, 25)], []),
    "GS724": ([str(i) for i in range(1, 25)], ["sfp1", "sfp2", "sfp3", "sfp4"]),
    "GS748": ([str(i) for i in range(1, 49)], ["sfp1", "sfp2", "sfp3", "sfp4"]),
    "JGS524": ([str(i) for i in range(1, 25)], []),
    # Endpoints — typically one NIC (plus extras where common)
    "Workstation": (["eth0"], []),
    "Desktop PC": (["eth0"], []),
    "Dell Optiplex SFF": (["eth0"], []),
    "HP EliteDesk SFF": (["eth0"], []),
    "Lenovo ThinkCentre SFF": (["eth0"], []),
    "Intel NUC": (["eth0"], []),
    "Custom Tower": (["eth0"], []),
    "KVM Switch 4-port": (["console", "pc1", "pc2", "pc3", "pc4"], []),
    "KVM Switch 8-port": (["console"] + [f"pc{i}" for i in range(1, 9)], []),
    "KVM Switch 16-port": (["console"] + [f"pc{i}" for i in range(1, 17)], []),
    "IP KVM": (["eth0", "console"], []),
    "Synology": (["eth0", "eth1"], []),
    "QNAP": (["eth0", "eth1"], []),
    "TrueNAS": (["eth0", "eth1"], []),
    "Buffalo": (["eth0"], []),
    "Smart TV": (["eth0", "wifi"], []),
    "Samsung Smart TV": (["eth0", "wifi"], []),
    "LG OLED TV": (["eth0", "wifi"], []),
    "Sony Bravia TV": (["eth0", "wifi"], []),
    "Apple TV": (["eth0", "wifi"], []),
    "Fire TV": (["wifi", "eth0"], []),
    "Roku": (["wifi", "eth0"], []),
    "Chromecast": (["wifi"], []),
    "NVIDIA Shield": (["eth0", "wifi"], []),
    "Android TV": (["eth0", "wifi"], []),
    "PlayStation": (["eth0", "wifi"], []),
    "Xbox": (["eth0", "wifi"], []),
    "Nintendo Switch": (["wifi", "dock-eth"], []),
    "Steam Deck": (["dock-eth", "wifi"], []),
}


def default_ports_for_model(model: str) -> list[str]:
    """Return default front-panel port names for a known model string."""
    raw = model or ""
    m = raw.upper().replace(" ", "")
    for key, (copper, sfp) in _MODEL_PORT_LAYOUT.items():
        if key.upper().replace(" ", "") in m or key.upper() in raw.upper():
            return list(copper) + list(sfp)
    if "CRS328" in raw.upper():
        return [str(i) for i in range(1, 25)] + ["sfp1", "sfp2", "sfp3", "sfp4"]
    if "CRS326" in raw.upper():
        return [str(i) for i in range(1, 25)] + ["sfp1", "sfp2"]
    # Generic endpoint fallbacks by keyword
    low = raw.lower()
    if any(x in low for x in ("kvm",)):
        return ["console", "pc1", "pc2", "pc3", "pc4"]
    if any(x in low for x in ("nas", "synology", "qnap", "truenas")):
        return ["eth0", "eth1"]
    if any(x in low for x in ("tv", "roku", "fire tv", "apple tv", "shield", "chromecast")):
        return ["eth0", "wifi"]
    if any(x in low for x in ("playstation", "xbox", "nintendo", "steam deck")):
        return ["eth0", "wifi"]
    if any(x in low for x in ("workstation", "desktop", "sff", "optiplex", "elitedesk", "nuc")):
        return ["eth0"]
    return []


def kind_for_model(model: str) -> str:
    """Best-effort device kind from model string."""
    m = (model or "").lower()
    if any(x in m for x in ("fortigate", "fortiswitch", "fortiap", "fortiwifi", "fortinet")) or (
        m.startswith(("fg-", "fgt", "fs-1", "fs-2", "fs-4"))
    ):
        return "fortinet"
    if any(x in m for x in ("cisco", "catalyst", "nexus", "isr4", "asr1", "asa55", "firepower")):
        return "cisco"
    if "linksys" in m or "velop" in m or re.match(r"^(ea|mr|mx|lgs|lrt|wrt)\d{3,4}", m):
        return "linksys"
    if "srx" in m or "juniper" in m:
        return "juniper"
    # HPE now owns Juniper (and Aruba/ProCurve) — treat as the Juniper/HPE kind.
    if any(x in m for x in ("aruba", "procurve", "hpe", "officeconnect")):
        return "juniper"
    if "edgerouter" in m or "edge router" in m:
        return "ubiquiti"
    if "unmanaged" in m:
        return "netgear-unmanaged"
    if "managed" in m or any(
        x in m for x in ("gs108e", "gs116e", "gs324", "gs724", "gs748", "m4250", "xs708")
    ):
        return "netgear-managed"
    if any(x in m for x in ("gs105", "gs108", "gs116", "gs308", "jgs524", "gs908")):
        return "netgear-unmanaged"
    if any(x in m for x in ("crs", "css", "ccr", "hex", "hap", "rb40", "rb50")):
        return "mikrotik"
    if "pfsense" in m:
        return "pfsense"
    if "opnsense" in m:
        return "opnsense"
    if "kvm" in m:
        return "kvm"
    if any(x in m for x in ("nas", "synology", "qnap", "truenas", "linkstation")):
        return "nas"
    if any(x in m for x in ("playstation", "xbox", "nintendo switch", "steam deck")):
        return "game-console"
    if any(
        x in m
        for x in (
            "apple tv",
            "fire tv",
            "roku",
            "chromecast",
            "shield tv",
            "android tv",
            "set-top",
            "sky q",
            "video box",
        )
    ):
        return "video-box"
    if "tv" in m and "apple" not in m:
        return "tv"
    if "sff" in m or "optiplex" in m or "elitedesk" in m or "thinkcentre" in m or "nuc" in m:
        return "sff"
    if "workstation" in m:
        return "workstation"
    if "desktop" in m or "tower" in m:
        return "desktop"
    return ""


LINK_KINDS = [
    "copper",
    "fiber",
    "sfp",
    "trunk",
    "access",
    "lag",
    "wireless",
    "vpn",
    "other",
]

VPN_KINDS = [
    "wireguard",
    "ipsec",
    "openvpn",
    "l2tp",
    "sstp",
    "gre",
    "eoip",
    "other",
]


def _csv_list(text: str) -> list[str]:
    return [p.strip() for p in text.replace(";", ",").split(",") if p.strip()]


def _list_csv(items: list[str]) -> str:
    return ", ".join(items)


DEVICE_ROLES = [
    "",
    "upstream",
    "isp",
    "egress",
    "firewall",
    "core-switch",
    "access-switch",
    "router",
    "access-point",
    "server",
    "workstation",
    "desktop",
    "sff",
    "kvm",
    "nas",
    "tv",
    "video-box",
    "game-console",
    "host",
    "remote-router",
    "other",
]

# Left→right column for physical-layout diagram (Excel-style).
ROLE_TIER = {
    "upstream": 0,
    "isp": 0,
    "egress": 1,
    "firewall": 2,
    "router": 2,
    "core-switch": 3,
    "core": 3,
    "access-switch": 4,
    "access": 4,
    "access-point": 5,
    "kvm": 5,
    "server": 5,
    "nas": 5,
    "workstation": 6,
    "desktop": 6,
    "sff": 6,
    "host": 6,
    "tv": 6,
    "video-box": 6,
    "game-console": 6,
    "remote-router": 7,
    "other": 4,
}


@dataclass
class PortComponent:
    """A NIC / switch port that is a component of a physical chassis."""

    name: str
    media: str = ""  # e.g. 1Gbps Eth, 1Gbps Fiber, or "100.48.62.1/24 · 1G"
    slot: str = ""  # e.g. Slot 1 Port 0 / pci0:1:0:0
    side: str = "right"  # left / right / bottom — preferred connector face
    address: str = ""  # assigned IPv4/IPv6 (primary), shown on topology NIC tiles

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "media": self.media,
            "slot": self.slot,
            "side": self.side,
            "address": self.address,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PortComponent":
        return cls(
            name=str(d.get("name", "")),
            media=str(d.get("media", "")),
            slot=str(d.get("slot", "")),
            side=str(d.get("side", "right") or "right"),
            address=str(d.get("address", "") or ""),
        )


@dataclass
class SshAccess:
    """SSH connection details for a device (session/login screen).

    Passwords are never stored here — only a credential_ref into the OS
    keyring, mirroring ConfigSource / MikroTik REST behaviour.
    """

    host: str = ""
    port: int = 22
    username: str = ""
    auth: str = "password"  # password | key
    key_path: str = ""
    credential_ref: str = ""
    last_status: str = ""  # ok | auth-fail | unreachable | never
    last_error: str = ""
    last_ok_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "auth": self.auth,
            "key_path": self.key_path,
            "credential_ref": self.credential_ref,
            "last_status": self.last_status,
            "last_error": self.last_error,
            "last_ok_at": self.last_ok_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "SshAccess | None":
        if not d:
            return None
        return cls(
            host=str(d.get("host", "")),
            port=int(d.get("port", 22) or 22),
            username=str(d.get("username", "")),
            auth=str(d.get("auth", "password") or "password"),
            key_path=str(d.get("key_path", "")),
            credential_ref=str(d.get("credential_ref", "")),
            last_status=str(d.get("last_status", "")),
            last_error=str(d.get("last_error", "")),
            last_ok_at=str(d.get("last_ok_at", "")),
        )


@dataclass
class ConfigSource:
    """How a device's configuration is obtained for analysis.

    Secrets are never stored here — only a credential_ref that maps into the
    OS keyring (Windows Credential Manager).
    """

    source_type: str = CONFIG_SOURCE_LOCAL  # local_file | mikrotik_rest
    # Local analyzable file (pfSense XML or MikroTik .rsc) or cached REST export.
    path: str = ""
    # Optional RouterOS binary .backup retained as restore evidence only.
    backup_artifact: str = ""
    # REST connection metadata (mikrotik_rest)
    host: str = ""
    port: int = 443
    username: str = ""
    verify_tls: bool = True
    ca_path: str = ""
    allow_insecure_tls: bool = False  # explicit opt-in for self-signed
    credential_ref: str = ""  # keyring service key / ref_id
    # Collection status
    last_collected_at: str = ""
    last_status: str = ""  # ok | error | stale | never
    last_error: str = ""
    export_hash: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_type": self.source_type,
            "path": self.path,
            "backup_artifact": self.backup_artifact,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "verify_tls": self.verify_tls,
            "ca_path": self.ca_path,
            "allow_insecure_tls": self.allow_insecure_tls,
            "credential_ref": self.credential_ref,
            "last_collected_at": self.last_collected_at,
            "last_status": self.last_status,
            "last_error": self.last_error,
            "export_hash": self.export_hash,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "ConfigSource | None":
        if not d:
            return None
        return cls(
            source_type=str(d.get("source_type", CONFIG_SOURCE_LOCAL) or CONFIG_SOURCE_LOCAL),
            path=str(d.get("path", "")),
            backup_artifact=str(d.get("backup_artifact", "")),
            host=str(d.get("host", "")),
            port=int(d.get("port", 443) or 443),
            username=str(d.get("username", "")),
            verify_tls=bool(d.get("verify_tls", True)),
            ca_path=str(d.get("ca_path", "")),
            allow_insecure_tls=bool(d.get("allow_insecure_tls", False)),
            credential_ref=str(d.get("credential_ref", "")),
            last_collected_at=str(d.get("last_collected_at", "")),
            last_status=str(d.get("last_status", "")),
            last_error=str(d.get("last_error", "")),
            export_hash=str(d.get("export_hash", "")),
            notes=str(d.get("notes", "")),
        )

    @classmethod
    def from_local_path(cls, path: str | Path) -> "ConfigSource":
        p = Path(path)
        suffix = p.suffix.lower()
        if suffix == ".backup":
            return cls(
                source_type=CONFIG_SOURCE_MIKROTIK_REST,
                backup_artifact=str(p),
                notes=(
                    "Binary .backup attached as restore evidence. "
                    "Analysis requires a live RouterOS 7 REST export."
                ),
                last_status="never",
            )
        return cls(
            source_type=CONFIG_SOURCE_LOCAL,
            path=str(p),
            last_status="ok" if p.is_file() else "error",
            last_error="" if p.is_file() else "Local config file not found",
        )

    def analyzable_path(self) -> str:
        """Path that check_file() can parse (XML or .rsc), if any."""
        return self.path or ""

    def display_status(self) -> str:
        if self.backup_artifact and not self.path:
            return "backup-only (needs REST export)"
        return self.last_status or "never"


@dataclass
class Device:
    name: str
    kind: str = "other"
    model: str = ""
    role: str = ""  # e.g. access-switch, core-switch, firewall, egress
    secpol: str = ""  # e.g. S1 / S5 — security policy zone
    priority: str = ""  # 0=main, 1=reserve, 2=backup (WAN path)
    hardware: str = ""  # e.g. Dell Optiplex 9010
    software_version: str = ""  # OS / firmware from SSH inventory or config pull
    config_file: str = ""  # legacy; mirrored from config_source.path
    config_source: ConfigSource | None = None
    ssh: SshAccess | None = None
    notes: str = ""
    ports: list[str] = field(default_factory=list)
    components: list[PortComponent] = field(default_factory=list)
    mgmt_ip: str = ""
    # Canvas position (scene pixels). None = auto-place.
    x: float | None = None
    y: float | None = None
    # Optional chassis size override (scene pixels). None = auto-fit content.
    w: float | None = None
    h: float | None = None
    # Port layout on the canvas: "row" (one row), "flat" (two rows, switch
    # style), "rect" (rows to fit the box). "" = row.
    port_layout: str = ""
    # Operator chose to ignore this device on Login to Routers (for example
    # the same box reached through another VLAN). Greyed out, never probed.
    ignored: bool = False
    # Last interface inventory (ssh_inventory.InventoryResult.to_dict()).
    inventory: dict[str, Any] = field(default_factory=dict)

    def ensure_ssh(self) -> SshAccess:
        """Return (creating if needed) the SSH access record for this device."""
        if self.ssh is None:
            self.ssh = SshAccess(host=self.mgmt_ip, last_status="never")
        elif not self.ssh.host and self.mgmt_ip:
            self.ssh.host = self.mgmt_ip
        return self.ssh

    def ensure_config_source(self) -> ConfigSource | None:
        """Migrate legacy config_file into config_source when needed."""
        if self.config_source is not None:
            if self.config_source.path and not self.config_file:
                self.config_file = self.config_source.path
            return self.config_source
        if self.config_file:
            self.config_source = ConfigSource.from_local_path(self.config_file)
            return self.config_source
        return None

    def attach_local_config(self, path: str | Path) -> ConfigSource:
        src = ConfigSource.from_local_path(path)
        # Preserve existing REST metadata when attaching a .backup only.
        if self.config_source and src.backup_artifact and not src.path:
            src.host = self.config_source.host
            src.port = self.config_source.port
            src.username = self.config_source.username
            src.verify_tls = self.config_source.verify_tls
            src.ca_path = self.config_source.ca_path
            src.allow_insecure_tls = self.config_source.allow_insecure_tls
            src.credential_ref = self.config_source.credential_ref
            src.path = self.config_source.path
            src.export_hash = self.config_source.export_hash
            src.last_collected_at = self.config_source.last_collected_at
            src.last_status = self.config_source.last_status or "never"
        self.config_source = src
        if src.path:
            self.config_file = src.path
        elif src.backup_artifact and not self.config_file:
            self.config_file = src.backup_artifact
        return src

    def to_dict(self) -> dict[str, Any]:
        self.ensure_config_source()
        return {
            "name": self.name,
            "kind": self.kind,
            "model": self.model,
            "role": self.role,
            "secpol": self.secpol,
            "priority": self.priority,
            "hardware": self.hardware,
            "software_version": self.software_version,
            "config_file": self.config_file,
            "config_source": self.config_source.to_dict() if self.config_source else None,
            "ssh": self.ssh.to_dict() if self.ssh else None,
            "notes": self.notes,
            "ports": list(self.ports),
            "components": [c.to_dict() for c in self.components],
            "mgmt_ip": self.mgmt_ip,
            "x": self.x,
            "y": self.y,
            "w": self.w,
            "h": self.h,
            "port_layout": self.port_layout,
            "ignored": self.ignored,
            "inventory": dict(self.inventory),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Device":
        comps = d.get("components", [])
        ports = [str(p) for p in d.get("ports", [])]
        components = [PortComponent.from_dict(c) for c in comps] if comps else []
        # Back-compat: synthesise components from bare port names
        if not components and ports:
            components = [PortComponent(name=p) for p in ports]
        x = d.get("x")
        y = d.get("y")
        w = d.get("w")
        h = d.get("h")
        src = ConfigSource.from_dict(d.get("config_source"))
        config_file = str(d.get("config_file", ""))
        device = cls(
            name=str(d.get("name", "")),
            kind=str(d.get("kind", "other")),
            model=str(d.get("model", "")),
            role=str(d.get("role", "")),
            secpol=str(d.get("secpol", "")),
            priority=str(d.get("priority", "")),
            hardware=str(d.get("hardware", "")),
            software_version=str(d.get("software_version", "")),
            config_file=config_file,
            config_source=src,
            ssh=SshAccess.from_dict(d.get("ssh")),
            notes=str(d.get("notes", "")),
            ports=ports,
            components=components,
            mgmt_ip=str(d.get("mgmt_ip", "")),
            x=float(x) if x is not None else None,
            y=float(y) if y is not None else None,
            w=float(w) if w is not None else None,
            h=float(h) if h is not None else None,
            port_layout=str(d.get("port_layout", "") or ""),
            ignored=bool(d.get("ignored", False)),
            inventory=dict(d.get("inventory") or {}),
        )
        device.ensure_config_source()
        return device

    def ensure_components(self) -> None:
        """Keep components in sync with ports list (ports remain the source of names)."""
        known = {c.name for c in self.components}
        for p in self.ports:
            if p and p not in known:
                self.components.append(PortComponent(name=p))
                known.add(p)
        # If components exist but ports empty, back-fill ports
        if not self.ports and self.components:
            self.ports = [c.name for c in self.components]

    def subtitle(self) -> str:
        bits = [x for x in (self.model or self.kind, self.role) if x]
        return " · ".join(bits)

    def _display_model(self) -> str:
        """Model string for headers — hardware model or a vendor kind fallback."""
        for candidate in (self.model, self.hardware):
            text = (candidate or "").strip()
            if text:
                return text
        kind = (self.kind or "").strip().lower()
        if kind in {
            "mikrotik",
            "pfsense",
            "opnsense",
            "juniper",
            "ubiquiti",
            "netgear-managed",
            "netgear-unmanaged",
            "fortinet",
            "cisco",
            "linksys",
        }:
            return kind.replace("-", " ").title()
        return ""

    def chassis_title(self) -> str:
        """Primary topology header — model and device name."""
        model = self._display_model()
        name = (self.name or "").strip()
        if model and name and model.casefold() != name.casefold():
            return f"{model} · {name}"
        if model:
            return model
        return name or "device"

    def chassis_subtitle(self) -> str:
        """Secondary topology header — role / SECPOL (name is in the title)."""
        title = self.chassis_title()
        parts: list[str] = []
        line = self.header_line()
        if line and line.lower() not in title.lower():
            parts.append(line)
        if not parts:
            role = (self.role or "").replace("-", " ").strip()
            if role and role.lower() not in title.lower():
                parts.append(role.title() if role.islower() else role)
        return " · ".join(parts)

    def tier(self) -> int:
        return ROLE_TIER.get((self.role or "").lower(), ROLE_TIER.get(self.kind, 4))

    def header_line(self) -> str:
        """Excel-style title e.g. 'Firewall 2   SECPOL: S5'."""
        role = (self.role or self.kind or "device").replace("-", " ").title()
        if self.secpol:
            return f"{role}   SECPOL: {self.secpol}"
        return role


@dataclass
class Link:
    a_device: str
    a_port: str = ""
    b_device: str = ""
    b_port: str = ""
    kind: str = "copper"  # copper / fiber / trunk / access / lag / vpn …
    speed: str = ""
    descr: str = ""
    vlans: list[str] = field(default_factory=list)  # tagged VLAN IDs on a trunk
    native_vlan: str = ""  # untagged / PVID
    bridge: str = ""  # optional site bridge this link belongs to

    def to_dict(self) -> dict[str, Any]:
        return {
            "a_device": self.a_device,
            "a_port": self.a_port,
            "b_device": self.b_device,
            "b_port": self.b_port,
            "kind": self.kind,
            "speed": self.speed,
            "descr": self.descr,
            "vlans": list(self.vlans),
            "native_vlan": self.native_vlan,
            "bridge": self.bridge,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Link":
        vlans = d.get("vlans", [])
        if isinstance(vlans, str):
            vlans = _csv_list(vlans)
        return cls(
            a_device=str(d.get("a_device", "")),
            a_port=str(d.get("a_port", "")),
            b_device=str(d.get("b_device", "")),
            b_port=str(d.get("b_port", "")),
            kind=str(d.get("kind", "copper")),
            speed=str(d.get("speed", "")),
            descr=str(d.get("descr", "")),
            vlans=[str(v) for v in vlans],
            native_vlan=str(d.get("native_vlan", "")),
            bridge=str(d.get("bridge", "")),
        )

    def label(self) -> str:
        a = f"{self.a_device}:{self.a_port}" if self.a_port else self.a_device
        b = f"{self.b_device}:{self.b_port}" if self.b_port else self.b_device
        base = f"{a} \u2194 {b}"
        bits: list[str] = []
        if self.kind and self.kind != "copper":
            bits.append(self.kind)
        if self.speed:
            bits.append(self.speed)
        if self.vlans:
            bits.append(f"vlans={_list_csv(self.vlans)}")
        if self.native_vlan:
            bits.append(f"native={self.native_vlan}")
        if self.descr:
            bits.append(self.descr)
        return f"{base}  ({'; '.join(bits)})" if bits else base


@dataclass
class SiteVlan:
    """A site-wide VLAN that may span multiple switches/routers.

    Field names mirror the Excel physical-layout cards:
    IF (if_label), NW (subnet), S-IP/GW (s_ip / gateway), DHCP (dhcp_pool).
    """

    id: str
    name: str = ""
    subnet: str = ""  # NW
    if_label: str = ""  # IF e.g. E5-S5-VL140-PFSense
    s_ip: str = ""  # station / interface IP
    dhcp_pool: str = ""
    devices: list[str] = field(default_factory=list)  # devices that carry it
    gateway: str = ""  # device (or IP) that routes this VLAN
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "subnet": self.subnet,
            "if_label": self.if_label,
            "s_ip": self.s_ip,
            "dhcp_pool": self.dhcp_pool,
            "devices": list(self.devices),
            "gateway": self.gateway,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SiteVlan":
        devices = d.get("devices", [])
        if isinstance(devices, str):
            devices = _csv_list(devices)
        return cls(
            id=str(d.get("id", "")),
            name=str(d.get("name", "")),
            subnet=str(d.get("subnet", "")),
            if_label=str(d.get("if_label", "")),
            s_ip=str(d.get("s_ip", "")),
            dhcp_pool=str(d.get("dhcp_pool", "")),
            devices=[str(x) for x in devices],
            gateway=str(d.get("gateway", "")),
            notes=str(d.get("notes", "")),
        )


@dataclass
class SiteBridge:
    """A bridge domain spanning ports/devices (L2 domain)."""

    name: str
    devices: list[str] = field(default_factory=list)
    ports: list[str] = field(default_factory=list)  # "Device:port" entries
    vlan: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "devices": list(self.devices),
            "ports": list(self.ports),
            "vlan": self.vlan,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SiteBridge":
        devices = d.get("devices", [])
        ports = d.get("ports", [])
        if isinstance(devices, str):
            devices = _csv_list(devices)
        if isinstance(ports, str):
            ports = _csv_list(ports)
        return cls(
            name=str(d.get("name", "")),
            devices=[str(x) for x in devices],
            ports=[str(x) for x in ports],
            vlan=str(d.get("vlan", "")),
            notes=str(d.get("notes", "")),
        )


@dataclass
class VpnAgreement:
    """A VPN tunnel / peer agreement between two devices (or device ↔ remote)."""

    name: str
    kind: str = "wireguard"
    a_device: str = ""
    b_device: str = ""
    local_endpoint: str = ""
    remote_endpoint: str = ""
    networks: list[str] = field(default_factory=list)  # routed subnets
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "a_device": self.a_device,
            "b_device": self.b_device,
            "local_endpoint": self.local_endpoint,
            "remote_endpoint": self.remote_endpoint,
            "networks": list(self.networks),
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "VpnAgreement":
        networks = d.get("networks", [])
        if isinstance(networks, str):
            networks = _csv_list(networks)
        return cls(
            name=str(d.get("name", "")),
            kind=str(d.get("kind", "wireguard")),
            a_device=str(d.get("a_device", "")),
            b_device=str(d.get("b_device", "")),
            local_endpoint=str(d.get("local_endpoint", "")),
            remote_endpoint=str(d.get("remote_endpoint", "")),
            networks=[str(x) for x in networks],
            notes=str(d.get("notes", "")),
        )


@dataclass
class EgressPath:
    """How traffic leaves the site: ISP / uplink / default route owner."""

    name: str
    device: str = ""  # egress router / firewall
    uplink_port: str = ""
    upstream: str = ""  # ISP / next hop device name
    wan_subnet: str = ""
    default_for: list[str] = field(default_factory=list)  # VLANs or "all"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "device": self.device,
            "uplink_port": self.uplink_port,
            "upstream": self.upstream,
            "wan_subnet": self.wan_subnet,
            "default_for": list(self.default_for),
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EgressPath":
        default_for = d.get("default_for", [])
        if isinstance(default_for, str):
            default_for = _csv_list(default_for)
        return cls(
            name=str(d.get("name", "")),
            device=str(d.get("device", "")),
            uplink_port=str(d.get("uplink_port", "")),
            upstream=str(d.get("upstream", "")),
            wan_subnet=str(d.get("wan_subnet", "")),
            default_for=[str(x) for x in default_for],
            notes=str(d.get("notes", "")),
        )


@dataclass
class SiteTopology:
    name: str = "My Site"
    devices: list[Device] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    vlans: list[SiteVlan] = field(default_factory=list)
    bridges: list[SiteBridge] = field(default_factory=list)
    vpn: list[VpnAgreement] = field(default_factory=list)
    egress: list[EgressPath] = field(default_factory=list)
    subnets: list[str] = field(default_factory=list)  # site CIDRs (login screen)
    grid_size: int = 20

    def device(self, name: str) -> Device | None:
        for d in self.devices:
            if d.name == name:
                return d
        return None

    def add_or_update_device(self, device: Device) -> None:
        existing = self.device(device.name)
        if existing is None:
            device.ensure_components()
            device.ensure_config_source()
            self.devices.append(device)
            return
        existing.kind = device.kind or existing.kind
        existing.model = device.model or existing.model
        existing.role = device.role or existing.role
        existing.secpol = device.secpol or existing.secpol
        existing.priority = device.priority or existing.priority
        existing.hardware = device.hardware or existing.hardware
        existing.config_file = device.config_file or existing.config_file
        if device.config_source is not None:
            existing.config_source = device.config_source
        existing.notes = device.notes or existing.notes
        existing.mgmt_ip = device.mgmt_ip or existing.mgmt_ip
        for p in device.ports:
            if p not in existing.ports:
                existing.ports.append(p)
        for c in device.components:
            if not any(x.name == c.name for x in existing.components):
                existing.components.append(c)
        existing.ensure_components()
        existing.ensure_config_source()

    def snap(self, value: float) -> float:
        g = max(5, int(self.grid_size or 20))
        return round(value / g) * g

    def arrange_by_tier(self, *, col_pitch: float = 280.0, row_pitch: float = 200.0) -> None:
        """Place devices on a grid by role tier (left→right)."""
        buckets: dict[int, list[Device]] = {}
        for d in self.devices:
            d.ensure_components()
            buckets.setdefault(d.tier(), []).append(d)
        for t, group in buckets.items():
            group.sort(key=lambda d: (d.priority or "9", d.name))
            for i, d in enumerate(group):
                d.x = self.snap(40 + t * col_pitch)
                d.y = self.snap(40 + i * row_pitch)

    def ensure_positions(self) -> None:
        """Assign grid positions to any device missing coordinates."""
        missing = [d for d in self.devices if d.x is None or d.y is None]
        if not missing:
            for d in self.devices:
                d.ensure_components()
            return
        if all(d.x is None for d in self.devices):
            self.arrange_by_tier()
            return
        # Place missing ones below existing
        max_y = max((d.y or 0) for d in self.devices if d.y is not None)
        x0 = self.snap(40)
        for i, d in enumerate(missing):
            d.ensure_components()
            d.x = x0
            d.y = self.snap(max_y + 200 + i * 200)

    def remove_device(self, name: str) -> None:
        self.devices = [d for d in self.devices if d.name != name]
        self.links = [
            l for l in self.links if l.a_device != name and l.b_device != name
        ]
        for vlan in self.vlans:
            vlan.devices = [d for d in vlan.devices if d != name]
            if vlan.gateway == name:
                vlan.gateway = ""
        for br in self.bridges:
            br.devices = [d for d in br.devices if d != name]
            br.ports = [p for p in br.ports if not p.startswith(f"{name}:")]
        self.vpn = [
            v for v in self.vpn if v.a_device != name and v.b_device != name
        ]
        for eg in self.egress:
            if eg.device == name:
                eg.device = ""
            if eg.upstream == name:
                eg.upstream = ""

    def validate(self) -> list[str]:
        problems: list[str] = []
        names = {d.name for d in self.devices}
        seen_ports: set[tuple[str, str]] = set()

        for i, link in enumerate(self.links):
            for dev in (link.a_device, link.b_device):
                if dev and dev not in names:
                    problems.append(f"Link {i + 1}: device '{dev}' is not defined")
            if link.a_device and link.a_device == link.b_device:
                problems.append(f"Link {i + 1}: connects '{link.a_device}' to itself")
            for dev, port in (
                (link.a_device, link.a_port),
                (link.b_device, link.b_port),
            ):
                if dev and port:
                    key = (dev, port)
                    if key in seen_ports:
                        problems.append(
                            f"Link {i + 1}: port {dev}:{port} used more than once"
                        )
                    seen_ports.add(key)
            if link.kind in ("trunk", "access") and not link.vlans and not link.native_vlan:
                problems.append(
                    f"Link {i + 1}: {link.kind} has no VLANs / native VLAN set"
                )

        vlan_ids = {v.id for v in self.vlans if v.id}
        for vlan in self.vlans:
            for dev in vlan.devices:
                if dev and dev not in names:
                    problems.append(f"VLAN {vlan.id}: unknown device '{dev}'")
            if vlan.gateway and vlan.gateway not in names:
                # gateway may be an IP; only warn if it looks like a device name
                if not any(c.isdigit() for c in vlan.gateway) or "." not in vlan.gateway:
                    if vlan.gateway not in names:
                        problems.append(
                            f"VLAN {vlan.id}: gateway '{vlan.gateway}' is not a known device"
                        )

        for link in self.links:
            for vid in link.vlans:
                if self.vlans and vid not in vlan_ids:
                    problems.append(
                        f"Link {link.a_device}\u2194{link.b_device}: "
                        f"VLAN {vid} not listed in site VLANs"
                    )

        for br in self.bridges:
            for dev in br.devices:
                if dev and dev not in names:
                    problems.append(f"Bridge {br.name}: unknown device '{dev}'")

        for vpn in self.vpn:
            for dev in (vpn.a_device, vpn.b_device):
                if dev and dev not in names:
                    problems.append(f"VPN {vpn.name}: unknown device '{dev}'")

        for eg in self.egress:
            if eg.device and eg.device not in names:
                problems.append(f"Egress {eg.name}: device '{eg.device}' not defined")
            if eg.upstream and eg.upstream not in names:
                # upstream may be ISP label; only soft-check if kind=isp exists
                pass

        return problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "grid_size": self.grid_size,
            "devices": [d.to_dict() for d in self.devices],
            "links": [l.to_dict() for l in self.links],
            "vlans": [v.to_dict() for v in self.vlans],
            "bridges": [b.to_dict() for b in self.bridges],
            "vpn": [v.to_dict() for v in self.vpn],
            "egress": [e.to_dict() for e in self.egress],
            "subnets": list(self.subnets),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SiteTopology":
        site = cls(
            name=str(d.get("name", "My Site")),
            grid_size=int(d.get("grid_size", 20) or 20),
            devices=[Device.from_dict(x) for x in d.get("devices", [])],
            links=[Link.from_dict(x) for x in d.get("links", [])],
            vlans=[SiteVlan.from_dict(x) for x in d.get("vlans", [])],
            bridges=[SiteBridge.from_dict(x) for x in d.get("bridges", [])],
            vpn=[VpnAgreement.from_dict(x) for x in d.get("vpn", [])],
            egress=[EgressPath.from_dict(x) for x in d.get("egress", [])],
            subnets=[str(x) for x in d.get("subnets", []) if str(x).strip()],
        )
        for dev in site.devices:
            dev.ensure_components()
        return site

    def save(self, path: Path | str) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), indent=2), encoding="utf-8"
        )

    @classmethod
    def load(cls, path: Path | str) -> "SiteTopology":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)


@dataclass
class EnrichmentReport:
    """What changed when a config was merged into a base topology."""

    device_name: str = ""
    created_device: bool = False
    ports_added: list[str] = field(default_factory=list)
    vlans_added: list[str] = field(default_factory=list)
    vlans_updated: list[str] = field(default_factory=list)
    bridges_added: list[str] = field(default_factory=list)
    bridges_updated: list[str] = field(default_factory=list)
    vpn_added: list[str] = field(default_factory=list)
    egress_added: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        bits: list[str] = []
        if self.created_device:
            bits.append(f"created device '{self.device_name}'")
        else:
            bits.append(f"enriched '{self.device_name}'")
        if self.ports_added:
            bits.append(f"+{len(self.ports_added)} ports")
        if self.vlans_added:
            bits.append(f"+{len(self.vlans_added)} VLANs")
        if self.vlans_updated:
            bits.append(f"~{len(self.vlans_updated)} VLANs")
        if self.bridges_added:
            bits.append(f"+{len(self.bridges_added)} bridges")
        if self.vpn_added:
            bits.append(f"+{len(self.vpn_added)} VPN")
        if self.egress_added:
            bits.append(f"+{len(self.egress_added)} egress")
        return " · ".join(bits)

    @property
    def changed(self) -> bool:
        return bool(
            self.created_device
            or self.ports_added
            or self.vlans_added
            or self.vlans_updated
            or self.bridges_added
            or self.bridges_updated
            or self.vpn_added
            or self.egress_added
        )


def device_from_result(result: Any) -> Device:
    """Build a Device (with ports) from a parsed CheckResult."""
    name = result.hostname or (result.path.stem if result.path else "device")
    source = getattr(result, "source_type", "")
    if source == "mikrotik":
        kind = "mikrotik"
        model = str(result.summary.get("model", "") or "")
    else:
        kind = "pfsense"
        model = "pfSense"
    ports = [i.name for i in result.interfaces]
    # Prefer physical/device names when logical names are wan/lan/opt*
    for iface in result.interfaces:
        if iface.device and iface.device not in ports:
            ports.append(iface.device)
    if kind in ("pfsense", "opnsense"):
        role = "firewall"
    elif any(x in model.upper() for x in ("CRS3", "CRS2")):
        role = "core-switch"
    elif any(x in model.upper() for x in ("CRS1", "CSS")):
        role = "access-switch"
    else:
        role = "router"
    return Device(
        name=name,
        kind=kind,
        model=model,
        role=role,
        config_file=str(result.path) if result.path else "",
        ports=ports,
    )


def _norm(s: str) -> str:
    return "".join(ch for ch in (s or "").lower() if ch.isalnum())


def match_device_for_result(
    site: SiteTopology, result: Any, *, strict: bool = False
) -> Device | None:
    """Find an existing base-topology device that this config should enrich.

    Match order:
    1. config_file path equals the result path
    2. hostname equals device name (case-insensitive)
    3. hostname / path stem loosely matches device name or model
    4. single device of matching kind (pfsense/mikrotik) if unambiguous

    With strict=True only exact matches (1 and 2) are used. Batch folder
    imports must be strict, otherwise multiple same-vendor configs collapse
    into whichever device happened to be created first.
    """
    path_str = str(result.path) if getattr(result, "path", None) else ""
    host = (result.hostname or "").strip()
    stem = result.path.stem if getattr(result, "path", None) else ""

    if path_str:
        for d in site.devices:
            if d.config_file and Path(d.config_file).resolve() == Path(path_str).resolve():
                return d
            if d.config_file and Path(d.config_file).name == Path(path_str).name:
                return d

    if host:
        for d in site.devices:
            if d.name.lower() == host.lower():
                return d

    if strict:
        return None

    candidates = []
    needles = {_norm(x) for x in (host, stem) if x}
    for d in site.devices:
        hay = {_norm(d.name), _norm(d.model)}
        if needles & hay or any(
            n and (n in h or h in n) for n in needles for h in hay if h
        ):
            candidates.append(d)
    if len(candidates) == 1:
        return candidates[0]

    source = getattr(result, "source_type", "")
    kind = "mikrotik" if source == "mikrotik" else "pfsense"
    kind_matches = [d for d in site.devices if d.kind == kind]
    if len(kind_matches) == 1:
        return kind_matches[0]
    # Also allow role=firewall for pfSense when kind was set generically
    if kind == "pfsense":
        fw = [d for d in site.devices if d.role == "firewall" or d.kind in ("pfsense", "opnsense")]
        if len(fw) == 1:
            return fw[0]
    return None


def _merge_unique(dst: list[str], items: list[str]) -> list[str]:
    added: list[str] = []
    for item in items:
        if item and item not in dst:
            dst.append(item)
            added.append(item)
    return added


def _iface_static_address(iface: Any) -> str:
    """Return ``ip/prefix`` for a static pfSense interface assignment."""
    ip = (getattr(iface, "ipaddr", "") or "").strip()
    if not ip or ip.lower() in {"dhcp", "pppoe"}:
        return ""
    sub = (getattr(iface, "subnet", "") or "").strip()
    if sub and "." in ip:
        return f"{ip}/{sub}"
    return ip


def apply_config_to_device(device: Device, result: Any) -> int:
    """Populate chassis ``components`` / ``ports`` from a parsed config file."""
    interfaces = list(getattr(result, "interfaces", []) or [])
    if not interfaces:
        return 0

    comps: list[PortComponent] = []
    seen: set[str] = set()
    for iface in interfaces:
        logical = (getattr(iface, "name", "") or "").strip()
        label = logical.upper() if logical else (getattr(iface, "device", "") or "?")
        if label in seen:
            continue
        seen.add(label)
        media_bits: list[str] = []
        physical = (getattr(iface, "device", "") or "").strip()
        if physical and physical.lower() != logical.lower():
            media_bits.append(physical)
        descr = (getattr(iface, "descr", "") or "").strip()
        if descr:
            media_bits.append(descr)
        if not getattr(iface, "enabled", True):
            media_bits.append("disabled")
        bridge_of = (getattr(iface, "bridge_of", "") or "").strip()
        if bridge_of:
            media_bits.append(f"bridge:{bridge_of}")
        kind = (getattr(iface, "kind", "") or "").strip()
        if kind and kind not in {"physical", ""}:
            media_bits.append(kind)
        comps.append(
            PortComponent(
                name=label,
                media=" · ".join(media_bits),
                address=_iface_static_address(iface),
                side="right",
            )
        )

    for vlan in getattr(result, "vlans", []) or []:
        name = (getattr(vlan, "vlanif", "") or "").strip()
        if not name:
            tag = (getattr(vlan, "tag", "") or "").strip()
            name = f"vlan{tag}" if tag else ""
        if not name or name in seen:
            continue
        seen.add(name)
        bits: list[str] = []
        tag = (getattr(vlan, "tag", "") or "").strip()
        if tag:
            bits.append(f"tag {tag}")
        parent = (getattr(vlan, "if_parent", "") or "").strip()
        if parent:
            bits.append(parent)
        descr = (getattr(vlan, "descr", "") or "").strip()
        if descr:
            bits.append(descr)
        comps.append(
            PortComponent(name=name, media=" · ".join(bits), side="right")
        )

    if not comps:
        return 0

    device.components = comps
    device.ports = [c.name for c in comps]

    version = (getattr(result, "version", "") or "").strip()
    if version:
        device.software_version = version
    summary = getattr(result, "summary", {}) or {}
    model = str(summary.get("model", "") or "").strip()
    if model:
        device.model = model
    elif not device.model and getattr(result, "source_type", "") == "pfsense":
        device.model = "pfSense"

    return len(comps)


def refresh_device_topology_from_config(device: Device) -> int:
    """Parse the device's attached ``config.xml`` and refresh chassis ports."""
    device.ensure_config_source()
    path_str = ""
    src = device.config_source
    if src is not None:
        path_str = src.analyzable_path()
    if not path_str:
        path_str = device.config_file or ""
    path = Path(path_str)
    if not path.is_file():
        from pfsense_checker.paths import PROJECT_ROOT
        from pfsense_checker.routeros_rest import _safe_filename, cache_dir

        ssh = device.ssh
        host = (device.mgmt_ip or "").strip()
        if not host and ssh is not None:
            host = (ssh.host or "").strip()
        guess = (
            cache_dir(PROJECT_ROOT / "data")
            / f"{_safe_filename(device.name, host)}_config.xml"
        )
        if guess.is_file():
            path = guess
            device.attach_local_config(path)
    if not path.is_file() or path.suffix.lower() != ".xml":
        return 0
    kind = (device.kind or "").lower()
    if kind not in {"pfsense", "opnsense", "", "router", "firewall", "host"}:
        return 0

    from pfsense_checker.checker import check_file

    try:
        result = check_file(path)
    except Exception:  # noqa: BLE001
        return 0
    if not getattr(result, "valid_xml", False):
        return 0
    return apply_config_to_device(device, result)


def enrich_from_result(
    site: SiteTopology,
    result: Any,
    *,
    device_name: str | None = None,
    create_if_missing: bool = True,
    strict_match: bool = False,
) -> EnrichmentReport:
    """Merge inventory from a parsed config into an existing base topology.

    Never removes user-defined links, devices, VLANs, bridges, VPN, or egress.
    Only fills empty fields and appends newly discovered ports / overlays.
    """
    report = EnrichmentReport()

    target: Device | None = None
    if device_name:
        target = site.device(device_name)
        if target is None and not create_if_missing:
            report.notes.append(f"device '{device_name}' not found")
            return report
        if target is None:
            target = device_from_result(result)
            target.name = device_name
            site.devices.append(target)
            report.created_device = True
        else:
            discovered = device_from_result(result)
            if not target.kind or target.kind == "other":
                target.kind = discovered.kind
            if not target.model:
                target.model = discovered.model
            if not target.role:
                target.role = discovered.role
            if discovered.config_file and not target.config_file:
                target.config_file = discovered.config_file
    else:
        target = match_device_for_result(site, result, strict=strict_match)
        if target is None:
            if not create_if_missing:
                report.notes.append(
                    "no matching device in base topology "
                    "(pick a target device or allow create)"
                )
                return report
            target = device_from_result(result)
            site.devices.append(target)
            report.created_device = True
        else:
            discovered = device_from_result(result)
            if not target.kind or target.kind == "other":
                target.kind = discovered.kind
            if not target.model:
                target.model = discovered.model
            if not target.role:
                target.role = discovered.role
            if discovered.config_file and not target.config_file:
                target.config_file = discovered.config_file

    report.device_name = target.name

    # Ensure config path is recorded (enrichment anchor for next time)
    if result.path:
        if not target.config_file:
            target.config_file = str(result.path)
        elif Path(target.config_file).name == Path(str(result.path)).name:
            target.config_file = str(result.path)

    # Ports from logical names + underlying devices
    new_ports: list[str] = []
    for iface in result.interfaces:
        if iface.name:
            new_ports.append(iface.name)
        if iface.device:
            new_ports.append(iface.device)
    for vlan in result.vlans:
        if vlan.vlanif:
            new_ports.append(vlan.vlanif)
        if vlan.if_parent:
            new_ports.append(vlan.if_parent)
    for br in result.bridges:
        if br.bridgeif:
            new_ports.append(br.bridgeif)
        new_ports.extend(br.members)
    for lg in result.laggs:
        if lg.laggif:
            new_ports.append(lg.laggif)
        new_ports.extend(lg.members)

    report.ports_added = _merge_unique(target.ports, new_ports)
    target.ensure_components()

    # Management IP hint for SSH / monitoring (prefer MAN/MGMT-named ifaces)
    if not target.mgmt_ip:
        static_ifaces = [
            i
            for i in result.interfaces
            if i.ipaddr and i.ipaddr.lower() not in ("dhcp", "pppoe") and "." in i.ipaddr
        ]
        mgmt = next(
            (
                i
                for i in static_ifaces
                if any(k in (i.name + i.descr).upper() for k in ("MAN", "MGMT", "LAN"))
            ),
            None,
        )
        pick = mgmt or (static_ifaces[0] if static_ifaces else None)
        if pick is not None:
            target.mgmt_ip = pick.ipaddr

    # Kind/role fill-ins only when blank
    source = getattr(result, "source_type", "")
    if not target.kind or target.kind == "other":
        target.kind = "mikrotik" if source == "mikrotik" else "pfsense"
    if not target.model and target.kind == "pfsense":
        target.model = "pfSense"
    if not target.role:
        target.role = "firewall" if target.kind in ("pfsense", "opnsense") else "router"

    # --- VLANs ---
    vlan_by_id = {v.id: v for v in site.vlans if v.id}
    for vlan in result.vlans:
        vid = str(vlan.tag or "").strip()
        if not vid:
            continue
        existing = vlan_by_id.get(vid)
        if existing is None:
            site.vlans.append(
                SiteVlan(
                    id=vid,
                    name=vlan.descr or vlan.vlanif or "",
                    if_label=vlan.vlanif or vlan.descr or "",
                    devices=[target.name],
                    gateway=target.name if target.role == "firewall" else "",
                    notes=f"from {Path(str(result.path)).name if result.path else 'config'}",
                )
            )
            vlan_by_id[vid] = site.vlans[-1]
            report.vlans_added.append(vid)
        else:
            changed = False
            if target.name not in existing.devices:
                existing.devices.append(target.name)
                changed = True
            if not existing.name and (vlan.descr or vlan.vlanif):
                existing.name = vlan.descr or vlan.vlanif
                changed = True
            if not existing.gateway and target.role == "firewall":
                existing.gateway = target.name
                changed = True
            if changed:
                report.vlans_updated.append(vid)

    # Subnet hints from interface addresses on VLAN-ish ifaces
    for iface in result.interfaces:
        if not iface.ipaddr or iface.ipaddr.lower() in ("dhcp", "pppoe", ""):
            continue
        # Match VLAN by assigned name / vlanif
        for vlan in result.vlans:
            if iface.name == vlan.assigned_as or iface.device == vlan.vlanif or iface.name == vlan.vlanif:
                vid = str(vlan.tag or "").strip()
                site_vlan = vlan_by_id.get(vid)
                if site_vlan and not site_vlan.subnet and iface.subnet:
                    site_vlan.subnet = f"{iface.ipaddr}/{iface.subnet}"
                    if vid not in report.vlans_updated and vid not in report.vlans_added:
                        report.vlans_updated.append(vid)

    # DHCP scopes → subnet notes on matching interface-named VLANs is hard;
    # attach scope interface as a note only when VLAN id is in the scope name.
    for scope in result.dhcp_scopes:
        iface_name = scope.get("interface", "")
        for vlan in result.vlans:
            if vlan.assigned_as == iface_name or vlan.vlanif == iface_name:
                vid = str(vlan.tag or "").strip()
                site_vlan = vlan_by_id.get(vid)
                if site_vlan and not site_vlan.gateway:
                    site_vlan.gateway = target.name

    # --- Bridges ---
    bridge_by_name = {b.name: b for b in site.bridges}
    for br in result.bridges:
        bname = br.bridgeif or br.assigned_as or ""
        if not bname:
            continue
        # Prefer namespaced name if collision with another device's bridge
        site_name = bname
        if site_name in bridge_by_name and target.name not in bridge_by_name[site_name].devices:
            site_name = f"{target.name}:{bname}"
        member_ports = [f"{target.name}:{m}" for m in br.members if m]
        if br.bridgeif:
            member_ports.append(f"{target.name}:{br.bridgeif}")
        existing = bridge_by_name.get(site_name)
        if existing is None:
            # Also match bare name already listing this device
            existing = bridge_by_name.get(bname)
        if existing is None:
            site.bridges.append(
                SiteBridge(
                    name=site_name,
                    devices=[target.name],
                    ports=member_ports,
                    notes=br.descr or f"from config on {target.name}",
                )
            )
            bridge_by_name[site_name] = site.bridges[-1]
            report.bridges_added.append(site_name)
        else:
            changed = False
            if target.name not in existing.devices:
                existing.devices.append(target.name)
                changed = True
            if _merge_unique(existing.ports, member_ports):
                changed = True
            if changed:
                report.bridges_updated.append(existing.name)

    # --- VPN ---
    existing_vpn_names = {v.name for v in site.vpn}
    for vpn in result.vpn:
        vname = vpn.name or vpn.kind
        # Avoid clobbering a hand-authored agreement with the same name
        candidate = vname
        if candidate in existing_vpn_names:
            # If already present and points at this device, skip add
            already = next(
                (
                    v
                    for v in site.vpn
                    if v.name == candidate
                    and (v.a_device == target.name or v.b_device == target.name)
                ),
                None,
            )
            if already:
                continue
            candidate = f"{target.name}:{vname}"
            if candidate in existing_vpn_names:
                continue
        kind = (vpn.kind or "other").lower()
        if "wireguard" in kind:
            vk = "wireguard"
        elif "ipsec" in kind:
            vk = "ipsec"
        elif "openvpn" in kind or "ovpn" in kind:
            vk = "openvpn"
        elif "gre" in kind or "eoip" in kind:
            vk = "gre"
        else:
            vk = "other"
        site.vpn.append(
            VpnAgreement(
                name=candidate,
                kind=vk,
                a_device=target.name,
                b_device="",
                local_endpoint=vpn.interface or "",
                notes=(vpn.details or f"from config ({vpn.kind})").strip(),
            )
        )
        existing_vpn_names.add(candidate)
        report.vpn_added.append(candidate)

    # --- Egress hint from WAN-ish interfaces ---
    wan_ifaces = [
        i
        for i in result.interfaces
        if i.enabled
        and (
            i.name.lower() in ("wan", "optwan")
            or "wan" in i.name.lower()
            or (i.descr and "wan" in i.descr.lower())
        )
    ]
    if not wan_ifaces:
        wan_ifaces = [
            i
            for i in result.interfaces
            if i.enabled and i.ipaddr.lower() in ("dhcp", "pppoe")
        ]
    if wan_ifaces and target.role in ("firewall", "router", "egress", ""):
        wan = wan_ifaces[0]
        uplink = wan.device or wan.name
        eg_name = f"{target.name}-WAN"
        if not any(e.name == eg_name or (e.device == target.name and e.uplink_port == uplink) for e in site.egress):
            site.egress.append(
                EgressPath(
                    name=eg_name,
                    device=target.name,
                    uplink_port=uplink,
                    wan_subnet=wan.ipaddr
                    + (f"/{wan.subnet}" if wan.subnet and wan.ipaddr not in ("dhcp", "pppoe") else ""),
                    default_for=["all"],
                    notes="auto from config WAN interface",
                )
            )
            report.egress_added.append(eg_name)

    if not report.changed:
        report.notes.append("config matched; nothing new to merge")
    return report


def example_crs_site() -> SiteTopology:
    """Excel-style HQ physical layout: ISP → egress → pfSense → CRS328 → CRS109s."""
    site = SiteTopology(name="HQ — Physical Layout (CRS / pfSense)")
    site.devices = [
        Device(
            name="Swish-WAN1",
            kind="isp",
            model="Swish Fiber 900Mbps",
            role="isp",
            priority="0",
            ports=["wan"],
            notes="Online - Priority 0 (main)",
        ),
        Device(
            name="TalkTalk-WAN2",
            kind="isp",
            model="TalkTalk 150Mbps Fiber",
            role="isp",
            priority="1",
            ports=["wan"],
            notes="Online - Priority 1 (reserve)",
        ),
        Device(
            name="Edgerouter-Egress",
            kind="router",
            model="Edgerouter 4",
            role="egress",
            secpol="S1",
            hardware="Egress Security Node",
            ports=["eth0", "eth1", "eth2", "eth3"],
        ),
        Device(
            name="pfSense-FW",
            kind="pfsense",
            model="pfSense",
            role="firewall",
            secpol="S5",
            hardware="Dell Optiplex 9010",
            ports=["em0", "bxe0", "bxe1", "bxe2", "igb3"],
        ),
        Device(
            name="CRS328-Core",
            kind="switch",
            model="CRS328-24P-4S+",
            role="core-switch",
            secpol="S5",
            ports=[str(i) for i in range(1, 21)] + ["C1", "C2", "sfp-sfpplus1"],
        ),
        Device(
            name="CRS109-Office",
            kind="switch",
            model="CRS109-8G-1S-2HnD",
            role="access-switch",
            ports=["1", "2", "3", "4", "5", "6", "7", "8", "sfp1"],
            notes="Office",
        ),
        Device(
            name="CRS109-Upstairs",
            kind="switch",
            model="CRS109-8G-1S-2HnD",
            role="access-switch",
            ports=["1", "2", "3", "4", "5", "6", "7", "8", "sfp1"],
            notes="Upstairs",
        ),
        Device(
            name="CRS109-Lounge",
            kind="switch",
            model="CRS109-8G-1S-2HnD",
            role="access-switch",
            ports=["1", "2", "3", "4", "5", "6", "7", "8", "sfp1"],
            notes="Lounge",
        ),
        Device(
            name="Remote-Site",
            kind="mikrotik",
            model="hEX",
            role="remote-router",
            ports=["ether1", "wg0"],
        ),
    ]
    site.links = [
        Link(
            a_device="Swish-WAN1", a_port="wan",
            b_device="Edgerouter-Egress", b_port="eth0",
            kind="fiber", speed="1G", descr="WAN1 main",
        ),
        Link(
            a_device="TalkTalk-WAN2", a_port="wan",
            b_device="Edgerouter-Egress", b_port="eth1",
            kind="fiber", speed="1G", descr="WAN2 reserve",
        ),
        Link(
            a_device="Edgerouter-Egress", a_port="eth2",
            b_device="pfSense-FW", b_port="em0",
            kind="copper", speed="1G", descr="egress → firewall",
        ),
        Link(
            a_device="pfSense-FW", a_port="bxe0",
            b_device="CRS328-Core", b_port="sfp-sfpplus1",
            kind="trunk", speed="1G",
            vlans=["10", "20", "30", "140"],
            native_vlan="1",
            descr="firewall trunk",
        ),
        Link(
            a_device="CRS328-Core", a_port="1",
            b_device="CRS109-Office", b_port="sfp1",
            kind="trunk", speed="1G",
            vlans=["10", "20", "30"],
            descr="to Office",
        ),
        Link(
            a_device="CRS328-Core", a_port="2",
            b_device="CRS109-Upstairs", b_port="sfp1",
            kind="trunk", speed="1G",
            vlans=["10", "20", "30"],
            descr="to Upstairs",
        ),
        Link(
            a_device="CRS328-Core", a_port="3",
            b_device="CRS109-Lounge", b_port="sfp1",
            kind="trunk", speed="1G",
            vlans=["10", "20", "30"],
            descr="to Lounge",
        ),
    ]
    site.vlans = [
        SiteVlan(
            id="10", name="LAN",
            if_label="E5-S5-VL10-LAN",
            subnet="100.48.48.0/24", s_ip="100.48.48.1",
            dhcp_pool="100.48.48.64/25",
            devices=["CRS109-Office", "CRS109-Upstairs", "CRS109-Lounge", "CRS328-Core", "pfSense-FW"],
            gateway="pfSense-FW",
        ),
        SiteVlan(
            id="20", name="Servers",
            if_label="E5-S5-VL20-SRV",
            subnet="120.144.180.0/24", s_ip="120.144.180.1",
            dhcp_pool="120.144.180.80/31",
            devices=["CRS328-Core", "pfSense-FW"],
            gateway="pfSense-FW",
        ),
        SiteVlan(
            id="30", name="Guest",
            if_label="E5-S5-VL30-GST",
            subnet="10.10.30.0/24", s_ip="10.10.30.1",
            dhcp_pool="10.10.30.64/25",
            devices=["CRS109-Office", "CRS109-Lounge", "CRS328-Core", "pfSense-FW"],
            gateway="pfSense-FW",
        ),
        SiteVlan(
            id="140", name="PFSense-Transit",
            if_label="E5-S5-VL140-PFSense",
            subnet="44.89.20.0/24", s_ip="44.89.20.1",
            dhcp_pool="44.89.20.64/25",
            devices=["pfSense-FW", "Edgerouter-Egress"],
            gateway="pfSense-FW",
        ),
    ]
    site.bridges = [
        SiteBridge(
            name="bridge-lan",
            devices=["CRS109-Office", "CRS328-Core"],
            ports=["CRS109-Office:2", "CRS109-Office:3", "CRS328-Core:10"],
            vlan="10",
            notes="LAN bridge domain",
        )
    ]
    site.vpn = [
        VpnAgreement(
            name="HQ-to-Remote",
            kind="wireguard",
            a_device="pfSense-FW",
            b_device="Remote-Site",
            local_endpoint="wan:51820",
            remote_endpoint="remote.example:51820",
            networks=["10.99.0.0/24", "100.48.48.0/24"],
            notes="site-to-site VPN agreement",
        )
    ]
    site.egress = [
        EgressPath(
            name="Primary-WAN",
            device="Edgerouter-Egress",
            uplink_port="eth0",
            upstream="Swish-WAN1",
            wan_subnet="dhcp",
            default_for=["10", "20", "30", "all"],
            notes="Priority 0 main path",
        )
    ]
    return site
