"""Interface inventory over SSH: ports, link state, speed, MAC, addresses.

Rebuilt 2026-11-07 — this file had been committed empty (BUG-024).

* pfSense / OPNsense / FreeBSD: ``ifconfig -a``, ``pciconf -lv``, version,
  hardware and uptime.
* MikroTik RouterOS: ``/interface``, ``/ip address``, ``/interface vlan``,
  ``/system resource`` and ``/system routerboard`` (terse prints), then
  ``/interface ethernet monitor … once`` for each running port's negotiated
  rate.

Only read commands are sent. Credentials come from the device's saved SSH
login (OS keyring) through :func:`ssh_session.run_ssh_commands`; nothing is
written to the device. Every fact is tagged with where it came from so the
viewer can show it.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from pfsense_checker.topology_site import Device, PortComponent

SOURCE_SSH = "ssh"

# Interfaces that are not ports: loopback, pf logging/sync, encapsulation.
_SKIP_PREFIXES = ("lo", "pflog", "pfsync", "enc", "plip", "ipfw")


@dataclass
class InterfaceInventory:
    name: str
    mac: str = ""
    addresses: list[str] = field(default_factory=list)  # CIDR strings
    media: str = ""  # e.g. "Ethernet autoselect (1000baseT <full-duplex>)" / "1Gbps full"
    status: str = ""  # active / no carrier / link-ok / no-link / running / disabled
    mtu: int | None = None
    speed_mbps: float | None = None  # negotiated, when known
    duplex: str = ""
    kind: str = ""  # ether / vlan / bridge / lagg / wlan / tunnel …
    vlan_id: str = ""
    parent: str = ""
    pci: str = ""  # FreeBSD PCI locator
    pci_vendor: str = ""  # vendor + device
    comment: str = ""
    source: str = SOURCE_SSH

    @property
    def primary_address(self) -> str:
        return self.addresses[0] if self.addresses else ""

    @property
    def up(self) -> bool:
        return self.status in ("active", "link-ok", "running", "up")


@dataclass
class InventoryResult:
    ok: bool
    platform: str = ""  # freebsd / routeros
    interfaces: list[InterfaceInventory] = field(default_factory=list)
    error: str = ""
    system: dict[str, str] = field(default_factory=dict)  # model, version, uptime, serial…
    source: str = SOURCE_SSH
    collected_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "source": self.source,
            "collected_at": self.collected_at,
            "system": dict(self.system),
            "interfaces": [asdict(i) for i in self.interfaces],
        }


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #

_MEDIA_RATE = re.compile(r"(\d+(?:\.\d+)?)\s*(G|M)?(?:b(?:ase|ps)|Base)", re.IGNORECASE)


def media_speed(text: str) -> float | None:
    """'1000baseT' → 1000, '10Gbase-SR' → 10000, '1Gbps' → 1000, '100Mbps' → 100."""
    m = _MEDIA_RATE.search(text or "")
    if not m:
        return None
    value = float(m.group(1))
    unit = (m.group(2) or "").upper()
    if unit == "G":
        return value * 1000
    return value


def _split_command_output(text: str) -> dict[str, str]:
    """Split ``run_ssh_commands`` output ("$ cmd" headers) back per command."""
    out: dict[str, str] = {}
    current = None
    lines: list[str] = []
    for line in (text or "").splitlines():
        if line.startswith("$ "):
            if current is not None:
                out[current] = "\n".join(lines).strip()
            current, lines = line[2:].strip(), []
        else:
            lines.append(line)
    if current is not None:
        out[current] = "\n".join(lines).strip()
    return out


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# --------------------------------------------------------------------------- #
# FreeBSD (pfSense / OPNsense)
# --------------------------------------------------------------------------- #

_IF_HEAD = re.compile(r"^([A-Za-z0-9_.\-]+): flags=\S+.*?\bmtu (\d+)")


def parse_ifconfig(text: str) -> list[InterfaceInventory]:
    ifaces: list[InterfaceInventory] = []
    cur: InterfaceInventory | None = None
    for raw in (text or "").splitlines():
        head = _IF_HEAD.match(raw)
        if head:
            cur = InterfaceInventory(name=head.group(1), mtu=int(head.group(2)))
            name = cur.name
            if "." in name:
                cur.kind, cur.parent, cur.vlan_id = "vlan", name.split(".")[0], name.split(".")[1]
            elif name.startswith("bridge"):
                cur.kind = "bridge"
            elif name.startswith("lagg"):
                cur.kind = "lagg"
            elif name.startswith(("ovpn", "tun", "wg", "gif", "gre", "ipsec")):
                cur.kind = "tunnel"
            else:
                cur.kind = "ether"
            ifaces.append(cur)
            continue
        if cur is None:
            continue
        line = raw.strip()
        if line.startswith("ether "):
            cur.mac = line.split()[1].lower()
        elif line.startswith("inet ") and " netmask " in line:
            parts = line.split()
            ip = parts[1]
            mask_hex = parts[parts.index("netmask") + 1]
            try:
                bits = bin(int(mask_hex, 16)).count("1") if mask_hex.startswith("0x") else \
                    ipaddress.ip_network(f"0.0.0.0/{mask_hex}").prefixlen
                cur.addresses.append(f"{ip}/{bits}")
            except ValueError:
                cur.addresses.append(ip)
        elif line.startswith("media:"):
            cur.media = line.split(":", 1)[1].strip()
            m = re.search(r"\(([^)<]+)(?:<([^>]+)>)?\)", cur.media)
            if m:
                cur.speed_mbps = media_speed(m.group(1))
                cur.duplex = "full" if "full" in (m.group(2) or "") else ("half" if "half" in (m.group(2) or "") else "")
        elif line.startswith("status:"):
            cur.status = line.split(":", 1)[1].strip()
        elif line.startswith("vlan:"):
            m = re.search(r"vlan:\s*(\d+).*?parent interface:\s*(\S+)", line)
            if m:
                cur.kind, cur.vlan_id, cur.parent = "vlan", m.group(1), m.group(2)
        elif line.startswith("description:"):
            cur.comment = line.split(":", 1)[1].strip()
    return ifaces


_PCI_HEAD = re.compile(r"^([A-Za-z]+\d+)@(pci[\d:]+):")


def parse_pciconf_lv(text: str) -> dict[str, tuple[str, str]]:
    """``pciconf -lv`` → {driver name: (pci locator, "vendor device")}."""
    out: dict[str, tuple[str, str]] = {}
    name = loc = vendor = device = ""

    def flush() -> None:
        if name:
            out[name] = (loc, " ".join(x for x in (vendor, device) if x))

    for raw in (text or "").splitlines():
        head = _PCI_HEAD.match(raw.strip())
        if head:
            flush()
            name, loc, vendor, device = head.group(1), head.group(2).rstrip(":"), "", ""
            continue
        m = re.match(r"\s*(vendor|device)\s*=\s*'(.*)'", raw)
        if m:
            if m.group(1) == "vendor":
                vendor = m.group(2)
            else:
                device = m.group(2)
    flush()
    return out


_FREEBSD_COMMANDS = [
    "uname -sr",
    "cat /etc/version 2>/dev/null",
    "sysctl -n hw.model",
    "sysctl -n kern.hostname",
    "ifconfig -a",
    "pciconf -lv",
]


def _freebsd_result(text: str) -> InventoryResult:
    parts = _split_command_output(text)
    ifaces = [i for i in parse_ifconfig(parts.get("ifconfig -a", "")) if _include_interface(i)]
    pci = parse_pciconf_lv(parts.get("pciconf -lv", ""))
    for iface in ifaces:
        if iface.name in pci:
            iface.pci, iface.pci_vendor = pci[iface.name]
    system = {
        "os": parts.get("uname -sr", ""),
        "version": parts.get("cat /etc/version 2>/dev/null", ""),
        "cpu": parts.get("sysctl -n hw.model", ""),
        "hostname": parts.get("sysctl -n kern.hostname", ""),
    }
    return InventoryResult(
        ok=bool(ifaces),
        platform="freebsd",
        interfaces=ifaces,
        system={k: v for k, v in system.items() if v},
        error="" if ifaces else "ifconfig returned no interfaces",
        collected_at=_now(),
    )


# --------------------------------------------------------------------------- #
# RouterOS
# --------------------------------------------------------------------------- #

_TERSE_LINE = re.compile(r"^\s*(\d+)\s+([A-Z ]*?)\s*(?=[a-z0-9\-.]+=)")


def _terse_rows(text: str) -> list[tuple[str, dict[str, str]]]:
    """RouterOS ``print terse`` → [(flags, {key: value})]."""
    from pfsense_checker.mikrotik import _parse_pairs

    rows = []
    for line in (text or "").splitlines():
        m = _TERSE_LINE.match(line)
        if not m:
            continue
        rows.append((m.group(2).replace(" ", ""), _parse_pairs(line[m.end():])))
    return rows


def _colon_block(text: str) -> dict[str, str]:
    """``key: value`` lines (``print`` / ``monitor once``) → dict."""
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            if key and " " not in key:
                out[key] = value.strip()
    return out


_ROS_FIRST = [
    "/system resource print",
    "/system routerboard print",
    "/system identity print",
    "/interface print terse without-paging",
    "/ip address print terse without-paging",
    "/interface vlan print terse without-paging",
]


def _routeros_interfaces(parts: dict[str, str]) -> list[InterfaceInventory]:
    ifaces: dict[str, InterfaceInventory] = {}
    for flags, row in _terse_rows(parts.get("/interface print terse without-paging", "")):
        name = row.get("name", "")
        if not name:
            continue
        kind = row.get("type", "")
        status = "disabled" if "X" in flags else ("running" if "R" in flags else "down")
        ifaces[name] = InterfaceInventory(
            name=name,
            mac=(row.get("mac-address") or "").lower(),
            status=status,
            mtu=int(row["mtu"]) if (row.get("mtu") or "").isdigit() else None,
            kind={"ether": "ether", "vlan": "vlan", "bridge": "bridge", "bond": "lagg",
                  "wlan": "wlan", "wifi": "wlan"}.get(kind, kind or "other"),
            comment=row.get("comment", ""),
        )
    for flags, row in _terse_rows(parts.get("/ip address print terse without-paging", "")):
        iface = ifaces.get(row.get("interface", ""))
        if iface is not None and row.get("address") and "X" not in flags:
            iface.addresses.append(row["address"])
    for _flags, row in _terse_rows(parts.get("/interface vlan print terse without-paging", "")):
        iface = ifaces.get(row.get("name", ""))
        if iface is not None:
            iface.vlan_id = row.get("vlan-id", "")
            iface.parent = row.get("interface", "")
    return list(ifaces.values())


def apply_ethernet_monitor(iface: InterfaceInventory, text: str) -> None:
    info = _colon_block(text)
    if info.get("status"):
        iface.status = info["status"]
    rate = info.get("rate", "")
    if rate:
        iface.speed_mbps = media_speed(rate)
        iface.media = rate + (" full-duplex" if info.get("full-duplex") == "yes" else "")
    if info.get("full-duplex"):
        iface.duplex = "full" if info["full-duplex"] == "yes" else "half"
    if info.get("sfp-module-present") == "yes":
        iface.pci_vendor = " ".join(x for x in (info.get("sfp-vendor-name"), info.get("sfp-vendor-part-number")) if x)


def _routeros_system(parts: dict[str, str]) -> dict[str, str]:
    res = _colon_block(parts.get("/system resource print", ""))
    board = _colon_block(parts.get("/system routerboard print", ""))
    ident = _colon_block(parts.get("/system identity print", ""))
    system = {
        "model": board.get("model") or res.get("board-name", ""),
        "version": res.get("version", ""),
        "uptime": res.get("uptime", ""),
        "serial": board.get("serial-number", ""),
        "firmware": board.get("current-firmware", ""),
        "cpu": res.get("cpu", ""),
        "hostname": ident.get("name", ""),
    }
    return {k: v for k, v in system.items() if v}


# --------------------------------------------------------------------------- #
# Filtering, applying, collecting
# --------------------------------------------------------------------------- #


def _include_interface(iface: InterfaceInventory) -> bool:
    return not iface.name.startswith(_SKIP_PREFIXES)


def _media_summary(iface: InterfaceInventory) -> str:
    bits = []
    if iface.speed_mbps:
        s = iface.speed_mbps
        bits.append(f"{s / 1000:g}G" if s >= 1000 else f"{s:g}M")
    if iface.status:
        bits.append(iface.status)
    return " · ".join(bits)


def apply_inventory_to_device(dev: Device, result: InventoryResult) -> int:
    """Write ports, addresses and system facts onto *dev*. Returns ports set."""
    comps = []
    for iface in result.interfaces:
        if not _include_interface(iface):
            continue
        comps.append(
            PortComponent(
                name=iface.name,
                media=_media_summary(iface),
                slot=iface.pci,
                address=iface.primary_address,
            )
        )
    if comps:
        dev.components = comps
        dev.ports = [c.name for c in comps]
    generic = (dev.kind or "") in ("", "router", "switch", "host", "other")
    if generic and result.platform == "freebsd":
        dev.kind = "pfsense"
    elif generic and result.platform == "routeros":
        dev.kind = "mikrotik"
    sysinfo = result.system
    if sysinfo.get("model") and not dev.model:
        dev.model = sysinfo["model"]
    if sysinfo.get("version"):
        dev.software_version = sysinfo["version"]
    dev.inventory = result.to_dict()
    return len(comps)


def _platform_for(dev: Device) -> str:
    """routeros / freebsd from the device kind, or "" when it cannot tell."""
    kind = (dev.kind or "").lower()
    if kind == "mikrotik" or "mikrotik" in kind:
        return "routeros"
    if kind in ("pfsense", "opnsense"):
        return "freebsd"
    return ""


def collect_interfaces(device: Device, *, password: str | None = None) -> InventoryResult:
    """Collect over SSH (read-only commands, saved credentials)."""
    from pfsense_checker.ssh_session import run_ssh_commands

    platform = _platform_for(device)
    if not platform:
        probe = run_ssh_commands(device, ["uname -s"], password=password)
        if not probe.ok:
            return InventoryResult(ok=False, error=probe.error)
        text = probe.output.lower()
        platform = "routeros" if ("bad command" in text or "syntax error" in text) else "freebsd"
    if platform == "freebsd":
        run = run_ssh_commands(device, _FREEBSD_COMMANDS, password=password)
        if not run.ok:
            return InventoryResult(ok=False, platform=platform, error=run.error)
        return _freebsd_result(run.output)

    run = run_ssh_commands(device, _ROS_FIRST, password=password)
    if not run.ok:
        return InventoryResult(ok=False, platform=platform, error=run.error)
    parts = _split_command_output(run.output)
    ifaces = _routeros_interfaces(parts)
    ethers = [i for i in ifaces if i.kind == "ether" and i.status == "running"]
    if ethers:
        cmds = [f"/interface ethernet monitor [find name=\"{i.name}\"] once" for i in ethers]
        mon = run_ssh_commands(device, cmds, password=password)
        if mon.ok:
            outs = _split_command_output(mon.output) if len(cmds) > 1 else {cmds[0]: mon.output}
            for iface, cmd in zip(ethers, cmds):
                apply_ethernet_monitor(iface, outs.get(cmd, ""))
    return InventoryResult(
        ok=bool(ifaces),
        platform=platform,
        interfaces=[i for i in ifaces if _include_interface(i)],
        system=_routeros_system(parts),
        error="" if ifaces else "RouterOS returned no interfaces",
        collected_at=_now(),
    )
