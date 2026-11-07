"""Which VLANs each physical port carries, and which ports a bridge wraps.

Read from the device's own config (MikroTik export or pfSense config.xml), so
the topology can colour ports by VLAN, stripe trunks, hide VLAN interfaces and
bridges (they are not ports) and draw each bridge around its member ports.

MikroTik
  * Switch-chip VLANs (CRS1xx/2xx, bridge vlan-filtering off): the switch VLAN
    table lists member ports, egress-vlan-tag lists tagged ports; members that
    are not tagged are access (untagged) ports.
  * Otherwise the bridge VLAN table (tagged / untagged lists) plus each bridge
    port's PVID for access ports.
pfSense / OPNsense
  * A NIC is tagged for every VLAN whose parent it is.

Qt-free; colours are plain hex strings. (added 2026-11-07)
"""

from __future__ import annotations

import colorsys
import re
from dataclasses import dataclass, field
from pathlib import Path

CPU_PORTS = ("switch1-cpu", "switch2-cpu")


@dataclass
class PortVlans:
    untagged: list[str] = field(default_factory=list)  # access VLAN(s); more than one is a fault
    tagged: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def vlans(self) -> list[str]:
        out = list(self.untagged)
        out += [v for v in self.tagged if v not in out]
        return sorted(out, key=_vid_key)

    @property
    def is_trunk(self) -> bool:
        return bool(self.tagged)

    def describe(self) -> str:
        bits = []
        if self.untagged:
            bits.append("untagged " + ", ".join(self.untagged))
        if self.tagged:
            bits.append("tagged " + ", ".join(sorted(self.tagged, key=_vid_key)))
        return "VLANs: " + "; ".join(bits) if bits else ""


@dataclass
class DeviceVlans:
    ports: dict[str, PortVlans] = field(default_factory=dict)  # lower port name →
    vlan_ifaces: set[str] = field(default_factory=set)  # lower names that are VLAN interfaces
    bridges: dict[str, list[str]] = field(default_factory=dict)  # bridge name → member ports (lower)
    hidden: set[str] = field(default_factory=set)  # lower names that are bridges / bridge assignments
    names: dict[str, str] = field(default_factory=dict)  # VLAN id → a readable name

    def port(self, name: str) -> PortVlans | None:
        return self.ports.get((name or "").lower())

    def bridge_of(self, port: str) -> str:
        low = (port or "").lower()
        return next((b for b, members in self.bridges.items() if low in members), "")


def _vid_key(v: str) -> tuple:
    return (0, int(v)) if str(v).isdigit() else (1, str(v))


def _list(text) -> list[str]:  # noqa: ANN001
    """Comma-separated RouterOS list (names may contain spaces)."""
    return [x.strip() for x in str(text or "").split(",") if x.strip()]


def _vids(text) -> list[str]:  # noqa: ANN001
    out: list[str] = []
    for part in _list(text):
        m = re.fullmatch(r"(\d+)-(\d+)", part)
        if m and int(m.group(2)) - int(m.group(1)) < 64:
            out += [str(v) for v in range(int(m.group(1)), int(m.group(2)) + 1)]
        elif part.isdigit():
            out.append(part)
    return out


def _off(row: dict) -> bool:
    return str(row.get("disabled", "no")).lower() in ("yes", "true")


# Distinct, mid-strength colours handed out in VLAN-id order across a site, so
# neighbouring VLANs never look alike (port labels sit on a white chip).
PALETTE = (
    "#4e79a7", "#f28e2b", "#59a14f", "#e15759", "#b07aa1",
    "#edc948", "#76b7b2", "#ff9da7", "#9c755f", "#86bcb6",
)


def assign_palette(vids) -> dict[str, str]:  # noqa: ANN001
    """VLAN id → colour for every VLAN on a canvas: the palette in VLAN order,
    then evenly spread hues past ten."""
    ordered = sorted({str(v) for v in vids}, key=_vid_key)
    out = {}
    for i, vid in enumerate(ordered):
        out[vid] = PALETTE[i] if i < len(PALETTE) else vlan_color(vid)
    return out


def vlan_color(vid: str, palette: dict[str, str] | None = None) -> str:
    """Colour for a VLAN: the canvas palette when given, else a stable hue."""
    if palette and str(vid) in palette:
        return palette[str(vid)]
    try:
        n = int(vid)
    except (TypeError, ValueError):
        n = sum(ord(c) for c in str(vid))
    hue = (n * 0.618033988749895) % 1.0
    r, g, b = colorsys.hsv_to_rgb(hue, 0.55, 0.93)
    return f"#{int(r * 255):02x}{int(g * 255):02x}{int(b * 255):02x}"


# --------------------------------------------------------------------------- #


def from_result(result) -> DeviceVlans:  # noqa: ANN001
    if getattr(result, "source_type", "") == "mikrotik":
        return _mikrotik(result.summary.get("raw", {}))
    return _pfsense(result)


def _mikrotik(raw: dict) -> DeviceVlans:
    info = DeviceVlans()
    for v in raw.get("interface vlan", []):
        name = v.get("name", "")
        if name:
            info.vlan_ifaces.add(name.lower())
            if v.get("vlan-id"):
                info.names.setdefault(str(v["vlan-id"]), name)
    bridge_names = [b.get("name", "") for b in raw.get("interface bridge", []) if b.get("name")]
    info.hidden |= {b.lower() for b in bridge_names}
    pvid: dict[str, str] = {}
    trunk_only: set[str] = set()
    for bp in raw.get("interface bridge port", []):
        if _off(bp):
            continue
        port, bridge = bp.get("interface", ""), bp.get("bridge", "")
        if not port or port.startswith("*"):
            continue
        info.bridges.setdefault(bridge, []).append(port.lower())
        if bp.get("pvid"):
            pvid[port.lower()] = str(bp["pvid"])
        if bp.get("frame-types") == "admit-only-vlan-tagged":
            trunk_only.add(port.lower())

    def entry(port: str) -> PortVlans:
        return info.ports.setdefault(port.lower(), PortVlans())

    skip = {b.lower() for b in bridge_names} | set(CPU_PORTS)
    chip = [r for r in raw.get("interface ethernet switch vlan", []) if not _off(r)]
    if chip:
        tagged_by_vid: dict[str, set[str]] = {}
        for r in raw.get("interface ethernet switch egress-vlan-tag", []):
            if not _off(r):
                for vid in _vids(r.get("vlan-id")):
                    tagged_by_vid.setdefault(vid, set()).update(p.lower() for p in _list(r.get("tagged-ports")))
        for r in chip:
            for vid in _vids(r.get("vlan-id")):
                for port in _list(r.get("ports")):
                    if port.lower() in skip or port.startswith("*"):
                        continue
                    pv = entry(port)
                    target = pv.tagged if port.lower() in tagged_by_vid.get(vid, set()) else pv.untagged
                    if vid not in target:
                        target.append(vid)
    else:
        for r in raw.get("interface bridge vlan", []):
            if _off(r):
                continue
            for vid in _vids(r.get("vlan-ids")):
                for key, attr in (("tagged", "tagged"), ("untagged", "untagged")):
                    for port in _list(r.get(key)):
                        if port.lower() in skip or port.startswith("*"):
                            continue
                        target = getattr(entry(port), attr)
                        if vid not in target:
                            target.append(vid)
        for port, vid in pvid.items():
            if vid == "1" or port in trunk_only:
                continue
            pv = entry(port)
            if vid in pv.tagged:
                continue  # trunk whose PVID is one of its tagged VLANs
            if not pv.untagged:
                pv.untagged.append(vid)
            elif vid not in pv.untagged:
                pv.notes.append(f"PVID {vid} but untagged member of {', '.join(pv.untagged)}")
    for pv in info.ports.values():
        if len(pv.untagged) > 1:
            pv.notes.append("untagged in more than one VLAN")
    return info


def _pfsense(result) -> DeviceVlans:  # noqa: ANN001
    info = DeviceVlans()
    by_device: dict[str, list[str]] = {}
    for v in result.vlans:
        if v.vlanif:
            info.vlan_ifaces.add(v.vlanif.lower())
        if v.tag:
            info.names.setdefault(str(v.tag), v.descr or v.vlanif)
            if v.if_parent:
                by_device.setdefault(v.if_parent.lower(), []).append(str(v.tag))
    assigned: dict[str, str] = {}  # interface name (lower) → NIC / device
    for i in result.interfaces:
        dev = (i.device or "").lower()
        assigned[i.name.lower()] = dev
        if "." in dev or i.kind == "vlan":
            info.vlan_ifaces.add(i.name.lower())
    port_of_device = {dev: iface for iface, dev in assigned.items() if "." not in dev}
    for b in result.bridges:
        name = b.bridgeif
        info.hidden.add(name.lower())
        if b.assigned_as:
            info.hidden.add(b.assigned_as.lower())
        for i in result.interfaces:
            if (i.device or "").lower() == name.lower():
                info.hidden.add(i.name.lower())
        members: list[str] = []
        vlans_bridged: list[str] = []
        for m in b.members:
            low = m.lower()
            dev = assigned.get(low, low)
            if "." in dev:  # a VLAN interface: draw the bridge round the port it rides on
                parent, _, tag = dev.partition(".")
                low = port_of_device.get(parent, parent)
                if tag not in vlans_bridged:
                    vlans_bridged.append(tag)
            if low not in members:
                members.append(low)
        label = f"{name} (VLAN {', '.join(vlans_bridged)})" if vlans_bridged else name
        info.bridges[label] = members
    for iface, dev in assigned.items():
        tags = by_device.get(dev)
        if tags and iface not in info.vlan_ifaces:
            info.ports[iface] = PortVlans(tagged=sorted(set(tags), key=_vid_key))
    for dev, tags in by_device.items():  # the NIC by its own name too
        info.ports.setdefault(dev, PortVlans(tagged=sorted(set(tags), key=_vid_key)))
    return info


_CACHE: dict[str, tuple[float, DeviceVlans]] = {}


def for_device(device) -> DeviceVlans:  # noqa: ANN001
    """VLAN facts for a topology device, from its config (empty when none)."""
    from pfsense_checker import device_identity

    path = device_identity.config_path_for(device)
    if not path or not Path(path).is_file():
        return DeviceVlans()
    try:
        mtime = Path(path).stat().st_mtime
    except OSError:
        return DeviceVlans()
    hit = _CACHE.get(path)
    if hit is not None and hit[0] == mtime:
        return hit[1]
    try:
        from pfsense_checker.checker import check_file

        info = from_result(check_file(path))
    except Exception:  # noqa: BLE001 - a bad config must not break the canvas
        info = DeviceVlans()
    _CACHE[path] = (mtime, info)
    return info
