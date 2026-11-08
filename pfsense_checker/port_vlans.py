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
  * Uplinks (WANs and outbound tunnels) are the interfaces named wan, those
    with an upstream gateway or a DHCP / PPPoE address, OpenVPN clients
    (ovpncN) and ones described as WAN or EVL (external VLAN).

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
    ssid: str = ""  # wireless: the SSID whose clients land in the VLAN
    via: str = ""  # wireless: where that came from, e.g. "CAPsMAN on CRS328-MASTER"


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
class CapsmanIface:
    """A radio (or virtual AP) the CAPsMAN controller provisions."""

    name: str
    radio: str  # radio-name, matches the CAP's own wireless radio-name
    master: str  # master-interface ("" / "none" for the physical radio)
    vid: str
    ssid: str

@dataclass
class DeviceVlans:
    ports: dict[str, PortVlans] = field(default_factory=dict)  # lower port name →
    vlan_ifaces: set[str] = field(default_factory=set)  # lower names that are VLAN interfaces
    bridges: dict[str, list[str]] = field(default_factory=dict)  # bridge name → member ports (lower)
    hidden: set[str] = field(default_factory=set)  # lower names that are bridges / bridge assignments
    names: dict[str, str] = field(default_factory=dict)  # VLAN id → a readable name
    identity: str = ""  # device identity / hostname from its config
    radios: dict[str, str] = field(default_factory=dict)  # wlan name (lower) → radio-name
    capsman: list[CapsmanIface] = field(default_factory=list)  # set on a CAPsMAN controller
    uplinks: set[str] = field(default_factory=set)  # lower port / NIC names that face upstream
    # Bridges of VLAN interfaces (pfSense): bridge → [(port, VLAN id)]. The
    # bridge joins one VLAN segment of each port, not the whole port.
    segments: dict[str, list[tuple[str, str]]] = field(default_factory=dict)

    def key(self, name: str) -> str:
        """The config's (lower-case) name for a port. An older inventory cut
        names at the first space ("Fujitsu" for "Fujitsu PC (VL630)"): such a
        name maps to the one config name it starts, if there is just one."""
        low = (name or "").lower()
        known = set(self.ports) | {m for ms in self.bridges.values() for m in ms} | self.uplinks
        if not low or low in known:
            return low
        longer = [k for k in known if k.startswith(low + " ")]
        return longer[0] if len(longer) == 1 else low

    def port(self, name: str) -> PortVlans | None:
        return self.ports.get(self.key(name))

    def bridge_of(self, port: str) -> str:
        low = self.key(port)
        return next((b for b, members in self.bridges.items() if low in members), "")

    def segments_of(self, port: str) -> list[tuple[str, str]]:
        """[(bridge, VLAN id)] for each VLAN segment of *port* that a bridge joins."""
        low = self.key(port)
        return [(b, vid) for b, segs in self.segments.items() for p, vid in segs if p == low]

    def bridge_group(self, port: str) -> str:
        """The bridge a port is drawn with: as a member, or through a VLAN segment."""
        segs = self.segments_of(port)
        return self.bridge_of(port) or (segs[0][0] if segs else "")


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
        info = _mikrotik(result.summary.get("raw", {}))
    else:
        info = _pfsense(result)
    info.identity = getattr(result, "hostname", "") or info.identity
    return info


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
    _mikrotik_wireless(raw, info)
    ident = next(iter(raw.get("system identity", [])), {})
    info.identity = ident.get("name", "")
    return info


def _tagged_vid(mode: str, vid: str) -> str:
    return vid if (mode or "use-tag") != "no-tag" and vid and vid != "1" else ""


def _mikrotik_wireless(raw: dict, info: DeviceVlans) -> None:
    """SSIDs are tied to VLANs: an SSID tagged into a VLAN is an access port for it."""
    for w in raw.get("interface wireless", []) + raw.get("interface wifi", []):
        name = w.get("name") or w.get("default-name") or ""
        if not name:
            continue
        if w.get("radio-name"):
            info.radios[name.lower()] = str(w["radio-name"]).upper()
        if _off(w):
            continue
        vid = _tagged_vid(w.get("vlan-mode") or w.get("datapath.vlan-mode") or "no-tag",
                          str(w.get("vlan-id") or w.get("datapath.vlan-id") or ""))
        if vid:
            info.ports[name.lower()] = PortVlans(untagged=[vid], ssid=w.get("ssid", "") or
                                                 w.get("configuration.ssid", ""), via="this device")
    # A CAP puts the radios CAPsMAN manages on its bridge (dynamic bridge ports
    # that never appear in an export): /interface wireless cap bridge=…
    for c in raw.get("interface wireless cap", []) + raw.get("interface wifi cap", []):
        bridge = c.get("bridge") or c.get("slaves-datapath.bridge") or ""
        if not bridge or bridge == "none" or _off(c):
            continue
        members = info.bridges.setdefault(bridge, [])
        for wlan in _list(c.get("interfaces")):
            if wlan.lower() not in members:
                members.append(wlan.lower())
    # CAPsMAN controller: each provisioned radio / virtual AP and its SSID's VLAN.
    datapaths = {d.get("name", ""): d for d in raw.get("caps-man datapath", []) if d.get("name")}
    configs: dict[str, tuple[str, str]] = {}
    for c in raw.get("caps-man configuration", []):
        dp = datapaths.get(c.get("datapath", ""), {})
        vid = c.get(".vlan-id") or c.get("datapath.vlan-id") or dp.get("vlan-id", "")
        mode = c.get(".vlan-mode") or c.get("datapath.vlan-mode") or dp.get("vlan-mode", "use-tag")
        configs[c.get("name", "")] = (_tagged_vid(mode, str(vid)), c.get("ssid", ""))
    for ci in raw.get("caps-man interface", []):
        if ci.get("name"):  # a CAP's radio as the controller sees it: not a port here
            info.hidden.add(ci["name"].lower())
        if _off(ci) or not ci.get("name"):
            continue
        vid, ssid = configs.get(ci.get("configuration", ""), ("", ""))
        info.capsman.append(CapsmanIface(ci["name"], str(ci.get("radio-name", "")).upper(),
                                         ci.get("master-interface", ""), vid, ssid))
        info.ports[ci["name"].lower()] = PortVlans(untagged=[vid] if vid else [], ssid=ssid,
                                                   via="CAPsMAN (this controller)")


def link_capsman(devices: list[tuple[str, DeviceVlans, list[str]]]) -> None:
    """Give each CAP's wireless interfaces the VLAN its CAPsMAN controller assigns.

    *devices*: (device name, its VlanInfo, its port names). A CAP radio is matched
    to the controller's interface by radio-name; the CAP's other wlan interfaces
    are the virtual APs for the controller's slave configurations, in order.
    """
    by_radio: dict[str, tuple[str, CapsmanIface]] = {}
    slaves: dict[tuple[str, str], list[CapsmanIface]] = {}
    for name, info, _ports in devices:
        label = info.identity or name
        for ci in info.capsman:
            if ci.radio:
                by_radio[ci.radio] = (label, ci)
            if ci.master and ci.master.lower() != "none":
                slaves.setdefault((label, ci.master.lower()), []).append(ci)
    if not by_radio:
        return
    for _name, info, ports in devices:
        for wlan, radio in info.radios.items():
            hit = by_radio.get(radio)
            if hit is None:
                continue
            ctrl, master = hit
            via = f"CAPsMAN on {ctrl}"
            info.ports[wlan] = PortVlans(untagged=[master.vid] if master.vid else [], ssid=master.ssid, via=via)
            extra = sorted(
                {p.lower() for p in ports if p.lower().startswith(("wlan", "wifi"))} - {wlan} - set(info.radios),
                key=lambda s: (len(s), s),
            )
            bridge = info.bridge_of(wlan)
            for virt, slave in zip(extra, slaves.get((ctrl, master.name.lower()), [])):
                info.ports[virt] = PortVlans(untagged=[slave.vid] if slave.vid else [], ssid=slave.ssid,
                                             via=f"{via} (virtual AP)")
                if bridge and virt not in info.bridges[bridge]:
                    info.bridges[bridge].append(virt)  # virtual APs join the same bridge


UPLINK_V4 = {"dhcp", "pppoe", "pptp", "l2tp"}
UPLINK_V6 = {"dhcp6", "slaac", "pppoe", "6rd", "6to4"}
UPLINK_WORD = re.compile(r"(?<![a-z])(wan|evl)\d*(?![a-z])", re.IGNORECASE)


def is_pfsense_uplink(iface) -> bool:  # noqa: ANN001
    """A pfSense interface that faces upstream: WAN-type or an outbound tunnel."""
    raw = getattr(iface, "raw", {}) or {}
    dev = (iface.device or "").lower()
    return (
        iface.name.lower() == "wan"
        or (iface.ipaddr or "").lower() in UPLINK_V4
        or (iface.ipaddrv6 or "").lower() in UPLINK_V6
        or bool(raw.get("gateway") or raw.get("gatewayv6"))
        or dev.startswith("ovpnc")
        or bool(UPLINK_WORD.search((iface.descr or "").replace("_", " ")))
    )


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
        elif is_pfsense_uplink(i):
            info.uplinks.add(i.name.lower())
            if dev:
                info.uplinks.add(dev)
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
        segments: list[tuple[str, str]] = []
        vlans_bridged: list[str] = []
        for m in b.members:
            low = m.lower()
            dev = assigned.get(low, low)
            if "." in dev:  # a VLAN interface: the bridge joins that VLAN segment of its port
                parent, _, tag = dev.partition(".")
                seg = (port_of_device.get(parent, parent), tag)
                if tag not in vlans_bridged:
                    vlans_bridged.append(tag)
                if seg not in segments:
                    segments.append(seg)
            elif low not in members:
                members.append(low)
        label = f"{name} (VLAN {', '.join(vlans_bridged)})" if vlans_bridged else name
        info.bridges[label] = members
        if segments:
            info.segments[label] = segments
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
