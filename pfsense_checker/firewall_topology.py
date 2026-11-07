"""Layer a firewall config as Internet + external VLANs | gateway groups | NIC | port name | VLANs.

The outside world is on the left of the physical NICs, in one column:
Internet and the external VLANs (tunnels such as OpenVPN, IPsec, GIF, GRE,
WireGuard, anything named EVL<n>, and a WAN carried on a VLAN). A WAN NIC in
a gateway group reaches Internet only through the group's card; a WAN NIC in
no group goes straight to Internet. A tunnel bound to a group hangs off the
group; a tunnel bound to a single WAN hangs off that NIC.

The inside is on the right: a NIC that has an assignment of its own (UPLINK
on igb0) feeds that port name, and the VLANs on the NIC hang off the port
name. A NIC with no assignment of its own feeds its VLANs directly.

The label is the name set on the port (the description); OPT15 and the
other assignment ids stay on the second line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from pfsense_checker.models import CheckResult, InterfaceInfo, VlanInfo, VpnEndpoint

LAYERS = ("ext", "gw", "phys", "port", "vlan", "bridge")
INTERNET = "internet"

_EXTERNAL_NAME = re.compile(r"(?:^|[^a-z])evl", re.IGNORECASE)
_ASSIGNED = re.compile(r"^(?:wan|lan|opt\d+)$", re.IGNORECASE)
_WAN_DESCR = re.compile(r"(?:^|[^a-z])wan", re.IGNORECASE)
_VIRTUAL = (
    "bridge",
    "lagg",
    "ovpn",
    "openvpn",
    "ipsec",
    "enc",
    "gif",
    "gre",
    "pppoe",
    "ppp",
    "lo",
    "tun",
    "wg",
    "wireguard",
)
_TUNNEL = ("ovpn", "openvpn", "ipsec", "enc", "gif", "gre", "tun", "wg", "wireguard")
_TUNNEL_KINDS = {"openvpn", "ipsec", "gif", "gre"}


@dataclass(frozen=True)
class TopoBox:
    layer: str
    node_id: str
    title: str
    subtitle: str
    kind: str
    dim: bool = False


@dataclass(frozen=True)
class TopoLink:
    src_layer: str
    src_id: str
    dst_layer: str
    dst_id: str
    kind: str


@dataclass
class ConfigTopology:
    layers: dict[str, list[str]] = field(default_factory=dict)
    boxes: dict[tuple[str, str], TopoBox] = field(default_factory=dict)
    edges: list[TopoLink] = field(default_factory=list)


@dataclass
class TopoLayout:
    """Row per card. ``spans`` holds cards that cover several rows (Internet)."""

    rows: dict[str, dict[str, int]]
    spans: dict[tuple[str, str], int] = field(default_factory=dict)


def is_hardware_port(name: str) -> bool:
    """True for igb0 / ixl1 / em0. False for OPT15, igb0.10, lagg0."""
    text = (name or "").strip().lower()
    if not text or _ASSIGNED.match(text):
        return False
    if "." in text or "vlan" in text:
        return False
    return not text.startswith(_VIRTUAL)


def is_tunnel_device(name: str) -> bool:
    return (name or "").strip().lower().startswith(_TUNNEL)


def is_wan(iface: InterfaceInfo) -> bool:
    """WAN, a second WAN on an OPT, or any interface with an upstream gateway."""
    if is_tunnel_device(iface.device) or iface.kind in _TUNNEL_KINDS:
        return False
    name = (iface.name or "").lower()
    if name.startswith("wan"):
        return True
    if (iface.raw or {}).get("gateway", "").strip():
        return True
    if (iface.ipaddr or "").lower() in {"dhcp", "pppoe"}:
        return True
    return bool(_WAN_DESCR.search(iface.descr or ""))


def _loose(name: str) -> str:
    text = re.sub(r"[^a-z0-9]", "", (name or "").lower())
    return text[:-5] if text.endswith("group") else text


def build_config_topology(result: CheckResult) -> ConfigTopology:
    """Internet ← external VLANs ← groups ← NIC → port name → VLANs."""
    graph = ConfigTopology()
    by_name = {(i.name or "").lower(): i for i in result.interfaces if i.name}
    by_device: dict[str, InterfaceInfo] = {}
    for iface in result.interfaces:
        dev = (iface.device or "").strip().lower()
        if dev and dev not in by_device:
            by_device[dev] = iface
    by_vlanif = {v.vlanif.lower(): v for v in result.vlans if v.vlanif}
    bridge_ifs = {(b.bridgeif or "").lower() for b in result.bridges if b.bridgeif}
    lagg_ifs = {(lg.laggif or "").lower() for lg in result.laggs if lg.laggif}

    def resolve_hardware(token: str, depth: int = 0) -> str:
        text = (token or "").strip()
        if not text or depth > 6:
            return ""
        if is_hardware_port(text):
            return text.lower()
        low = text.lower()
        iface = by_name.get(low)
        if iface is not None and (iface.device or "").strip().lower() not in {"", low}:
            found = resolve_hardware(iface.device, depth + 1)
            if found:
                return found
        vlan = by_vlanif.get(low)
        if vlan is not None and (vlan.if_parent or "").strip():
            found = resolve_hardware(vlan.if_parent, depth + 1)
            if found:
                return found
        if "." in text:
            parent = text.split(".", 1)[0]
            if is_hardware_port(parent):
                return parent.lower()
        return ""

    wans = [iface for iface in result.interfaces if is_wan(iface)]
    wan_names = {iface.name.lower() for iface in wans}

    def is_external_vlan(vlan: VlanInfo) -> bool:
        assigned = _interface_for_vlan(vlan, result.interfaces)
        names = [vlan.descr or ""]
        if assigned is not None:
            names.append(assigned.descr or "")
            if assigned.name.lower() in wan_names:
                return True
        return any(_EXTERNAL_NAME.search(name) for name in names)

    external_vlans = {
        v.vlanif.lower() for v in result.vlans if v.vlanif and is_external_vlan(v)
    }

    wan_nics: list[str] = []
    for iface in wans:
        nic = resolve_hardware(iface.device)
        if nic and nic not in wan_nics:
            wan_nics.append(nic)
    gw_iface = {
        str(gw.get("name", "")).lower(): str(gw.get("interface", "")).lower()
        for gw in result.gateways
    }
    group_members: dict[str, list[str]] = {}
    for group in result.gateway_groups:
        name = str(group.get("name", "")).strip()
        members: list[str] = []
        for gw_name in group.get("members", []):
            nic = resolve_hardware(gw_iface.get(str(gw_name).lower(), ""))
            if nic and nic not in members:
                members.append(nic)
        if name and members:
            group_members[name.lower()] = members
    grouped = {nic for members in group_members.values() for nic in members}
    # A WAN straight on a NIC and in no group: its port card sits left of the
    # NIC, in the gateway column, and feeds Internet.
    wan_ports = {
        iface.name.lower(): iface.device.strip().lower()
        for iface in wans
        if is_hardware_port(iface.device) and iface.device.strip().lower() not in grouped
    }

    def card_of(iface: InterfaceInfo) -> tuple[str, str]:
        """Where an assigned interface is drawn."""
        dev = (iface.device or "").strip().lower()
        if iface.name.lower() in wan_ports:
            return ("gw", iface.name.lower())
        if dev in by_vlanif:
            return ("ext" if dev in external_vlans else "vlan", dev)
        if dev in bridge_ifs:
            return ("bridge", dev)
        if is_tunnel_device(dev) or iface.kind in _TUNNEL_KINDS:
            return ("ext", iface.name.lower())
        if _EXTERNAL_NAME.search(iface.descr or "") and not is_hardware_port(dev):
            return ("ext", iface.name.lower())
        return ("port", iface.name.lower())

    def carrier(token: str) -> tuple[str, str] | None:
        """The card a VLAN, bridge member, or LAGG child hangs from."""
        low = (token or "").strip().lower()
        if not low:
            return None
        if low in by_name:
            card = card_of(by_name[low])
            return ("phys", wan_ports[card[1]]) if card[0] == "gw" else card
        if low in by_device:
            card = card_of(by_device[low])
            return ("phys", wan_ports[card[1]]) if card[0] == "gw" else card
        if low in lagg_ifs:
            return ("port", low)
        if low in by_vlanif:
            return ("ext" if low in external_vlans else "vlan", low)
        if low in bridge_ifs:
            return ("bridge", low)
        nic = resolve_hardware(low)
        if nic:
            return ("phys", nic)
        return None

    def add_box(box: TopoBox) -> None:
        key = (box.layer, box.node_id)
        if key not in graph.boxes:
            graph.boxes[key] = box
            graph.layers.setdefault(box.layer, []).append(box.node_id)

    def add_edge(src: tuple[str, str] | None, dst: tuple[str, str], kind: str) -> None:
        if src is None or src == dst:
            return
        if src not in graph.boxes or dst not in graph.boxes:
            return
        link = TopoLink(src[0], src[1], dst[0], dst[1], kind)
        if link not in graph.edges:
            graph.edges.append(link)

    # Physical NICs that carry anything.
    nics: list[str] = []
    for vlan in result.vlans:
        nics.append(resolve_hardware(vlan.if_parent))
    for bridge in result.bridges:
        nics.extend(resolve_hardware(m) for m in bridge.members)
    for lagg in result.laggs:
        nics.extend(resolve_hardware(m) for m in lagg.members)
    for iface in result.interfaces:
        if is_hardware_port(iface.device):
            nics.append(iface.device.strip().lower())
    for nic in nics:
        if nic:
            add_box(TopoBox("phys", nic, nic, "physical port", "physical"))

    # Port names: interfaces assigned straight onto a NIC or LAGG, plus
    # anything else that is neither a VLAN, a bridge, nor external.
    for iface in result.interfaces:
        layer, node_id = card_of(iface)
        if layer in {"port", "gw"}:
            add_box(
                TopoBox(
                    layer,
                    node_id,
                    _port_title(iface),
                    ("WAN port · " if layer == "gw" else "") + _port_subtitle(iface),
                    "wanport" if layer == "gw" else iface.kind or "other",
                    dim=not iface.enabled,
                )
            )
    for lagg in result.laggs:
        key = (lagg.laggif or "lagg").lower()
        if key not in by_device:
            add_box(TopoBox("port", key, lagg.laggif or "lagg", f"lagg · {lagg.proto or '—'}", "lagg"))

    # VLANs (inside on the right, external on the left), bridges, tunnels.
    for index, vlan in enumerate(result.vlans):
        node_id = (vlan.vlanif or f"vlan{vlan.tag or index}").lower()
        assigned = _interface_for_vlan(vlan, result.interfaces)
        nic = resolve_hardware(vlan.if_parent)
        external = node_id in external_vlans
        bits = [f"external VLAN {vlan.tag}" if external else f"VLAN {vlan.tag}" if vlan.tag else "VLAN"]
        if nic:
            bits.append(f"on {nic}")
        if assigned is not None:
            bits.append(assigned.name.upper())
            if assigned.ipaddr:
                bits.append(_address(assigned))
        add_box(
            TopoBox(
                "ext" if external else "vlan",
                node_id,
                _vlan_title(vlan, assigned),
                " · ".join(bits),
                "external" if external else "vlan",
                dim=assigned is not None and not assigned.enabled,
            )
        )
    for bridge in result.bridges:
        key = (bridge.bridgeif or "bridge").lower()
        assigned = by_device.get(key)
        title = (
            (assigned.descr or "").strip() if assigned is not None else ""
        ) or (bridge.descr or "").strip() or bridge.bridgeif or "bridge"
        bits = [bridge.bridgeif or "bridge", "stp " + ("on" if bridge.stp_enabled else "off")]
        if assigned is not None:
            bits.append(assigned.name.upper())
        add_box(TopoBox("bridge", key, title, " · ".join(bits), "bridge"))
    tunnels: list[InterfaceInfo] = []
    for iface in result.interfaces:
        layer, node_id = card_of(iface)
        if layer == "ext" and node_id == iface.name.lower():
            tunnels.append(iface)
            add_box(
                TopoBox(
                    "ext",
                    node_id,
                    _port_title(iface),
                    "external · " + _port_subtitle(iface),
                    iface.kind if iface.kind in _TUNNEL_KINDS else "external",
                    dim=not iface.enabled,
                )
            )

    # NIC → port name.
    for iface in result.interfaces:
        layer, node_id = card_of(iface)
        if layer not in {"port", "gw"}:
            continue
        dev = (iface.device or "").strip().lower()
        if is_hardware_port(dev):
            add_edge(("phys", dev), (layer, node_id), "physical")
    # LAGG members → LAGG port.
    for lagg in result.laggs:
        dst = carrier(lagg.laggif)
        if dst is None:
            continue
        for member in lagg.members:
            nic = resolve_hardware(member)
            if nic:
                add_edge(("phys", nic), dst, "lagg")
    # Port name (or bare NIC) → VLAN; NIC → external VLAN.
    for vlan in result.vlans:
        node_id = (vlan.vlanif or "").lower()
        if not node_id:
            continue
        if node_id in external_vlans:
            nic = resolve_hardware(vlan.if_parent)
            add_edge(("phys", nic) if nic else None, ("ext", node_id), "external")
        else:
            add_edge(carrier(vlan.if_parent), ("vlan", node_id), "vlan")
    # Bridge members → bridge.
    for bridge in result.bridges:
        dst = ("bridge", (bridge.bridgeif or "bridge").lower())
        for member in bridge.members:
            add_edge(carrier(member), dst, "bridge")

    # Gateway groups: member NICs → group → Internet. A NIC in a group reaches
    # Internet only through the group; a WAN in no group goes through its own
    # port card (or straight from the NIC when it is not on one NIC).
    gid_name = {str(g.get("name", "")).strip().lower(): str(g.get("name", "")).strip() for g in result.gateway_groups}
    for gid, members in group_members.items():
        add_box(TopoBox("gw", gid, gid_name.get(gid, gid), "gateway group · " + " + ".join(members), "gwgroup"))
    if wans or group_members:
        add_box(TopoBox("ext", INTERNET, "Internet", "upstream", "edge"))
    for gid, members in group_members.items():
        for nic in members:
            add_edge(("phys", nic), ("gw", gid), "gwgroup")
        add_edge(("gw", gid), ("ext", INTERNET), "edge")
    wan_card = {nic: ("gw", name) for name, nic in wan_ports.items()}
    for iface in wans:
        nic = resolve_hardware(iface.device)
        if nic in grouped:
            continue
        if iface.name.lower() in wan_ports:
            add_edge(("gw", iface.name.lower()), ("ext", INTERNET), "edge")
        else:
            add_edge(("phys", nic) if nic else card_of(iface), ("ext", INTERNET), "edge")

    # Tunnels → the gateway group or WAN they are bound to.
    names = {gid: graph.boxes[("gw", gid)].title for gid in group_members}
    loose_refs: dict[str, set[str]] = {}
    for iface in tunnels:
        node = ("ext", iface.name.lower())
        bound = _tunnel_binding(iface, result.vpn)
        low = bound.lower()
        gid = low if low in group_members else ""
        if not gid and low:
            for name in group_members:
                a, b = _loose(name), _loose(low)
                if a and b and (a.startswith(b) or b.startswith(a)):
                    gid = name
                    loose_refs.setdefault(name, set()).add(bound)
                    break
        if gid:
            add_edge(("gw", gid), node, iface.kind or "openvpn")
            continue
        nic = resolve_hardware(bound) if low else ""
        if not nic and wan_nics:
            nic = next((n for n in wan_nics if by_device.get(n) and by_device[n].name == "wan"), wan_nics[0])
        if nic in grouped:
            gid = next(g for g, members in group_members.items() if nic in members)
            add_edge(("gw", gid), node, iface.kind or "openvpn")
        elif nic:
            add_edge(wan_card.get(nic, ("phys", nic)), node, iface.kind or "openvpn")
    for gid, refs in loose_refs.items():
        box = graph.boxes[("gw", gid)]
        note = ", ".join(sorted(refs))
        graph.boxes[("gw", gid)] = TopoBox(
            box.layer, box.node_id, names[gid], f"{box.subtitle} · tunnels name it '{note}'", box.kind
        )

    for layer, ids in graph.layers.items():
        graph.layers[layer] = sorted(ids, key=lambda node_id: graph.boxes[(layer, node_id)].title.lower())
    return graph


def _tunnel_binding(iface: InterfaceInfo, vpns: list[VpnEndpoint]) -> str:
    """The interface or gateway group a tunnel interface rides on."""
    dev = (iface.device or "").strip().lower()
    match = re.match(r"^ovpn([cs])(\d+)$", dev)
    if match:
        kind = "openvpn-client" if match.group(1) == "c" else "openvpn-server"
        for vpn in vpns:
            if vpn.kind == kind and vpn.vpnid == match.group(2):
                return vpn.interface
        return ""
    match = re.match(r"^ipsec(\d+)$", dev)
    if match:
        ikeid = str(int(match.group(1)) // 1000)
        for vpn in vpns:
            if vpn.kind == "ipsec-phase1" and vpn.vpnid == ikeid:
                return vpn.interface
    return ""


def tree_order(graph: ConfigTopology) -> TopoLayout:
    """Rows chosen so no two links cross.

    The external VLANs fill the top of the left column. Below them each
    gateway group sits level with its first member NIC, the other members
    follow, then the WAN NICs that are in no group. Internet is one tall card
    under the external VLANs covering every row that feeds it, so each of
    those links runs straight along its own row. Every other NIC starts a
    fresh band of rows; its port names and VLANs sit level with it or below.
    """
    rank = {layer: index for index, layer in enumerate(LAYERS)}
    out: dict[tuple[str, str], list[tuple[str, str]]] = {}
    into: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for link in graph.edges:
        src, dst = (link.src_layer, link.src_id), (link.dst_layer, link.dst_id)
        out.setdefault(src, []).append(dst)
        into.setdefault(dst, []).append(src)

    def title(node: tuple[str, str]) -> str:
        return graph.boxes[node].title.lower()

    rows: dict[str, dict[str, int]] = {layer: {} for layer in LAYERS}
    spans: dict[tuple[str, str], int] = {}
    next_free = {layer: 0 for layer in LAYERS}
    seen: set[tuple[str, str]] = set()

    def put(node: tuple[str, str], row: int) -> int:
        row = max(row, next_free[node[0]])
        rows[node[0]][node[1]] = row
        next_free[node[0]] = row + 1
        seen.add(node)
        return row

    def right_subtree(nic: tuple[str, str], floor: int) -> int:
        """Port names and VLANs under ``nic``. Returns the first row below them."""
        bottom = floor + 1
        stack = [(child, floor) for child in reversed(_inside(out.get(nic, []), rank, title))]
        while stack:
            node, parent_row = stack.pop()
            if node in seen:
                continue
            row = put(node, parent_row)
            bottom = max(bottom, row + 1)
            kids = [n for n in out.get(node, []) if rank[n[0]] >= rank[node[0]]]
            kids.sort(key=lambda n: (rank[n[0]], title(n)))
            stack.extend((kid, row) for kid in reversed(kids))
        return bottom

    def direct_tunnels(nic: tuple[str, str]) -> list[tuple[str, str]]:
        return sorted(
            (n for n in out.get(nic, []) if n[0] == "ext" and n[1] != INTERNET and n not in seen),
            key=title,
        )

    def place_nic(nic: tuple[str, str], start: int) -> tuple[int, int]:
        """Place a NIC, its direct tunnels below it on the left, and its right side."""
        row = put(nic, start)
        left_bottom = row + 1
        for tunnel in direct_tunnels(nic):
            left_bottom = put(tunnel, left_bottom) + 1
        return row, max(left_bottom, right_subtree(nic, row))

    def band_start() -> int:
        return max(next_free.values())

    internet = ("ext", INTERNET)
    groups = sorted(
        (n for n in graph.boxes if n[0] == "gw"),
        key=lambda n: (graph.boxes[n].kind != "gwgroup", title(n)),
    )
    direct_wans = sorted((n for n in into.get(internet, []) if n[0] == "phys"), key=title)

    def tunnels_of(node: tuple[str, str]) -> list[tuple[str, str]]:
        return sorted(
            (n for n in out.get(node, []) if n[0] == "ext" and n != internet and n not in seen),
            key=title,
        )

    for node in groups + direct_wans:
        for tunnel in tunnels_of(node):
            put(tunnel, 0)

    feeds: list[int] = []
    start = band_start()
    for group in groups:
        members = sorted((n for n in into.get(group, []) if n[0] == "phys" and n not in seen), key=title)
        row = put(group, start)
        if internet in out.get(group, []):
            feeds.append(row)
        after = row
        for member in members:
            _, after = place_nic(member, after)
        start = max(after, row + 1)
    for nic in direct_wans:
        if nic in seen:
            continue
        row, start = place_nic(nic, start)
        feeds.append(row)
    if internet in graph.boxes:
        top = max(min(feeds) if feeds else 0, next_free["ext"])
        put(internet, top)
        spans[internet] = max(max(feeds) - top + 1, 1) if feeds else 1
        next_free["ext"] = top + spans[internet]

    for nic in sorted((n for n in graph.boxes if n[0] == "phys"), key=title):
        if nic not in seen:
            place_nic(nic, band_start())
    for layer in LAYERS:
        for node_id in graph.layers.get(layer, []):
            node = (layer, node_id)
            if node not in seen:
                right_subtree(node, put(node, band_start()))
    return TopoLayout(rows=rows, spans=spans)


def _inside(nodes: list[tuple[str, str]], rank: dict[str, int], title) -> list[tuple[str, str]]:  # noqa: ANN001
    phys = rank["phys"]
    return sorted((n for n in nodes if rank[n[0]] > phys), key=lambda n: (rank[n[0]], title(n)))


def _address(iface: InterfaceInfo) -> str:
    ip = iface.ipaddr or ""
    if iface.subnet and ip.lower() not in {"", "dhcp", "pppoe"}:
        ip = f"{ip}/{iface.subnet}"
    return ip


def _port_title(iface: InterfaceInfo) -> str:
    descr = (iface.descr or "").strip()
    if descr:
        return descr
    device = (iface.device or "").strip()
    if device and not _ASSIGNED.match(device):
        return device
    return (iface.name or "?").upper()


def _port_subtitle(iface: InterfaceInfo) -> str:
    assigned = (iface.name or "").upper()
    bits = [assigned]
    device = (iface.device or "").strip()
    if device and device.lower() != assigned.lower() and device != _port_title(iface):
        bits.append(device)
    ip = _address(iface)
    if ip:
        bits.append(ip)
    elif not iface.ipaddr and not iface.ipaddrv6:
        bits.append("no ip")
    return " · ".join(bits)


def _vlan_title(vlan: VlanInfo, assigned: InterfaceInfo | None) -> str:
    if assigned is not None and (assigned.descr or "").strip():
        return assigned.descr.strip()
    if (vlan.descr or "").strip():
        return vlan.descr.strip()
    if vlan.tag:
        return f"VLAN {vlan.tag}"
    return vlan.vlanif or "VLAN"


def _interface_for_vlan(vlan: VlanInfo, interfaces: list[InterfaceInfo]) -> InterfaceInfo | None:
    vlanif = (vlan.vlanif or "").lower()
    for iface in interfaces:
        if vlan.assigned_as and iface.name.lower() == vlan.assigned_as.lower():
            return iface
        if vlanif and (iface.device or "").lower() == vlanif:
            return iface
    return None
