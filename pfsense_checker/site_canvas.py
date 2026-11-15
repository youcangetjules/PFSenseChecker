"""Flexible, grid-locked site canvas: chassis devices containing NIC components.

Switches render as wide front-panels with discrete RJ45 / SFP port cells so
cables can land on individual ports (CRS326/CRS328, Netgear, etc.).
"""

from __future__ import annotations

import math
import re
import time
from html import escape as html_escape

from PySide6.QtCore import QLineF, QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetrics,
    QImage,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPixmap,
    QPainterPathStroker,
    QPen,
    QPolygonF,
    QTransform,
)
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsItem,
    QGraphicsObject,
    QGraphicsPathItem,
    QGraphicsScene,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QMenu,
    QSlider,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

HANDLE_SIZE = 12.0
MIN_CHASSIS_W = 160.0
MIN_CHASSIS_H = 80.0

from pfsense_checker import device_identity, port_vlans, vlan_plan
from pfsense_checker.topology_site import Link, PortComponent
from pfsense_checker.viz import DEVICE_KIND_COLORS, LINK_KIND_COLORS

# Compact faceplate RJ45 / SFP cells (switch front-panel style)
RJ45_W = 16.0
RJ45_H = 26.0
SFP_W = 22.0
SFP_H = 26.0
NAMED_PORT_H = 38.0  # a front-panel port with a given name: name above, port id below
NAMED_PORT_MIN_W = 46.0  # and wide enough to read some of it
PORT_GAP = 3.0
GROUP_GAP = 10.0  # gap every 8 copper ports
CHASSIS_PAD = 12.0
HEADER_H = 48.0

# Non-switch (router/firewall) NIC tiles — one horizontal row per device
NIC_W = 72.0
NIC_H = 22.0
NIC_H_WITH_ADDR = 36.0
NIC_GAP = 4.0
CABLE_CORRIDOR_H = 40.0  # space below port grid for link dog-legs
# Vendor logo fills the chassis title bar (less this inset), aspect kept,
# never wider than this share of the box.
# Chassis border; a selected chassis is 1px thicker and pulses slightly.
BORDER = 2.0
SELECTED_BORDER = BORDER + 1.0
PULSE_WIDTH = 0.8  # extra width at the top of a pulse
PULSE_FADE = 90  # alpha dip at the bottom of a pulse
PULSE_PERIOD_S = 1.6
PULSE_FRAME_MS = 50
# Bridges are drawn around their member ports (they are not ports themselves).
BRIDGE_PAD = 3.0
BRIDGE_LABEL_H = 14.0  # the bridge name chip, fully below the title bar
BRIDGE_LABEL_STRIP = BRIDGE_LABEL_H + BRIDGE_PAD + 6.0  # title bar → ports when a bridge is drawn
PORTS_GAP_BELOW_TITLE = 6.0  # title bar → ports otherwise
# Uplinks (WANs, outbound tunnels) sit in the middle of the title bar,
# between the device name and the logo, and their cables leave upwards.
UPLINK_GAP = 12.0  # clear space either side of the uplink row
UPLINK_NAME = re.compile(r"^wan\d*$", re.IGNORECASE)  # wan, wan1… on any vendor
BRIDGE_EDGE = "#00838f"
BRIDGE_FILL = "#1400838f"  # ARGB: faint teal wash
# Port labels sit on a white chip so they read over any VLAN colour.
LABEL_CHIP = QColor(255, 255, 255, 228)
LOGO_INSET = 4.0
LOGO_MAX_SHARE = 0.4
LOGO_SUPERSAMPLE = 2  # rendered at 2x so it stays sharp when zoomed

# Port layouts (right-click the chassis title). Cells stretch to fill the width.
LAYOUT_ROW = "row"  # every port in one row
LAYOUT_FLAT = "flat"  # two rows, switch style: 1 over 2, 3 over 4, …
LAYOUT_RECT = "rect"  # as many rows as needed to fit the box width
LAYOUTS: tuple[tuple[str, str], ...] = (
    (LAYOUT_ROW, "One row"),
    (LAYOUT_FLAT, "Flat — two rows, switch style"),
    (LAYOUT_RECT, "Rectangular — rows to fit the box"),
)
MAX_CELL_W = 200.0
RECT_CELL_W = {True: 56.0, False: 84.0}  # rectangular target cell width: faceplate / NIC
ROW_GAP = 6.0
FACEPLATE_MIN_W = 480.0


def plan_ports(
    groups: list[str],
    min_cell_w: float,
    *,
    layout: str = LAYOUT_ROW,
    user_w: float | None = None,
    cell_h: float = SFP_H,
    min_body_w: float = 160.0,
    faceplate: bool = True,
    top: float | None = None,
) -> tuple[float, float, float, list[tuple[float, float]]]:
    """Place *len(groups)* port cells. Returns (box w, box h, cell w, [(x, y)]).

    Cells share one width that stretches to fill the box (up to MAX_CELL_W).
    In one-row and flat layouts a gap separates groups (copper / SFP / bridge /
    VLAN / …); flat fills columns top-then-bottom like a switch faceplate.
    """
    n = len(groups)
    top = HEADER_H if top is None else top  # where the first row of ports starts
    if layout not in (LAYOUT_ROW, LAYOUT_FLAT, LAYOUT_RECT):
        layout = LAYOUT_ROW
    if n == 0:
        w = max(min_body_w, user_w or 0.0)
        return w, top + cell_h + CHASSIS_PAD + 12, min_cell_w, []
    target = RECT_CELL_W[faceplate]
    if layout == LAYOUT_ROW:
        rows, cols = 1, n
    elif layout == LAYOUT_FLAT:
        rows = 2 if n > 1 else 1
        cols = -(-n // rows)
    else:
        if user_w:
            cols = int((user_w - 2 * CHASSIS_PAD + PORT_GAP) // (target + PORT_GAP))
        else:
            cols = int(-(-((2 * n) ** 0.5) // 1))
        cols = max(1, min(n, cols))
        rows = -(-n // cols)
        cols = -(-n // rows)  # balance: 16 ports in 2 rows is 8 + 8, not 15 + 1

    def cell(i: int) -> tuple[int, int]:  # (row, col)
        if layout == LAYOUT_FLAT:
            return i % rows, i // rows
        return i // cols, i % cols

    extra = [0.0] * cols  # group gap before each column
    if layout != LAYOUT_RECT:
        col_groups: list[set[str]] = [set() for _ in range(cols)]
        for i, g in enumerate(groups):
            col_groups[cell(i)[1]].add(g)
        for c in range(1, cols):
            if col_groups[c] != col_groups[c - 1]:
                extra[c] = GROUP_GAP
    cum = [0.0] * cols
    for c in range(1, cols):
        cum[c] = cum[c - 1] + extra[c]
    gaps = (cols - 1) * PORT_GAP + cum[-1]
    natural_cell = target if (layout == LAYOUT_RECT and not user_w) else min_cell_w
    natural_w = 2 * CHASSIS_PAD + gaps + cols * natural_cell
    body_w = max(min_body_w, natural_w, user_w or 0.0)
    cell_w = (body_w - 2 * CHASSIS_PAD - gaps) / cols
    cell_w = max(min_cell_w, min(MAX_CELL_W, cell_w))
    places = []
    for i in range(n):
        r, c = cell(i)
        places.append((CHASSIS_PAD + c * (cell_w + PORT_GAP) + cum[c], top + r * (cell_h + ROW_GAP)))
    body_h = top + rows * cell_h + (rows - 1) * ROW_GAP + CHASSIS_PAD + 12
    return body_w, body_h, cell_w, places


VLAN_LINK_KIND = "vlan"  # a cable drawn from one VLAN stripe to another


def link_vid(link) -> str:  # noqa: ANN001
    """The VLAN of a per-VLAN cable, "" for a whole-port cable."""
    vlans = list(getattr(link, "vlans", []) or [])
    return str(vlans[0]) if getattr(link, "kind", "") == VLAN_LINK_KIND and len(vlans) == 1 else ""


BUNDLE_WIDTH = 25.0  # one rainbow connector for every VLAN between two ports
BUNDLE_BLEND = 0.55  # share of each stripe's width that fades into its neighbours
BUNDLE_INSIDE_OPACITY = 0.3  # a ribbon runs faintly behind a device box to reach its port
CABLE_CLEARANCE = 6.0  # a thin cable's long run stays this far from a device's edge
DRAG_GRAB = 6.0  # how near the long run a press must be to pick it up


def vlan_bundles(links: list, port_vids) -> dict[int, list[int]]:  # noqa: ANN001
    """{first link index: [link indices]} for per-VLAN cables that between them
    join every VLAN on one port to every VLAN on the other (same set on both
    ports, two VLANs or more). *port_vids(device, port)* gives a port's VLANs."""
    groups: dict[frozenset, list[int]] = {}
    for i, link in enumerate(links):
        if link_vid(link):
            key = frozenset({(link.a_device, link.a_port), (link.b_device, link.b_port)})
            groups.setdefault(key, []).append(i)
    out: dict[int, list[int]] = {}
    for idx in groups.values():
        vids = {link_vid(links[i]) for i in idx}
        first = links[idx[0]]
        a_vids = set(port_vids(first.a_device, first.a_port))
        b_vids = set(port_vids(first.b_device, first.b_port))
        if len(vids) >= 2 and vids == a_vids == b_vids:
            out[idx[0]] = idx
    return out


def segment_bridge_text(bridge: str) -> str:
    """Chip text for a bridge of VLAN segments: "bridge bridge0 — only VLAN 710"."""
    m = re.fullmatch(r"(.*?) \(VLAN ([^)]*)\)", bridge)
    return f"bridge {m.group(1)} — only VLAN {m.group(2)}" if m else f"bridge {bridge}"


def segment_wires(chip: QRectF, ends: list[QPointF]) -> list[list[QPointF]]:
    """A wire from the bridge chip to each joined stripe: out of the chip's side at
    its mid-height, across to above the stripe, then straight down to it. A
    stripe under the chip itself gets a straight drop from the chip's bottom."""
    wires = []
    mid_y = chip.center().y()
    for end in ends:
        if chip.left() + 3 <= end.x() <= chip.right() - 3:
            wires.append([QPointF(end.x(), chip.bottom()), QPointF(end)])
        else:
            start_x = chip.left() if end.x() < chip.left() + 3 else chip.right()
            wires.append([QPointF(start_x, mid_y), QPointF(end.x(), mid_y), QPointF(end)])
    return wires


def device_type_key(device) -> str:  # noqa: ANN001
    """Devices with the same key are "the same type" for equal box sizes: the
    model (case and spacing ignored), else the kind."""
    model = re.sub(r"[^a-z0-9+]+", "", (getattr(device, "model", "") or "").lower())  # spaces, hyphens…
    return f"model:{model}" if model else f"kind:{(getattr(device, 'kind', '') or '').lower()}"


def drawn_devices(site) -> list:  # noqa: ANN001
    """Devices the canvas draws. Left out: ones marked ignored, and empty
    entries (no ports) whose address belongs to another device's interface
    — a network scan finds a router once per address, e.g. its LAN and its
    VLAN gateways, but it is one box."""
    owned: dict[str, str] = {}
    for dev in site.devices:
        for comp in dev.components:
            ip = (comp.address or "").split("/")[0].strip()
            if ip:
                owned.setdefault(ip, dev.name)
    out = []
    for dev in site.devices:
        if getattr(dev, "ignored", False):
            continue
        ip = (dev.mgmt_ip or (dev.ssh.host if dev.ssh else "") or "").strip()
        if not dev.components and not dev.ports and owned.get(ip, dev.name) != dev.name:
            continue
        out.append(dev)
    return out


def _is_switch_like(device) -> bool:  # noqa: ANN001
    role = (device.role or "").lower()
    kind = (device.kind or "").lower()
    if role in ("core-switch", "access-switch", "core", "access"):
        return True
    if kind == "linksys" and (device.model or "").upper().startswith("LGS"):
        return True  # Linksys LGS business switches have a front panel
    if kind in (
        "switch",
        "mikrotik",
        "netgear-managed",
        "netgear-unmanaged",
    ):
        # MikroTik routers (hEX etc.) are not faceplate switches
        model = (device.model or "").upper()
        if kind == "mikrotik" and not any(
            x in model for x in ("CRS", "CSS", "CSS326")
        ):
            if role in ("router", "firewall", "egress", "access-point"):
                return False
            if any(x in model for x in ("HEX", "HAP", "RB", "CCR")):
                return False
        return kind != "mikrotik" or "CRS" in model or "CSS" in model or role.endswith("switch")
    return False


# Vendor wordmark badges drawn in the chassis header (brand-ish accent colors).
# HPE now owns Juniper (and Aruba/ProCurve), so the "juniper" kind wears the HPE badge.
_VENDOR_BADGES: dict[str, tuple[str, str, str]] = {
    "pfsense": ("pfSense", "#c62828", "#ffffff"),
    "opnsense": ("OPNsense", "#ad1457", "#ffffff"),
    "mikrotik": ("MikroTik", "#293c4a", "#ffffff"),
    "juniper": ("HPE", "#01a982", "#ffffff"),
    "ubiquiti": ("Ubiquiti", "#0559c9", "#ffffff"),
    "fortinet": ("FORTINET", "#da291c", "#ffffff"),
    "cisco": ("Cisco", "#049fd9", "#ffffff"),
    "linksys": ("Linksys", "#1e5bd8", "#ffffff"),
    "netgear": ("NETGEAR", "#262626", "#ffffff"),
    "netgear-managed": ("NETGEAR", "#262626", "#ffffff"),
    "netgear-unmanaged": ("NETGEAR", "#262626", "#ffffff"),
}


def _vendor_badge(kind: str, model: str) -> tuple[str, str, str] | None:
    """Return (label, bg_hex, fg_hex) for a device's vendor wordmark, if known."""
    k = (kind or "").lower()
    m = (model or "").lower()
    if k in _VENDOR_BADGES:
        text, bg, fg = _VENDOR_BADGES[k]
        # Keep the Juniper name visible on SRX gear while flagging HPE ownership.
        if k == "juniper" and ("srx" in m or "juniper" in m):
            return ("HPE · Juniper", bg, fg)
        return (text, bg, fg)
    # Fall back to model keywords when the kind is generic (switch/router/other).
    if "pfsense" in m:
        return _VENDOR_BADGES["pfsense"]
    if "opnsense" in m:
        return _VENDOR_BADGES["opnsense"]
    if any(x in m for x in ("crs", "css", "ccr", "hex", "hap", "rb40", "rb50", "mikrotik")):
        return _VENDOR_BADGES["mikrotik"]
    if any(x in m for x in ("aruba", "procurve", "hpe", "officeconnect")):
        return _VENDOR_BADGES["juniper"]
    if "srx" in m or "juniper" in m:
        return ("HPE · Juniper", *_VENDOR_BADGES["juniper"][1:])
    if any(x in m for x in ("edgerouter", "edge router", "unifi", "ubiquiti")):
        return _VENDOR_BADGES["ubiquiti"]
    return None


_LOGO_CACHE: dict[tuple, QPixmap | None] = {}  # (path, mtime, height) → scaled logo
_LOGO_SOURCE: dict[tuple, QImage | None] = {}  # (path, mtime) → cleaned, trimmed logo


def logo_target(header: QRectF, box_width: float, size: tuple[int, int] | None) -> QRectF:
    """Where the logo goes: right of the title bar, as tall as the bar less
    LOGO_INSET top and bottom, aspect kept, at most LOGO_MAX_SHARE of the box
    wide (then shorter, centred). *size* None gives just the target height.
    """
    h = max(8.0, header.height() - 2 * LOGO_INSET)
    if not size or size[1] <= 0:
        return QRectF(box_width - 8, header.top() + LOGO_INSET, 0, h)
    w = size[0] * h / size[1]
    max_w = max(24.0, box_width * LOGO_MAX_SHARE)
    if w > max_w:
        w, h = max_w, max_w * size[1] / size[0]
    y = header.top() + (header.height() - h) / 2
    return QRectF(box_width - 8 - w, y, w, h)


def _logo_pixmap(vendor: str, height: int) -> QPixmap | None:
    """Vendor logo scaled to *height* pixels, aspect kept, from assets/logos."""
    path = device_identity.logo_path(vendor)
    if path is None:
        return None
    try:
        key = (str(path), path.stat().st_mtime, height)
    except OSError:
        return None
    if key in _LOGO_CACHE:
        return _LOGO_CACHE[key]
    pix: QPixmap | None = None
    src_key = key[:2]
    if src_key not in _LOGO_SOURCE:
        raw = _load_logo_image(path)
        # Background knock-out + trim: done once per file version, not per size.
        _LOGO_SOURCE[src_key] = (
            trim_logo_margins(knock_out_background(raw)) if raw is not None and not raw.isNull() else None
        )
    img = _LOGO_SOURCE[src_key]
    if img is not None and not img.isNull():
        pix = QPixmap.fromImage(
            img.scaledToHeight(max(1, height), Qt.TransformationMode.SmoothTransformation)
        )
    _LOGO_CACHE[key] = pix
    return pix


def _load_logo_image(path) -> QImage | None:  # noqa: ANN001
    """The logo as an image: SVGs are rendered 512px tall first."""
    if path.suffix.lower() == ".svg":
        from PySide6.QtSvg import QSvgRenderer

        renderer = QSvgRenderer(str(path))
        if not renderer.isValid():
            return None
        size = renderer.defaultSize()
        h = 512
        w = max(1, int(size.width() * h / max(1, size.height())))
        img = QImage(w, h, QImage.Format.Format_ARGB32_Premultiplied)
        img.fill(Qt.GlobalColor.transparent)
        p = QPainter(img)
        renderer.render(p)
        p.end()
        return img
    img = QImage(str(path))
    return None if img.isNull() else img


def _is_backdrop(c: QColor) -> bool:
    """Light and colourless: white, or the grey squares of a fake transparency
    checkerboard baked into a downloaded JPG."""
    r, g, b = c.red(), c.green(), c.blue()
    return min(r, g, b) > 185 and max(r, g, b) - min(r, g, b) < 18


def _has_transparency(img: QImage) -> bool:
    if not img.hasAlphaChannel():
        return False
    w, h = img.width(), img.height()
    step = max(1, max(w, h) // 200)
    return any(img.pixelColor(x, y).alpha() < 250 for y in range(0, h, step) for x in range(0, w, step))


def knock_out_background(img: QImage, max_pixels: int = 1_500_000) -> QImage:
    """Make the flat background of a logo transparent, starting from its edges.

    Only for images with no real transparency (JPGs, flattened PNGs). Flood fill
    from the border over light, colourless pixels, so white parts inside the
    logo itself are kept. Large images are left alone (cost).
    """
    w, h = img.width(), img.height()
    if w * h > max_pixels or _has_transparency(img):
        return img
    out = img.convertToFormat(QImage.Format.Format_ARGB32)
    seen = bytearray(w * h)
    stack = [(x, y) for x in range(w) for y in (0, h - 1)] + [(x, y) for y in range(h) for x in (0, w - 1)]
    clear = QColor(0, 0, 0, 0)
    while stack:
        x, y = stack.pop()
        i = y * w + x
        if seen[i]:
            continue
        seen[i] = 1
        if not _is_backdrop(out.pixelColor(x, y)):
            continue
        out.setPixelColor(x, y, clear)
        if x > 0:
            stack.append((x - 1, y))
        if x < w - 1:
            stack.append((x + 1, y))
        if y > 0:
            stack.append((x, y - 1))
        if y < h - 1:
            stack.append((x, y + 1))
    return out


def trim_logo_margins(img: QImage) -> QImage:
    """Crop transparent or plain-white margins so the visible logo, not its
    canvas, fills the title bar. Sampled on a grid (fast on large files),
    then widened by one grid step so no edge of the logo is lost.
    """
    w, h = img.width(), img.height()
    step = max(1, max(w, h) // 300)
    left, top, right, bottom = w, h, -1, -1
    for y in range(0, h, step):
        for x in range(0, w, step):
            c = img.pixelColor(x, y)
            if c.alpha() > 24 and not (c.red() > 242 and c.green() > 242 and c.blue() > 242):
                left, right = min(left, x), max(right, x)
                top, bottom = min(top, y), max(bottom, y)
    if right < 0:
        return img
    left, top = max(0, left - step), max(0, top - step)
    right, bottom = min(w - 1, right + step), min(h - 1, bottom + step)
    if (left, top, right, bottom) == (0, 0, w - 1, h - 1):
        return img
    return img.copy(left, top, right - left + 1, bottom - top + 1)


# Port classes: fill / edge colours, and left-to-right group order.

PORT_CLASS_STYLE: dict[str, tuple[str, str]] = {
    "physical": ("#cfd8dc", "#455a64"),
    "bridge": ("#e0f2f1", "#00897b"),
    "vlan": ("#fff3e0", "#ef6c00"),
    "virtual": ("#ede7f6", "#5e35b1"),  # tunnels, CAPsMAN interfaces
    "wireless": ("#e8f5e9", "#2e7d32"),
}
_CLASS_ORDER = {"physical": 0, "bridge": 1, "vlan": 2, "wireless": 3, "virtual": 4}
_VIRTUAL_TOKENS = ("openvpn", "ipsec", "wireguard", "wg", "gif", "gre", "ppp", "cap", "loopback", "tunnel")


def _media_tokens(media: str) -> list[str]:
    return [t.strip() for t in (media or "").split("\u00b7") if t.strip()]


def port_class(comp) -> tuple[str, bool]:  # noqa: ANN001
    """(class, disabled) from a component's media tags and name."""
    tokens = [x.lower() for x in _media_tokens(getattr(comp, "media", ""))]
    name = (comp.name or "").lower()
    disabled = "disabled" in tokens
    if "vlan" in tokens or any(x.startswith("tag ") for x in tokens) or (
        "." in name and name.split(".")[-1].isdigit()
    ):
        return "vlan", disabled
    if "bridge" in tokens or name.startswith("bridge"):
        return "bridge", disabled
    if "wlan" in tokens or name.startswith(("wlan", "wifi")):
        return "wireless", disabled
    if any(x in _VIRTUAL_TOKENS for x in tokens) or name.startswith(("ovpn", "ipsec", "wg", "gif", "gre")):
        return "virtual", disabled
    return "physical", disabled


def port_display(device, comp) -> tuple[str, str]:  # noqa: ANN001
    """(label, second line) for a port tile.

    pfSense / OPNsense ports show their own interface names (descriptions);
    the OPTn assignment and NIC go on the second line unless an address does.
    """
    name = comp.name or ""
    address = (getattr(comp, "address", "") or "").split("/")[0]
    kind = (getattr(device, "kind", "") or "").lower()
    tokens = _media_tokens(getattr(comp, "media", ""))
    # Device-library ports carry "speed · medium" (e.g. "2.5G · copper"), not
    # "NIC · description": keep their own name as the label.
    library_media = bool(tokens) and re.fullmatch(r"\d+(\.\d+)?[GM]", tokens[0]) is not None
    if kind in ("pfsense", "opnsense") and tokens and not library_media:
        flags = {"vlan", "bridge", "disabled", "openvpn", "ipsec", "wireguard", "ppp", "gif", "gre"}
        words = [x for x in tokens if x.lower() not in flags and not x.lower().startswith("tag ")]
        if tokens[0].lower().startswith("tag ") and words:
            descr, nic = words[-1], ""  # raw VLAN: "tag 630 · mce1 · descr"
        else:
            nic = words[0] if words else ""
            descr = words[1] if len(words) > 1 else ""
        if descr and descr.lower() != name.lower():
            second = address or " · ".join(x for x in (name, nic) if x)
            return descr, second
    return name, address


def cage_rank(comp) -> int:  # noqa: ANN001
    """Front-panel order of a physical port: copper 0, SFP 1, combo 2, SFP+ 3,
    SFP28 4, QSFP 5 (by name, or the library's media tags)."""
    name = (comp.name or "").lower()
    tags = {t.lower() for t in _media_tokens(getattr(comp, "media", ""))}
    if "qsfp" in name or tags & {"qsfp", "qsfp+", "qsfp28"}:
        return 5
    if "sfp28" in name or "sfp28" in tags:
        return 4
    if "sfpplus" in name or "sfp+" in name or "sfp+" in tags or name.startswith("xe-"):
        return 3
    if name.startswith("combo") or "combo" in tags:
        return 2
    if _is_sfp_name(name) or "sfp" in tags:
        return 1
    return 0


def _natural_key(text: str) -> list:
    import re as _re

    return [int(x) if x.isdigit() else x.lower() for x in _re.split(r"(\d+)", text or "")]


def _is_sfp_name(name: str) -> bool:
    n = name.lower()
    # "c1".."c4" (combo cages) only as the whole name: as a substring it also
    # matched igc1 / igc2 / igc3 (Intel NICs on pfSense).
    return any(tok in n for tok in ("sfp", "sfpplus", "sfp+", "qsfp", "xe-")) or n in (
        "c1", "c2", "c3", "c4"
    ) or n.startswith("s") and n[1:].isdigit() and int(n[1:]) <= 8 and "slot" not in n


def _vlan_label(vid: str, names: dict[str, str]) -> str:
    name = names.get(vid, "")
    return f"{vid} ({name})" if name and name != vid else vid


def port_vlan_tip(vlans: "port_vlans.PortVlans | None", names: dict[str, str]) -> list[str]:
    """Hover lines for a port's VLANs: access / trunk, each VLAN named, faults."""
    if vlans is None or not vlans.vlans:
        return []
    out = []
    if vlans.ssid or vlans.via:
        ssid = f"SSID '{vlans.ssid}'" if vlans.ssid else "Wi-Fi"
        out.append(f"{ssid} → VLAN " + ", ".join(_vlan_label(v, names) for v in vlans.vlans))
        if vlans.via:
            out.append(f"Set by {vlans.via}")
    elif vlans.is_trunk:
        out.append("Trunk — tagged VLANs: " + ", ".join(_vlan_label(v, names) for v in vlans.tagged))
        if vlans.untagged:
            out.append("Untagged (native) VLAN: " + ", ".join(_vlan_label(v, names) for v in vlans.untagged))
    else:
        out.append("Access port — VLAN " + ", ".join(_vlan_label(v, names) for v in vlans.untagged))
    out += [f"Check: {n}" for n in vlans.notes]
    return out


class VlanLegend(QFrame):
    """VLAN colours at the top of the canvas, plus how trunks and bridges look."""

    def __init__(self, view: "SiteTopologyView") -> None:
        super().__init__(view)
        self.setObjectName("vlanLegend")
        self.setStyleSheet(
            "#vlanLegend { background: rgba(255, 255, 255, 230); border: 1px solid #b0bec5;"
            " border-radius: 6px; }"
        )
        row = QHBoxLayout(self)
        row.setContentsMargins(8, 4, 8, 4)
        self.label = QLabel()
        self.label.setTextFormat(Qt.TextFormat.RichText)
        self.label.setWordWrap(True)
        row.addWidget(self.label)
        self.hide()

    def set_vlans(self, vlans: dict[str, str], palette: dict[str, str] | None = None) -> None:
        """*vlans*: VLAN id → name for every VLAN on the canvas's ports."""
        if not vlans:
            self.hide()
            return

        def swatch(color: str) -> str:
            return (f"<span style='background:{color}; color:{color};'>&nbsp;&nbsp;&nbsp;&nbsp;</span>")

        chips = [
            f"{swatch(port_vlans.vlan_color(v, palette))}&nbsp;<b>{v}</b>"
            + (f"&nbsp;{html_escape(n)}" if n and n != v else "")
            for v, n in sorted(vlans.items(), key=lambda kv: port_vlans._vid_key(kv[0]))  # noqa: SLF001
        ]
        trunk = "".join(
            f"<span style='background:{port_vlans.vlan_color(v, palette)};'>&nbsp;</span>"
            for v in sorted(vlans, key=port_vlans._vid_key)[:6]  # noqa: SLF001
        )
        chips.append(f"{trunk}&nbsp;trunk (VLANs it carries)")
        chips.append(f"<span style='color:{BRIDGE_EDGE};'><b>┆ ┆</b></span>&nbsp;bridge (around its ports)")
        self.label.setText("<span style='color:#37474f;'><b>VLANs</b>&nbsp;&nbsp;"
                           + "&nbsp;&nbsp;&nbsp; ".join(chips) + "</span>")
        self.show()


class PortItem(QGraphicsObject):
    """NIC / switch-port component owned by a chassis."""

    def __init__(
        self,
        device_name: str,
        port_name: str,
        media: str = "",
        *,
        address: str = "",
        faceplate: bool = False,
        sfp: bool = False,
        port_cls: str = "physical",
        disabled: bool = False,
        label: str = "",
        second: str = "",
        tall: bool = False,
        width: float | None = None,
        vlans: "port_vlans.PortVlans | None" = None,
        vlan_names: dict[str, str] | None = None,
        bridge: str = "",
        palette: dict[str, str] | None = None,
        segments: list[tuple[str, str]] | None = None,
        planned: set[str] | None = None,
        given_name: str = "",
        height: float | None = None,
    ) -> None:
        super().__init__()
        self.device_name = device_name
        self.port_name = port_name
        self.given_name = (given_name or "").strip()  # the name the operator gave this port
        self.vlans = vlans
        self.planned = set(planned or ())  # VLAN ids planned here, not on the device yet
        self.bridge = bridge
        self.segments = list(segments or [])  # [(bridge, VLAN id)] joined by a bridge
        self.selected_vid = ""  # the VLAN stripe picked for a per-VLAN cable
        # Access port: its VLAN's colour. Trunk: the colours of every VLAN it carries.
        self.vlan_colors = [port_vlans.vlan_color(v, palette) for v in vlans.vlans] if vlans else []
        self.media = media
        self.address = (address or "").strip()
        self.faceplate = faceplate
        self.sfp = sfp
        self.port_cls = port_cls
        self.disabled = disabled
        self.label = label or port_name
        self.second = second
        self.w = SFP_W if (faceplate and sfp) else (RJ45_W if faceplate else NIC_W)
        if width:
            self.w = float(width)
        if faceplate:
            self.h = float(height) if height else SFP_H
        elif tall or self.second:
            self.h = NIC_H_WITH_ADDR
        else:
            self.h = NIC_H
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setAcceptHoverEvents(True)
        self.setAcceptedMouseButtons(
            Qt.MouseButton.LeftButton | Qt.MouseButton.RightButton
        )
        self.setZValue(3)
        kind = "SFP" if sfp else ("RJ45" if faceplate else "NIC")
        tip_bits = [f"{device_name} · {port_name} ({kind})"]
        if self.given_name:
            tip_bits.append(f"Name: {self.given_name}")
        if self.label != port_name:
            tip_bits.append(self.label)
        tip_bits.append(f"{port_cls} port" + (" · disabled" if disabled else ""))
        tip_bits += port_vlan_tip(vlans, vlan_names or {})
        if bridge:
            tip_bits.append(f"In bridge {bridge}")
        for seg_bridge, vid in self.segments:
            tip_bits.append(f"VLAN {vid} segment in bridge {seg_bridge}")
        if self.planned:
            tip_bits.append("Planned (hatched, not on the device yet): VLAN "
                            + ", ".join(sorted(self.planned, key=port_vlans._vid_key))  # noqa: SLF001
                            + " — right-click → Show commands for planned VLANs")
        if self.address:
            tip_bits.append(self.address)
        if media:
            tip_bits.append(media)
        if vlans and len(vlans.vlans) > 1:
            tip_bits.append("click a VLAN stripe to select it, then drag from it to link that VLAN;"
                            " Shift-drag links the whole port")
        else:
            tip_bits.append("drag onto another device's port to link")
        self._base_tip = "\n".join(tip_bits)
        self._vlan_names = dict(vlan_names or {})
        self._hover_vid = ""
        self.setToolTip(self._base_tip)

    def boundingRect(self) -> QRectF:  # noqa: N802
        return QRectF(0, 0, self.w, self.h)

    def vlan_tip(self, vid: str) -> str:
        """Hover text for the VLAN stripe *vid*: its number and name, tagged or not."""
        name = self._vlan_names.get(vid, "")
        how = ""
        if self.vlans is not None:
            how = "untagged (access)" if vid in self.vlans.untagged else "tagged"
        head = f"VLAN {vid}" + (f" — {name}" if name and name != vid else "") + (f" · {how}" if how else "")
        if vid in self.planned:
            head += " · PLANNED (not on the device yet)"
        return head + "\n" + self._base_tip

    def hoverMoveEvent(self, event) -> None:  # noqa: ANN001, N802
        """Over a VLAN stripe, say which VLAN it is."""
        vid = self.vid_at(event.pos())
        if vid != self._hover_vid:
            self._hover_vid = vid
            text = self.vlan_tip(vid) if vid else self._base_tip
            self.setToolTip(text)
            from PySide6.QtWidgets import QToolTip

            if QToolTip.isVisible():
                QToolTip.showText(event.screenPos(), text)
        super().hoverMoveEvent(event)

    def hoverLeaveEvent(self, event) -> None:  # noqa: ANN001, N802
        self._hover_vid = ""
        self.setToolTip(self._base_tip)
        super().hoverLeaveEvent(event)

    def vid_at(self, local: QPointF) -> str:
        """The VLAN whose stripe is under *local* (only on ports with several VLANs)."""
        vids = self.vlans.vlans if self.vlans else []
        if len(vids) < 2:
            return ""
        for vid in vids:
            r = self.stripe_rect(vid)
            if r is not None and r.left() <= local.x() <= r.right():
                return vid
        return ""

    def select_vid(self, vid: str) -> None:
        if vid != self.selected_vid:
            self.selected_vid = vid
            self.update()

    def stripe_anchor(self, vid: str, facing: str = "bottom") -> QPointF | None:
        """Where a cable for VLAN *vid* meets this port: the middle of its stripe's edge."""
        r = self.stripe_rect(vid)
        if r is None:
            return None
        y = r.top() if facing == "top" else r.bottom()
        return self.mapToScene(QPointF(r.center().x(), y))

    def stripe_rect(self, vid: str) -> QRectF | None:
        """Where VLAN *vid*'s colour stripe is on this port (local coordinates)."""
        vids = self.vlans.vlans if self.vlans else []
        if vid not in vids:
            return None
        r = self.boundingRect().adjusted(0.5, 0.5, -0.5, -0.5)
        n = len(vids)
        i = vids.index(vid)
        return QRectF(r.left() + r.width() * i / n, r.top(), r.width() / n, r.height())

    def paint(self, painter, option, widget=None) -> None:  # noqa: ANN001, N802
        del option, widget
        selected = self.isSelected()
        if self.sfp:
            edge = "#6a1b9a" if selected else "#7b1fa2"
            fill = QColor("#f3e5f5" if selected else "#ede7f6")
        else:
            base_fill, base_edge = PORT_CLASS_STYLE.get(self.port_cls, PORT_CLASS_STYLE["physical"])
            edge = "#1565c0" if selected else base_edge
            fill = QColor("#e3f2fd" if selected else base_fill)
        if self.disabled:
            fill.setAlpha(110)
        pen = QPen(QColor(edge))
        pen.setWidth(2 if selected else 1)
        if self.disabled:
            pen.setStyle(Qt.PenStyle.DashLine)
        r = self.boundingRect().adjusted(0.5, 0.5, -0.5, -0.5)
        if self.vlan_colors:
            # VLAN colour fill: one colour (access) or a stripe per VLAN (trunk).
            shape = QPainterPath()
            shape.addRoundedRect(r, 2, 2)
            painter.save()
            painter.setClipPath(shape)
            painter.setPen(Qt.PenStyle.NoPen)
            n = len(self.vlan_colors)
            for i, col in enumerate(self.vlan_colors):
                c = QColor(col)
                if self.disabled:
                    c.setAlpha(110)
                painter.setBrush(QBrush(c))
                painter.drawRect(QRectF(r.left() + r.width() * i / n, r.top(), r.width() / n + 0.6, r.height()))
            painter.restore()
            fill = QColor(0, 0, 0, 0)
        painter.setPen(pen)
        painter.setBrush(QBrush(fill))
        painter.drawRoundedRect(r, 2, 2)
        # The VLAN stripe picked for a cable: thick dark frame and a light wash.
        picked = self.stripe_rect(self.selected_vid) if self.selected_vid else None
        if picked is not None:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(255, 255, 255, 90))
            painter.drawRect(picked)
            frame = QPen(QColor("#0d47a1"), 2.6)
            frame.setJoinStyle(Qt.PenJoinStyle.MiterJoin)
            painter.setPen(frame)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRect(picked.adjusted(1.3, 1.3, -1.3, -1.3))

        # Discrete "jack" line for faceplate RJ45 (a named port shows its name there instead)
        if self.faceplate and not self.sfp and not self.given_name:
            painter.setPen(QPen(QColor("#78909c")))
            mid = self.w / 2
            # Wide cells carry the whole name: keep the jack above it.
            bottom = 9.0 if self.w >= 30 else self.h - 10
            painter.drawLine(QPointF(mid - 3, 3), QPointF(mid - 3, bottom))
            painter.drawLine(QPointF(mid + 3, 3), QPointF(mid + 3, bottom))
            painter.drawLine(QPointF(mid - 4, bottom + 2), QPointF(mid + 4, bottom + 2))

        painter.setPen(QColor("#212121"))
        font = QFont()
        font.setPointSize(7 if (not self.faceplate or self.w >= 40) else 6)
        font.setBold(True)
        painter.setFont(font)
        if self.faceplate:
            if self.given_name:  # the operator's name for the port, on the top line
                nfont = QFont(font)
                nfont.setPointSizeF(6.5)
                painter.setFont(nfont)
                shown = QFontMetrics(nfont).elidedText(self.given_name, Qt.TextElideMode.ElideRight, int(self.w - 4))
                self._text(painter, self.boundingRect().adjusted(2, 2, -2, -2),
                           Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, shown)
                painter.setFont(font)
            metrics = QFontMetrics(font)
            label = self.port_name
            if metrics.horizontalAdvance(label) > self.w - 2:
                # Narrow cell: keep the distinguishing end (ether12 → er12),
                # otherwise elide the full name to the cell.
                label = label[-4:] if self.w < 30 else metrics.elidedText(
                    label, Qt.TextElideMode.ElideMiddle, int(self.w - 2)
                )
            self._text(painter, 
                self.boundingRect().adjusted(1, 1, -1, -2),
                Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignBottom,
                label,
            )
            self._paint_planned(painter)  # switch ports get the overlays too
            self._paint_bridged_segments(painter)
            return
        # Router/firewall NIC tile: name (elided) + second line (IP or OPTn · NIC).
        if self.disabled:
            painter.setPen(QColor("#90a4ae"))
        metrics = QFontMetrics(font)
        name_txt = metrics.elidedText(self.label, Qt.TextElideMode.ElideRight, int(self.w - 4))
        if self.h > NIC_H:
            self._text(painter, 
                QRectF(2, 1, self.w - 4, 14),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                name_txt,
            )
            if self.second:
                font2 = QFont()
                # IP addresses 2pt larger than the other second-line text.
                font2.setPointSize(8 if self.address and self.second.startswith(self.address.split("/")[0]) else 6)
                painter.setFont(font2)
                painter.setPen(QColor("#1565c0" if self.address else "#546e7a"))
                sub = QFontMetrics(font2).elidedText(self.second, Qt.TextElideMode.ElideRight, int(self.w - 4))
                self._text(painter, 
                    QRectF(2, 15, self.w - 4, 18),
                    Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
                    sub,
                )
        else:
            self._text(painter, 
                self.boundingRect().adjusted(2, 1, -2, -2),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                name_txt,
            )
        self._paint_planned(painter)
        self._paint_bridged_segments(painter)

    def _paint_planned(self, painter) -> None:  # noqa: ANN001
        """Planned VLANs: white diagonal hatching and a dashed frame over the stripe."""
        for vid in self.planned:
            stripe = self.stripe_rect(vid)
            if stripe is None:
                continue
            painter.save()
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(QColor(255, 255, 255, 190), Qt.BrushStyle.BDiagPattern))
            painter.drawRect(stripe)
            dash = QPen(QColor("#263238"), 1.4, Qt.PenStyle.DashLine)
            painter.setPen(dash)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRect(stripe.adjusted(1, 1, -1, -1))
            painter.restore()

    def _paint_bridged_segments(self, painter) -> None:  # noqa: ANN001
        """Mark the VLAN stripe(s) a bridge joins — and only those: a teal frame
        and a pointer on the top edge, drawn over the labels so a name or an
        address can never hide which stripe it is."""
        for _bridge, vid in self.segments:
            stripe = self.stripe_rect(vid)
            if stripe is None:
                continue
            painter.save()
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(0, 131, 143, 46))  # light teal wash over the stripe
            painter.drawRect(stripe)
            frame = QPen(QColor(BRIDGE_EDGE), 2.4)
            frame.setJoinStyle(Qt.PenJoinStyle.MiterJoin)
            painter.setPen(frame)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRect(stripe.adjusted(1.2, 1.2, -1.2, -1.2))
            cx = stripe.center().x()
            tip = QPainterPath(QPointF(cx - 4.5, stripe.top()))
            tip.lineTo(QPointF(cx + 4.5, stripe.top()))
            tip.lineTo(QPointF(cx, stripe.top() + 6))
            tip.closeSubpath()
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(BRIDGE_EDGE))
            painter.drawPath(tip)
            painter.restore()

    def _text(self, painter, rect: QRectF, flags, text: str) -> None:  # noqa: ANN001
        """Draw a label; on a VLAN-coloured port, on a white chip so it always reads."""
        if self.vlan_colors and text:
            bound = painter.boundingRect(rect, flags, text).adjusted(-2, 0, 2, 0)
            bound = bound.intersected(self.boundingRect().adjusted(1, 1, -1, -1))
            painter.save()
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(LABEL_CHIP))
            painter.drawRoundedRect(bound, 2, 2)
            painter.restore()
        painter.drawText(rect, flags, text)

    def mousePressEvent(self, event) -> None:  # noqa: ANN001, N802
        """Start a port→port cable drag when the canvas is unlocked. On a trunk,
        the first click picks a VLAN stripe; dragging from the picked stripe makes
        a cable for that VLAN (Shift-drag: the whole port)."""
        if event.button() == Qt.MouseButton.RightButton:
            event.ignore()
            return
        if event.button() == Qt.MouseButton.LeftButton and self.scene():
            for view in self.scene().views():
                if isinstance(view, SiteTopologyView) and not view._locked:
                    whole = bool(event.modifiers() & Qt.KeyboardModifier.ShiftModifier)
                    vid = "" if whole else self.vid_at(event.pos())
                    if vid and vid != self.selected_vid:
                        view.select_port_vlan(self, vid)  # first click: pick the stripe
                    else:
                        view.begin_port_link(self, event.scenePos(), vid=vid)
                    event.accept()
                    return
        super().mousePressEvent(event)

    def anchor_scene(self, facing: str = "bottom") -> QPointF:
        r = self.boundingRect()
        if facing == "left":
            local = QPointF(0, r.height() / 2)
        elif facing == "right":
            local = QPointF(r.width(), r.height() / 2)
        elif facing == "top":
            local = QPointF(r.width() / 2, 0)
        else:
            local = QPointF(r.width() / 2, r.height())
        return self.mapToScene(local)


class ResizeHandle(QGraphicsObject):
    """Bottom-right grip to stretch a chassis."""

    def __init__(self, chassis: "ChassisItem") -> None:
        super().__init__(chassis)
        self._chassis = chassis
        self._dragging = False
        self._origin = QPointF()
        self._start_w = 0.0
        self._start_h = 0.0
        self.setAcceptedMouseButtons(Qt.MouseButton.LeftButton)
        self.setAcceptHoverEvents(True)
        self.setCursor(Qt.CursorShape.SizeFDiagCursor)
        self.setZValue(20)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIgnoresParentOpacity, True)

    def boundingRect(self) -> QRectF:  # noqa: N802
        return QRectF(0, 0, HANDLE_SIZE, HANDLE_SIZE)

    def paint(self, painter, option, widget=None) -> None:  # noqa: ANN001, N802
        del option, widget
        if self._chassis._locked:
            return
        r = self.boundingRect().adjusted(1, 1, -1, -1)
        painter.setPen(QPen(QColor("#455a64"), 1))
        painter.setBrush(QBrush(QColor("#eceff1")))
        painter.drawRoundedRect(r, 2, 2)
        painter.setPen(QPen(QColor("#607d8b"), 1.5))
        for i in range(3):
            d = 3 + i * 3
            painter.drawLine(QPointF(d, HANDLE_SIZE - 3), QPointF(HANDLE_SIZE - 3, d))

    def mousePressEvent(self, event) -> None:  # noqa: ANN001, N802
        if self._chassis._locked:
            event.ignore()
            return
        self._dragging = True
        self._origin = event.scenePos()
        self._start_w, self._start_h = self._chassis.current_size()
        event.accept()

    def mouseMoveEvent(self, event) -> None:  # noqa: ANN001, N802
        if not self._dragging:
            return
        delta = event.scenePos() - self._origin
        self._chassis.apply_size(self._start_w + delta.x(), self._start_h + delta.y())
        event.accept()

    def mouseReleaseEvent(self, event) -> None:  # noqa: ANN001, N802
        if self._dragging:
            self._dragging = False
            self._chassis.finish_resize()
        event.accept()


class ChassisItem(QGraphicsObject):
    """Physical device box; NICs/ports are child PortItems (components)."""

    moved = Signal(str, float, float)  # device_name, x, y — every step of a drag
    resized = Signal(str, float, float)  # device_name, w, h — every step of a resize
    edit_finished = Signal(str)  # device_name — drag / resize / layout change done

    def __init__(self, device, *, snap: bool = True, grid: int = 20,  # noqa: ANN001
                 palette: dict[str, str] | None = None) -> None:
        super().__init__()
        self.device = device
        self.device_name = device.name
        self._palette = palette  # VLAN id → colour, shared by the whole canvas
        self.pulse = 1.0  # 0..1 while selected; the view animates it
        self._drag_moved = False
        self._snap = snap
        self._grid = max(5, grid)
        self._locked = False
        self._faceplate = _is_switch_like(device)
        self._vlans = port_vlans.for_device(device)  # VLANs per port, bridges (from config)
        self._bridge_rects: list[tuple[str, QRectF]] = []
        self.port_items: dict[str, PortItem] = {}
        self._user_w = float(device.w) if getattr(device, "w", None) else None
        self._user_h = float(device.h) if getattr(device, "h", None) else None
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges, True)
        self.setAcceptedMouseButtons(
            Qt.MouseButton.LeftButton | Qt.MouseButton.RightButton
        )
        self.setCursor(Qt.CursorShape.OpenHandCursor)
        self.setZValue(2)
        self._handle = ResizeHandle(self)
        self._rebuild_ports()
        self._place_handle()
        self.setPos(device.x or 0, device.y or 0)
        self.setToolTip(
            f"{device.name}\nRight-click the title: port layout (one row / flat / rectangular)\n"
            "Right-click: Pull Config · Show more (OS / hardware / "
            "uptime / SNMP alerts)"
        )

    def set_snap(self, enabled: bool, grid: int | None = None) -> None:
        self._snap = enabled
        if grid is not None:
            self._grid = max(5, grid)

    def set_locked(self, locked: bool) -> None:
        self._locked = locked
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, not locked)
        self.setCursor(
            Qt.CursorShape.ArrowCursor if locked else Qt.CursorShape.OpenHandCursor
        )
        self._handle.setVisible(not locked)
        self._handle.update()

    def current_size(self) -> tuple[float, float]:
        return self._content_size()

    def apply_size(self, width: float, height: float) -> None:
        """Live-resize while dragging the grip (snaps when snap is on)."""
        w = max(MIN_CHASSIS_W, width)
        h = max(MIN_CHASSIS_H, height)
        if self._snap:
            g = self._grid
            w = max(MIN_CHASSIS_W, round(w / g) * g)
            h = max(MIN_CHASSIS_H, round(h / g) * g)
        self.prepareGeometryChange()
        self._user_w = w
        self._user_h = h
        self._rebuild_ports()
        self._place_handle()
        self.update()
        self.resized.emit(self.device_name, w, h)

    def finish_resize(self) -> None:
        w, h = self.current_size()
        self.device.w = w
        self.device.h = h
        self.resized.emit(self.device_name, w, h)
        self.edit_finished.emit(self.device_name)

    def _place_handle(self) -> None:
        w, h = self._content_size()
        self._handle.setPos(w - HANDLE_SIZE - 1, h - HANDLE_SIZE - 1)
        self._handle.setVisible(not self._locked)

    def _components(self) -> list[PortComponent]:
        """Real ports only: VLAN interfaces and bridges are not ports — VLANs
        colour the ports that carry them, bridges are drawn around their
        member ports."""
        self.device.ensure_components()
        comps = list(self.device.components) or [
            PortComponent(name=p) for p in self.device.ports
        ]
        info = self._vlans
        out = []
        for c in comps:
            low = (c.name or "").lower()
            cls = port_class(c)[0]
            if cls in ("vlan", "bridge") or low in info.vlan_ifaces or low in info.hidden:
                continue
            if "cap" in {t.lower() for t in _media_tokens(c.media)}:
                continue  # CAPsMAN interface: the radio belongs to the CAP, not the controller
            out.append(c)
        return out

    @property
    def port_layout(self) -> str:
        return getattr(self.device, "port_layout", "") or LAYOUT_ROW

    def set_port_layout(self, layout: str) -> None:
        """Switch one row / flat / rectangular; keeps the width, refits the height."""
        if layout == self.port_layout:
            return
        self.prepareGeometryChange()
        self.device.port_layout = layout
        self._user_h = None
        self.device.h = None
        self._rebuild_ports()
        self._place_handle()
        self.update()
        w, h = self._content_size()
        self.resized.emit(self.device_name, w, h)
        self.edit_finished.emit(self.device_name)

    def _layout_metrics(self) -> tuple[float, float, list[tuple[PortComponent, float, float, bool, float]]]:
        """Return (width, height, list of (comp, x, y, is_sfp, cell width)).

        Ports are grouped physical copper → SFP → bridge → VLAN → wireless →
        tunnels, so every cable lands on a visible port, and stretch to fill
        the box in the chosen layout (one row, flat, rectangular).
        """
        info = self._vlans

        def kind_of(c: PortComponent) -> str:
            cls = port_class(c)[0]
            # SFP by name (sfp1, sfp-sfpplus1…) or by the library's media tag.
            tags = {t.lower() for t in _media_tokens(getattr(c, "media", ""))}
            sfp = _is_sfp_name(c.name) or bool(tags & {"sfp", "sfp+", "sfp28", "qsfp"})
            return "sfp" if cls == "physical" and sfp else cls

        def key(c: PortComponent) -> tuple:
            # Front-panel order: copper, SFP, combo, SFP+, then faster cages.
            # Bridged ports sit together (the bridge is drawn around them),
            # then the rest; within each, copper → SFP → wireless → tunnels.
            bridge = info.bridge_group(c.name)
            cls = port_class(c)[0]
            return (0 if bridge else 1, bridge.lower(), _CLASS_ORDER.get(cls, 9),
                    cage_rank(c), _natural_key(c.name))

        everything = sorted(self._components(), key=key)
        uplinks = [c for c in everything if self.is_uplink(c.name)]
        ordered = [c for c in everything if c not in uplinks]
        kinds = [kind_of(c) for c in ordered]
        groups = [f"{info.bridge_group(c.name)}|{k}|{cage_rank(c)}" for c, k in zip(ordered, kinds)]
        if self._faceplate:
            min_cell = SFP_W if "sfp" in kinds else RJ45_W
            cell_h = SFP_H
            if any(self.port_given_name(c.name) for c in everything):
                cell_h = NAMED_PORT_H  # room for the name above the port id
                min_cell = max(min_cell, NAMED_PORT_MIN_W)
            self._cell_h = cell_h
            min_body = FACEPLATE_MIN_W
            self._row_tall = False
        else:
            tall = any(port_display(self.device, c)[1] for c in everything)
            self._row_tall = tall
            min_cell = NIC_W
            cell_h = NIC_H_WITH_ADDR if tall else NIC_H
            min_body = MIN_CHASSIS_W
        left_res, right_res = self._header_reserve() if uplinks else (0.0, 0.0)
        if uplinks:  # the title bar must hold name + uplinks + logo
            up_need = len(uplinks) * min_cell + (len(uplinks) - 1) * PORT_GAP
            min_body = max(min_body, left_res + right_res + up_need)
        body_w, natural_h, cell_w, places = plan_ports(
            groups,
            min_cell,
            layout=self.port_layout,
            user_w=self._user_w,
            cell_h=cell_h,
            min_body_w=min_body,
            faceplate=self._faceplate,
            top=self._ports_top(ordered),
        )
        placed = [
            (comp, x, y, self._faceplate and k == "sfp", cell_w)
            for comp, k, (x, y) in zip(ordered, kinds, places)
        ]
        self._uplink_span: tuple[float, float] | None = None
        if uplinks:
            n = len(uplinks)
            room = body_w - left_res - right_res
            up_w = cell_w if ordered else MAX_CELL_W
            up_w = max(min_cell, min(up_w, (room - (n - 1) * PORT_GAP) / n))
            total = n * up_w + (n - 1) * PORT_GAP
            x0 = (body_w - total) / 2  # centred on the title bar…
            x0 = max(left_res, min(x0, body_w - right_res - total))  # …clear of name and logo
            y0 = max(2.0, (HEADER_H - 2 - cell_h) / 2)
            for i, comp in enumerate(uplinks):
                k = kind_of(comp)
                placed.append((comp, x0 + i * (up_w + PORT_GAP), y0, self._faceplate and k == "sfp", up_w))
            self._uplink_span = (x0, x0 + total)
        body_h = max(natural_h, self._user_h or 0.0)
        return body_w, body_h, placed

    def port_given_name(self, port: str) -> str:
        """The operator's name for a port: set on the map (Rename), else the one
        given on the device (a RouterOS comment)."""
        low = (port or "").lower()
        labels = getattr(self.device, "port_labels", None) or {}
        if low in labels:
            return labels[low]
        return self._vlans.comments.get(self._vlans.key(low), "") or self._vlans.comments.get(low, "")

    def is_uplink(self, port: str) -> bool:
        """Uplink port: set by hand (right-click the port), else a WAN /
        outbound tunnel from the config, or a port named wan, wan1…."""
        low = (port or "").lower()
        override = (getattr(self.device, "uplink_overrides", None) or {}).get(low)
        if override is not None:
            return override
        return self.auto_uplink(low)

    def auto_uplink(self, port: str) -> bool:
        """Uplink by the config or the port's name; a bridged port stays with its bridge."""
        low = (port or "").lower()
        if self._vlans.bridge_group(low):
            return False
        return self._vlans.key(low) in self._vlans.uplinks or bool(UPLINK_NAME.match(low))

    def set_uplink(self, port: str, on: bool) -> None:
        """Move a port into the title bar (uplink) or back to the port rows."""
        low = (port or "").lower()
        overrides = self.device.uplink_overrides
        if on == self.auto_uplink(low):
            overrides.pop(low, None)  # back to what the config says
        else:
            overrides[low] = on
        self.prepareGeometryChange()
        self._user_h = None
        self.device.h = None
        self._rebuild_ports()
        self._place_handle()
        self.update()
        w, h = self._content_size()
        self.resized.emit(self.device_name, w, h)  # cables re-route
        self.edit_finished.emit(self.device_name)

    def _header_logo(self) -> tuple[QPixmap | None, tuple[str, str, str] | None]:
        """The vendor logo for the title bar, else a wordmark badge."""
        ident = device_identity.identity_for(self.device)
        hdr = QRectF(0, 0, 100, HEADER_H - 2)
        logo = _logo_pixmap(
            ident.vendor or (self.device.kind or "").lower(),
            int(round(logo_target(hdr, 100, None).height() * LOGO_SUPERSAMPLE)),
        )
        if logo is not None:
            return logo, None
        return None, _vendor_badge(
            self.device.kind if self.device.kind in _VENDOR_BADGES else ident.vendor or self.device.kind,
            ident.model or self.device.model,
        )

    def _header_reserve(self) -> tuple[float, float]:
        """Title-bar width kept for the name (left) and the logo (right)."""
        bold = QFont()
        bold.setBold(True)
        bold.setPointSize(9)
        small = QFont()
        small.setPointSize(7)
        title_w = QFontMetrics(bold).horizontalAdvance(self.device.chassis_title())
        sub_w = QFontMetrics(small).horizontalAdvance(device_identity.type_line(self.device))
        left = 8 + max(title_w, min(sub_w, 240)) + UPLINK_GAP
        logo, badge = self._header_logo()
        if logo is not None:
            h = logo_target(QRectF(0, 0, 100, HEADER_H - 2), 100, None).height()
            right = 8 + logo.width() * h / max(1, logo.height()) + UPLINK_GAP
        elif badge:
            bfont = QFont()
            bfont.setBold(True)
            bfont.setPointSize(7)
            right = 8 + QFontMetrics(bfont).horizontalAdvance(badge[0]) + 14 + UPLINK_GAP
        else:
            right = UPLINK_GAP
        return left, right

    def _ports_top(self, ports: list[PortComponent]) -> float:
        """Ports sit clear of the title bar; a bridge gets a strip for its name."""
        bridged = any(self._vlans.bridge_group(c.name) for c in ports)
        return HEADER_H + (BRIDGE_LABEL_STRIP if bridged else PORTS_GAP_BELOW_TITLE)

    def _content_size(self) -> tuple[float, float]:
        w, h, _ = self._layout_metrics()
        return w, h

    def _rebuild_ports(self) -> None:
        for child in list(self.childItems()):
            if isinstance(child, PortItem):
                child.setParentItem(None)
                if child.scene():
                    child.scene().removeItem(child)
        self.port_items.clear()
        _w, _h, placed = self._layout_metrics()
        info = self._vlans
        members: dict[str, list[QRectF]] = {}
        stripes: dict[str, list[QRectF]] = {}
        for comp, x, y, is_sfp, cell_w in placed:
            cls, disabled = port_class(comp)
            label, second = port_display(self.device, comp)
            bridge = info.bridge_of(comp.name)
            # The port's VLANs from its config, plus any the operator has planned.
            port_plan = vlan_plan.merged(info.port(comp.name),
                                         vlan_plan.plan_of(self.device).get(comp.name.lower()))
            given = self.port_given_name(comp.name)
            if given and not self._faceplate and comp.name.lower() in (getattr(self.device, "port_labels", None) or {}):
                label = given  # a NIC tile's label is its name: Rename replaces it
            item = PortItem(
                self.device_name,
                comp.name,
                comp.media,
                given_name=given,
                height=getattr(self, "_cell_h", None) if self._faceplate else None,
                address=getattr(comp, "address", "") or "",
                faceplate=self._faceplate,
                sfp=is_sfp,
                port_cls=cls,
                disabled=disabled,
                label=label,
                second=second,
                tall=getattr(self, "_row_tall", False),
                width=cell_w,
                vlans=port_plan[0],
                vlan_names=info.names,
                bridge=bridge,
                palette=self._palette,
                segments=info.segments_of(comp.name),
                planned=port_plan[1],
            )
            item.setParentItem(self)
            item.setPos(x, y)
            self.port_items[comp.name] = item
            if bridge:
                members.setdefault(bridge, []).append(QRectF(x, y, item.w, item.h))
            for seg_bridge, vid in item.segments:
                stripe = item.stripe_rect(vid)
                if stripe is not None:
                    stripes.setdefault(seg_bridge, []).append(stripe.translated(x, y))
        # Bridges of VLAN segments: a chip with a line to each segment it joins.
        self._segment_links: list[tuple[str, list[QRectF]]] = list(stripes.items())
        # One outline per bridge per row of ports it wraps.
        self._bridge_rects: list[tuple[str, QRectF]] = []
        for bridge, rects in members.items():
            rows: dict[float, list[QRectF]] = {}
            for r in rects:
                rows.setdefault(round(r.top(), 1), []).append(r)
            for row in rows.values():
                box = QRectF(min(r.left() for r in row), min(r.top() for r in row), 0, 0)
                box.setRight(max(r.right() for r in row))
                box.setBottom(max(r.bottom() for r in row))
                self._bridge_rects.append((bridge, box.adjusted(-BRIDGE_PAD, -BRIDGE_PAD, BRIDGE_PAD, BRIDGE_PAD)))

    def boundingRect(self) -> QRectF:  # noqa: N802
        w, h = self._content_size()
        return QRectF(0, 0, w, h)

    def paint(self, painter, option, widget=None) -> None:  # noqa: ANN001, N802
        del option, widget
        color = DEVICE_KIND_COLORS.get(self.device.kind, DEVICE_KIND_COLORS["other"])
        if self.device.role == "egress":
            color = DEVICE_KIND_COLORS["egress"]
        rect = self.boundingRect()
        edge = QColor(color)
        if self.isSelected():
            # Selected: border 1px thicker, gently pulsing (view drives self.pulse 0..1).
            width = SELECTED_BORDER + PULSE_WIDTH * self.pulse
            edge.setAlpha(int(255 - PULSE_FADE * (1.0 - self.pulse)))
        else:
            width = BORDER
        pen = QPen(edge)
        pen.setWidthF(width)
        fill = QColor(color)
        fill.setAlpha(28)
        painter.setPen(pen)
        painter.setBrush(QBrush(fill))
        inset = width / 2
        painter.drawRoundedRect(rect.adjusted(inset, inset, -inset, -inset), 6, 6)

        hdr = QRectF(0, 0, rect.width(), HEADER_H - 2)
        hf = QColor(color)
        hf.setAlpha(70)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(hf))
        painter.drawRoundedRect(hdr.adjusted(1, 1, -1, 0), 6, 6)

        # Vendor logo (assets/logos/<vendor>.svg|png) or wordmark badge, top-right.
        name_width = rect.width() - 16
        logo, badge = self._header_logo()
        if logo is not None:
            target = logo_target(hdr, rect.width(), (logo.width(), logo.height()))
            painter.save()
            painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
            painter.drawPixmap(target, logo, QRectF(logo.rect()))
            painter.restore()
            name_width = max(40.0, target.left() - 14)
        if badge:
            label, bg, fg = badge
            bfont = QFont()
            bfont.setBold(True)
            bfont.setPointSize(7)
            bw = QFontMetrics(bfont).horizontalAdvance(label) + 14
            bh = 16.0
            bx = rect.width() - bw - 8
            by = 6.0
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(QColor(bg)))
            painter.drawRoundedRect(QRectF(bx, by, bw, bh), 4, 4)
            painter.setFont(bfont)
            painter.setPen(QColor(fg))
            painter.drawText(QRectF(bx, by, bw, bh), Qt.AlignmentFlag.AlignCenter, label)
            name_width = max(40.0, bx - 8 - 6)
        span = getattr(self, "_uplink_span", None)
        if span:  # name and type line end where the uplinks begin
            name_width = max(40.0, min(name_width, span[0] - 8 - 6))

        painter.setPen(QColor("#212121"))
        font = QFont()
        font.setBold(True)
        font.setPointSize(9)
        painter.setFont(font)
        painter.drawText(
            QRectF(8, 4, name_width, 16),
            Qt.AlignmentFlag.AlignLeft,
            self.device.chassis_title(),
        )

        font2 = QFont()
        font2.setPointSize(7)
        painter.setFont(font2)
        painter.setPen(QColor("#37474f"))
        type_text = device_identity.type_line(self.device)
        extra = self.device.chassis_subtitle()
        sub = type_text
        if extra and extra.lower() not in type_text.lower():
            sub = f"{type_text} · {extra}" if type_text else extra
        # With a logo filling the title bar, stop the type line short of it.
        sub_width = name_width if (logo is not None or span) else rect.width() - 16
        painter.drawText(
            QRectF(8, 22, sub_width, 16),
            Qt.AlignmentFlag.AlignLeft,
            QFontMetrics(font2).elidedText(sub, Qt.TextElideMode.ElideRight, int(sub_width)),
        )

        painter.setPen(QColor("#78909c"))
        n = len(self.port_items)
        style = "front-panel ports" if self._faceplate else "NIC components"
        painter.drawText(
            QRectF(8, rect.height() - 14, rect.width() - HANDLE_SIZE - 16, 12),
            Qt.AlignmentFlag.AlignLeft,
            f"{n} {style}",
        )
        self._paint_bridges(painter)

    def _paint_bridges(self, painter) -> None:  # noqa: ANN001
        """A bridge is drawn around the ports it joins, with its name on the edge."""
        self._paint_segment_bridges(painter)
        if not self._bridge_rects:
            return
        painter.save()
        pen = QPen(QColor(BRIDGE_EDGE))
        pen.setWidthF(1.4)
        pen.setStyle(Qt.PenStyle.DashLine)
        font = QFont()
        font.setPointSize(7)
        font.setBold(True)
        metrics = QFontMetrics(font)
        labelled: set[str] = set()
        for bridge, box in self._bridge_rects:
            painter.setPen(pen)
            painter.setBrush(QBrush(QColor(BRIDGE_FILL)))
            painter.drawRoundedRect(box, 4, 4)
            if bridge in labelled:
                continue
            labelled.add(bridge)
            text = metrics.elidedText(f"bridge {bridge}", Qt.TextElideMode.ElideRight,
                                      int(max(40.0, box.width() - 20)))
            # Sits on the outline's top edge, in the strip below the title bar.
            chip = QRectF(box.left() + 8, box.top() - BRIDGE_LABEL_H + 3,
                          metrics.horizontalAdvance(text) + 12, BRIDGE_LABEL_H)
            painter.setPen(QPen(QColor(BRIDGE_EDGE)))
            painter.setBrush(QBrush(QColor("#ffffff")))
            painter.drawRoundedRect(chip, 3, 3)
            painter.setFont(font)
            painter.setPen(QColor(BRIDGE_EDGE))
            painter.drawText(chip, Qt.AlignmentFlag.AlignCenter, text)
        painter.restore()

    def segment_links(self) -> list[tuple[str, QRectF, list[QPointF]]]:
        """For each VLAN-segment bridge: its chip and where its lines end
        (the top middle of each joined segment), in chassis coordinates."""
        out = []
        font = QFont()
        font.setPointSize(7)
        font.setBold(True)
        metrics = QFontMetrics(font)
        for bridge, rects in getattr(self, "_segment_links", []):
            top = min(r.top() for r in rects)
            row = [r for r in rects if abs(r.top() - top) < 1]
            ends = [QPointF(r.center().x(), r.top()) for r in rects]
            text = segment_bridge_text(bridge)
            w = metrics.horizontalAdvance(text) + 12
            mid = (min(r.left() for r in row) + max(r.right() for r in row)) / 2
            x = max(4.0, min(mid - w / 2, self.boundingRect().width() - w - 4))
            chip = QRectF(x, top - BRIDGE_LABEL_STRIP + 2, w, BRIDGE_LABEL_H)
            out.append((bridge, chip, ends))
        return out

    def _paint_segment_bridges(self, painter) -> None:  # noqa: ANN001
        """Bridge chip above the ports, joined by a line to each VLAN segment."""
        links = self.segment_links()
        if not links:
            return
        painter.save()
        line = QPen(QColor(BRIDGE_EDGE))
        line.setWidthF(1.6)
        font = QFont()
        font.setPointSize(7)
        font.setBold(True)
        for bridge, chip, ends in links:
            # One wire per joined stripe, out of the side of the chip and down to
            # that stripe alone (no bar across the ports: the other VLANs on them
            # are not in the bridge).
            for wire in segment_wires(chip, ends):
                painter.setPen(line)
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawPolyline(wire)
                end = wire[-1]
                head = QPainterPath(QPointF(end.x() - 4, end.y() - 6))
                head.lineTo(QPointF(end.x() + 4, end.y() - 6))
                head.lineTo(end)
                head.closeSubpath()
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor(BRIDGE_EDGE))
                painter.drawPath(head)
            painter.setPen(line)
            painter.setBrush(QBrush(QColor("#ffffff")))
            painter.drawRoundedRect(chip, 3, 3)
            painter.setFont(font)
            painter.setPen(QColor(BRIDGE_EDGE))
            painter.drawText(chip, Qt.AlignmentFlag.AlignCenter, segment_bridge_text(bridge))
        painter.restore()

    def itemChange(self, change, value):  # noqa: ANN001, N802
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionChange and self.scene():
            pos = value
            if self._snap:
                g = self._grid
                pos = QPointF(round(pos.x() / g) * g, round(pos.y() / g) * g)
            return pos
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            self._drag_moved = True
            self.moved.emit(self.device_name, self.pos().x(), self.pos().y())
        return super().itemChange(change, value)

    def mousePressEvent(self, event) -> None:  # noqa: ANN001, N802
        if event.button() != Qt.MouseButton.LeftButton:
            event.ignore()
            return
        self._drag_moved = False
        self.setCursor(Qt.CursorShape.ClosedHandCursor)
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event) -> None:  # noqa: ANN001, N802
        self.setCursor(
            Qt.CursorShape.ArrowCursor if self._locked else Qt.CursorShape.OpenHandCursor
        )
        super().mouseReleaseEvent(event)
        if self._drag_moved:
            # One announcement per drag, after the mouse is let go (BUG-046).
            self._drag_moved = False
            self.edit_finished.emit(self.device_name)

    def port_anchor(self, port_name: str, toward: QPointF | None = None, facing: str = "bottom",
                    vid: str = "") -> QPointF:
        item = self.port_items.get(port_name)
        if item is not None and vid:
            stripe = item.stripe_anchor(vid, facing)  # a per-VLAN cable meets its own stripe
            if stripe is not None:
                return stripe
        if item is None:
            r = self.boundingRect()
            center = self.mapToScene(r.center())
            if toward is not None and toward.x() < center.x():
                return self.mapToScene(QPointF(0, r.height() / 2))
            return self.mapToScene(QPointF(r.width(), r.height() / 2))
        # Cables leave from the bottom (or top, toward a device above) of the
        # exact port, so which port a cable belongs to is obvious.
        return item.anchor_scene(facing)


HOP_RADIUS = 5.0  # the jump a cable makes over another it crosses


def _segs(pts: list[QPointF]) -> list[tuple[QPointF, QPointF]]:
    return [(a, b) for a, b in zip(pts, pts[1:]) if abs(a.x() - b.x()) > 0.01 or abs(a.y() - b.y()) > 0.01]


def count_crossings(pts: list[QPointF], others: list[list[QPointF]]) -> int:
    """How often the polyline *pts* crosses the other cables (right-angle crossings
    away from segment ends, as drawn with hops)."""
    n = 0
    mine = _segs(pts)
    for other in others:
        for c, d in _segs(other):
            for a, b in mine:
                h1, v2 = abs(a.y() - b.y()) < 0.01, abs(c.x() - d.x()) < 0.01
                h2, v1 = abs(c.y() - d.y()) < 0.01, abs(a.x() - b.x()) < 0.01
                if h1 and v2:
                    hx0, hx1, hy, vx, vy0, vy1 = min(a.x(), b.x()), max(a.x(), b.x()), a.y(), c.x(), min(c.y(), d.y()), max(c.y(), d.y())
                elif v1 and h2:
                    hx0, hx1, hy, vx, vy0, vy1 = min(c.x(), d.x()), max(c.x(), d.x()), c.y(), a.x(), min(a.y(), b.y()), max(a.y(), b.y())
                else:
                    continue
                if hx0 + 1 < vx < hx1 - 1 and vy0 + 1 < hy < vy1 - 1:
                    n += 1
    return n


def find_hops(links: list) -> dict[int, dict[int, list[float]]]:  # noqa: C901
    """{link index: {segment index: [x, …]}}: where a horizontal run of one cable
    crosses a vertical run of another (not at either run's ends). Hops closer
    than two radii on one run are merged."""
    r = HOP_RADIUS
    vertical: list[tuple[int, float, float, float]] = []  # (link, x, y_lo, y_hi)
    for li, link in enumerate(links):
        for _i, a, b in link.segments():
            if abs(a.x() - b.x()) < 0.01 and abs(a.y() - b.y()) > 0.01:
                vertical.append((li, a.x(), min(a.y(), b.y()), max(a.y(), b.y())))
    out: dict[int, dict[int, list[float]]] = {}
    for li, link in enumerate(links):
        for i, a, b in link.segments():
            if abs(a.y() - b.y()) > 0.01:
                continue
            y = a.y()
            lo, hi = min(a.x(), b.x()), max(a.x(), b.x())
            xs = sorted(
                x for (lj, x, y0, y1) in vertical
                if lj != li and lo + r + 1 < x < hi - r - 1 and y0 + 1 < y < y1 - 1
            )
            kept: list[float] = []
            for x in xs:
                if not kept or x - kept[-1] >= 2 * r + 2:
                    kept.append(x)
            if kept:
                out.setdefault(li, {})[i] = kept
    return out


def ribbon_stops(colours: list[str], blend: float = BUNDLE_BLEND) -> list[tuple[float, str]]:
    """Gradient stops across a ribbon: each colour keeps a solid core and fades
    into its neighbours over *blend* of its width (0 = razor-sharp bands)."""
    n = len(colours)
    if n == 0:
        return []
    core = max(0.0, min(1.0, 1.0 - blend)) / 2  # half-width of the solid part, in stripes
    stops: list[tuple[float, str]] = []
    for k, colour in enumerate(colours):
        stops.append((max(0.0, (k + 0.5 - core) / n), colour))
        stops.append((min(1.0, (k + 0.5 + core) / n), colour))
    return stops


class LinkItem(QGraphicsPathItem):
    """Orthogonal cable between two chassis ports (or chassis edges)."""

    def __init__(
        self,
        a: ChassisItem,
        b: ChassisItem,
        *,
        a_port: str = "",
        b_port: str = "",
        color: str = "#546e7a",
        label: str = "",
        lane: int = 0,
        vid: str = "",
        route: list[tuple[float, float]] | None = None,
        lane_offset: float | None = None,
        bundle: list[str] | None = None,
        bundle_colors: list[str] | None = None,
        bundle_links: list[int] | None = None,
    ) -> None:
        super().__init__()
        self.lane_offset = lane_offset  # Re-arrange cable's choice (Link.lane)
        self.bundle = list(bundle or [])  # VLANs carried as one rainbow connector
        self.bundle_colors = list(bundle_colors or [])
        self.bundle_links = list(bundle_links or [lane])  # site.links indices drawn by this item
        self.a = a
        self.b = b
        self.lane = lane
        self.vid = vid  # set: a cable for this one VLAN, from stripe to stripe
        # Auto-arrange (ELK) route, used until either device moves.
        self.route = list(route) if route else None
        self._route_at = (QPointF(a.pos()), QPointF(b.pos()))
        self.points: list[QPointF] = []  # the cable's corners, port to port
        self.hops: dict[int, list[float]] = {}  # segment index → x of each jump over another cable
        self.a_port = a_port
        self.b_port = b_port
        self.color = color
        self.label = label
        self.setZValue(1)
        pen = QPen(QColor(color))
        pen.setWidth(2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        self.setPen(pen)
        a.moved.connect(lambda *_: self.rebuild())
        b.moved.connect(lambda *_: self.rebuild())
        a.resized.connect(lambda *_: self.rebuild())
        b.resized.connect(lambda *_: self.rebuild())
        self.setAcceptHoverEvents(True)
        self.setToolTip(
            f"{a.device.name}:{a_port or '?'} ↔ {b.device.name}:{b_port or '?'}"
            + (f"\n{label}" if label else "")
            + "\nRight-click to delete this cable"
        )
        self.rebuild()

    def shape(self) -> QPainterPath:  # noqa: D102
        stroker = QPainterPathStroker()
        stroker.setWidth(BUNDLE_WIDTH + 2 if self.bundle else 10)
        return stroker.createStroke(self.path())

    def boundingRect(self) -> QRectF:  # noqa: N802, D102
        pad = BUNDLE_WIDTH / 2 + 2 if self.bundle else 0
        return super().boundingRect().adjusted(-pad, -pad, pad, pad)

    def ribbon(self) -> list[list[QPointF]]:
        """One polyline per VLAN stripe, side by side across BUNDLE_WIDTH."""
        pts = self.points
        n = len(self.bundle)
        if n == 0 or len(pts) < 2:
            return []
        step = BUNDLE_WIDTH / n
        lanes = []
        for k in range(n):
            off = (k - (n - 1) / 2) * step
            line = []
            for i, pt in enumerate(pts):
                dx = dy = 0.0
                for a, b in ((pts[i - 1], pt) if i > 0 else (None, None), (pt, pts[i + 1]) if i < len(pts) - 1 else (None, None)):
                    if a is None:
                        continue
                    if abs(a.x() - b.x()) < 0.01:  # vertical run: shift sideways
                        dx = off if b.y() > a.y() else -off
                    else:  # horizontal run: shift up / down
                        dy = -off if b.x() > a.x() else off
                line.append(QPointF(pt.x() + dx, pt.y() + dy))
            lanes.append(line)
        return lanes

    def paint(self, painter, option, widget=None) -> None:  # noqa: ANN001, N802, D102
        if not self.bundle:
            super().paint(painter, option, widget)
            return
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        quads = self.ribbon_quads()
        if not quads:
            return
        stops = ribbon_stops(self.bundle_colors)
        boxes = QPainterPath()
        for ch in (self.a, self.b):
            boxes.addRect(ch.sceneBoundingRect())
        everywhere = QPainterPath()
        everywhere.addRect(self.boundingRect())
        edge = QPen(QColor(38, 50, 56, 110), 1.0)
        # Full strength in the open; faint where it runs behind a device box to its port.
        for clip, opacity in ((everywhere.subtracted(boxes), 1.0), (boxes, BUNDLE_INSIDE_OPACITY)):
            painter.save()
            painter.setClipPath(clip, Qt.ClipOperation.IntersectClip)
            painter.setOpacity(opacity)
            for poly, g0, g1 in quads:
                grad = QLinearGradient(g0, g1)
                for pos, colour in stops:
                    grad.setColorAt(pos, QColor(colour))
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QBrush(grad))
                painter.drawPolygon(poly)
                painter.setPen(edge)
                painter.drawLine(poly[0], poly[1])
                painter.drawLine(poly[3], poly[2])
            painter.restore()

    def ribbon_quads(self) -> list[tuple[QPolygonF, QPointF, QPointF]]:
        """The ribbon as one four-cornered piece per run, mitred where it turns, each
        with the two ends of its colour gradient (first VLAN's side → last VLAN's side)."""
        pts = self.points
        if len(pts) < 2:
            return []
        half = BUNDLE_WIDTH / 2
        normals = []
        for a, b in zip(pts, pts[1:]):
            if abs(a.x() - b.x()) < 0.01:
                normals.append((1.0, 0.0) if b.y() > a.y() else (-1.0, 0.0))
            else:
                normals.append((0.0, -1.0) if b.x() > a.x() else (0.0, 1.0))

        def corner(j: int) -> QPointF:
            if j == 0:
                n = normals[0]
            elif j == len(pts) - 1:
                n = normals[-1]
            else:
                p_, q_ = normals[j - 1], normals[j]
                n = q_ if p_ == q_ else (p_[0] + q_[0], p_[1] + q_[1])
            return QPointF(n[0] * half, n[1] * half)

        quads = []
        for i, (a, b) in enumerate(zip(pts, pts[1:])):
            ca, cb = corner(i), corner(i + 1)
            n = QPointF(normals[i][0] * half, normals[i][1] * half)
            quads.append((QPolygonF([a + ca, b + cb, b - cb, a - ca]), a - n, a + n))
        return quads

    def hoverEnterEvent(self, event) -> None:  # noqa: ANN001, N802
        pen = self.pen()
        pen.setWidth(4)
        self.setPen(pen)
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event) -> None:  # noqa: ANN001, N802
        pen = self.pen()
        pen.setWidth(2)
        self.setPen(pen)
        super().hoverLeaveEvent(event)

    def rebuild(self) -> None:
        ar = self.a.sceneBoundingRect()
        br = self.b.sceneBoundingRect()
        if self.route is not None:
            if self.a.pos() == self._route_at[0] and self.b.pos() == self._route_at[1]:
                self._follow_route(ar, br)
                return
            self.route = None  # a device moved: back to our own routing
        self.set_points(self.points_for(self.lane_offset))

    def clearance(self) -> float:
        """How far the long run stays from a device's edge (a ribbon needs its half-width)."""
        return BUNDLE_WIDTH / 2 + CABLE_CLEARANCE if self.bundle else CABLE_CLEARANCE

    def lane_frame(self) -> tuple[str, float, float, float]:
        """Where the long run may sit: (kind, reference y, smallest offset, largest offset).

        kind "gap": between the two boxes, offsets measured down from the upper box's
        bottom edge. "below" / "above": side-by-side boxes, the run goes under both
        (or over both, for two uplinks), offsets measured away from them."""
        ar, br = self.a.sceneBoundingRect(), self.b.sceneBoundingRect()
        margin = self.clearance()
        for upper, lower in ((ar, br), (br, ar)):
            if upper.bottom() + 12 < lower.top():
                gap = lower.top() - upper.bottom()
                lo, hi = margin, gap - margin
                if hi < lo:  # too tight for the margins: the middle of the gap
                    lo = hi = gap / 2
                return "gap", upper.bottom(), lo, hi
        a_up = self.a_port in self.a.port_items and self.a.is_uplink(self.a_port)
        b_up = self.b_port in self.b.port_items and self.b.is_uplink(self.b_port)
        if a_up and b_up:
            return "above", min(ar.top(), br.top()), margin + 4, margin + 400
        return "below", max(ar.bottom(), br.bottom()), margin + 4, margin + 400

    def run_y(self, lane_offset: float | None) -> float:
        """The y of the long run for *lane_offset* (None: this cable's default lane)."""
        kind, ref, lo, hi = self.lane_frame()
        if lane_offset is None:
            lane_offset = lo + (self.lane * 8) % max(4.0, hi - lo) if kind == "gap" else lo + 6 + self.lane * 8
        off = min(max(lane_offset, lo), hi)
        return ref - off if kind == "above" else ref + off

    def offset_for_y(self, y: float) -> float:
        """The lane offset that puts the long run at scene y (kept within its limits)."""
        kind, ref, lo, hi = self.lane_frame()
        off = (ref - y) if kind == "above" else (y - ref)
        return min(max(off, lo), hi)

    def lane_options(self) -> list[float]:
        """Every lane Re-arrange cable may try for the long horizontal run."""
        kind, _ref, lo, hi = self.lane_frame()
        if kind == "gap":
            return [lo + 6.0 * k for k in range(int(max(0.0, hi - lo) // 6) + 1)]
        return [lo + 8.0 * k for k in range(14)]

    def long_run(self) -> tuple[float, float, float] | None:
        """(y, x from, x to) of the cable's longest horizontal run: the bar that can be dragged."""
        best = None
        for _i, a, b in self.segments():
            if abs(a.y() - b.y()) < 0.01:
                length = abs(a.x() - b.x())
                if best is None or length > best[0]:
                    best = (length, a.y(), min(a.x(), b.x()), max(a.x(), b.x()))
        return best[1:] if best else None

    def on_long_run(self, scene_pos: QPointF) -> bool:
        run = self.long_run()
        if run is None:
            return False
        y, x0, x1 = run
        grab = BUNDLE_WIDTH / 2 + 2 if self.bundle else DRAG_GRAB
        return abs(scene_pos.y() - y) <= grab and x0 - grab <= scene_pos.x() <= x1 + grab

    def _view(self):  # noqa: ANN202
        scene = self.scene()
        return next((v for v in (scene.views() if scene else []) if isinstance(v, SiteTopologyView)), None)

    def hoverMoveEvent(self, event) -> None:  # noqa: ANN001, N802
        view = self._view()
        if view is not None and not view._locked and self.on_long_run(event.scenePos()):  # noqa: SLF001
            self.setCursor(Qt.CursorShape.SizeVerCursor)  # this bar can be dragged up / down
        else:
            self.unsetCursor()
        super().hoverMoveEvent(event)

    def mousePressEvent(self, event) -> None:  # noqa: ANN001, N802
        view = self._view()
        if (event.button() == Qt.MouseButton.LeftButton and view is not None and not view._locked  # noqa: SLF001
                and self.on_long_run(event.scenePos())):
            self._dragging_run = True
            event.accept()
            return
        event.ignore()

    def mouseMoveEvent(self, event) -> None:  # noqa: ANN001, N802
        if getattr(self, "_dragging_run", False):
            self.move_long_run(event.scenePos().y())
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:  # noqa: ANN001, N802
        if getattr(self, "_dragging_run", False):
            self._dragging_run = False
            view = self._view()
            if view is not None:
                view.cable_lane_changed(self)
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def move_long_run(self, scene_y: float) -> None:
        """Put the long run at *scene_y* (within its limits); the route becomes ours."""
        self.route = None
        self.lane_offset = self.offset_for_y(scene_y)
        self.set_points(self.points_for(self.lane_offset))

    def points_for(self, lane_offset: float | None) -> list[QPointF]:  # noqa: C901
        """The cable's corners with its long run in lane *lane_offset* (None: default)."""
        ar = self.a.sceneBoundingRect()
        br = self.b.sceneBoundingRect()
        gap_top, gap_bottom = None, None
        if ar.bottom() + 12 < br.top():  # a above b: run in the gap between
            a_face, b_face, gap_top, gap_bottom = "bottom", "top", ar.bottom(), br.top()
        elif br.bottom() + 12 < ar.top():  # b above a
            a_face, b_face, gap_top, gap_bottom = "top", "bottom", br.bottom(), ar.top()
        else:  # side by side: corridor below both
            a_face = b_face = "bottom"
        a_up = self.a_port in self.a.port_items and self.a.is_uplink(self.a_port)
        b_up = self.b_port in self.b.port_items and self.b.is_uplink(self.b_port)
        start = self.a.port_anchor(self.a_port, facing="top" if a_up else a_face, vid=self.vid)
        end = self.b.port_anchor(self.b_port, facing="top" if b_up else b_face, vid=self.vid)
        mid_y = self.run_y(lane_offset)  # clear of both boxes, in the chosen lane
        # An uplink cable that has to head down climbs out of its box first
        # and goes round the side nearer the other end.
        head = [start] + self._round_box(start, ar, a_up and mid_y > ar.top(), end)
        tail = self._round_box(end, br, b_up and mid_y > br.top(), start)
        far = tail[-1] if tail else end
        return [*head, QPointF(head[-1].x(), mid_y), QPointF(far.x(), mid_y), *reversed(tail), end]

    def _follow_route(self, ar: QRectF, br: QRectF) -> None:
        """Port → ELK's orthogonal route (box edge to box edge) → port."""
        pts = [QPointF(x, y) for x, y in self.route or []]
        fa = "bottom" if pts[0].y() >= ar.center().y() else "top"
        fb = "bottom" if pts[-1].y() >= br.center().y() else "top"
        start = self.a.port_anchor(self.a_port, facing=fa, vid=self.vid)
        end = self.b.port_anchor(self.b_port, facing=fb, vid=self.vid)
        self.set_points([start, QPointF(start.x(), pts[0].y()), *pts, QPointF(end.x(), pts[-1].y()), end])

    def set_points(self, pts: list[QPointF]) -> None:
        """New corners: draw now (keeping known hops), and ask the view to
        work out the crossings again."""
        clean: list[QPointF] = []
        for pt in pts:  # drop repeats so segment indices are stable
            if not clean or (abs(pt.x() - clean[-1].x()) > 0.01 or abs(pt.y() - clean[-1].y()) > 0.01):
                clean.append(QPointF(pt))
        if clean != self.points:
            self.points = clean
            self.hops = {}
        self.draw()
        scene = self.scene()
        for view in (scene.views() if scene else []):
            if isinstance(view, SiteTopologyView):
                view.schedule_hops()

    def segments(self) -> list[tuple[int, QPointF, QPointF]]:
        return [(i, a, b) for i, (a, b) in enumerate(zip(self.points, self.points[1:]))]

    def draw(self) -> None:
        """The path through the corners, with a small semicircle wherever this
        cable jumps over another one (horizontal runs hop over vertical runs)."""
        if not self.points:
            self.setPath(QPainterPath())
            return
        path = QPainterPath(self.points[0])
        r = HOP_RADIUS
        for i, a, b in self.segments():
            xs = self.hops.get(i) or []
            if xs and abs(a.y() - b.y()) < 0.01:
                rightwards = b.x() > a.x()
                for x in sorted(xs, reverse=not rightwards):
                    y = a.y()
                    if rightwards:
                        path.lineTo(QPointF(x - r, y))
                        path.arcTo(QRectF(x - r, y - r, 2 * r, 2 * r), 180, -180)
                    else:
                        path.lineTo(QPointF(x + r, y))
                        path.arcTo(QRectF(x - r, y - r, 2 * r, 2 * r), 0, 180)
            path.lineTo(b)
        self.setPath(path)

    def _round_box(self, port: QPointF, box: QRectF, needed: bool, other: QPointF) -> list[QPointF]:
        """Waypoints from a top-facing port up and over to the side of its box."""
        if not needed:
            return []
        above = box.top() - 12 - self.lane * 6
        if other.x() < box.center().x():
            side = box.left() - 12 - self.lane * 6
        else:
            side = box.right() + 12 + self.lane * 6
        return [QPointF(port.x(), above), QPointF(side, above)]


PAN_MARGIN = 800.0  # empty canvas kept around the devices, so there is room to pan
PAN_START_PX = 4  # right-button movement that turns a click into a pan
ZOOM_MIN = 0.1
ZOOM_MAX = 4.0
_ZOOM_STEPS = 200  # slider resolution; positions map logarithmically to zoom


def zoom_to_slider(z: float) -> int:
    z = max(ZOOM_MIN, min(ZOOM_MAX, z))
    return round(_ZOOM_STEPS * math.log(z / ZOOM_MIN) / math.log(ZOOM_MAX / ZOOM_MIN))


def slider_to_zoom(pos: int) -> float:
    return ZOOM_MIN * (ZOOM_MAX / ZOOM_MIN) ** (pos / _ZOOM_STEPS)


class ZoomBar(QFrame):
    """− / slider / + / percent / Fit, floating in the canvas's bottom-right corner."""

    def __init__(self, view: "SiteTopologyView") -> None:
        super().__init__(view)
        self._view = view
        self.setObjectName("zoomBar")
        self.setStyleSheet(
            "#zoomBar { background: rgba(255, 255, 255, 225); border: 1px solid #b0bec5;"
            " border-radius: 6px; }"
            "#zoomBar QToolButton { border: none; min-width: 20px; font-weight: 600; color: #37474f; }"
            "#zoomBar QToolButton:hover { background: #e3f2fd; border-radius: 3px; }"
            "#zoomBar QLabel { color: #37474f; }"
        )
        row = QHBoxLayout(self)
        row.setContentsMargins(6, 3, 6, 3)
        row.setSpacing(4)
        minus = QToolButton()
        minus.setText("−")
        minus.setToolTip("Zoom out")
        minus.clicked.connect(lambda: view.set_zoom(view.zoom() / 1.25))
        self.slider = QSlider(Qt.Orientation.Horizontal)
        self.slider.setRange(0, _ZOOM_STEPS)
        self.slider.setFixedWidth(150)
        self.slider.setToolTip("Zoom (Ctrl+wheel also zooms)")
        self.slider.valueChanged.connect(lambda v: view.set_zoom(slider_to_zoom(v)))
        plus = QToolButton()
        plus.setText("+")
        plus.setToolTip("Zoom in")
        plus.clicked.connect(lambda: view.set_zoom(view.zoom() * 1.25))
        self.percent = QToolButton()
        self.percent.setToolTip("Back to 100%")
        self.percent.setMinimumWidth(44)
        self.percent.clicked.connect(lambda: view.set_zoom(1.0))
        fit = QToolButton()
        fit.setText("Fit")
        fit.setToolTip("Zoom to show every device")
        fit.clicked.connect(view.zoom_to_fit)
        for w in (minus, self.slider, plus, self.percent, fit):
            row.addWidget(w)
        self.show_zoom(1.0)

    def show_zoom(self, z: float) -> None:
        self.slider.blockSignals(True)
        self.slider.setValue(zoom_to_slider(z))
        self.slider.blockSignals(False)
        self.percent.setText(f"{round(z * 100)}%")


class SiteTopologyView(QGraphicsView):
    """Editable physical map: grid-locked chassis with NIC / faceplate ports."""

    positions_changed = Signal()
    cable_message = Signal(str)  # result of Re-arrange cable, for the status bar
    links_changed = Signal()
    device_changed = Signal(str)  # device name after Pull Config / similar
    device_selected = Signal(str)  # one chassis selected on the canvas ("" = none)

    def __init__(self) -> None:
        self._scene = QGraphicsScene()
        super().__init__(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setBackgroundBrush(QBrush(QColor("#f4f6f8")))
        self.setMinimumHeight(420)
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.DefaultContextMenu)
        self.viewport().setContextMenuPolicy(Qt.ContextMenuPolicy.DefaultContextMenu)
        self._site = None
        self._chassis: dict[str, ChassisItem] = {}
        self._links: list[LinkItem] = []
        self._hops_timer = QTimer(self)
        self._hops_timer.setSingleShot(True)
        self._hops_timer.setInterval(0)
        self._hops_timer.timeout.connect(self.update_hops)
        self._snap = True
        self._grid = 20
        self._locked = False
        self._draw_grid = True
        self._highlight_devices: set[str] = set()
        self._highlight_path: list[str] = []
        self._wire_from: tuple[str, str] | None = None  # (device, port)
        self._wire_vid = ""  # the VLAN being cabled, "" for the whole port
        self._wire_line = None
        self._ssh_password_provider = None
        self.zoom_bar = ZoomBar(self)
        self.vlan_legend = VlanLegend(self)
        self._place_overlays()
        self._quiet_selection = False
        self._pan_origin: QPointF | None = None
        self._panning = False
        self._suppress_menu = False
        self._pulse_t0 = time.monotonic()
        self._pulse_timer = QTimer(self)
        self._pulse_timer.setInterval(PULSE_FRAME_MS)
        self._pulse_timer.timeout.connect(self._pulse_tick)
        self._scene.selectionChanged.connect(self._on_scene_selection)

    def set_snap(self, enabled: bool) -> None:
        self._snap = enabled
        for ch in self._chassis.values():
            ch.set_snap(enabled, self._grid)

    def set_grid_size(self, size: int) -> None:
        self._grid = max(5, int(size))
        if self._site is not None:
            self._site.grid_size = self._grid
        for ch in self._chassis.values():
            ch.set_snap(self._snap, self._grid)
        self.viewport().update()

    def set_locked(self, locked: bool) -> None:
        self._locked = locked
        for ch in self._chassis.values():
            ch.set_locked(locked)
        if locked:
            self._cancel_port_link()

    def clear(self) -> None:
        self._cancel_port_link()
        self._pulse_timer.stop()
        # Forget the items first: clearing the scene fires selectionChanged
        # while they are being deleted.
        self._chassis.clear()
        self._links.clear()
        self._quiet_selection = True
        try:
            self._scene.clear()
        finally:
            self._quiet_selection = False

    # ---- selection: tell the page which device was picked; pulse it ----------

    def selected_device(self) -> str:
        live = set(map(id, self._live_chassis()))
        names = [n for n, ch in self._chassis.items() if id(ch) in live and ch.isSelected()]
        return names[0] if len(names) == 1 else ""

    def select_device(self, name: str, *, ensure_visible: bool = True) -> None:
        """Select *name*'s chassis (from the device list) without echoing back."""
        ch = self._chassis.get(name)
        self._quiet_selection = True
        try:
            for other in self._chassis.values():
                if other is not ch:
                    other.setSelected(False)
            if ch is not None:
                ch.setSelected(True)
                if ensure_visible:
                    self.ensureVisible(ch.sceneBoundingRect(), 40, 40)
        finally:
            self._quiet_selection = False
        self._update_pulse()

    def _on_scene_selection(self) -> None:
        self._update_pulse()
        if self._quiet_selection:
            return
        try:
            name = self.selected_device()
        except RuntimeError:  # items being torn down
            return
        if name:
            self.device_selected.emit(name)

    def _on_chassis_edit_finished(self, _name: str) -> None:
        if self._site is not None and getattr(self._site, "uniform_sizes", False):
            # A resized box takes its same-type siblings with it.
            edited = self._chassis.get(_name)
            if edited is not None:
                w, h = edited.current_size()
                key = device_type_key(edited.device)
                for ch in self._live_chassis():
                    if ch is not edited and device_type_key(ch.device) == key:
                        r = ch.boundingRect()
                        if abs(r.width() - w) > 0.5 or abs(r.height() - h) > 0.5:
                            ch.apply_size(w, h)
                            ch.device.w, ch.device.h = ch.current_size()
        # A moved or stretched box keeps PAN_MARGIN of canvas around it.
        items = self._scene.itemsBoundingRect()
        grown = self._scene.sceneRect().united(items.adjusted(-PAN_MARGIN, -PAN_MARGIN, PAN_MARGIN, PAN_MARGIN))
        if grown != self._scene.sceneRect():
            self._scene.setSceneRect(grown)
        self.positions_changed.emit()

    def _live_chassis(self) -> list["ChassisItem"]:
        out = []
        for ch in list(self._chassis.values()):
            try:
                ch.isSelected()
            except RuntimeError:  # C++ item already deleted (view closing)
                continue
            out.append(ch)
        return out

    def _update_pulse(self) -> None:
        live = self._live_chassis()
        selected = [ch for ch in live if ch.isSelected()]
        if selected and not self._pulse_timer.isActive():
            self._pulse_t0 = time.monotonic()
            self._pulse_timer.start()
        elif not selected:
            self._pulse_timer.stop()
        for ch in live:
            if not ch.isSelected() and ch.pulse != 1.0:
                ch.pulse = 1.0
                ch.update()

    def _pulse_tick(self) -> None:
        phase = (time.monotonic() - self._pulse_t0) / PULSE_PERIOD_S
        value = 0.5 + 0.5 * math.sin(2 * math.pi * phase)
        any_selected = False
        for ch in self._live_chassis():
            if ch.isSelected():
                any_selected = True
                ch.pulse = value
                ch.update()
        if not any_selected:
            self._pulse_timer.stop()

    def set_ssh_password_provider(self, provider) -> None:  # noqa: ANN001
        """Optional callable returning the typed SSH password from Login."""
        self._ssh_password_provider = provider

    def _typed_ssh_password(self) -> str | None:
        provider = self._ssh_password_provider
        if provider is None:
            return None
        try:
            text = provider()
        except Exception:  # noqa: BLE001
            return None
        text = (text or "").strip()
        return text or None

    def _chassis_item_at(self, scene_pos: QPointF) -> ChassisItem | None:
        for item in self._scene.items(scene_pos):
            cur = item
            while cur is not None:
                if isinstance(cur, ChassisItem):
                    return cur
                cur = cur.parentItem()
        return None

    def _link_item_at(self, scene_pos: QPointF) -> "LinkItem | None":
        for item in self._scene.items(scene_pos):
            if isinstance(item, LinkItem):
                return item
        return None

    def delete_link(self, a_dev: str, a_port: str, b_dev: str, b_port: str, vid: str = "",
                    *, indices: list[int] | None = None) -> bool:
        """Remove the cable between the two ports (either direction): the whole-port
        cable, or with *vid* that VLAN's cable only; *indices* removes exactly those
        site links (a rainbow bundle)."""
        if self._site is None:
            return False
        before = len(self._site.links)
        if indices:
            drop = set(indices)
            self._site.links = [ln for i, ln in enumerate(self._site.links) if i not in drop]
        else:
            self._site.links = [
                link for link in self._site.links
                if not (
                    link_vid(link) == vid
                    and ((link.a_device, link.a_port, link.b_device, link.b_port) == (a_dev, a_port, b_dev, b_port)
                         or (link.a_device, link.a_port, link.b_device, link.b_port) == (b_dev, b_port, a_dev, a_port))
                )
            ]
        if len(self._site.links) == before:
            return False
        self.render_site(self._site)
        self.links_changed.emit()
        return True

    def contextMenuEvent(self, event) -> None:  # noqa: ANN001, N802
        if self._suppress_menu or self._panning:
            self._suppress_menu = False  # the right button was used to pan
            event.accept()
            return
        sp = self.mapToScene(event.pos())
        link_item = self._link_item_at(sp)
        if link_item is not None and not self._locked:
            a_dev, b_dev = link_item.a.device.name, link_item.b.device.name
            menu = QMenu(self)
            title = menu.addAction(f"{a_dev}:{link_item.a_port or '?'} ↔ {b_dev}:{link_item.b_port or '?'}")
            title.setEnabled(False)
            menu.addSeparator()
            act_rearrange = menu.addAction("Re-arrange cable")
            act_rearrange.setToolTip("Move this cable's long run to the lane where it crosses the fewest others")
            act_all = menu.addAction("Re-arrange all cables")
            menu.addSeparator()
            act_delete = menu.addAction(
                f"Delete all {len(link_item.bundle)} VLAN cables" if link_item.bundle else "Delete cable")
            chosen = menu.exec(event.globalPos())
            if chosen is act_delete:
                self.delete_link(a_dev, link_item.a_port, b_dev, link_item.b_port, link_item.vid,
                                 indices=link_item.bundle_links if link_item.bundle else None)
            elif chosen is act_rearrange:
                self.cable_message.emit(self.rearrange_cable(link_item))
            elif chosen is act_all:
                self.cable_message.emit(self.rearrange_all_cables())
            event.accept()
            return
        chassis = self._chassis_item_at(sp)
        if chassis is None:
            super().contextMenuEvent(event)
            return
        port = self._port_item_at(sp)
        on_title = chassis.mapFromScene(sp).y() < HEADER_H and port is None
        self._popup_chassis_menu(chassis.device, event.globalPos(), chassis=chassis if on_title else None,
                                 port=(chassis, port.port_name) if port is not None else None)
        event.accept()

    def _popup_chassis_menu(self, device, global_pos, *, chassis: "ChassisItem | None" = None,  # noqa: ANN001
                            port: "tuple[ChassisItem, str] | None" = None) -> None:
        """Chassis menu; right-clicking the title also offers the port layouts,
        right-clicking a port offers to make it an uplink."""
        from pfsense_checker.chassis_actions import CHASSIS_MENU_ITEMS, perform_chassis_action

        menu = QMenu(self)
        title_act = menu.addAction(
            device.chassis_title()
            if device.chassis_title() != device.name
            else (device.name or "Chassis")
        )
        title_act.setEnabled(False)
        menu.addSeparator()
        uplink_act = None
        vlan_acts: dict = {}
        if port is not None:
            owner, port_name = port
            head = menu.addAction(f"Port {port_name}" + (" (canvas locked)" if self._locked else ""))
            head.setEnabled(False)
            uplink_act = menu.addAction("Uplink — in the title bar, cables go north")
            uplink_act.setCheckable(True)
            uplink_act.setChecked(owner.is_uplink(port_name))
            uplink_act.setEnabled(not self._locked)
            rename_act = menu.addAction("Rename port…")
            rename_act.setEnabled(not self._locked)
            vlan_acts[rename_act] = ("rename", "")
            add_vlan_act = menu.addAction("Add VLAN to this port…")
            add_vlan_act.setEnabled(not self._locked)
            vlan_acts[add_vlan_act] = ("add", "")
            for vid, tagged in vlan_plan.planned_on(owner.device, port_name):
                act = menu.addAction(f"Remove planned VLAN {vid} ({'tagged' if tagged else 'untagged'})")
                act.setEnabled(not self._locked)
                vlan_acts[act] = ("remove", vid)
            if vlan_plan.plan_of(owner.device):
                vlan_acts[menu.addAction("Show commands for planned VLANs…")] = ("commands", "")
            menu.addSeparator()
        layouts = {}
        if chassis is not None:
            head = menu.addAction("Port layout" + (" (canvas locked)" if self._locked else ""))
            head.setEnabled(False)
            for mode, label in LAYOUTS:
                act = menu.addAction(label)
                act.setCheckable(True)
                act.setChecked(chassis.port_layout == mode)
                act.setEnabled(not self._locked)
                layouts[act] = mode
            menu.addSeparator()
        actions = {}
        for action_id, label in CHASSIS_MENU_ITEMS:
            actions[menu.addAction(label)] = action_id
        chosen = menu.exec(global_pos)
        if uplink_act is not None and chosen is uplink_act and port is not None:
            port[0].set_uplink(port[1], uplink_act.isChecked())
            return
        if chosen in vlan_acts and port is not None:
            what, vid = vlan_acts[chosen]
            if what == "rename":
                self.rename_port(port[0], port[1])
            elif what == "add":
                self.add_vlan_to_port(port[0], port[1])
            elif what == "remove":
                self.remove_planned_vlan(port[0], port[1], vid)
            else:
                self.show_planned_commands(port[0].device)
            return
        if chosen in layouts and chassis is not None:
            chassis.set_port_layout(layouts[chosen])
            return
        action_id = actions.get(chosen)
        if not action_id:
            return
        pulled = perform_chassis_action(
            self,
            device,
            action_id,
            password=self._typed_ssh_password(),
        )
        if pulled:
            self.device_changed.emit(device.name)

    def select_port_vlan(self, port_item: PortItem, vid: str) -> None:
        """Highlight one VLAN stripe (only one picked on the canvas at a time)."""
        for ch in self._live_chassis():
            for item in ch.port_items.values():
                if item is not port_item:
                    item.select_vid("")
        port_item.select_vid(vid)

    def clear_port_vlans(self) -> None:
        for ch in self._live_chassis():
            for item in ch.port_items.values():
                item.select_vid("")

    def begin_port_link(self, port_item: PortItem, scene_pos: QPointF, *, vid: str = "") -> None:
        """Start dragging a cable from *port_item* (unlocked canvas only); with
        *vid*, a cable for that VLAN from its stripe."""
        if self._locked or self._site is None:
            return
        self._cancel_port_link()
        self._wire_from = (port_item.device_name, port_item.port_name)
        self._wire_vid = vid
        facing = "bottom" if port_item.faceplate else "right"
        anchor = (port_item.stripe_anchor(vid, "bottom") if vid else None) or port_item.anchor_scene(facing)
        pen = QPen(QColor(port_vlans.vlan_color(vid, self._palette)) if vid else QColor("#1565c0"))
        pen.setWidth(3 if vid else 2)
        pen.setStyle(Qt.PenStyle.DashLine)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        self._wire_line = self._scene.addLine(QLineF(anchor, scene_pos), pen)
        self._wire_line.setZValue(100)
        self.setDragMode(QGraphicsView.DragMode.NoDrag)
        self.viewport().grabMouse()

    def _cancel_port_link(self) -> None:
        self._wire_from = None
        self._wire_vid = ""
        if self._wire_line is not None:
            try:
                self._scene.removeItem(self._wire_line)
            except RuntimeError:
                pass
            self._wire_line = None
        try:
            self.viewport().releaseMouse()
        except RuntimeError:
            pass
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)

    def _port_item_at(self, scene_pos: QPointF) -> PortItem | None:
        for item in self._scene.items(scene_pos):
            cur = item
            while cur is not None:
                if isinstance(cur, PortItem):
                    return cur
                cur = cur.parentItem()
        return None

    def _link_exists(self, a_dev: str, a_port: str, b_dev: str, b_port: str, vid: str = "") -> bool:
        if self._site is None:
            return False
        for link in self._site.links:
            if link_vid(link) != vid:
                continue  # each VLAN has its own cable between the same ports
            if (
                link.a_device == a_dev
                and link.a_port == a_port
                and link.b_device == b_dev
                and link.b_port == b_port
            ):
                return True
            if (
                link.a_device == b_dev
                and link.a_port == b_port
                and link.b_device == a_dev
                and link.b_port == a_port
            ):
                return True
        return False

    def _complete_port_link(self, b_device: str, b_port: str) -> None:
        if self._site is None or self._wire_from is None:
            self._cancel_port_link()
            return
        a_device, a_port = self._wire_from
        vid = getattr(self, "_wire_vid", "")
        if a_device == b_device and a_port == b_port:
            self._cancel_port_link()
            return
        self._cancel_port_link()
        if a_device == b_device:
            return  # require another device
        if self._link_exists(a_device, a_port, b_device, b_port, vid):
            return
        self._site.links.append(
            Link(
                a_device=a_device,
                a_port=a_port,
                b_device=b_device,
                b_port=b_port,
                kind=VLAN_LINK_KIND if vid else "copper",
                vlans=[vid] if vid else [],
            )
        )
        self.clear_port_vlans()
        self.render_site(self._site)
        self.links_changed.emit()
        self.positions_changed.emit()

    # Right button: a click opens the menu; a drag pans the canvas. (Qt would
    # otherwise start a rubber-band selection on any button.)

    def mousePressEvent(self, event) -> None:  # noqa: ANN001, N802
        if event.button() == Qt.MouseButton.RightButton:
            self._pan_origin = event.position()
            self._panning = False
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:  # noqa: ANN001, N802
        if self._wire_from is not None and self._wire_line is not None:
            sp = self.mapToScene(event.position().toPoint())
            line = self._wire_line.line()
            self._wire_line.setLine(QLineF(line.p1(), sp))
            event.accept()
            return
        if self._pan_origin is not None and event.buttons() & Qt.MouseButton.RightButton:
            delta = event.position() - self._pan_origin
            if not self._panning and delta.manhattanLength() >= PAN_START_PX:
                self._panning = True
                self.viewport().setCursor(Qt.CursorShape.ClosedHandCursor)
            if self._panning:
                h, v = self.horizontalScrollBar(), self.verticalScrollBar()
                h.setValue(h.value() - round(delta.x()))
                v.setValue(v.value() - round(delta.y()))
                self._pan_origin = event.position()
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:  # noqa: ANN001, N802
        if event.button() == Qt.MouseButton.RightButton and self._pan_origin is not None:
            if self._panning:
                self._suppress_menu = True  # a pan is not a right-click
                self.viewport().unsetCursor()
            self._pan_origin = None
            self._panning = False
            event.accept()
            return
        if self._wire_from is not None and event.button() == Qt.MouseButton.LeftButton:
            sp = self.mapToScene(event.position().toPoint())
            target = self._port_item_at(sp)
            if target is not None:
                self._complete_port_link(target.device_name, target.port_name)
            else:
                self._cancel_port_link()
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def keyPressEvent(self, event) -> None:  # noqa: ANN001, N802
        if event.key() == Qt.Key.Key_Escape and self._wire_from is not None:
            self._cancel_port_link()
            event.accept()
            return
        if event.key() == Qt.Key.Key_Escape:
            self.clear_port_vlans()
        super().keyPressEvent(event)

    def drawBackground(self, painter, rect) -> None:  # noqa: ANN001, N802
        super().drawBackground(painter, rect)
        if not self._draw_grid:
            return
        g = self._grid
        painter.setPen(QPen(QColor("#d0d7de")))
        left = int(rect.left()) - (int(rect.left()) % g)
        top = int(rect.top()) - (int(rect.top()) % g)
        x = left
        while x < rect.right():
            painter.drawLine(x, int(rect.top()), x, int(rect.bottom()))
            x += g
        y = top
        while y < rect.bottom():
            painter.drawLine(int(rect.left()), y, int(rect.right()), y)
            y += g

    def wheelEvent(self, event) -> None:  # noqa: ANN001, N802
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
            self.set_zoom(self.zoom() * factor, anchor_mouse=True)
            event.accept()
            return
        super().wheelEvent(event)

    # ---- zoom (slider overlay + Ctrl+wheel) --------------------------------

    def zoom(self) -> float:
        return self.transform().m11()

    def set_zoom(self, value: float, *, anchor_mouse: bool = False) -> None:
        """Zoom to *value* (1.0 = 100%), clamped; keeps the view centre (or the
        point under the mouse for Ctrl+wheel) where it was."""
        value = max(ZOOM_MIN, min(ZOOM_MAX, value))
        current = self.zoom()
        if abs(value - current) < 1e-6:
            self._sync_zoom_bar()
            return
        if anchor_mouse:
            self.scale(value / current, value / current)  # AnchorUnderMouse
        else:
            centre = self.mapToScene(self.viewport().rect().center())
            self.setTransform(QTransform.fromScale(value, value))
            self.centerOn(centre)
        self._sync_zoom_bar()

    def zoom_to_fit(self) -> None:
        items = self._scene.itemsBoundingRect()
        if items.isEmpty():
            self.set_zoom(1.0)
            return
        self.fitInView(items.adjusted(-30, -30, 30, 30), Qt.AspectRatioMode.KeepAspectRatio)
        if not (ZOOM_MIN <= self.zoom() <= ZOOM_MAX):
            self.set_zoom(self.zoom())
            self.centerOn(items.center())
        self._sync_zoom_bar()

    def _sync_zoom_bar(self) -> None:
        bar = getattr(self, "zoom_bar", None)
        if bar is not None:
            bar.show_zoom(self.zoom())

    def resizeEvent(self, event) -> None:  # noqa: ANN001, N802
        super().resizeEvent(event)
        self._place_overlays()

    def _place_overlays(self) -> None:
        """Zoom bar bottom-right; VLAN legend across the top."""
        vp = self.viewport().geometry()
        bar = getattr(self, "zoom_bar", None)
        if bar is not None:
            bar.adjustSize()
            bar.move(vp.right() - bar.width() - 10, vp.bottom() - bar.height() - 10)
            bar.raise_()
        legend = getattr(self, "vlan_legend", None)
        if legend is not None and legend.isVisibleTo(self):
            room = max(200, vp.width() - 20 - 18)
            label = legend.label
            label.setWordWrap(False)
            label.setMinimumWidth(0)
            label.setMaximumWidth(16777215)
            natural = label.sizeHint().width()
            if natural > room:  # wrap onto more lines only when the canvas is too narrow
                label.setWordWrap(True)
                label.setFixedWidth(room)
            else:
                label.setFixedWidth(natural)
            legend.adjustSize()
            legend.move(vp.left() + 10, vp.top() + 8)
            legend.raise_()

    _place_zoom_bar = _place_overlays  # older name

    def _on_chassis_moved(self, name: str, x: float, y: float) -> None:
        if self._site is None:
            return
        dev = self._site.device(name)
        if dev is None:
            return
        # Every pixel of a drag lands here. Only record it: listeners re-render
        # the whole site (Login to Routers rebuilds every chassis), which used
        # to destroy the box under the mouse mid-drag and make it jump
        # (BUG-046). positions_changed goes out once, on edit_finished.
        dev.x = x
        dev.y = y

    def _on_chassis_resized(self, name: str, w: float, h: float) -> None:
        if self._site is None:
            return
        dev = self._site.device(name)
        if dev is None:
            return
        dev.w = w
        dev.h = h  # live resize: recorded; announced on edit_finished (BUG-046)

    # -- Port names --------------------------------------------------------------- #

    def rename_port(self, chassis: "ChassisItem", port: str, name: str | None = None) -> bool:
        """Give a port a name on the map (asks when *name* is None). An empty name goes
        back to the one on the device, if it has one. The device itself is not changed."""
        if self._site is None or self._locked:
            return False
        device = chassis.device
        if name is None:
            from PySide6.QtWidgets import QInputDialog

            current = chassis.port_given_name(port)
            name, ok = QInputDialog.getText(
                self, f"Rename {port}",
                f"Name for {device.name} · {port}\n(shown in the port; leave empty to use the device's own name)",
                text=current)
            if not ok:
                return False
        name = (name or "").strip()
        labels = device.port_labels
        if name:
            labels[port.lower()] = name
        else:
            labels.pop(port.lower(), None)
        self.render_site(self._site)
        self.positions_changed.emit()  # saved with the topology
        self.cable_message.emit(f"{device.name} {port}: named '{name}' on the map" if name
                                else f"{device.name} {port}: map name removed")
        return True

    # -- Planned VLANs on ports -------------------------------------------------- #

    def known_vlans(self) -> dict[str, str]:
        """VLAN id → name for every VLAN on the canvas (configs and plans)."""
        out: dict[str, str] = {}
        for ch in self._live_chassis():
            for item in ch.port_items.values():
                for vid in (item.vlans.vlans if item.vlans else []):
                    out.setdefault(vid, "")
            for vid, name in ch._vlans.names.items():  # noqa: SLF001
                if name and not out.get(vid):
                    out[vid] = name
        return out

    def add_vlan_to_port(self, chassis: "ChassisItem", port: str, *, vid: str = "", tagged: bool = True) -> str:
        """Plan a VLAN on a port. With no *vid*, asks (Add VLAN dialog). Returns
        "" when it was added, else why not."""
        if self._site is None or self._locked:
            return "The layout is locked." if self._locked else "No site."
        device = chassis.device
        existing = chassis._vlans.port(port)  # noqa: SLF001
        if vid:
            problem = vlan_plan.add(device, port, vid, tagged, existing)
            if problem:
                return problem
        else:
            from PySide6.QtWidgets import QDialog

            from pfsense_checker.add_vlan_dialog import AddVlanDialog

            dlg = AddVlanDialog(device, port, existing, self.known_vlans(), self)
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return "cancelled"
        self.render_site(self._site)
        self.positions_changed.emit()  # saved with the topology
        self.cable_message.emit(f"{device.name} {port}: VLAN planned. Right-click the port → "
                                "Show commands for planned VLANs.")
        return ""

    def remove_planned_vlan(self, chassis: "ChassisItem", port: str, vid: str) -> bool:
        if self._site is None or self._locked or not vlan_plan.remove(chassis.device, port, vid):
            return False
        # A cable drawn for that VLAN from this port has nothing to stand on now.
        name = chassis.device_name
        self._site.links = [
            ln for ln in self._site.links
            if not (link_vid(ln) == vid and ((ln.a_device, ln.a_port) == (name, port)
                                             or (ln.b_device, ln.b_port) == (name, port)))
        ]
        self.render_site(self._site)
        self.links_changed.emit()
        self.positions_changed.emit()
        return True

    def planned_commands_text(self, device) -> str:  # noqa: ANN001
        return "\n".join(vlan_plan.commands(device))

    def show_planned_commands(self, device) -> None:  # noqa: ANN001
        from PySide6.QtWidgets import QApplication, QDialog, QDialogButtonBox, QPlainTextEdit

        text = self.planned_commands_text(device)
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Planned VLANs — what to enter on {device.name}")
        dlg.resize(900, 420)
        lay = QVBoxLayout(dlg)
        note = QLabel("NetCheck has not changed the device. Check each line, enter it on the device, then pull "
                      "its config again: the planned stripes become real ones.")
        note.setWordWrap(True)
        lay.addWidget(note)
        box = QPlainTextEdit(text)
        box.setReadOnly(True)
        box.setFont(QFont("Consolas", 10))
        lay.addWidget(box)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        copy = buttons.addButton("Copy", QDialogButtonBox.ButtonRole.ActionRole)
        copy.clicked.connect(lambda: QApplication.clipboard().setText(text))
        buttons.rejected.connect(dlg.reject)
        lay.addWidget(buttons)
        dlg.exec()

    # -- Same size for the same type --------------------------------------------- #

    def set_uniform_sizes(self, on: bool) -> None:
        """Turn "same device types the same size" on or off (saved on the site)."""
        if self._site is None:
            return
        self._site.uniform_sizes = bool(on)
        if on:
            self.apply_uniform_sizes()
        self.render_site(self._site)
        self.positions_changed.emit()

    def apply_uniform_sizes(self) -> int:
        """Give every device the largest current size among its type. Returns how
        many boxes changed."""
        if self._site is None:
            return 0
        groups: dict[str, list[ChassisItem]] = {}
        for ch in self._live_chassis():
            groups.setdefault(device_type_key(ch.device), []).append(ch)
        changed = 0
        for members in groups.values():
            if len(members) < 2:
                continue
            w = max(ch.boundingRect().width() for ch in members)
            h = max(ch.boundingRect().height() for ch in members)
            for ch in members:
                r = ch.boundingRect()
                if abs(r.width() - w) > 0.5 or abs(r.height() - h) > 0.5:
                    ch.device.w, ch.device.h = w, h
                    changed += 1
        return changed

    def cable_lane_changed(self, item: "LinkItem") -> None:
        """The operator dragged a cable's long run: remember the lane on its link(s)."""
        if self._site is None:
            return
        for idx in item.bundle_links:
            if 0 <= idx < len(self._site.links):
                self._site.links[idx].lane = item.lane_offset
        self.update_hops()
        self.links_changed.emit()
        self.positions_changed.emit()

    # -- Re-arrange cable ------------------------------------------------------- #

    def _cable_cost(self, item: "LinkItem", pts: list[QPointF], others: list[list[QPointF]]) -> int:
        """Crossings, plus a heavy penalty for a run straight through a device box."""
        cost = count_crossings(pts, others) * 10
        for a, b in _segs(pts):
            if abs(a.y() - b.y()) > 0.01:
                continue
            lo, hi = min(a.x(), b.x()), max(a.x(), b.x())
            for ch in self._live_chassis():
                r = ch.sceneBoundingRect()
                if r.top() - 3 < a.y() < r.bottom() + 3 and lo < r.right() and hi > r.left():
                    cost += 1000
        return cost

    def rearrange_cable(self, item: "LinkItem", *, quiet: bool = False) -> str:
        """Put *item*'s long run in the lane with the fewest crossings (saved on the link)."""
        if self._site is None or self._locked:
            return "The layout is locked: unlock it to re-arrange cables." if self._locked else ""
        others = [li.points for li in self._links if li is not item and li.points]
        current = item.points or item.points_for(item.lane_offset)
        best_cost = self._cable_cost(item, current, others)
        best_lane = item.lane_offset
        for lane in item.lane_options():
            cost = self._cable_cost(item, item.points_for(lane), others)
            if cost < best_cost:
                best_cost, best_lane = cost, lane
        if best_lane == item.lane_offset and item.route is None:
            return "" if quiet else f"{item.a_port} ↔ {item.b_port}: already as clear as it gets."
        for idx in item.bundle_links:
            if 0 <= idx < len(self._site.links):
                self._site.links[idx].lane = best_lane
        item.lane_offset = best_lane
        item.route = None  # our routing from here on
        item.rebuild()
        self.update_hops()
        if not quiet:
            self.links_changed.emit()
            self.positions_changed.emit()
        if quiet:
            return ""
        was = count_crossings(current, others)
        now = count_crossings(item.points, others)
        return f"{item.a_port} ↔ {item.b_port}: re-arranged, crossings {was} → {now}"

    def rearrange_all_cables(self) -> str:
        """Re-arrange every cable in turn, twice (the second pass settles the first)."""
        if self._site is None or self._locked:
            return "The layout is locked: unlock it to re-arrange cables." if self._locked else ""
        before = sum(len(v) for d in find_hops(self._links).values() for v in d.values())
        for _ in range(2):
            for item in list(self._links):
                self.rearrange_cable(item, quiet=True)
        after = self.update_hops()
        self.links_changed.emit()
        self.positions_changed.emit()
        return f"Re-arranged {len(self._links)} cable(s): crossings {before} → {after}."

    # -- Hops where cables cross ---------------------------------------------- #

    def schedule_hops(self) -> None:
        """Work the crossings out once, after the current batch of cable changes."""
        self._hops_timer.start()

    def update_hops(self) -> int:
        """Give every cable its hops over the cables it crosses. Returns how many."""
        links = []
        for li in self._links:
            try:
                if li.bundle:
                    continue  # 25 px ribbons: crossings show as an overlap, no hop
            except RuntimeError:
                continue
            links.append(li)
        found = find_hops(links)
        total = 0
        for li, link in enumerate(links):
            hops = found.get(li, {})
            total += sum(len(v) for v in hops.values())
            if hops != link.hops:
                link.hops = hops
                link.draw()
        return total

    # -- Auto-arrange (ELK) ---------------------------------------------------- #

    def auto_arrange(self) -> str:
        """Lay the site out with ELK (layered, top-down, orthogonal cables).
        Returns a one-line result; raises elk_layout.ElkUnavailable without ELK."""
        from pfsense_checker import elk_layout

        if self._site is None or not self._chassis:
            return "Nothing to arrange."
        if self._locked:
            return "The layout is locked: unlock it to auto-arrange."
        boxes: dict[str, elk_layout.BoxInfo] = {}
        for name, ch in self._chassis.items():
            try:
                rect = ch.boundingRect()
            except RuntimeError:
                continue
            dev = ch.device
            tier = elk_layout.tier_of(dev.kind, dev.tier())
            if ch._faceplate and tier >= 4:  # noqa: SLF001 - switches above what hangs off them
                tier = 3
            box = elk_layout.BoxInfo(name, rect.width(), rect.height(), tier)
            for port, item in ch.port_items.items():
                box.ports[port] = item.pos().x() + item.w / 2
                for vid in (item.vlans.vlans if item.vlans else []):
                    stripe = item.stripe_rect(vid)
                    if stripe is not None:
                        box.vlan_x[(port, vid)] = item.pos().x() + stripe.center().x()
                if ch.is_uplink(port):
                    box.uplinks.add(port)
            boxes[name] = box
        cables = [
            elk_layout.CableInfo(i, ln.a_device, ln.a_port, ln.b_device, ln.b_port, link_vid(ln))
            for i, ln in enumerate(self._site.links)
        ]
        placed = [d for d in self._site.devices if d.name in boxes and d.x is not None and d.y is not None]
        origin = (min((d.x for d in placed), default=40.0), min((d.y for d in placed), default=40.0))
        result = elk_layout.arrange(boxes, cables, origin)
        self._pre_arrange = {d.name: (d.x, d.y) for d in self._site.devices}
        for dev in self._site.devices:
            if dev.name in result.positions:
                dev.x, dev.y = result.positions[dev.name]
        self._elk_routes = (result.routes, dict(result.positions))
        self.render_site(self._site)
        self.positions_changed.emit()
        n = len(result.positions)
        return f"Arranged {n} device{'s' if n != 1 else ''} and {len(result.routes)} cable(s) with ELK."

    def undo_arrange(self) -> bool:
        before = getattr(self, "_pre_arrange", None)
        if self._site is None or not before:
            return False
        for dev in self._site.devices:
            if dev.name in before:
                dev.x, dev.y = before[dev.name]
        self._pre_arrange = None
        self._elk_routes = None
        self.render_site(self._site)
        self.positions_changed.emit()
        return True

    def can_undo_arrange(self) -> bool:
        return bool(getattr(self, "_pre_arrange", None))

    def _elk_route(self, index: int, link) -> list[tuple[float, float]] | None:  # noqa: ANN001
        """The ELK route for link *index*, if both ends are still where ELK put them."""
        held = getattr(self, "_elk_routes", None)
        if not held or self._site is None:
            return None
        routes, positions = held
        for name in (link.a_device, link.b_device):
            dev = self._site.device(name)
            if dev is None or positions.get(name) != (dev.x, dev.y):
                return None
        return routes.get(index)

    def arrange_by_tier(self) -> None:
        if self._site is None:
            return
        # Wider pitch so CRS faceplates don't overlap
        self._site.arrange_by_tier(col_pitch=560.0, row_pitch=220.0)
        self.render_site(self._site)

    def render_site(self, site) -> None:  # noqa: ANN001
        keep_centre = (
            self.mapToScene(self.viewport().rect().center()) if self._chassis else None
        )
        self._site = site
        self._grid = max(5, int(getattr(site, "grid_size", 20) or 20))
        site.ensure_positions()
        self.clear()

        tip = self._scene.addText(
            "Drag chassis · right-click chassis for Pull Config / Show more · "
            "drag a port onto another device's port to link · "
            "Save Topology to persist · Esc cancels a cable · right-drag to pan · zoom: slider (bottom right) or Ctrl+wheel"
        )
        tip.setDefaultTextColor(QColor("#90a4ae"))
        tipf = QFont()
        tipf.setPointSize(8)
        tip.setFont(tipf)
        tip.setPos(8, -24)

        title = self._scene.addText(site.name or "Physical Layout")
        tf = QFont()
        tf.setPointSize(12)
        tf.setBold(True)
        title.setFont(tf)
        title.setDefaultTextColor(QColor("#263238"))
        title.setPos(8, -48)

        # Wireless interfaces get their SSID's VLAN from the CAPsMAN controller
        # (another device's config), and join their CAP's bridge.
        linked = []
        shown = drawn_devices(site)
        for dev in shown:
            dev.ensure_components()
            names = [c.name for c in dev.components] or list(dev.ports)
            linked.append((dev.name, port_vlans.for_device(dev), names))
        port_vlans.link_capsman(linked)
        # One VLAN colour per VLAN across the whole canvas, in VLAN order.
        vids: set[str] = set()
        for _name, info, _names in linked:
            for pv in info.ports.values():
                vids.update(pv.vlans)
        for dev in shown:  # planned VLANs are coloured like any other
            for entry in (getattr(dev, "planned_vlans", None) or {}).values():
                vids.update(entry.get("tagged", []))
                vids.update(entry.get("untagged", []))
        self._palette = port_vlans.assign_palette(vids)
        for dev in shown:
            dev.ensure_components()
            if not (dev.model or "").strip():
                # Hardware model from the device's config (# model = …), so the
                # header names the box instead of just the vendor.
                dev.model = device_identity.identity_for(dev).model
            ch = ChassisItem(dev, snap=self._snap, grid=self._grid, palette=self._palette)
            ch.set_locked(self._locked)
            ch.moved.connect(self._on_chassis_moved)
            ch.resized.connect(self._on_chassis_resized)
            ch.edit_finished.connect(self._on_chassis_edit_finished)
            self._scene.addItem(ch)
            self._chassis[dev.name] = ch

        if getattr(site, "uniform_sizes", False) and self.apply_uniform_sizes():
            for ch in self._chassis.values():  # same type, same (largest) size
                if ch.device.w and ch.device.h:
                    ch.apply_size(float(ch.device.w), float(ch.device.h))

        # Legend: every VLAN that colours a port on this canvas, named.
        legend: dict[str, str] = {}
        for ch in self._chassis.values():
            for item in ch.port_items.values():
                for vid in (item.vlans.vlans if item.vlans else []):
                    legend.setdefault(vid, "")
            for vid, name in ch._vlans.names.items():  # noqa: SLF001
                if vid in legend and not legend[vid]:
                    legend[vid] = name
        self.vlan_legend.set_vlans(legend, self._palette)
        self._place_overlays()

        def port_vids(device: str, port: str) -> list[str]:
            ch = self._chassis.get(device)
            item = ch.port_items.get(port) if ch else None
            return list(item.vlans.vlans) if item is not None and item.vlans else []

        bundles = vlan_bundles(site.links, port_vids)
        in_bundle = {i for idx in bundles.values() for i in idx}
        for lane, link in enumerate(site.links):
            a = self._chassis.get(link.a_device)
            b = self._chassis.get(link.b_device)
            if a is None or b is None:
                continue
            if lane in in_bundle and lane not in bundles:
                continue  # drawn as part of its bundle's ribbon
            bundle_idx = bundles.get(lane, [])
            bundle = sorted({link_vid(site.links[i]) for i in bundle_idx}, key=port_vlans._vid_key)  # noqa: SLF001
            vid = "" if bundle else link_vid(link)
            color = (port_vlans.vlan_color(vid, self._palette) if vid
                     else LINK_KIND_COLORS.get(link.kind, LINK_KIND_COLORS["other"]))
            bits = []
            if link.a_port or link.b_port:
                bits.append(f"{link.a_port or '?'} ↔ {link.b_port or '?'}")
            if link.kind and link.kind not in ("copper", VLAN_LINK_KIND):
                bits.append(link.kind)
            if link.speed:
                bits.append(link.speed)
            if bundle:
                bits.append("all VLANs " + ",".join(bundle))
            elif vid:
                bits.append(f"VLAN {vid}")
            elif link.vlans:
                bits.append("VLANs " + ",".join(link.vlans[:5]))
            item = LinkItem(
                a, b,
                a_port=link.a_port,
                b_port=link.b_port,
                color=color,
                label=" · ".join(bits),
                lane=lane,
                vid=vid,
                route=self._elk_route(lane, link),
                lane_offset=getattr(link, "lane", None),
                bundle=bundle,
                bundle_colors=[port_vlans.vlan_color(v, self._palette) for v in bundle],
                bundle_links=bundle_idx or [lane],
            )
            if vid:
                pen = item.pen()
                pen.setWidth(3)
                item.setPen(pen)
            self._scene.addItem(item)
            self._links.append(item)
            if bundle:
                item.setZValue(1.5)  # over thin cables
            if bits:
                ac = a.mapToScene(a.boundingRect().center())
                bc = b.mapToScene(b.boundingRect().center())
                below = max(a.mapToScene(QPointF(0, a.boundingRect().height())).y(),
                            b.mapToScene(QPointF(0, b.boundingRect().height())).y())
                mid = QPointF((ac.x() + bc.x()) / 2, below + 16 + lane * 8 - 12)
                lt = self._scene.addText(" · ".join(bits))
                lf = QFont()
                lf.setPointSize(6)
                lt.setFont(lf)
                lt.setDefaultTextColor(QColor("#37474f"))
                lt.setZValue(4)
                lt.setPos(mid)

        self.update_hops()  # cables are built before they are in the scene

        for vpn in site.vpn:
            a = self._chassis.get(vpn.a_device)
            b = self._chassis.get(vpn.b_device)
            if a is None or b is None:
                continue
            ac = a.mapToScene(a.boundingRect().center())
            bc = b.mapToScene(b.boundingRect().center())
            pen = QPen(QColor(LINK_KIND_COLORS["vpn"]))
            pen.setWidth(2)
            pen.setStyle(Qt.PenStyle.DashDotLine)
            self._scene.addLine(ac.x(), ac.y() + 30, bc.x(), bc.y() + 30, pen)

        if not site.devices:
            empty = self._scene.addText(
                "No devices — add MikroTik / Juniper SRX / Ubiquiti EdgeRouter / "
                "Netgear switches, or Import Excel."
            )
            empty.setDefaultTextColor(QColor("#9e9e9e"))
            empty.setPos(20, 20)

        bounds = self._scene.itemsBoundingRect()
        # Room all round so right-drag can pan even when everything fits.
        self._scene.setSceneRect(bounds.adjusted(-PAN_MARGIN, -PAN_MARGIN, PAN_MARGIN, PAN_MARGIN))
        if keep_centre is not None:
            self.centerOn(keep_centre)  # redraws keep the view where it was
        else:
            # First draw: the devices' top-left corner near the view's top-left.
            vp = self.viewport().rect()
            z = self.zoom() or 1.0
            self.centerOn(bounds.left() - 20 + vp.width() / (2 * z), bounds.top() - 20 + vp.height() / (2 * z))
        if self._highlight_devices or self._highlight_path:
            self.highlight_devices(
                self._highlight_devices or self._highlight_path,
                path=self._highlight_path,
            )

    def clear_highlight(self) -> None:
        self._highlight_devices = set()
        self._highlight_path = []
        for ch in self._chassis.values():
            ch.setOpacity(1.0)
            ch.setSelected(False)
        for link in self._links:
            pen = link.pen()
            pen.setWidth(2)
            link.setPen(pen)
            link.setOpacity(1.0)

    def highlight_devices(
        self,
        devices: list[str] | set[str],
        *,
        path: list[str] | None = None,
    ) -> None:
        """Dim unrelated chassis/links; emphasize the given devices / path."""
        names = {str(d) for d in devices if d}
        path_names = [str(p) for p in (path or []) if p]
        self._highlight_devices = names
        self._highlight_path = path_names
        focus = names | set(path_names)
        if not focus:
            self.clear_highlight()
            return
        for name, ch in self._chassis.items():
            if name in focus:
                ch.setOpacity(1.0)
                ch.setSelected(True)
            else:
                ch.setOpacity(0.25)
                ch.setSelected(False)
        path_pairs = set()
        for i in range(len(path_names) - 1):
            a, b = path_names[i], path_names[i + 1]
            path_pairs.add((a, b))
            path_pairs.add((b, a))
        for link in self._links:
            a_name = link.a.device_name
            b_name = link.b.device_name
            on_path = (a_name, b_name) in path_pairs
            involved = a_name in focus and b_name in focus
            pen = link.pen()
            if on_path or involved:
                pen.setWidth(4)
                link.setPen(pen)
                link.setOpacity(1.0)
            else:
                pen.setWidth(1)
                link.setPen(pen)
                link.setOpacity(0.2)
