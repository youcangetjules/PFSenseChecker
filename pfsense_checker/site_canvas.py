"""Flexible, grid-locked site canvas: chassis devices containing NIC components.

Switches render as wide front-panels with discrete RJ45 / SFP port cells so
cables can land on individual ports (CRS326/CRS328, Netgear, etc.).
"""

from __future__ import annotations

from PySide6.QtCore import QLineF, QPointF, QRectF, Qt, Signal
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetrics,
    QPainter,
    QPainterPath,
    QPen,
)
from PySide6.QtWidgets import (
    QGraphicsItem,
    QGraphicsObject,
    QGraphicsPathItem,
    QGraphicsScene,
    QGraphicsView,
    QMenu,
    QWidget,
)

HANDLE_SIZE = 12.0
MIN_CHASSIS_W = 160.0
MIN_CHASSIS_H = 80.0

from pfsense_checker.topology_site import Link, PortComponent
from pfsense_checker.viz import DEVICE_KIND_COLORS, LINK_KIND_COLORS

# Compact faceplate RJ45 / SFP cells (switch front-panel style)
RJ45_W = 16.0
RJ45_H = 26.0
SFP_W = 22.0
SFP_H = 26.0
PORT_GAP = 3.0
GROUP_GAP = 10.0  # gap every 8 copper ports
CHASSIS_PAD = 12.0
HEADER_H = 48.0

# Non-switch (router/firewall) NIC tiles
NIC_W = 92.0
NIC_H = 22.0
NIC_H_WITH_ADDR = 36.0
NIC_GAP = 4.0
CABLE_CORRIDOR_H = 40.0  # space below port grid for link dog-legs
OPTIONS_SIZE = 14.0


def _is_switch_like(device) -> bool:  # noqa: ANN001
    role = (device.role or "").lower()
    kind = (device.kind or "").lower()
    if role in ("core-switch", "access-switch", "core", "access"):
        return True
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


def _is_sfp_name(name: str) -> bool:
    n = name.lower()
    return any(
        tok in n
        for tok in ("sfp", "sfpplus", "sfp+", "qsfp", "xe-", "c1", "c2", "c3", "c4")
    ) or n.startswith("s") and n[1:].isdigit() and int(n[1:]) <= 8 and "slot" not in n


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
    ) -> None:
        super().__init__()
        self.device_name = device_name
        self.port_name = port_name
        self.media = media
        self.address = (address or "").strip()
        self.faceplate = faceplate
        self.sfp = sfp
        self.w = SFP_W if (faceplate and sfp) else (RJ45_W if faceplate else NIC_W)
        if faceplate:
            self.h = SFP_H
        elif self.address:
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
        if self.address:
            tip_bits.append(self.address)
        if media:
            tip_bits.append(media)
        tip_bits.append("component of chassis")
        tip_bits.append("drag onto another device's port to link")
        self.setToolTip("\n".join(tip_bits))

    def boundingRect(self) -> QRectF:  # noqa: N802
        return QRectF(0, 0, self.w, self.h)

    def paint(self, painter, option, widget=None) -> None:  # noqa: ANN001, N802
        del option, widget
        selected = self.isSelected()
        if self.sfp:
            edge = "#6a1b9a" if selected else "#7b1fa2"
            fill = QColor("#f3e5f5" if selected else "#ede7f6")
        else:
            edge = "#1565c0" if selected else "#455a64"
            fill = QColor("#e3f2fd" if selected else "#cfd8dc")
        pen = QPen(QColor(edge))
        pen.setWidth(2 if selected else 1)
        painter.setPen(pen)
        painter.setBrush(QBrush(fill))
        r = self.boundingRect().adjusted(0.5, 0.5, -0.5, -0.5)
        painter.drawRoundedRect(r, 2, 2)

        # Discrete "jack" line for faceplate RJ45
        if self.faceplate and not self.sfp:
            painter.setPen(QPen(QColor("#78909c")))
            mid = self.w / 2
            painter.drawLine(QPointF(mid - 3, 4), QPointF(mid - 3, self.h - 10))
            painter.drawLine(QPointF(mid + 3, 4), QPointF(mid + 3, self.h - 10))
            painter.drawLine(QPointF(mid - 4, self.h - 8), QPointF(mid + 4, self.h - 8))

        painter.setPen(QColor("#212121"))
        font = QFont()
        font.setPointSize(6 if self.faceplate else 7)
        font.setBold(True)
        painter.setFont(font)
        label = self.port_name
        if self.faceplate and len(label) > 4:
            label = label[-4:]
        if self.faceplate:
            painter.drawText(
                self.boundingRect().adjusted(1, 1, -1, -2),
                Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignBottom,
                label,
            )
            return
        # Router/firewall NIC tile: name + assigned IP when known.
        if self.address:
            painter.drawText(
                QRectF(2, 1, self.w - 4, 14),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                label,
            )
            font2 = QFont()
            font2.setPointSize(6)
            painter.setFont(font2)
            painter.setPen(QColor("#1565c0"))
            ip_label = self.address.split("/")[0]
            if len(ip_label) > 15:
                ip_label = ip_label[:14] + "…"
            painter.drawText(
                QRectF(2, 15, self.w - 4, 18),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
                ip_label,
            )
        else:
            painter.drawText(
                self.boundingRect().adjusted(2, 1, -2, -2),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                label,
            )

    def mousePressEvent(self, event) -> None:  # noqa: ANN001, N802
        """Start a port→port cable drag when the canvas is unlocked."""
        if event.button() == Qt.MouseButton.RightButton:
            event.ignore()
            return
        if event.button() == Qt.MouseButton.LeftButton and self.scene():
            for view in self.scene().views():
                if isinstance(view, SiteTopologyView) and not view._locked:
                    view.begin_port_link(self, event.scenePos())
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


class LayoutOptionsHandle(QGraphicsObject):
    """Bottom-right layout menu (columns / single row / reset size)."""

    def __init__(self, chassis: "ChassisItem") -> None:
        super().__init__(chassis)
        self._chassis = chassis
        self.setAcceptedMouseButtons(Qt.MouseButton.LeftButton)
        self.setAcceptHoverEvents(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setZValue(21)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIgnoresParentOpacity, True)
        self.setToolTip(
            "Port layout — single row, column count, or reset chassis size"
        )

    def boundingRect(self) -> QRectF:  # noqa: N802
        return QRectF(0, 0, OPTIONS_SIZE, OPTIONS_SIZE)

    def paint(self, painter, option, widget=None) -> None:  # noqa: ANN001, N802
        del option, widget
        if self._chassis._locked:
            return
        r = self.boundingRect().adjusted(0.5, 0.5, -0.5, -0.5)
        painter.setPen(QPen(QColor("#455a64"), 1))
        painter.setBrush(QBrush(QColor("#eceff1")))
        painter.drawRoundedRect(r, 2, 2)
        painter.setPen(QColor("#37474f"))
        font = QFont()
        font.setBold(True)
        font.setPointSize(7)
        painter.setFont(font)
        painter.drawText(r, Qt.AlignmentFlag.AlignCenter, "…")

    def mousePressEvent(self, event) -> None:  # noqa: ANN001, N802
        if self._chassis._locked:
            event.ignore()
            return
        self._show_menu(event)
        event.accept()

    def _show_menu(self, event) -> None:  # noqa: ANN001
        views = self.scene().views() if self.scene() else []
        parent = views[0] if views else None
        menu = QMenu(parent if isinstance(parent, QWidget) else None)
        flat = menu.addAction("Single row (flat)")
        auto = menu.addAction("Auto columns (from width)")
        menu.addSeparator()
        col_actions = {}
        for n in (2, 3, 4, 6, 8):
            col_actions[menu.addAction(f"{n} columns")] = n
        menu.addSeparator()
        fit = menu.addAction("Reset size — fit all ports")
        chosen = menu.exec(event.screenPos())
        if chosen is flat:
            self._chassis.set_port_layout(1)
        elif chosen is auto:
            self._chassis.set_port_layout(None)
        elif chosen in col_actions:
            self._chassis.set_port_layout(col_actions[chosen])
        elif chosen is fit:
            self._chassis.reset_chassis_layout()


class ChassisItem(QGraphicsObject):
    """Physical device box; NICs/ports are child PortItems (components)."""

    moved = Signal(str, float, float)  # device_name, x, y
    resized = Signal(str, float, float)  # device_name, w, h

    def __init__(self, device, *, snap: bool = True, grid: int = 20) -> None:  # noqa: ANN001
        super().__init__()
        self.device = device
        self.device_name = device.name
        self._snap = snap
        self._grid = max(5, grid)
        self._locked = False
        self._faceplate = _is_switch_like(device)
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
            f"{device.name}\nRight-click: Pull Config · Show more (OS / hardware / "
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

    def _place_handle(self) -> None:
        w, h = self._content_size()
        self._handle.setPos(w - HANDLE_SIZE - 1, h - HANDLE_SIZE - 1)
        self._handle.setVisible(not self._locked)

    def _components(self) -> list[PortComponent]:
        self.device.ensure_components()
        return list(self.device.components) or [
            PortComponent(name=p) for p in self.device.ports
        ]

    def _layout_metrics(self) -> tuple[float, float, list[tuple[PortComponent, float, float, bool]]]:
        """Return (width, height, list of (comp, x, y, is_sfp))."""
        comps = self._components()
        placed: list[tuple[PortComponent, float, float, bool]] = []

        if self._faceplate:
            # Single-row (or dual-row if > 28) wide faceplate with group gaps
            copper = [c for c in comps if not _is_sfp_name(c.name)]
            sfp = [c for c in comps if _is_sfp_name(c.name)]
            # Prefer one wide row so every jack is a discrete visible cell.
            # Only wrap to two rows when copper count is huge (48+).
            use_two_rows = len(copper) >= 40
            x = CHASSIS_PAD
            y0 = HEADER_H
            if use_two_rows:
                half = (len(copper) + 1) // 2
                rows = [copper[:half], copper[half:]]
            else:
                rows = [copper]

            max_x = x
            for ri, row in enumerate(rows):
                x = CHASSIS_PAD
                y = y0 + ri * (RJ45_H + PORT_GAP + 6)
                for i, comp in enumerate(row):
                    if i and i % 8 == 0:
                        x += GROUP_GAP
                    placed.append((comp, x, y, False))
                    x += RJ45_W + PORT_GAP
                max_x = max(max_x, x)

            # SFP / combo cages to the right, visually distinct
            sx = max_x + GROUP_GAP * 1.5
            sy = y0
            for i, comp in enumerate(sfp):
                placed.append((comp, sx + i * (SFP_W + PORT_GAP), sy, True))
            end_x = sx + max(len(sfp), 0) * (SFP_W + PORT_GAP) + CHASSIS_PAD
            if not sfp:
                end_x = max_x + CHASSIS_PAD
            rows_h = len(rows)
            natural_h = HEADER_H + rows_h * (RJ45_H + PORT_GAP + 6) + CHASSIS_PAD + 12
            # Minimum width ~ full 24-port faceplate
            natural_w = max(480.0, end_x)
            body_w = max(natural_w, self._user_w or 0.0)
            body_h = max(natural_h, self._user_h or 0.0)
            return body_w, body_h, placed

        # Compact NIC grid for routers / firewalls — columns follow chassis width
        n = len(comps) or 1
        row_h = (
            NIC_H_WITH_ADDR
            if any(getattr(c, "address", "") for c in comps)
            else NIC_H
        )
        cell = NIC_W + NIC_GAP
        target_w = self._user_w
        if target_w is None:
            cols = min(4, n)
            natural_w = max(220.0, cols * cell + CHASSIS_PAD * 2)
        else:
            usable = max(cell, target_w - CHASSIS_PAD * 2)
            cols = max(1, min(n, int((usable + NIC_GAP) // cell)))
            natural_w = max(MIN_CHASSIS_W, cols * cell + CHASSIS_PAD * 2)
        rows = max(1, (n + cols - 1) // cols)
        natural_h = HEADER_H + rows * (row_h + NIC_GAP) + CHASSIS_PAD + 10
        body_w = max(natural_w, self._user_w or 0.0)
        body_h = max(natural_h, self._user_h or 0.0)
        # Recalc columns from final width so stretch adds more NIC columns
        usable = max(cell, body_w - CHASSIS_PAD * 2)
        cols = max(1, min(n, int((usable + NIC_GAP) // cell)))
        rows = max(1, (n + cols - 1) // cols)
        content_h = HEADER_H + rows * (row_h + NIC_GAP) + CHASSIS_PAD + 10
        body_h = max(content_h, self._user_h or 0.0)
        for i, comp in enumerate(comps):
            r, c = i // cols, i % cols
            placed.append(
                (
                    comp,
                    CHASSIS_PAD + c * (NIC_W + NIC_GAP),
                    HEADER_H + r * (row_h + NIC_GAP),
                    False,
                )
            )
        return body_w, body_h, placed

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
        for comp, x, y, is_sfp in placed:
            item = PortItem(
                self.device_name,
                comp.name,
                comp.media,
                address=getattr(comp, "address", "") or "",
                faceplate=self._faceplate,
                sfp=is_sfp,
            )
            item.setParentItem(self)
            item.setPos(x, y)
            self.port_items[comp.name] = item

    def boundingRect(self) -> QRectF:  # noqa: N802
        w, h = self._content_size()
        return QRectF(0, 0, w, h)

    def paint(self, painter, option, widget=None) -> None:  # noqa: ANN001, N802
        del option, widget
        color = DEVICE_KIND_COLORS.get(self.device.kind, DEVICE_KIND_COLORS["other"])
        if self.device.role == "egress":
            color = DEVICE_KIND_COLORS["egress"]
        rect = self.boundingRect()
        pen = QPen(QColor(color))
        pen.setWidth(2 if not self.isSelected() else 3)
        fill = QColor(color)
        fill.setAlpha(28)
        painter.setPen(pen)
        painter.setBrush(QBrush(fill))
        painter.drawRoundedRect(rect.adjusted(0.5, 0.5, -0.5, -0.5), 6, 6)

        hdr = QRectF(0, 0, rect.width(), HEADER_H - 2)
        hf = QColor(color)
        hf.setAlpha(70)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(hf))
        painter.drawRoundedRect(hdr.adjusted(1, 1, -1, 0), 6, 6)

        # Vendor wordmark badge (top-right of header).
        name_width = rect.width() - 16
        badge = _vendor_badge(self.device.kind, self.device.model)
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
        sub = self.device.chassis_subtitle()[:90]
        painter.drawText(
            QRectF(8, 22, rect.width() - 16, 16),
            Qt.AlignmentFlag.AlignLeft,
            sub,
        )

        painter.setPen(QColor("#78909c"))
        n = len(self.port_items)
        style = "front-panel ports" if self._faceplate else "NIC components"
        painter.drawText(
            QRectF(8, rect.height() - 14, rect.width() - HANDLE_SIZE - 16, 12),
            Qt.AlignmentFlag.AlignLeft,
            f"{n} {style}",
        )

    def itemChange(self, change, value):  # noqa: ANN001, N802
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionChange and self.scene():
            pos = value
            if self._snap:
                g = self._grid
                pos = QPointF(round(pos.x() / g) * g, round(pos.y() / g) * g)
            return pos
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            self.moved.emit(self.device_name, self.pos().x(), self.pos().y())
        return super().itemChange(change, value)

    def mousePressEvent(self, event) -> None:  # noqa: ANN001, N802
        if event.button() != Qt.MouseButton.LeftButton:
            event.ignore()
            return
        self.setCursor(Qt.CursorShape.ClosedHandCursor)
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event) -> None:  # noqa: ANN001, N802
        self.setCursor(
            Qt.CursorShape.ArrowCursor if self._locked else Qt.CursorShape.OpenHandCursor
        )
        super().mouseReleaseEvent(event)

    def port_anchor(self, port_name: str, toward: QPointF | None = None) -> QPointF:
        item = self.port_items.get(port_name)
        if item is None:
            r = self.boundingRect()
            center = self.mapToScene(r.center())
            if toward is not None and toward.x() < center.x():
                return self.mapToScene(QPointF(0, r.height() / 2))
            return self.mapToScene(QPointF(r.width(), r.height() / 2))
        if self._faceplate:
            # Cables leave from bottom of the jack (discrete line out)
            return item.anchor_scene("bottom")
        center = self.mapToScene(self.boundingRect().center())
        facing = "left" if (toward is not None and toward.x() < center.x()) else "right"
        return item.anchor_scene(facing)


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
    ) -> None:
        super().__init__()
        self.a = a
        self.b = b
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
        self.rebuild()

    def rebuild(self) -> None:
        ac = self.a.mapToScene(self.a.boundingRect().center())
        bc = self.b.mapToScene(self.b.boundingRect().center())
        start = self.a.port_anchor(self.a_port, toward=bc)
        end = self.b.port_anchor(self.b_port, toward=ac)
        # Drop vertically from faceplate jacks, then run horizontally
        if self.a._faceplate or self.b._faceplate:
            drop = 28.0
            s2 = QPointF(start.x(), start.y() + (drop if self.a._faceplate else 0))
            e2 = QPointF(end.x(), end.y() + (drop if self.b._faceplate else 0))
            mid_y = max(s2.y(), e2.y()) + 10
            path = QPainterPath(start)
            path.lineTo(s2)
            path.lineTo(QPointF(s2.x(), mid_y))
            path.lineTo(QPointF(e2.x(), mid_y))
            path.lineTo(e2)
            path.lineTo(end)
        else:
            mid_x = (start.x() + end.x()) / 2
            path = QPainterPath(start)
            path.lineTo(mid_x, start.y())
            path.lineTo(mid_x, end.y())
            path.lineTo(end)
        self.setPath(path)


class SiteTopologyView(QGraphicsView):
    """Editable physical map: grid-locked chassis with NIC / faceplate ports."""

    positions_changed = Signal()
    links_changed = Signal()
    device_changed = Signal(str)  # device name after Pull Config / similar

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
        self._snap = True
        self._grid = 20
        self._locked = False
        self._draw_grid = True
        self._highlight_devices: set[str] = set()
        self._highlight_path: list[str] = []
        self._wire_from: tuple[str, str] | None = None  # (device, port)
        self._wire_line = None
        self._ssh_password_provider = None

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
        self._scene.clear()
        self._chassis.clear()
        self._links.clear()

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

    def contextMenuEvent(self, event) -> None:  # noqa: ANN001, N802
        sp = self.mapToScene(event.pos())
        chassis = self._chassis_item_at(sp)
        if chassis is None:
            super().contextMenuEvent(event)
            return
        self._popup_chassis_menu(chassis.device, event.globalPos())
        event.accept()

    def _popup_chassis_menu(self, device, global_pos) -> None:  # noqa: ANN001
        from pfsense_checker.chassis_actions import CHASSIS_MENU_ITEMS, perform_chassis_action

        menu = QMenu(self)
        title_act = menu.addAction(
            device.chassis_title()
            if device.chassis_title() != device.name
            else (device.name or "Chassis")
        )
        title_act.setEnabled(False)
        menu.addSeparator()
        actions = {}
        for action_id, label in CHASSIS_MENU_ITEMS:
            actions[menu.addAction(label)] = action_id
        chosen = menu.exec(global_pos)
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

    def begin_port_link(self, port_item: PortItem, scene_pos: QPointF) -> None:
        """Start dragging a cable from *port_item* (unlocked canvas only)."""
        if self._locked or self._site is None:
            return
        self._cancel_port_link()
        self._wire_from = (port_item.device_name, port_item.port_name)
        anchor = port_item.anchor_scene("bottom" if port_item.faceplate else "right")
        pen = QPen(QColor("#1565c0"))
        pen.setWidth(2)
        pen.setStyle(Qt.PenStyle.DashLine)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        self._wire_line = self._scene.addLine(QLineF(anchor, scene_pos), pen)
        self._wire_line.setZValue(100)
        self.setDragMode(QGraphicsView.DragMode.NoDrag)
        self.viewport().grabMouse()

    def _cancel_port_link(self) -> None:
        self._wire_from = None
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

    def _link_exists(self, a_dev: str, a_port: str, b_dev: str, b_port: str) -> bool:
        if self._site is None:
            return False
        for link in self._site.links:
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
        if a_device == b_device and a_port == b_port:
            self._cancel_port_link()
            return
        self._cancel_port_link()
        if a_device == b_device:
            return  # require another device
        if self._link_exists(a_device, a_port, b_device, b_port):
            return
        self._site.links.append(
            Link(
                a_device=a_device,
                a_port=a_port,
                b_device=b_device,
                b_port=b_port,
                kind="copper",
            )
        )
        self.render_site(self._site)
        self.links_changed.emit()
        self.positions_changed.emit()

    def mouseMoveEvent(self, event) -> None:  # noqa: ANN001, N802
        if self._wire_from is not None and self._wire_line is not None:
            sp = self.mapToScene(event.position().toPoint())
            line = self._wire_line.line()
            self._wire_line.setLine(QLineF(line.p1(), sp))
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:  # noqa: ANN001, N802
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
            self.scale(factor, factor)
            event.accept()
            return
        super().wheelEvent(event)

    def _on_chassis_moved(self, name: str, x: float, y: float) -> None:
        if self._site is None:
            return
        dev = self._site.device(name)
        if dev is None:
            return
        dev.x = x
        dev.y = y
        self.positions_changed.emit()

    def _on_chassis_resized(self, name: str, w: float, h: float) -> None:
        if self._site is None:
            return
        dev = self._site.device(name)
        if dev is None:
            return
        dev.w = w
        dev.h = h
        self.positions_changed.emit()

    def arrange_by_tier(self) -> None:
        if self._site is None:
            return
        # Wider pitch so CRS faceplates don't overlap
        self._site.arrange_by_tier(col_pitch=560.0, row_pitch=220.0)
        self.render_site(self._site)

    def render_site(self, site) -> None:  # noqa: ANN001
        self._site = site
        self._grid = max(5, int(getattr(site, "grid_size", 20) or 20))
        site.ensure_positions()
        self.clear()

        tip = self._scene.addText(
            "Drag chassis · right-click chassis for Pull Config / Show more · "
            "drag a port onto another device's port to link · "
            "Save Topology to persist · Esc cancels a cable · Ctrl+wheel zoom"
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

        for dev in site.devices:
            dev.ensure_components()
            ch = ChassisItem(dev, snap=self._snap, grid=self._grid)
            ch.set_locked(self._locked)
            ch.moved.connect(self._on_chassis_moved)
            ch.resized.connect(self._on_chassis_resized)
            self._scene.addItem(ch)
            self._chassis[dev.name] = ch

        for link in site.links:
            a = self._chassis.get(link.a_device)
            b = self._chassis.get(link.b_device)
            if a is None or b is None:
                continue
            color = LINK_KIND_COLORS.get(link.kind, LINK_KIND_COLORS["other"])
            bits = []
            if link.a_port or link.b_port:
                bits.append(f"{link.a_port or '?'} ↔ {link.b_port or '?'}")
            if link.kind and link.kind != "copper":
                bits.append(link.kind)
            if link.speed:
                bits.append(link.speed)
            if link.vlans:
                bits.append("VLANs " + ",".join(link.vlans[:5]))
            item = LinkItem(
                a, b,
                a_port=link.a_port,
                b_port=link.b_port,
                color=color,
                label=" · ".join(bits),
            )
            self._scene.addItem(item)
            self._links.append(item)
            if bits:
                ac = a.mapToScene(a.boundingRect().center())
                bc = b.mapToScene(b.boundingRect().center())
                mid = QPointF((ac.x() + bc.x()) / 2, max(ac.y(), bc.y()) + 40)
                lt = self._scene.addText(" · ".join(bits))
                lf = QFont()
                lf.setPointSize(6)
                lt.setFont(lf)
                lt.setDefaultTextColor(QColor("#37474f"))
                lt.setZValue(4)
                lt.setPos(mid)

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
        self._scene.setSceneRect(bounds.adjusted(-80, -80, 160, 160))
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
