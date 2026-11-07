"""Reusable Qt6 visualization widgets: KPI cards, charts and a topology view."""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCharts import (
    QBarCategoryAxis,
    QBarSeries,
    QBarSet,
    QChart,
    QChartView,
    QLineSeries,
    QPieSeries,
    QValueAxis,
)
from PySide6.QtCore import QPointF, Qt, QRectF, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QFontMetrics, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsItem,
    QGraphicsObject,
    QGraphicsPathItem,
    QGraphicsScene,
    QGraphicsView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

# Shared palette
COLOR_ERROR = "#c62828"
COLOR_WARN = "#ef6c00"
COLOR_INFO = "#1565c0"
COLOR_OK = "#2e7d32"
COLOR_MUTED = "#9e9e9e"

KIND_COLORS = {
    "physical": "#1565c0",
    "bridge": "#6a1b9a",
    "vlan": "#00838f",
    "lagg": "#ad1457",
    "openvpn": "#2e7d32",
    "ipsec": "#4527a0",
    "gif": "#795548",
    "gre": "#5d4037",
    "ppp": "#ff8f00",
    "external": "#2e7d32",
    "edge": COLOR_OK,
    "gwgroup": "#6d4c41",
    "wanport": "#00695c",
    "other": "#616161",
}


class KpiCard(QFrame):
    """A compact metric card with a big value and a caption."""

    def __init__(self, caption: str, value: str = "—", color: str = "#263238") -> None:
        super().__init__()
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setMinimumWidth(140)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._base_color = color
        self._apply_style(color)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(2)

        self.value_label = QLabel(value)
        vfont = QFont()
        vfont.setPointSize(22)
        vfont.setBold(True)
        self.value_label.setFont(vfont)
        self.value_label.setStyleSheet(f"color: {color};")

        self.caption_label = QLabel(caption)
        self.caption_label.setStyleSheet("color: #607d8b; font-size: 11px;")
        self.caption_label.setWordWrap(True)

        layout.addWidget(self.value_label)
        layout.addWidget(self.caption_label)

    def _apply_style(self, color: str) -> None:
        self.setStyleSheet(
            "QFrame {"
            "  background: #fafafa;"
            "  border: 1px solid #e0e0e0;"
            "  border-radius: 8px;"
            "}"
        )

    def set_value(self, value: str, color: str | None = None) -> None:
        self.value_label.setText(value)
        if color:
            self.value_label.setStyleSheet(f"color: {color};")
        else:
            self.value_label.setStyleSheet(f"color: {self._base_color};")


def _chart_view(chart: QChart) -> QChartView:
    view = QChartView(chart)
    view.setRenderHint(QPainter.RenderHint.Antialiasing)
    view.setMinimumHeight(220)
    return view


class DonutChartView(QChartView):
    """A donut chart for categorical counts."""

    def __init__(self, title: str) -> None:
        self._chart = QChart()
        self._chart.setTitle(title)
        self._chart.legend().setAlignment(Qt.AlignmentFlag.AlignRight)
        self._chart.setAnimationOptions(QChart.AnimationOption.SeriesAnimations)
        super().__init__(self._chart)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setMinimumHeight(240)

    def set_data(self, data: list[tuple[str, int, str]]) -> None:
        """data: list of (label, value, color_hex)."""
        self._chart.removeAllSeries()
        series = QPieSeries()
        series.setHoleSize(0.45)
        total = sum(v for _, v, _ in data)
        for label, value, color in data:
            if value <= 0:
                continue
            pct = (value / total * 100) if total else 0
            slice_ = series.append(f"{label} ({value})", value)
            slice_.setColor(QColor(color))
            slice_.setLabelVisible(True)
            slice_.setLabelColor(QColor("#37474f"))
            if pct >= 12:
                slice_.setLabelPosition(slice_.LabelPosition.LabelInsideHorizontal)
        if series.count() == 0:
            # placeholder empty slice
            s = series.append("no data", 1)
            s.setColor(QColor(COLOR_MUTED))
        self._chart.addSeries(series)


class BarChartView(QChartView):
    """A simple vertical bar chart for labeled counts."""

    def __init__(self, title: str) -> None:
        self._chart = QChart()
        self._chart.setTitle(title)
        self._chart.legend().setVisible(False)
        self._chart.setAnimationOptions(QChart.AnimationOption.SeriesAnimations)
        super().__init__(self._chart)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setMinimumHeight(240)

    def set_data(self, data: list[tuple[str, int, str]]) -> None:
        self._chart.removeAllSeries()
        for ax in list(self._chart.axes()):
            self._chart.removeAxis(ax)

        series = QBarSeries()
        categories: list[str] = []
        max_val = 1
        for label, value, color in data:
            bar_set = QBarSet(label)
            bar_set.append(value)
            bar_set.setColor(QColor(color))
            series.append(bar_set)
            categories.append(label)
            max_val = max(max_val, value)
        self._chart.addSeries(series)

        axis_x = QBarCategoryAxis()
        axis_x.append(categories)
        axis_x.setLabelsAngle(-45)
        self._chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
        series.attachAxis(axis_x)

        axis_y = QValueAxis()
        axis_y.setRange(0, max_val * 1.15 + 1)
        axis_y.setLabelFormat("%d")
        self._chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)
        series.attachAxis(axis_y)


class TimeSeriesChartView(QChartView):
    """Multi-series time-based line chart (e.g. latency per target)."""

    def __init__(self, title: str, y_label: str = "ms") -> None:
        self._chart = QChart()
        self._chart.setTitle(title)
        self._chart.legend().setAlignment(Qt.AlignmentFlag.AlignBottom)
        super().__init__(self._chart)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setMinimumHeight(260)
        self._y_label = y_label

    def set_series(self, series_map: dict[str, list[tuple[float, float]]]) -> None:
        """series_map: name -> list of (x_epoch_seconds, y_value)."""
        self._chart.removeAllSeries()
        for ax in list(self._chart.axes()):
            self._chart.removeAxis(ax)

        palette = [
            "#1565c0", "#c62828", "#2e7d32", "#ef6c00",
            "#6a1b9a", "#00838f", "#ad1457", "#5d4037",
        ]
        min_x = None
        max_x = None
        min_y = 0.0
        max_y = 1.0
        for i, (name, points) in enumerate(sorted(series_map.items())):
            if not points:
                continue
            line = QLineSeries()
            line.setName(name)
            pen = QPen(QColor(palette[i % len(palette)]))
            pen.setWidth(2)
            line.setPen(pen)
            for x, y in points:
                line.append(x, y)
                min_x = x if min_x is None else min(min_x, x)
                max_x = x if max_x is None else max(max_x, x)
                max_y = max(max_y, y)
            self._chart.addSeries(line)

        if min_x is None:
            return

        axis_x = QValueAxis()
        axis_x.setRange(min_x, max_x if max_x > min_x else min_x + 1)
        axis_x.setLabelFormat("%d")
        axis_x.setTitleText("seconds ago (0 = now)")
        self._chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)

        axis_y = QValueAxis()
        axis_y.setRange(min_y, max_y * 1.2 + 1)
        axis_y.setTitleText(self._y_label)
        self._chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)

        for s in self._chart.series():
            s.attachAxis(axis_x)
            s.attachAxis(axis_y)


def badge_font() -> QFont:
    font = QFont()
    font.setBold(True)
    font.setPointSize(7)
    return font


class _TopoNode(QGraphicsObject):
    """Draggable topology node; X stays in its layer column."""

    moved = Signal()
    user_moved = Signal()

    def __init__(
        self,
        node_id: str,
        layer: str,
        title: str,
        subtitle: str,
        color: str,
        *,
        dim: bool = False,
        width: float = 170,
        height: float = 46,
    ) -> None:
        super().__init__()
        self.node_id = node_id
        self.layer = layer
        self.title = title
        self.subtitle = subtitle
        self.color = color
        self.dim = dim
        self.w = width
        self.h = height
        self.column_x = 0.0
        self.order_index = 0
        self.row_span = 1
        self.badge: tuple[str, str] | None = None  # (text, colour)
        self._press_y = 0.0
        self._locked = False
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setCursor(Qt.CursorShape.OpenHandCursor)
        self.setZValue(2)
        self.setAcceptHoverEvents(True)

    def set_locked(self, locked: bool) -> None:
        self._locked = locked
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, not locked)
        self.setCursor(
            Qt.CursorShape.ArrowCursor if locked else Qt.CursorShape.OpenHandCursor
        )

    def boundingRect(self) -> QRectF:  # noqa: N802
        return QRectF(0, 0, self.w, self.h)

    def paint(self, painter, option, widget=None) -> None:  # noqa: ANN001, N802
        del option, widget
        pen = QPen(QColor(self.color))
        pen.setWidth(2 if not self.isSelected() else 3)
        base = QColor(self.color)
        mix = 0.16 if not self.dim else 0.08
        fill = QColor(
            int(base.red() * mix + 255 * (1 - mix)),
            int(base.green() * mix + 255 * (1 - mix)),
            int(base.blue() * mix + 255 * (1 - mix)),
        )
        painter.setPen(pen)
        painter.setBrush(QBrush(fill))
        painter.drawRoundedRect(self.boundingRect().adjusted(0.5, 0.5, -0.5, -0.5), 4, 4)

        room = self.w - 16
        if self.badge:
            text, colour = self.badge
            bfont = badge_font()
            bw = QFontMetrics(bfont).horizontalAdvance(text) + 10
            rect = QRectF(self.w - bw - 6, 7, bw, 15)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(QColor(colour)))
            painter.drawRoundedRect(rect, 7, 7)
            painter.setPen(QColor("#ffffff"))
            painter.setFont(bfont)
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, text)
            room -= bw + 4

        painter.setPen(QColor("#b0b0b0") if self.dim else QColor("#212121"))
        font = QFont()
        font.setBold(True)
        font.setPointSize(9)
        painter.setFont(font)
        title = QFontMetrics(font).elidedText(
            self.title, Qt.TextElideMode.ElideRight, int(room)
        )
        painter.drawText(QRectF(8, 6, room, 20), Qt.AlignmentFlag.AlignLeft, title)

        if self.subtitle:
            painter.setPen(QColor("#78909c"))
            font2 = QFont()
            font2.setPointSize(8)
            painter.setFont(font2)
            subtitle = QFontMetrics(font2).elidedText(
                self.subtitle, Qt.TextElideMode.ElideRight, int(self.w - 16)
            )
            painter.drawText(
                QRectF(8, 26, self.w - 16, 20),
                Qt.AlignmentFlag.AlignLeft,
                subtitle,
            )

    def itemChange(self, change, value):  # noqa: ANN001, N802
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionChange and self.scene():
            # Constrain to column X; free vertical movement.
            pos = value
            return QPointF(self.column_x, pos.y())
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            self.moved.emit()
        return super().itemChange(change, value)

    def mousePressEvent(self, event) -> None:  # noqa: ANN001, N802
        self._press_y = self.pos().y()
        self.setCursor(Qt.CursorShape.ClosedHandCursor)
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event) -> None:  # noqa: ANN001, N802
        self.setCursor(
            Qt.CursorShape.ArrowCursor if self._locked else Qt.CursorShape.OpenHandCursor
        )
        super().mouseReleaseEvent(event)
        if abs(self.pos().y() - self._press_y) > 0.5:
            self.user_moved.emit()

    def center_right(self) -> QPointF:
        return self.mapToScene(QPointF(self.w, self.h / 2))

    def center_left(self) -> QPointF:
        return self.mapToScene(QPointF(0, self.h / 2))


class _TopoEdge(QGraphicsPathItem):
    """Orthogonal elbow that stays in the gutters and the gaps."""

    def __init__(self, src: _TopoNode, dst: _TopoNode, color: str, view: TopologyView) -> None:
        super().__init__()
        self.src = src
        self.dst = dst
        self.color = color
        self._view = view
        self.lanes: dict[int, float] = {}
        self.setZValue(0)
        pen = QPen(QColor(color))
        pen.setWidth(2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        self.setPen(pen)
        src.moved.connect(self.rebuild)
        dst.moved.connect(self.rebuild)
        self.rebuild()

    def rebuild(self) -> None:
        view = self._view
        if view is None or view._reflowing:
            return
        from pfsense_checker.topo_route import route_edge

        layers = view._layers
        columns = [(view._col_x[name], 0.0, view._col_w[name], 0.0) for name in layers]
        boxes: list[list[tuple[float, float, float, float]]] = [[] for _ in layers]
        index = {name: i for i, name in enumerate(layers)}
        for node in view._nodes.values():
            slot = index.get(node.layer)
            if slot is None:
                continue
            pos = node.pos()
            boxes[slot].append((pos.x(), pos.y(), node.w, node.h))
        src_pos = self.src.pos()
        dst_pos = self.dst.pos()
        points = route_edge(
            (src_pos.x(), src_pos.y(), self.src.w, self.src.h),
            (dst_pos.x(), dst_pos.y(), self.dst.w, self.dst.h),
            columns,
            boxes,
            lanes=self.lanes,
            flat_dst=self.dst.row_span > 1,
        )
        if not points:
            return
        path = QPainterPath(QPointF(points[0][0], points[0][1]))
        for x, y in points[1:]:
            path.lineTo(x, y)
        self.setPath(path)


class TopologyView(QGraphicsView):
    """Editable layered topology with crossing-minimized auto-layout."""

    def __init__(self) -> None:
        self._scene = QGraphicsScene()
        super().__init__(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setBackgroundBrush(QBrush(QColor("#fbfbfb")))
        self.setMinimumHeight(360)
        self.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
        self._nodes: dict[str, _TopoNode] = {}
        self._edges: list[_TopoEdge] = []
        self._header_items: dict[str, object] = {}
        self._tip_item = None
        self._locked = False
        self._reflowing = False
        self._rendering = False
        self._dragged: set[str] = set()
        self._custom_y: dict[str, float] = {}
        self._last_result = None
        self._last_path: str | None = None
        from pfsense_checker.firewall_topology import LAYERS

        self._layers: list[str] = list(LAYERS)
        self._col_x = {name: 16.0 + i * 304.0 for i, name in enumerate(LAYERS)}
        self._col_w = {name: 220.0 for name in LAYERS}
        self._gutter = 72.0
        self._chassis_item = None
        self._chassis_label = None
        self.segmentation = None
        self._node_h = 52.0
        self._gap_y = 28.0
        self._row_top = 36.0

    def clear(self) -> None:
        self._scene.clear()
        self._nodes.clear()
        self._edges.clear()
        self._header_items.clear()
        self._tip_item = None
        self._chassis_item = None
        self._chassis_label = None

    def set_locked(self, locked: bool) -> None:
        self._locked = locked
        for node in self._nodes.values():
            node.set_locked(locked)

    def reset_layout(self) -> None:
        """Clear manual positions and re-run auto-layout."""
        self._custom_y.clear()
        self._dragged.clear()
        if self._last_result is not None:
            self.render_topology(self._last_result)

    def apply_auto_layout(self) -> None:
        """Re-order by crossing minimization but keep manual Y overrides cleared."""
        self._custom_y.clear()
        self._dragged.clear()
        if self._last_result is not None:
            self.render_topology(self._last_result)

    def _remember_positions(self) -> None:
        for nid, node in self._nodes.items():
            self._custom_y[nid] = node.pos().y()

    def _on_node_moved(self) -> None:
        if self._reflowing or self._rendering:
            return
        self._remember_positions()
        self._update_chassis()
        bounds = self._scene.itemsBoundingRect()
        self._scene.setSceneRect(bounds.adjusted(-24, -48, 24, 24))

    def _add_chassis(self, result) -> None:  # noqa: ANN001
        """One frame around the physical NICs: the firewall itself."""
        pen = QPen(QColor("#37474f"))
        pen.setWidth(2)
        frame = self._scene.addRect(QRectF(), pen, QBrush(QColor("#eceff1")))
        frame.setZValue(-1)
        vendor = {"pfsense": "pfSense", "opnsense": "OPNsense"}.get(
            (getattr(result, "source_type", "") or "").lower(), "Firewall"
        )
        host = (getattr(result, "hostname", "") or "").strip()
        label = self._scene.addText(vendor + (f"\n{host}" if host else ""))
        label.setDefaultTextColor(QColor("#37474f"))
        font = QFont()
        font.setBold(True)
        font.setPointSize(8)
        label.setFont(font)
        label.setZValue(3)
        domain = (getattr(result, "domain", "") or "").strip()
        tip = f"{vendor} {host}.{domain}" if host and domain else f"{vendor} {host}".strip()
        frame.setToolTip(tip)
        label.setToolTip(tip)
        self._chassis_item = frame
        self._chassis_label = label
        self._update_chassis()

    def _update_chassis(self) -> None:
        frame, label = self._chassis_item, self._chassis_label
        if frame is None or label is None:
            return
        nics = [node for node in self._nodes.values() if node.layer == "phys"]
        if not nics:
            frame.setVisible(False)
            label.setVisible(False)
            return
        pad = 8.0
        head = label.boundingRect().height() + 2
        top = min(node.pos().y() for node in nics) - pad - head
        bottom = max(node.pos().y() + node.h for node in nics) + pad
        left = self._col_x["phys"] - pad
        width = self._col_w["phys"] + 2 * pad
        frame.setRect(QRectF(left, top, width, bottom - top))
        label.setTextWidth(width)
        label.setPos(left, top + 1)

    def _segmentation_badges(self, result, graph) -> dict[tuple[str, str], tuple[str, str, str]]:  # noqa: ANN001
        """(layer, id) → (badge text, colour, tooltip) for every routed inside subnet."""
        from pfsense_checker.segmentation import LIMITED, OPEN, analyse_segmentation

        try:
            seg = analyse_segmentation(result)
        except Exception:  # noqa: BLE001
            self.segmentation = None
            return {}
        self.segmentation = seg
        others = len(seg.zones) - 1
        titles = {z.name: z.title for z in seg.zones}
        out = {}
        for zone in seg.zones:
            key = next(
                (
                    k
                    for k in (("vlan", zone.device), ("bridge", zone.device), ("port", zone.name))
                    if k in graph.boxes
                ),
                None,
            )
            summary = seg.summaries.get(zone.name)
            if key is None or summary is None or others < 1:
                continue
            lines = [f"{zone.title} · {zone.network}"]
            if summary.grade == OPEN:
                text, colour = f"open {len(summary.open_to)}/{others}", COLOR_ERROR
            elif summary.grade == LIMITED:
                text, colour = f"limited {len(summary.limited_to)}/{others}", COLOR_WARN
            else:
                text, colour = "isolated", COLOR_OK
            for dst in summary.open_to:
                reach = seg.reach[(zone.name, dst)]
                rules = ", ".join(f"#{n}" for n in reach.rules)
                lines.append(f"→ {titles[dst]}: any protocol (rule {rules})")
            for dst in summary.limited_to:
                reach = seg.reach[(zone.name, dst)]
                lines.append(f"→ {titles[dst]}: {', '.join(reach.services)}")
            if summary.grade not in {OPEN, LIMITED}:
                lines.append("No rule lets it reach another inside subnet.")
            out[key] = (text, colour, "\n".join(lines))
        return out

    def _measure_columns(self, graph, headers: dict[str, str], badges=None) -> None:  # noqa: ANN001
        """Each column is as wide as its longest label, within limits."""
        badges = badges or {}
        badge_fm = QFontMetrics(badge_font())
        title_font = QFont()
        title_font.setBold(True)
        title_font.setPointSize(9)
        sub_font = QFont()
        sub_font.setPointSize(8)
        head_font = QFont()
        head_font.setBold(True)
        head_font.setPointSize(10)
        title_fm, sub_fm, head_fm = QFontMetrics(title_font), QFontMetrics(sub_font), QFontMetrics(head_font)
        for layer in self._layers:
            widest = head_fm.horizontalAdvance(headers.get(layer, ""))
            for node_id in graph.layers.get(layer, []):
                box = graph.boxes[(layer, node_id)]
                badge = badges.get((layer, node_id))
                extra = badge_fm.horizontalAdvance(badge[0]) + 14 if badge else 0
                widest = max(
                    widest,
                    title_fm.horizontalAdvance(box.title) + extra,
                    sub_fm.horizontalAdvance(box.subtitle),
                )
            self._col_w[layer] = max(120.0, min(270.0, widest + 32.0))

    def resizeEvent(self, event) -> None:  # noqa: ANN001, N802
        super().resizeEvent(event)
        if self._rendering or self._reflowing or not self._nodes:
            return
        self._reflow()

    def _fit_columns(self) -> None:
        """Pack the columns side by side at their measured widths."""
        x = 12.0
        for layer in self._layers:
            self._col_x[layer] = x
            x += self._col_w[layer] + self._gutter

    def _fit_spacing(self, count: int) -> None:
        """Open the rows up when the view is taller than the packed cards."""
        self._node_h = 52.0
        self._row_top = 36.0
        height = max(self.viewport().height(), self.height())
        if height < 300:
            height = 800
        usable = height - self._row_top - 24.0
        if count <= 1:
            self._gap_y = 28.0
            return
        gap = (usable - count * self._node_h) / (count - 1)
        self._gap_y = max(26.0, min(72.0, gap))

    def _assign_lanes(self) -> None:
        """One vertical lane per card in each gutter, ordered by the card's row.

        Links that fan into one card share that card's lane, so they join as a
        bracket. Other links take their source card's lane.
        """
        from pfsense_checker.topo_route import same_column_gutter

        layers = self._layers
        index = {name: i for i, name in enumerate(layers)}
        last = len(layers) - 1

        def gutters_of(edge: _TopoEdge) -> list[int]:
            a, b = index[edge.src.layer], index[edge.dst.layer]
            if a == b:
                return [same_column_gutter(a, last)]
            return list(range(min(a, b), max(a, b)))

        fan_in: dict[tuple[int, str], int] = {}
        for edge in self._edges:
            for gutter in gutters_of(edge):
                key = (gutter, f"{edge.dst.layer}:{edge.dst.node_id}")
                fan_in[key] = fan_in.get(key, 0) + 1
        rows: dict[int, dict[str, float]] = {}
        slots: list[tuple[_TopoEdge, list[tuple[int, str]]]] = []
        for edge in self._edges:
            pairs = []
            for gutter in gutters_of(edge):
                dst_key = f"{edge.dst.layer}:{edge.dst.node_id}"
                if fan_in.get((gutter, dst_key), 0) > 1 and edge.dst.row_span == 1:
                    key, y = "in:" + dst_key, edge.dst.pos().y()
                else:
                    key, y = "out:" + f"{edge.src.layer}:{edge.src.node_id}", edge.src.pos().y()
                rows.setdefault(gutter, {})[key] = y
                pairs.append((gutter, key))
            slots.append((edge, pairs))
        gutter_w = self._gutter
        offsets: dict[tuple[int, str], float] = {}
        for gutter, keys in rows.items():
            ordered = sorted(keys, key=lambda k: (keys[k], k))
            count = len(ordered)
            spacing = min(10.0, max(gutter_w - 24.0, 0.0) / max(count - 1, 1))
            for i, key in enumerate(ordered):
                offsets[(gutter, key)] = (i - (count - 1) / 2) * spacing
        for edge, pairs in slots:
            edge.lanes = {gutter: offsets[(gutter, key)] for gutter, key in pairs}

    def _span_height(self, span: int) -> float:
        return span * self._node_h + (span - 1) * self._gap_y

    def _mark_dragged(self, node: _TopoNode) -> None:
        self._dragged.add(f"{node.layer}:{node.node_id}")

    def _reflow(self) -> None:
        """Keep a dragged card where the operator put it; spread the rest."""
        if not self._nodes or self._reflowing:
            return
        layers = self._layers

        old = (
            round(self._gap_y, 1),
            tuple(round(self._col_x[name], 1) for name in layers),
        )
        self._fit_columns()
        tallest = max(node.order_index + node.row_span for node in self._nodes.values())
        self._fit_spacing(tallest)
        new = (
            round(self._gap_y, 1),
            tuple(round(self._col_x[name], 1) for name in layers),
        )
        if new == old:
            return
        self._reflowing = True
        try:
            for layer, item in self._header_items.items():
                item.setPos(self._col_x.get(layer, 16.0), -18)
            if self._tip_item is not None:
                self._tip_item.setPos(16, -40)
            for node in self._nodes.values():
                node.prepareGeometryChange()
                node.w = self._col_w.get(node.layer, node.w)
                node.h = self._span_height(node.row_span)
                node.column_x = self._col_x.get(node.layer, node.column_x)
                key = f"{node.layer}:{node.node_id}"
                if key in self._dragged:
                    y = node.pos().y()
                else:
                    y = self._row_top + node.order_index * (self._node_h + self._gap_y)
                node.setPos(node.column_x, y)
        finally:
            self._reflowing = False
        # Edges skip rebuilds while _reflowing; route them once every card has moved.
        self._update_chassis()
        self._assign_lanes()
        for edge in self._edges:
            edge.rebuild()
        bounds = self._scene.itemsBoundingRect()
        self._scene.setSceneRect(bounds.adjusted(-24, -48, 24, 24))

    def render_topology(self, result) -> None:  # noqa: ANN001
        """Build an editable, crossing-minimized diagram from a CheckResult."""
        self._rendering = True
        try:
            self._render_topology(result)
        finally:
            self._rendering = False

    def _render_topology(self, result) -> None:  # noqa: ANN001
        path_key = str(result.path) if getattr(result, "path", None) else None
        if path_key != self._last_path:
            self._custom_y.clear()
            self._dragged.clear()
            self._last_path = path_key
        prev_y = dict(self._custom_y)
        self._last_result = result
        self.clear()
        self._custom_y = prev_y

        from pfsense_checker.firewall_topology import LAYERS, build_config_topology, tree_order

        graph = build_config_topology(result)
        self._layers = [name for name in LAYERS if name == "phys" or graph.layers.get(name)]
        raw_edges = [
            (
                e.src_layer,
                e.src_id,
                e.dst_layer,
                e.dst_id,
                COLOR_OK if e.kind == "edge" else KIND_COLORS.get(e.kind, KIND_COLORS["other"]),
            )
            for e in graph.edges
        ]
        layout = tree_order(graph)
        orders = layout.rows
        headers = {
            "ext": "Internet / External VLANs",
            "gw": "Gateway groups / WAN ports",
            "phys": "Physical NICs",
            "port": "Port name",
            "vlan": "VLANs",
            "bridge": "Bridges",
        }

        badges = self._segmentation_badges(result, graph)
        self._measure_columns(graph, headers, badges)
        self._fit_columns()
        tallest = max(
            (
                row + layout.spans.get((layer, nid), 1)
                for layer, rows in orders.items()
                for nid, row in rows.items()
            ),
            default=1,
        )
        self._fit_spacing(max(tallest, 1))

        # Place nodes
        for layer in self._layers:
            label = headers[layer]
            hdr = self._scene.addText(label)
            hdr.setDefaultTextColor(QColor("#455a64"))
            hf = QFont()
            hf.setBold(True)
            hf.setPointSize(10)
            hdr.setFont(hf)
            hdr.setPos(self._col_x[layer], -18)
            hdr.setZValue(3)
            self._header_items[layer] = hdr

        def place(layer: str, node_id: str, title: str, subtitle: str, color: str, dim: bool = False) -> _TopoNode:
            node = _TopoNode(node_id, layer, title, subtitle, color, dim=dim,
                             width=self._col_w[layer], height=self._node_h)
            node.column_x = self._col_x[layer]
            rows = orders.get(layer, {})
            idx = rows.get(node_id, tallest)
            node.order_index = idx
            node.row_span = layout.spans.get((layer, node_id), 1)
            node.h = self._span_height(node.row_span)
            auto_y = self._row_top + idx * (self._node_h + self._gap_y)
            y = self._custom_y.get(f"{layer}:{node_id}", auto_y)
            node.setPos(node.column_x, y)
            node.set_locked(self._locked)
            if (layer, node_id) in badges:
                text, colour, tip = badges[(layer, node_id)]
                node.badge = (text, colour)
                node.setToolTip(tip)
            node.moved.connect(self._on_node_moved)
            node.user_moved.connect(lambda node=node: self._mark_dragged(node))
            self._scene.addItem(node)
            self._nodes[f"{layer}:{node_id}"] = node
            return node

        for pid in orders.get("phys", []):
            box = graph.boxes.get(("phys", pid))
            if box is None:
                continue
            place("phys", pid, box.title, box.subtitle, KIND_COLORS.get(box.kind, KIND_COLORS["physical"]), dim=box.dim)

        if not orders.get("phys"):
            place("phys", "(none)", "(no NICs)", "", COLOR_MUTED, dim=True)

        for layer in ("ext", "gw", "port", "vlan", "bridge"):
            for nid in orders.get(layer, []):
                box = graph.boxes.get((layer, nid))
                if box is None:
                    continue
                place(
                    layer,
                    nid,
                    box.title,
                    box.subtitle,
                    KIND_COLORS.get(box.kind, KIND_COLORS["other"]),
                    dim=box.dim,
                )

        # Draw edges (orthogonal). Sort by source then dest Y after layout so
        # stub ordering is stable.
        def node_key(layer: str, nid: str) -> str:
            return f"{layer}:{nid}"

        for src_layer, src_id, dst_layer, dst_id, color in raw_edges:
            src = self._nodes.get(node_key(src_layer, src_id))
            dst = self._nodes.get(node_key(dst_layer, dst_id))
            if src is None or dst is None:
                continue
            edge = _TopoEdge(src, dst, color, self)
            self._scene.addItem(edge)
            self._edges.append(edge)
        self._assign_lanes()
        for edge in self._edges:
            edge.rebuild()

        tip = self._scene.addText(
            "Drag nodes vertically to edit · Links stay in the gaps · Lock to freeze"
        )
        tip.setDefaultTextColor(QColor("#90a4ae"))
        tf = QFont()
        tf.setPointSize(8)
        tip.setFont(tf)
        tip.setPos(16, -40)
        tip.setZValue(3)
        self._tip_item = tip
        self._add_chassis(result)

        bounds = self._scene.itemsBoundingRect()
        self._scene.setSceneRect(bounds.adjusted(-24, -48, 24, 24))
        self._remember_positions()


DEVICE_KIND_COLORS = {
    "pfsense": "#c62828",
    "opnsense": "#ad1457",
    "mikrotik": "#1565c0",
    "juniper": "#2e7d32",
    "ubiquiti": "#0559c9",
    "netgear-managed": "#6a1b9a",
    "netgear-unmanaged": "#8e24aa",
    "switch": "#2e7d32",
    "router": "#0277bd",
    "access-point": "#00838f",
    "server": "#4527a0",
    "workstation": "#37474f",
    "desktop": "#455a64",
    "sff": "#546e7a",
    "kvm": "#00838f",
    "nas": "#5d4037",
    "tv": "#283593",
    "video-box": "#3949ab",
    "game-console": "#00695c",
    "host": "#607d8b",
    "isp": "#ef6c00",
    "egress": "#e65100",
    "other": "#616161",
}

LINK_KIND_COLORS = {
    "copper": "#546e7a",
    "fiber": "#6a1b9a",
    "sfp": "#6a1b9a",
    "trunk": "#1565c0",
    "access": "#00838f",
    "lag": "#ad1457",
    "wireless": "#00838f",
    "vpn": "#c62828",
    "other": "#78909c",
}


TIER_LABELS = {
    0: "Internet / ISP",
    1: "Egress",
    2: "Firewall",
    3: "Core switch",
    4: "Access",
    5: "Hosts / AP",
    6: "Remote",
}


class SiteTopologyView(QGraphicsView):
    """Excel-style physical layout: left→right tiers with device cards + IF/NW/S-IP/DHCP."""

    def __init__(self) -> None:
        self._scene = QGraphicsScene()
        super().__init__(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setBackgroundBrush(QBrush(QColor("#f7f9fb")))
        self.setMinimumHeight(420)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)

    def clear(self) -> None:
        self._scene.clear()

    def _draw_card(
        self,
        x: float,
        y: float,
        w: float,
        title: str,
        lines: list[tuple[str, str]],
        color: str,
        *,
        ports: list[str] | None = None,
    ) -> QRectF:
        """Draw a device card; returns its bounding rect."""
        port_h = 22 if ports else 0
        body_h = 28 + 14 * max(len(lines), 1) + port_h + 8
        rect = QRectF(x, y, w, body_h)

        pen = QPen(QColor(color))
        pen.setWidth(2)
        fill = QColor(color)
        fill.setAlpha(22)
        self._scene.addRect(rect, pen, QBrush(fill))

        # Header bar
        hdr = QRectF(x, y, w, 22)
        hdr_fill = QColor(color)
        hdr_fill.setAlpha(55)
        self._scene.addRect(hdr, QPen(Qt.PenStyle.NoPen), QBrush(hdr_fill))

        t = self._scene.addText(title)
        tf = QFont()
        tf.setBold(True)
        tf.setPointSize(8)
        t.setFont(tf)
        t.setDefaultTextColor(QColor("#212121"))
        t.setPos(x + 6, y + 2)

        yy = y + 24
        for label, value in lines:
            if not value and not label:
                continue
            row = self._scene.addText(f"{label}: {value}" if label else value)
            rf = QFont()
            rf.setPointSize(7)
            row.setFont(rf)
            row.setDefaultTextColor(QColor("#37474f"))
            row.setPos(x + 6, yy)
            yy += 14

        if ports:
            # Port strip like CRS328 1..20 C1 C2
            strip_y = y + body_h - port_h - 2
            pw = max(14.0, (w - 12) / max(len(ports), 1))
            for i, p in enumerate(ports[:24]):
                pr = QRectF(x + 6 + i * pw, strip_y, pw - 2, 16)
                self._scene.addRect(
                    pr,
                    QPen(QColor("#90a4ae")),
                    QBrush(QColor("#eceff1")),
                )
                pt = self._scene.addText(str(p)[:4])
                pf = QFont()
                pf.setPointSize(6)
                pt.setFont(pf)
                pt.setDefaultTextColor(QColor("#455a64"))
                pt.setPos(pr.left() + 1, pr.top())

        return rect

    def _draw_vlan_chip(
        self, x: float, y: float, vlan, color: str = "#00838f"  # noqa: ANN001
    ) -> QRectF:
        """IF / NW / S-IP / DHCP attachment card under a device."""
        rows = [
            ("IF", vlan.if_label or vlan.name or f"VLAN{vlan.id}"),
            ("NW", vlan.subnet),
            ("S-IP", vlan.s_ip or vlan.gateway),
            ("DHCP", vlan.dhcp_pool),
        ]
        rows = [(a, b) for a, b in rows if b]
        w, h = 150.0, 16.0 + 12 * len(rows)
        rect = QRectF(x, y, w, h)
        pen = QPen(QColor(color))
        pen.setStyle(Qt.PenStyle.DashLine)
        fill = QColor(color)
        fill.setAlpha(18)
        self._scene.addRect(rect, pen, QBrush(fill))
        title = self._scene.addText(f"VLAN {vlan.id}")
        tf = QFont()
        tf.setPointSize(7)
        tf.setBold(True)
        title.setFont(tf)
        title.setDefaultTextColor(QColor(color))
        title.setPos(x + 4, y)
        yy = y + 14
        for lab, val in rows:
            t = self._scene.addText(f"{lab}  {val}")
            f = QFont()
            f.setPointSize(6)
            t.setFont(f)
            t.setDefaultTextColor(QColor("#455a64"))
            t.setPos(x + 4, yy)
            yy += 11
        return rect

    def _ortho(self, a: QRectF, b: QRectF, color: str, label: str = "") -> None:
        start = QPointF(a.right(), a.center().y())
        end = QPointF(b.left(), b.center().y())
        mid_x = (start.x() + end.x()) / 2
        path = QPainterPath(start)
        path.lineTo(mid_x, start.y())
        path.lineTo(mid_x, end.y())
        path.lineTo(end)
        pen = QPen(QColor(color))
        pen.setWidth(2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        item = self._scene.addPath(path, pen)
        item.setZValue(0)
        if label:
            mid = QPointF(mid_x + 4, (start.y() + end.y()) / 2 - 8)
            lt = self._scene.addText(label)
            lf = QFont()
            lf.setPointSize(6)
            lt.setFont(lf)
            lt.setDefaultTextColor(QColor("#37474f"))
            br = lt.boundingRect()
            bg = self._scene.addRect(
                QRectF(mid.x() - 2, mid.y() - 1, br.width() + 4, br.height() + 2),
                QPen(Qt.PenStyle.NoPen),
                QBrush(QColor(255, 255, 255, 230)),
            )
            bg.setZValue(1)
            lt.setPos(mid)
            lt.setZValue(2)

    def render_site(self, site) -> None:  # noqa: ANN001
        """Render an Excel-like left→right physical layout."""
        self._scene.clear()

        if not site.devices:
            empty = self._scene.addText(
                "No devices yet — build ISP → egress → pfSense → CRS328 → CRS109 below.\n"
                "Use Load CRS example for a layout like your spreadsheet."
            )
            empty.setDefaultTextColor(QColor("#9e9e9e"))
            empty.setPos(20, 20)
            self._scene.setSceneRect(self._scene.itemsBoundingRect().adjusted(-20, -20, 20, 20))
            return

        # Title
        title = self._scene.addText(site.name or "Physical Layout")
        tf = QFont()
        tf.setPointSize(12)
        tf.setBold(True)
        title.setFont(tf)
        title.setDefaultTextColor(QColor("#263238"))
        title.setPos(20, 4)

        # Bucket devices by tier
        tiers: dict[int, list] = {}
        for dev in site.devices:
            tiers.setdefault(dev.tier(), []).append(dev)

        # Barycenter-ish vertical order within tiers using link neighbours
        name_tier = {d.name: d.tier() for d in site.devices}
        neighbours: dict[str, list[str]] = {d.name: [] for d in site.devices}
        for link in site.links:
            if link.a_device in neighbours and link.b_device in neighbours:
                neighbours[link.a_device].append(link.b_device)
                neighbours[link.b_device].append(link.a_device)

        # Order tier 0 alphabetically/by priority, then propagate
        ordered: dict[int, list] = {}
        for t in sorted(tiers):
            ordered[t] = list(tiers[t])

        for t in sorted(ordered):
            if t == min(ordered):
                ordered[t].sort(key=lambda d: (d.priority or "9", d.name))
                continue
            # Sort by average index of left-tier neighbours
            left_t = max((x for x in ordered if x < t), default=None)
            if left_t is None:
                continue
            left_pos = {d.name: i for i, d in enumerate(ordered[left_t])}

            def score(dev, lp=left_pos, nb=neighbours):  # noqa: ANN001
                hits = [lp[n] for n in nb.get(dev.name, []) if n in lp]
                return (sum(hits) / len(hits) if hits else 999, dev.name)

            ordered[t].sort(key=score)

        card_w = 210.0
        gap_x = 70.0
        gap_y = 28.0
        col_x0 = 20.0
        row_y0 = 50.0

        tier_list = sorted(ordered)
        col_x = {t: col_x0 + i * (card_w + gap_x) for i, t in enumerate(tier_list)}

        # Column headers
        for t in tier_list:
            hdr = self._scene.addText(TIER_LABELS.get(t, f"Tier {t}"))
            hf = QFont()
            hf.setBold(True)
            hf.setPointSize(9)
            hdr.setFont(hf)
            hdr.setDefaultTextColor(QColor("#546e7a"))
            hdr.setPos(col_x[t], 28)

        rects: dict[str, QRectF] = {}
        chip_bottom: dict[str, float] = {}

        for t in tier_list:
            y = row_y0
            for dev in ordered[t]:
                color = DEVICE_KIND_COLORS.get(dev.kind, DEVICE_KIND_COLORS["other"])
                if dev.role == "egress":
                    color = DEVICE_KIND_COLORS["egress"]
                lines: list[tuple[str, str]] = []
                lines.append(("", f"{dev.model or dev.kind}" + (f" · {dev.hardware}" if dev.hardware else "")))
                if dev.notes:
                    lines.append(("", dev.notes))
                if dev.mgmt_ip:
                    lines.append(("Mgmt", dev.mgmt_ip))
                if dev.priority != "":
                    lines.append(("Priority", dev.priority))
                # Show a compact port strip for switches
                show_ports = None
                if dev.role in ("core-switch", "access-switch", "core", "access") or dev.kind == "switch":
                    show_ports = list(dev.ports[:22]) if dev.ports else None

                rect = self._draw_card(
                    col_x[t],
                    y,
                    card_w,
                    f"{dev.header_line()} — {dev.name}",
                    lines,
                    color,
                    ports=show_ports,
                )
                rects[dev.name] = rect

                # VLAN chips under card for VLANs this device carries (max 3)
                chip_y = rect.bottom() + 6
                shown = 0
                for vlan in site.vlans:
                    if dev.name not in vlan.devices:
                        continue
                    if shown >= 3:
                        break
                    chip = self._draw_vlan_chip(col_x[t] + 8, chip_y, vlan)
                    chip_y = chip.bottom() + 4
                    shown += 1
                chip_bottom[dev.name] = chip_y
                y = max(chip_y, rect.bottom()) + gap_y

        # Orthogonal links between devices (ordered to reduce crossings)
        for link in site.links:
            a = rects.get(link.a_device)
            b = rects.get(link.b_device)
            if a is None or b is None:
                continue
            # Always draw left→right by tier
            ta = name_tier.get(link.a_device, 0)
            tb = name_tier.get(link.b_device, 0)
            if ta <= tb:
                left, right = a, b
                left_port, right_port = link.a_port, link.b_port
            else:
                left, right = b, a
                left_port, right_port = link.b_port, link.a_port
            color = LINK_KIND_COLORS.get(link.kind, LINK_KIND_COLORS["other"])
            bits = []
            if left_port or right_port:
                bits.append(f"{left_port or '?'}↔{right_port or '?'}")
            if link.kind and link.kind != "copper":
                bits.append(link.kind)
            if link.speed:
                bits.append(link.speed)
            if link.vlans:
                bits.append("VLANs " + ",".join(link.vlans[:6]))
            self._ortho(left, right, color, " · ".join(bits))

        # VPN overlays (dashed)
        for vpn in site.vpn:
            a = rects.get(vpn.a_device)
            b = rects.get(vpn.b_device)
            if a is None or b is None:
                continue
            start = QPointF(a.center().x(), a.bottom() + 4)
            end = QPointF(b.center().x(), b.bottom() + 4)
            pen = QPen(QColor(LINK_KIND_COLORS["vpn"]))
            pen.setWidth(2)
            pen.setStyle(Qt.PenStyle.DashDotLine)
            self._scene.addLine(start.x(), start.y(), end.x(), end.y(), pen)
            mid = QPointF((start.x() + end.x()) / 2, (start.y() + end.y()) / 2)
            lt = self._scene.addText(f"VPN {vpn.name} ({vpn.kind})")
            lf = QFont()
            lf.setPointSize(7)
            lt.setFont(lf)
            lt.setDefaultTextColor(QColor(LINK_KIND_COLORS["vpn"]))
            lt.setPos(mid)

        # Egress badges
        for eg in site.egress:
            r = rects.get(eg.device)
            if r is None:
                continue
            badge = QRectF(r.left(), r.top() - 16, 64, 14)
            self._scene.addRect(
                badge,
                QPen(QColor(DEVICE_KIND_COLORS["egress"])),
                QBrush(QColor(255, 236, 179)),
            )
            t = self._scene.addText("EGRESS")
            f = QFont()
            f.setPointSize(7)
            f.setBold(True)
            t.setFont(f)
            t.setDefaultTextColor(QColor(DEVICE_KIND_COLORS["egress"]))
            t.setPos(badge.left() + 4, badge.top() - 1)

        tip = self._scene.addText(
            "Physical layout (Excel-style): ISP → Egress → Firewall → Core → Access. "
            "Cards show SECPOL, ports, and IF/NW/S-IP/DHCP VLAN attachments."
        )
        tipf = QFont()
        tipf.setPointSize(8)
        tip.setFont(tipf)
        tip.setDefaultTextColor(QColor("#90a4ae"))
        tip.setPos(20, -18)

        bounds = self._scene.itemsBoundingRect()
        self._scene.setSceneRect(bounds.adjusted(-30, -40, 40, 40))


class SegmentationMatrix(QWidget):
    """Which inside subnet may reach which: rows are sources, columns destinations."""

    _CELL = {
        "open": ("ANY", COLOR_ERROR),
        "limited": ("some", COLOR_WARN),
        "blocked": ("—", COLOR_OK),
    }

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.summary = QLabel("Load a config to see how the subnets are separated.")
        self.summary.setWordWrap(True)
        self.summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.summary)
        self.table = QTableWidget()
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.table, stretch=1)

    def set_segmentation(self, seg) -> None:  # noqa: ANN001
        self.table.clear()
        if seg is None or not seg.reach:
            self.table.setRowCount(0)
            self.table.setColumnCount(0)
            self.summary.setText("Fewer than two routed inside subnets: nothing to separate.")
            return
        zones = seg.zones
        colour = COLOR_OK if seg.score >= 90 else COLOR_WARN if seg.score >= 60 else COLOR_ERROR
        text = (
            f"<b style='color:{colour}'>Segmentation {seg.score}/100: {seg.verdict}.</b> "
            f"{seg.count('open')} of {seg.pairs} subnet pairs allow any protocol, "
            f"{seg.count('limited')} allow some services, {seg.count('blocked')} are blocked. "
            "Rows are the source subnet (rules on its interface), columns the destination."
        )
        extra = seg.layer2 + seg.notes
        if extra:
            text += "<br>" + "<br>".join(f"• {line}" for line in extra)
        self.summary.setText(text)

        self.table.setRowCount(len(zones))
        self.table.setColumnCount(len(zones))
        labels = [f"{z.title}\n{z.name.upper()} · {z.network}" for z in zones]
        self.table.setVerticalHeaderLabels(labels)
        self.table.setHorizontalHeaderLabels([z.name.upper() for z in zones])
        for c, label in enumerate(labels):
            self.table.horizontalHeaderItem(c).setToolTip(label)
        for r, src in enumerate(zones):
            for c, dst in enumerate(zones):
                if src.name == dst.name:
                    item = QTableWidgetItem("")
                    item.setBackground(QBrush(QColor("#eceff1")))
                    self.table.setItem(r, c, item)
                    continue
                reach = seg.reach[(src.name, dst.name)]
                label, col = self._CELL[reach.level]
                item = QTableWidgetItem(label)
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                item.setForeground(QBrush(QColor("#ffffff")))
                item.setBackground(QBrush(QColor(col)))
                tip = f"{src.title} → {dst.title}: "
                if reach.level == "open":
                    tip += f"any protocol (rule {', '.join(f'#{n}' for n in reach.rules)})"
                elif reach.level == "limited":
                    tip += ", ".join(reach.services)
                else:
                    tip += "blocked (no pass rule matches)"
                if reach.note:
                    tip += f"\n{reach.note}"
                item.setToolTip(tip)
                self.table.setItem(r, c, item)


def flow_row(*widgets: QWidget) -> QWidget:
    """Lay widgets out in a horizontal row inside a container widget."""
    container = QWidget()
    row = QHBoxLayout(container)
    row.setContentsMargins(0, 0, 0, 0)
    row.setSpacing(8)
    for w in widgets:
        row.addWidget(w)
    return container


def epoch_seconds(ts_iso: str) -> float | None:
    """Parse an ISO-8601 UTC timestamp to epoch seconds."""
    if not ts_iso:
        return None
    try:
        return datetime.fromisoformat(ts_iso).timestamp()
    except ValueError:
        return None
