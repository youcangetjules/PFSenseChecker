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
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsItem,
    QGraphicsObject,
    QGraphicsPathItem,
    QGraphicsScene,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
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


class _TopoNode(QGraphicsObject):
    """Draggable topology node; X stays in its layer column."""

    moved = Signal()

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
        fill = QColor(self.color)
        fill.setAlpha(40 if not self.dim else 15)
        painter.setPen(pen)
        painter.setBrush(QBrush(fill))
        painter.drawRoundedRect(self.boundingRect().adjusted(0.5, 0.5, -0.5, -0.5), 4, 4)

        painter.setPen(QColor("#b0b0b0") if self.dim else QColor("#212121"))
        font = QFont()
        font.setBold(True)
        font.setPointSize(9)
        painter.setFont(font)
        painter.drawText(QRectF(8, 5, self.w - 16, 18), Qt.AlignmentFlag.AlignLeft, self.title)

        if self.subtitle:
            painter.setPen(QColor("#78909c"))
            font2 = QFont()
            font2.setPointSize(7)
            painter.setFont(font2)
            painter.drawText(
                QRectF(8, 22, self.w - 16, 18),
                Qt.AlignmentFlag.AlignLeft,
                self.subtitle,
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
        self.setCursor(Qt.CursorShape.ClosedHandCursor)
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event) -> None:  # noqa: ANN001, N802
        self.setCursor(
            Qt.CursorShape.ArrowCursor if self._locked else Qt.CursorShape.OpenHandCursor
        )
        super().mouseReleaseEvent(event)

    def center_right(self) -> QPointF:
        return self.mapToScene(QPointF(self.w, self.h / 2))

    def center_left(self) -> QPointF:
        return self.mapToScene(QPointF(0, self.h / 2))


class _TopoEdge(QGraphicsPathItem):
    """Orthogonal elbow edge between two nodes (right → left of next column)."""

    def __init__(self, src: _TopoNode, dst: _TopoNode, color: str) -> None:
        super().__init__()
        self.src = src
        self.dst = dst
        self.color = color
        self.setZValue(1)
        pen = QPen(QColor(color))
        pen.setWidth(2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        self.setPen(pen)
        src.moved.connect(self.rebuild)
        dst.moved.connect(self.rebuild)
        self.rebuild()

    def rebuild(self) -> None:
        a = self.src.center_right()
        b = self.dst.center_left()
        mid_x = (a.x() + b.x()) / 2
        path = QPainterPath(a)
        # Orthogonal: horizontal → vertical → horizontal. Same-layer order
        # (after barycenter layout) keeps these from crossing.
        path.lineTo(mid_x, a.y())
        path.lineTo(mid_x, b.y())
        path.lineTo(b)
        self.setPath(path)


def _count_crossings(order_a: list[str], order_b: list[str], edges: list[tuple[str, str]]) -> int:
    pos_a = {n: i for i, n in enumerate(order_a)}
    pos_b = {n: i for i, n in enumerate(order_b)}
    pairs = [
        (pos_a[u], pos_b[v])
        for u, v in edges
        if u in pos_a and v in pos_b
    ]
    crossings = 0
    for i in range(len(pairs)):
        for j in range(i + 1, len(pairs)):
            a1, b1 = pairs[i]
            a2, b2 = pairs[j]
            if (a1 - a2) * (b1 - b2) < 0:
                crossings += 1
    return crossings


def _barycenter_order(
    fixed: list[str],
    movable: list[str],
    edges: list[tuple[str, str]],
    *,
    from_left: bool,
) -> list[str]:
    """Reorder ``movable`` by average neighbour index in ``fixed``."""
    pos = {n: i for i, n in enumerate(fixed)}
    scores: dict[str, float] = {}
    counts: dict[str, int] = {}
    for u, v in edges:
        left, right = (u, v) if from_left else (v, u)
        if from_left:
            if right not in movable or left not in pos:
                continue
            scores[right] = scores.get(right, 0.0) + pos[left]
            counts[right] = counts.get(right, 0) + 1
        else:
            if left not in movable or right not in pos:
                continue
            scores[left] = scores.get(left, 0.0) + pos[right]
            counts[left] = counts.get(left, 0) + 1

    def key(n: str) -> tuple[float, str]:
        if counts.get(n):
            return (scores[n] / counts[n], n)
        # Unconnected nodes keep relative alphabetical fallback at the end
        return (len(fixed) + 0.5, n)

    return sorted(movable, key=key)


def minimize_layer_crossings(
    layers: dict[str, list[str]],
    edges: list[tuple[str, str, str, str]],
    layer_order: list[str],
    *,
    passes: int = 8,
) -> dict[str, list[str]]:
    """Sugiyama-style barycenter heuristic across consecutive layers."""
    orders = {k: list(v) for k, v in layers.items()}
    # Adjacent-layer edge lists
    adj: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for src_layer, src_id, dst_layer, dst_id in edges:
        adj.setdefault((src_layer, dst_layer), []).append((src_id, dst_id))

    for _ in range(passes):
        # Left → right
        for i in range(len(layer_order) - 1):
            left, right = layer_order[i], layer_order[i + 1]
            e = adj.get((left, right), [])
            if not e:
                continue
            orders[right] = _barycenter_order(orders[left], orders[right], e, from_left=True)
        # Right → left
        for i in range(len(layer_order) - 1, 0, -1):
            left, right = layer_order[i - 1], layer_order[i]
            e = adj.get((left, right), [])
            if not e:
                continue
            orders[left] = _barycenter_order(orders[right], orders[left], e, from_left=False)
    return orders


class TopologyView(QGraphicsView):
    """Editable layered topology with crossing-minimized auto-layout."""

    def __init__(self) -> None:
        self._scene = QGraphicsScene()
        super().__init__(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setBackgroundBrush(QBrush(QColor("#fbfbfb")))
        self.setMinimumHeight(360)
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
        self._nodes: dict[str, _TopoNode] = {}
        self._edges: list[_TopoEdge] = []
        self._locked = False
        self._custom_y: dict[str, float] = {}
        self._last_result = None
        self._last_path: str | None = None
        self._col_x = {"phys": 20.0, "agg": 260.0, "logical": 500.0, "edge": 740.0}
        self._node_w = 170.0
        self._node_h = 46.0
        self._gap_y = 14.0

    def clear(self) -> None:
        self._scene.clear()
        self._nodes.clear()
        self._edges.clear()

    def set_locked(self, locked: bool) -> None:
        self._locked = locked
        for node in self._nodes.values():
            node.set_locked(locked)

    def reset_layout(self) -> None:
        """Clear manual positions and re-run auto-layout."""
        self._custom_y.clear()
        if self._last_result is not None:
            self.render_topology(self._last_result)

    def apply_auto_layout(self) -> None:
        """Re-order by crossing minimization but keep manual Y overrides cleared."""
        self._custom_y.clear()
        if self._last_result is not None:
            self.render_topology(self._last_result)

    def _remember_positions(self) -> None:
        for nid, node in self._nodes.items():
            self._custom_y[nid] = node.pos().y()

    def _on_node_moved(self) -> None:
        self._remember_positions()
        bounds = self._scene.itemsBoundingRect()
        self._scene.setSceneRect(bounds.adjusted(-40, -40, 40, 40))

    def render_topology(self, result) -> None:  # noqa: ANN001
        """Build an editable, crossing-minimized diagram from a CheckResult."""
        path_key = str(result.path) if getattr(result, "path", None) else None
        if path_key != self._last_path:
            self._custom_y.clear()
            self._last_path = path_key
        prev_y = dict(self._custom_y)
        self._last_result = result
        self.clear()
        self._custom_y = prev_y

        # --- Collect layered nodes ---
        phys: dict[str, str] = {}
        for b in result.bridges:
            for m in b.members:
                phys.setdefault(m, "bridge member")
        for lg in result.laggs:
            for m in lg.members:
                phys.setdefault(m, "lagg member")
        for v in result.vlans:
            if v.if_parent:
                phys.setdefault(v.if_parent, "vlan parent")
        for i in result.interfaces:
            if i.kind == "physical" and i.device:
                phys.setdefault(i.device, "assigned")

        agg_meta: dict[str, tuple[str, str, str]] = {}  # id -> (title, subtitle, color)
        for b in result.bridges:
            key = (b.bridgeif or "bridge").lower()
            agg_meta[key] = (
                b.bridgeif or "bridge",
                f"bridge · stp {'on' if b.stp_enabled else 'off'}",
                KIND_COLORS["bridge"],
            )
        for lg in result.laggs:
            key = (lg.laggif or "lagg").lower()
            agg_meta[key] = (
                lg.laggif or "lagg",
                f"lagg · {lg.proto}",
                KIND_COLORS["lagg"],
            )
        for v in result.vlans:
            key = (v.vlanif or f"vlan{v.tag}").lower()
            agg_meta[key] = (
                v.vlanif or f"vlan{v.tag}",
                f"vlan {v.tag} on {v.if_parent}",
                KIND_COLORS["vlan"],
            )

        logical_meta: dict[str, tuple[str, str, str, bool]] = {}
        for i in result.interfaces:
            key = i.name.lower()
            ip = i.ipaddr
            if i.subnet and i.ipaddr not in ("dhcp", ""):
                ip = f"{i.ipaddr}/{i.subnet}"
            logical_meta[key] = (
                i.name.upper(),
                f"{i.device} · {ip or 'no ip'}",
                KIND_COLORS.get(i.kind, KIND_COLORS["other"]),
                not i.enabled,
            )

        # --- Edges as (src_layer, src_id, dst_layer, dst_id, color) ---
        raw_edges: list[tuple[str, str, str, str, str]] = []

        for b in result.bridges:
            dst = (b.bridgeif or "").lower()
            for m in b.members:
                src = m.lower()
                if src in {k.lower() for k in phys} and dst in agg_meta:
                    raw_edges.append(("phys", src, "agg", dst, KIND_COLORS["bridge"]))
        for lg in result.laggs:
            dst = (lg.laggif or "").lower()
            for m in lg.members:
                src = m.lower()
                if src in {k.lower() for k in phys} and dst in agg_meta:
                    raw_edges.append(("phys", src, "agg", dst, KIND_COLORS["lagg"]))
        for v in result.vlans:
            dst = (v.vlanif or f"vlan{v.tag}").lower()
            if v.if_parent:
                src = v.if_parent.lower()
                if src in {k.lower() for k in phys} and dst in agg_meta:
                    raw_edges.append(("phys", src, "agg", dst, KIND_COLORS["vlan"]))

        phys_keys = {k.lower() for k in phys}
        for i in result.interfaces:
            dst = i.name.lower()
            src = (i.device or "").lower()
            color = KIND_COLORS.get(i.kind, KIND_COLORS["other"])
            if src in agg_meta:
                raw_edges.append(("agg", src, "logical", dst, color))
            elif src in phys_keys:
                raw_edges.append(("phys", src, "logical", dst, color))

        wan_ids = [
            i.name.lower()
            for i in result.interfaces
            if i.name.lower() == "wan" or "wan" in i.name.lower()
        ]
        if wan_ids:
            for wid in wan_ids:
                raw_edges.append(("logical", wid, "edge", "internet", COLOR_OK))

        # Initial layer membership
        layers: dict[str, list[str]] = {
            "phys": sorted({k.lower() for k in phys}),
            "agg": sorted(agg_meta.keys()),
            "logical": sorted(logical_meta.keys()),
            "edge": ["internet"] if wan_ids else [],
        }

        layout_edges = [(a, b, c, d) for a, b, c, d, _ in raw_edges]
        # Only keep edges between consecutive conceptual layers for ordering;
        # phys→logical is treated as phys→agg phantom via inserting through order.
        # For crossing min, include phys-logical by routing through a virtual hop:
        # we still minimize on real consecutive pairs, and separately on phys-logical.
        orders = minimize_layer_crossings(
            layers, layout_edges, ["phys", "agg", "logical", "edge"], passes=10
        )

        # Extra pass for direct phys→logical edges
        phys_log = [(b, d) for a, b, c, d in layout_edges if a == "phys" and c == "logical"]
        if phys_log:
            orders["logical"] = _barycenter_order(
                orders["phys"], orders["logical"], phys_log, from_left=True
            )
            orders["phys"] = _barycenter_order(
                orders["logical"], orders["phys"], phys_log, from_left=False
            )

        # Place nodes
        headers = {
            "phys": "Physical NICs",
            "agg": "Aggregation",
            "logical": "Interfaces",
            "edge": "Edge",
        }
        for layer, label in headers.items():
            hdr = self._scene.addText(label)
            hdr.setDefaultTextColor(QColor("#455a64"))
            hf = QFont()
            hf.setBold(True)
            hf.setPointSize(10)
            hdr.setFont(hf)
            hdr.setPos(self._col_x[layer], -8)
            hdr.setZValue(0)

        def place(layer: str, node_id: str, title: str, subtitle: str, color: str, dim: bool = False) -> _TopoNode:
            node = _TopoNode(node_id, layer, title, subtitle, color, dim=dim,
                             width=self._node_w, height=self._node_h)
            node.column_x = self._col_x[layer]
            order = orders.get(layer, [])
            try:
                idx = order.index(node_id)
            except ValueError:
                idx = len(order)
            auto_y = 24 + idx * (self._node_h + self._gap_y)
            y = self._custom_y.get(f"{layer}:{node_id}", auto_y)
            node.setPos(node.column_x, y)
            node.set_locked(self._locked)
            node.moved.connect(self._on_node_moved)
            self._scene.addItem(node)
            self._nodes[f"{layer}:{node_id}"] = node
            return node

        for pid in orders["phys"]:
            # recover original case note
            note = next((n for k, n in phys.items() if k.lower() == pid), "nic")
            title = next((k for k in phys if k.lower() == pid), pid)
            place("phys", pid, title, note, KIND_COLORS["physical"])

        if not orders["phys"]:
            place("phys", "(none)", "(no NICs)", "", COLOR_MUTED, dim=True)

        for aid in orders["agg"]:
            title, subtitle, color = agg_meta[aid]
            place("agg", aid, title, subtitle, color)

        for lid in orders["logical"]:
            title, subtitle, color, dim = logical_meta[lid]
            place("logical", lid, title, subtitle, color, dim=dim)

        if orders["edge"]:
            place("edge", "internet", "Internet", "upstream / WAN", COLOR_OK)

        # Draw edges (orthogonal). Sort by source then dest Y after layout so
        # stub ordering is stable.
        def node_key(layer: str, nid: str) -> str:
            return f"{layer}:{nid}"

        for src_layer, src_id, dst_layer, dst_id, color in raw_edges:
            src = self._nodes.get(node_key(src_layer, src_id))
            dst = self._nodes.get(node_key(dst_layer, dst_id))
            if src is None or dst is None:
                continue
            edge = _TopoEdge(src, dst, color)
            self._scene.addItem(edge)
            self._edges.append(edge)

        # Nudge: if two nodes share nearly the same Y and an edge would be flat
        # across a long gap, fine — orthogonal midpoints still won't cross when
        # orders are consistent.

        tip = self._scene.addText(
            "Drag nodes vertically to edit · Auto-layout minimises crossings · Lock to freeze"
        )
        tip.setDefaultTextColor(QColor("#90a4ae"))
        tf = QFont()
        tf.setPointSize(8)
        tip.setFont(tf)
        tip.setPos(20, -28)

        bounds = self._scene.itemsBoundingRect()
        self._scene.setSceneRect(bounds.adjusted(-40, -40, 40, 40))
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
