"""Topology auto-arrange with ELK (Eclipse Layout Kernel, "layered" algorithm).

ELK is built for diagrams of boxes with ports on their edges joined by
square-cornered cables. We run the vendored ``elk.bundled.js`` (elkjs 0.12.1,
EPL-2.0, see vendor/elk/README.md) inside Qt's own JavaScript engine, so no
Node.js is needed at run time.

The graph: one ELK node per device (its real box size), one ELK port per cable
end at the x of the port it leaves from — on the top edge when the cable goes
up to an upstream device, on the bottom edge when it goes down. Cables are
directed upstream → downstream (a cable into a port the device uses as an
uplink comes from above; otherwise firewalls / routers above switches above
access points), so layers run top-down. Result: device positions and an
orthogonal route per cable. (added 2026-11-15)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

ELK_JS = Path(__file__).resolve().parent / "vendor" / "elk" / "elk.bundled.js"
MAX_ROUNDS = 400

LAYOUT_OPTIONS = {
    "elk.algorithm": "layered",
    "elk.direction": "DOWN",
    "elk.edgeRouting": "ORTHOGONAL",
    "elk.spacing.nodeNode": "70",
    "elk.layered.spacing.nodeNodeBetweenLayers": "110",
    "elk.spacing.edgeEdge": "12",
    "elk.layered.spacing.edgeEdgeBetweenLayers": "12",
    # Balanced placement: wide boxes stay roughly centred over what they feed
    # instead of sliding sideways to make one cable perfectly straight.
    "elk.layered.nodePlacement.strategy": "BRANDES_KOEPF",
    "elk.layered.nodePlacement.bk.fixedAlignment": "BALANCED",
    "elk.layered.crossingMinimization.strategy": "LAYER_SWEEP",
    "elk.separateConnectedComponents": "true",
    "elk.spacing.componentComponent": "90",
    "elk.padding": "[top=20,left=20,bottom=20,right=20]",
}

# Kinds that sit at the top when nothing else says which way a cable runs.
_UPPER_KINDS = {"pfsense": 2, "opnsense": 2, "fortinet": 2, "juniper": 2}


class ElkUnavailable(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# The engine


class ElkEngine:
    """elk.bundled.js loaded once into a QJSEngine (needs a Q(Core)Application)."""

    _instance: "ElkEngine | None" = None

    def __init__(self) -> None:
        from PySide6.QtQml import QJSEngine

        if not ELK_JS.is_file():
            raise ElkUnavailable(f"ELK is missing: {ELK_JS}")
        self.js = QJSEngine()
        self.js.installExtensions(QJSEngine.Extension.ConsoleExtension)  # ELK logs to console
        # elkjs's in-process worker schedules with setTimeout; QJSEngine has none,
        # so queue the callbacks and run them from Python.
        self.js.evaluate(
            "var __timers = []; function setTimeout(f, ms) { __timers.push(f); return __timers.length; }"
            " function clearTimeout(id) {} var self = this;"
        )
        res = self.js.evaluate(ELK_JS.read_text(encoding="utf-8"), "elk.bundled.js")
        if res.isError() or self.js.evaluate("typeof ELK").toString() != "function":
            raise ElkUnavailable(f"ELK did not load: {res.toString()}")
        made = self.js.evaluate("var __elk = new ELK(); typeof __elk")
        if made.isError() or made.toString() != "object":
            raise ElkUnavailable(f"ELK did not start: {made.toString()}")

    @classmethod
    def get(cls) -> "ElkEngine":
        if cls._instance is None:
            cls._instance = ElkEngine()
        return cls._instance

    def layout(self, graph: dict) -> dict:
        """Run ELK on *graph* (ELK JSON) and return the laid-out graph."""
        self.js.globalObject().setProperty("__in", json.dumps(graph))
        res = self.js.evaluate(
            "var __out = null, __err = null;"
            " __elk.layout(JSON.parse(__in)).then(function (g) { __out = JSON.stringify(g); },"
            " function (e) { __err = String(e && e.message || e); }); 0"
        )
        if res.isError():
            raise RuntimeError(res.toString())
        from PySide6.QtCore import QCoreApplication

        for _ in range(MAX_ROUNDS):
            self.js.evaluate("var __t = __timers; __timers = []; for (var i = 0; i < __t.length; i++) __t[i]();")
            QCoreApplication.processEvents()  # promise callbacks run from the event loop
            if self.js.evaluate("__out !== null || __err !== null").toBool():
                break
        err = self.js.evaluate("__err")
        if not err.isNull():
            raise RuntimeError(f"ELK: {err.toString()}")
        out = self.js.evaluate("__out")
        if out.isNull():
            raise RuntimeError("ELK did not finish")
        return json.loads(out.toString())


def available() -> bool:
    return ELK_JS.is_file()


# --------------------------------------------------------------------------- #
# Building the graph


@dataclass
class BoxInfo:
    """What the canvas knows about one device box."""

    name: str
    width: float
    height: float
    tier: int = 4
    ports: dict[str, float] = field(default_factory=dict)  # port → x of its middle in the box
    vlan_x: dict[tuple[str, str], float] = field(default_factory=dict)  # (port, vid) → x of the stripe
    uplinks: set[str] = field(default_factory=set)


@dataclass
class CableInfo:
    index: int  # position in site.links
    a: str
    a_port: str
    b: str
    b_port: str
    vid: str = ""


@dataclass
class Arrangement:
    positions: dict[str, tuple[float, float]]  # device → top-left
    routes: dict[int, list[tuple[float, float]]]  # link index → points from a's end to b's end


def tier_of(kind: str, role_tier: int) -> int:
    return min(role_tier, _UPPER_KINDS.get((kind or "").lower(), role_tier))


def _orient(c: CableInfo, boxes: dict[str, BoxInfo], degree: dict[str, int]) -> bool:
    """True when the cable runs a → b (a upstream of b): an uplink port points up;
    otherwise the higher tier (firewall over switch over access point); otherwise
    the better-connected device (a core switch over the things hanging off it)."""
    a, b = boxes[c.a], boxes[c.b]
    if c.b_port in b.uplinks and c.a_port not in a.uplinks:
        return True
    if c.a_port in a.uplinks and c.b_port not in b.uplinks:
        return False
    if a.tier != b.tier:
        return a.tier < b.tier
    if degree.get(c.a, 0) != degree.get(c.b, 0):
        return degree.get(c.a, 0) > degree.get(c.b, 0)
    return c.a <= c.b


def _port_x(box: BoxInfo, port: str, vid: str) -> float:
    if vid and (port, vid) in box.vlan_x:
        return box.vlan_x[(port, vid)]
    return box.ports.get(port, box.width / 2)


def build_graph(boxes: dict[str, BoxInfo], cables: list[CableInfo]) -> tuple[dict, dict[str, tuple[int, bool]]]:
    """ELK JSON for the boxes and cables, plus edge id → (link index, a→b?)."""
    nodes: dict[str, dict] = {}
    for name, box in boxes.items():
        nodes[name] = {
            "id": f"n:{name}",
            "width": round(box.width, 1),
            "height": round(box.height, 1),
            "ports": [],
            "layoutOptions": {"elk.portConstraints": "FIXED_POS"},
        }
    edges = []
    edge_map: dict[str, tuple[int, bool]] = {}
    degree: dict[str, int] = {}
    for c in cables:
        if c.a != c.b and c.a in boxes and c.b in boxes:
            degree[c.a] = degree.get(c.a, 0) + 1
            degree[c.b] = degree.get(c.b, 0) + 1
    for c in cables:
        if c.a not in boxes or c.b not in boxes or c.a == c.b:
            continue
        forward = _orient(c, boxes, degree)
        up, up_port, down, down_port = (c.a, c.a_port, c.b, c.b_port) if forward else (c.b, c.b_port, c.a, c.a_port)
        src = f"p:{c.index}:s"
        dst = f"p:{c.index}:t"
        nodes[up]["ports"].append({"id": src, "width": 1, "height": 1,
                                   "x": round(_port_x(boxes[up], up_port, c.vid), 1),
                                   "y": round(boxes[up].height, 1),
                                   "layoutOptions": {"elk.port.side": "SOUTH"}})
        nodes[down]["ports"].append({"id": dst, "width": 1, "height": 1,
                                     "x": round(_port_x(boxes[down], down_port, c.vid), 1), "y": -1,
                                     "layoutOptions": {"elk.port.side": "NORTH"}})
        eid = f"e:{c.index}"
        edges.append({"id": eid, "sources": [src], "targets": [dst]})
        edge_map[eid] = (c.index, forward)
    graph = {"id": "root", "layoutOptions": dict(LAYOUT_OPTIONS), "children": list(nodes.values()), "edges": edges}
    return graph, edge_map


def read_result(result: dict, edge_map: dict[str, tuple[int, bool]],
                origin: tuple[float, float] = (0.0, 0.0)) -> Arrangement:
    """Device top-left corners and cable routes, moved so the layout starts at *origin*."""
    raw = {str(c["id"])[2:]: (float(c.get("x", 0)), float(c.get("y", 0))) for c in result.get("children", [])}
    # ELK can hand back negative coordinates: start the layout exactly at *origin*.
    min_x = min((x for x, _y in raw.values()), default=0.0)
    min_y = min((y for _x, y in raw.values()), default=0.0)
    ox, oy = origin[0] - min_x, origin[1] - min_y
    positions = {name: (ox + x, oy + y) for name, (x, y) in raw.items()}
    routes: dict[int, list[tuple[float, float]]] = {}
    for edge in result.get("edges", []):
        idx, forward = edge_map.get(edge.get("id"), (None, True))
        if idx is None or not edge.get("sections"):
            continue
        sec = edge["sections"][0]
        pts = [sec["startPoint"], *sec.get("bendPoints", []), sec["endPoint"]]
        line = [(ox + float(p["x"]), oy + float(p["y"])) for p in pts]
        routes[idx] = line if forward else list(reversed(line))
    return Arrangement(positions, routes)


def arrange(boxes: dict[str, BoxInfo], cables: list[CableInfo],
            origin: tuple[float, float] = (40.0, 40.0)) -> Arrangement:
    graph, edge_map = build_graph(boxes, cables)
    return read_result(ElkEngine.get().layout(graph), edge_map, origin)
