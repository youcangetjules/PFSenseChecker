"""Topology links must not run across a card."""

from pfsense_checker.topo_route import route_edge

COLUMNS = [(16.0, 0.0, 220.0, 0.0), (320.0, 0.0, 220.0, 0.0), (624.0, 0.0, 220.0, 0.0), (928.0, 0.0, 220.0, 0.0)]


def _stack(x: float, count: int, *, top: float = 36.0, height: float = 52.0, gap: float = 26.0):
    return [(x, top + index * (height + gap), 220.0, height) for index in range(count)]


def _hits(points, rect, *, eps: float = 0.6) -> bool:
    x, y, w, h = rect
    x += eps
    y += eps
    w -= 2 * eps
    h -= 2 * eps
    if w <= 0 or h <= 0:
        return False
    for (x1, y1), (x2, y2) in zip(points, points[1:]):
        if abs(x1 - x2) < 0.1:
            if x < x1 < x + w:
                lo, hi = sorted((y1, y2))
                if hi > y and lo < y + h:
                    return True
        elif abs(y1 - y2) < 0.1:
            if y < y1 < y + h:
                lo, hi = sorted((x1, x2))
                if hi > x and lo < x + w:
                    return True
        else:
            return True
    return False


def _clear_of(points, rect, clearance: float = 3.0) -> bool:
    x, y, w, h = rect
    grown = (x - clearance, y - clearance, w + 2 * clearance, h + 2 * clearance)
    return not _hits(points, grown, eps=0.0)


def test_neighbouring_link_stays_in_the_gutter() -> None:
    phys = _stack(16, 1)
    vlans = _stack(320, 4)
    ports = _stack(624, 4)
    boxes = [phys, vlans, ports, []]
    points = route_edge(phys[0], vlans[2], COLUMNS, boxes)
    assert all(abs(a[0] - b[0]) < 0.1 or abs(a[1] - b[1]) < 0.1 for a, b in zip(points, points[1:]))
    for box in phys + vlans + ports:
        assert not _hits(points, box)
    for box in vlans:
        if box is not vlans[2]:
            assert _clear_of(points, box)


def test_skip_column_runs_straight_through_an_empty_row() -> None:
    phys = [(16.0, 36.0 + 3 * 78.0, 220.0, 52.0)]
    middle = _stack(320, 2)
    far = [(624.0, 36.0 + 3 * 78.0, 220.0, 52.0)]
    points = route_edge(phys[0], far[0], COLUMNS, [phys, middle, far, []])
    assert len(points) == 2 and abs(points[0][1] - points[1][1]) < 0.1
    for box in middle:
        assert _clear_of(points, box)


def test_lanes_split_links_in_one_gutter() -> None:
    src = _stack(16, 2)
    dst = _stack(320, 4)
    boxes = [src, dst, [], []]
    a = route_edge(src[0], dst[3], COLUMNS, boxes, lanes={0: -8.0})
    b = route_edge(src[1], dst[2], COLUMNS, boxes, lanes={0: 8.0})
    assert abs(a[1][0] - b[1][0] - (-16.0)) < 0.1


def test_skip_column_crosses_in_a_gap() -> None:
    phys = _stack(16, 1)
    vlans = _stack(320, 4)
    ports = _stack(624, 4)
    boxes = [phys, vlans, ports, []]
    points = route_edge(phys[0], ports[3], COLUMNS, boxes)
    for box in vlans:
        assert not _hits(points, box)
        assert _clear_of(points, box)
    for box in phys + ports:
        assert not _hits(points, box)


def test_packed_column_is_crossed_below_the_cards() -> None:
    phys = [(16.0, 36.0, 220.0, 52.0)]
    packed = [(320.0, 36.0, 220.0, 52.0), (320.0, 88.0, 220.0, 52.0)]
    port = [(624.0, 36.0, 220.0, 52.0)]
    points = route_edge(phys[0], port[0], COLUMNS, [phys, packed, [port], []])
    for box in packed:
        assert _clear_of(points, box, clearance=6)
    assert max(point[1] for point in points) > 88.0 + 52.0


def test_skip_from_the_top_row_does_not_run_above_the_card() -> None:
    phys = [(16.0, 36.0, 220.0, 52.0)]
    vlans = _stack(320, 3)
    port = [(624.0, 36.0, 220.0, 52.0)]
    points = route_edge(phys[0], port[0], COLUMNS, [phys, vlans, [port], []])
    top = vlans[0][1]
    left = vlans[0][0]
    right = left + vlans[0][2]
    for (x1, y1), (x2, y2) in zip(points, points[1:]):
        if abs(y1 - y2) < 0.1 and min(y1, y2) < top:
            lo, hi = sorted((x1, x2))
            assert hi <= left or lo >= right
    for box in vlans:
        assert _clear_of(points, box)


def test_same_column_link_uses_the_side_gutter() -> None:
    bridge = (320.0, 36.0, 220.0, 52.0)
    middle = (320.0, 114.0, 220.0, 52.0)
    vlan = (320.0, 192.0, 220.0, 52.0)
    points = route_edge(vlan, bridge, COLUMNS, [[], [bridge, middle, vlan], [], []])
    assert not _hits(points, middle)
    assert _clear_of(points, middle)
    assert max(point[0] for point in points) <= 320.0
    assert min(point[0] for point in points) < 320.0


def test_view_routes_around_cards_and_uses_the_width(tmp_path) -> None:
    import os
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    script = tmp_path / "topo_view_probe.py"
    script.write_text(
        "\n".join(
            [
                "import os",
                "os.environ['QT_QPA_PLATFORM'] = 'offscreen'",
                "from PySide6.QtWidgets import QApplication",
                "from pfsense_checker.models import BridgeInfo, CheckResult, InterfaceInfo, VlanInfo, VpnEndpoint",
                "from pfsense_checker.viz import TopologyView",
                "",
                "app = QApplication([])",
                "result = CheckResult()",
                "result.interfaces = [",
                "    InterfaceInfo(name='opt1', device='igb0', descr='TRUNK', enabled=True, kind='physical'),",
                "    InterfaceInfo(name='opt2', device='igb0.10', descr='CAMERAS', enabled=True, kind='vlan'),",
                "    InterfaceInfo(name='opt3', device='igb0.20', descr='GUEST', enabled=True, kind='vlan'),",
                "    InterfaceInfo(name='opt4', device='igb1', descr='DIRECT', enabled=True, kind='physical'),",
                "    InterfaceInfo(name='opt5', device='bridge0', descr='BRIDGE', enabled=True, kind='bridge'),",
                "    InterfaceInfo(name='wan', device='igb3', descr='LAST_LINE', enabled=True, ipaddr='dhcp'),",
                "    InterfaceInfo(name='opt6', device='em0', descr='SECONDARY', enabled=True, ipaddr='dhcp'),",
                "    InterfaceInfo(name='opt7', device='mce0', descr='FIB_MAIN', enabled=True, ipaddr='dhcp'),",
                "    InterfaceInfo(name='opt8', device='ovpnc1', descr='3_EVL1_A', enabled=True, kind='openvpn'),",
                "    InterfaceInfo(name='opt9', device='ovpnc2', descr='3_EVL2_B', enabled=True, kind='openvpn'),",
                "    InterfaceInfo(name='opt10', device='ovpnc3', descr='3_EVL3_C', enabled=True, kind='openvpn'),",
                "]",
                "result.gateways = [{'name': 'G1', 'interface': 'opt6'}, {'name': 'G2', 'interface': 'opt7'}]",
                "result.gateway_groups = [{'name': 'FailoverGW', 'members': ['G1', 'G2']}]",
                "result.vpn = [VpnEndpoint(kind='openvpn-client', name=f'V{i}', interface='FailoverGW', vpnid=str(i)) for i in (1, 2, 3)]",
                "result.vlans = [",
                "    VlanInfo(tag='10', if_parent='igb0', vlanif='igb0.10', descr='CAMERAS'),",
                "    VlanInfo(tag='20', if_parent='igb0', vlanif='igb0.20', descr='GUEST'),",
                "]",
                "result.bridges = [BridgeInfo(bridgeif='bridge0', members=['igb0.10'])]",
                "view = TopologyView()",
                "view.resize(1400, 820)",
                "view.show()",
                "app.processEvents()",
                "view.render_topology(result)",
                "last = view._layers[-1]",
                "spread = view._col_x[last] + view._col_w[last]",
                "assert spread < 1400, (spread, dict(view._col_w))",
                "assert view._col_w['phys'] <= view._col_w['port'], dict(view._col_w)",
                "assert min(view._col_w.values()) >= 120 and view._gutter >= 72",
                "assert view._layers == ['ext', 'gw', 'phys', 'port', 'vlan', 'bridge'], view._layers",
                "xs = [view._col_x[name] for name in view._layers]",
                "assert xs == sorted(xs), xs",
                "",
                "def hits(points, rect):",
                "    x, y, w, h = rect",
                "    x, y, w, h = x + 1, y + 1, w - 2, h - 2",
                "    for (x1, y1), (x2, y2) in zip(points, points[1:]):",
                "        ortho = abs(x1 - x2) < 0.1 or abs(y1 - y2) < 0.1",
                "        assert ortho, (x1, y1, x2, y2)",
                "        if abs(x1 - x2) < 0.1 and x < x1 < x + w:",
                "            lo, hi = sorted((y1, y2))",
                "            if hi > y and lo < y + h:",
                "                return True",
                "        if abs(y1 - y2) < 0.1 and y < y1 < y + h:",
                "            lo, hi = sorted((x1, x2))",
                "            if hi > x and lo < x + w:",
                "                return True",
                "    return False",
                "",
                "assert view._edges",
                "view.resize(1800, 980)",
                "app.processEvents()",
                "assert view._col_x[last] + view._col_w[last] == spread, dict(view._col_x)",
                "frame = view._chassis_item.rect()",
                "for node in view._nodes.values():",
                "    if node.layer == 'phys':",
                "        assert frame.left() < node.pos().x() and node.pos().x() + node.w < frame.right()",
                "        assert frame.top() < node.pos().y() and node.pos().y() + node.h < frame.bottom()",
                "",
                "def touches(point, node):",
                "    x, y = point",
                "    left, right = node.pos().x(), node.pos().x() + node.w",
                "    mid = node.pos().y() + node.h / 2",
                "    on_side = abs(x - left) < 0.5 or abs(x - right) < 0.5",
                "    if node.row_span > 1:",
                "        return on_side and node.pos().y() < y < node.pos().y() + node.h",
                "    return abs(y - mid) < 0.5 and on_side",
                "",
                "for edge in view._edges:",
                "    path = edge.path()",
                "    points = [(path.elementAt(i).x, path.elementAt(i).y) for i in range(path.elementCount())]",
                "    assert touches(points[0], edge.src), (edge.src.node_id, points[0])",
                "    assert touches(points[-1], edge.dst), (edge.dst.node_id, points[-1])",
                "    for node in view._nodes.values():",
                "        rect = (node.pos().x(), node.pos().y(), node.w, node.h)",
                "        assert not hits(points, rect), (edge.src.node_id, edge.dst.node_id, node.node_id, points)",
                "",
                "def segs(edge):",
                "    path = edge.path()",
                "    pts = [(path.elementAt(i).x, path.elementAt(i).y) for i in range(path.elementCount())]",
                "    return list(zip(pts, pts[1:]))",
                "",
                "def crosses(s, t):",
                "    for h, v in ((s, t), (t, s)):",
                "        (hx1, hy1), (hx2, hy2) = h",
                "        (vx1, vy1), (vx2, vy2) = v",
                "        if abs(hy1 - hy2) < 0.1 and abs(vx1 - vx2) < 0.1:",
                "            lo_x, hi_x = sorted((hx1, hx2))",
                "            lo_y, hi_y = sorted((vy1, vy2))",
                "            if lo_x + 0.5 < vx1 < hi_x - 0.5 and lo_y + 0.5 < hy1 < hi_y - 0.5:",
                "                return True",
                "    return False",
                "",
                "edges = view._edges",
                "bad = [",
                "    (a.src.node_id, a.dst.node_id, b.src.node_id, b.dst.node_id)",
                "    for i, a in enumerate(edges) for b in edges[i + 1:]",
                "    if any(crosses(s, t) for s in segs(a) for t in segs(b))",
                "]",
                "assert not bad, bad",
                "print('ok', len(view._edges), round(spread, 1))",
            ]
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root) + os.pathsep + env.get("PYTHONPATH", "")
    env["QT_QPA_PLATFORM"] = "offscreen"
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        check=False,
        cwd=root,
        env=env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
