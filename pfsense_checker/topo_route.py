"""Orthogonal routes that stay off the topology cards.

A link between neighbouring columns uses the gutter between them.
A link that skips a column crosses that column in a gap between cards,
or below the column when the cards are packed. It does not run across
the top of a card.
"""

from __future__ import annotations

Rect = tuple[float, float, float, float]
Point = tuple[float, float]


def route_edge(
    src: Rect,
    dst: Rect,
    columns: list[Rect],
    boxes_by_column: list[list[Rect]],
    *,
    pad: float = 8.0,
    lanes: dict[int, float] | None = None,
    flat_dst: bool = False,
) -> list[Point]:
    """Return elbow points from ``src`` to ``dst``. ``columns`` are ``(x, y, w, h)`` with ``y`` ignored; only ``x`` and ``w`` matter. Pass ``(x, 0, w, 0)``.

    ``lanes`` shifts the vertical run in gutter ``i`` (between column ``i`` and
    ``i + 1``) so links from different cards do not share one line.
    ``flat_dst`` lets a link enter a tall card level with its source, so links
    from several rows reach it as straight lines.
    """
    shift = lanes or {}
    if not columns:
        return _simplify([_center_right(src), _center_left(dst)])
    src_col = _column_index(src[0], columns)
    dst_col = _column_index(dst[0], columns)
    if src_col == dst_col:
        return _route_same_column(src, dst, columns, src_col, shift)

    step = 1 if dst_col > src_col else -1
    start = _center_right(src) if step > 0 else _center_left(src)
    if flat_dst and dst[1] + pad <= start[1] <= dst[1] + dst[3] - pad:
        dst = (dst[0], start[1] - dst[3] / 2, dst[2], dst[3])
    points: list[Point] = [start]
    y = start[1]
    col = src_col
    while col != dst_col:
        nxt = col + step
        gutter = min(col, nxt)
        gx = _gutter_between(columns, gutter) + shift.get(gutter, 0.0)
        points.append((gx, y))
        if nxt == dst_col:
            end = _center_left(dst) if step > 0 else _center_right(dst)
            points.append((gx, end[1]))
            points.append(end)
            break
        end_y = (_center_left(dst) if step > 0 else _center_right(dst))[1]
        gap = clear_y(_boxes(boxes_by_column, nxt), (y + end_y) / 2, pad)
        points.append((gx, gap))
        far = nxt + step
        gx2 = _gutter_between(columns, min(nxt, far)) + shift.get(min(nxt, far), 0.0)
        points.append((gx2, gap))
        y = gap
        col = nxt
    return _simplify(points)


def clear_y(boxes: list[Rect], prefer: float, pad: float) -> float:
    """A horizontal channel that misses every box, nearest to ``prefer``."""
    if not boxes:
        return prefer
    blocked: list[list[float]] = []
    for _x, y, _w, h in boxes:
        blocked.append([y - pad, y + h + pad])
    blocked.sort()
    merged: list[list[float]] = []
    for start, end in blocked:
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)

    if not any(start <= prefer <= end for start, end in merged):
        return prefer
    candidates: list[tuple[float, int, float]] = []
    for index in range(len(merged) - 1):
        opening = merged[index + 1][0] - merged[index][1]
        if opening >= 6:
            gap = (merged[index][1] + merged[index + 1][0]) / 2
            candidates.append((abs(gap - prefer), 0, gap))
    # Below the column. A channel above the first card reads as a line
    # across the top of that card, which is what the diagram must not do.
    below = merged[-1][1] + 2
    candidates.append((abs(below - prefer), 1, below))
    candidates.sort()
    return candidates[0][2]


def same_column_gutter(index: int, last: int) -> int:
    """The gutter a link between two cards of column ``index`` runs in.

    The last column uses the free space on its right (gutter ``last``), so a
    bridge link does not cut across the links coming into that column.
    """
    if index == last:
        return last
    return index - 1 if index > 0 else index


def _route_same_column(
    src: Rect, dst: Rect, columns: list[Rect], index: int, shift: dict[int, float]
) -> list[Point]:
    last = len(columns) - 1
    offset = shift.get(same_column_gutter(index, last), 0.0)
    if index == last:
        gx = columns[index][0] + columns[index][2] + 28 + offset
        start = _center_right(src)
        end = _center_right(dst)
    elif index > 0:
        gx = _gutter_between(columns, index - 1) + offset
        start = _center_left(src)
        end = _center_left(dst)
    else:
        gx = _gutter_after(columns, index) + offset
        start = _center_right(src)
        end = _center_right(dst)
    return _simplify([start, (gx, start[1]), (gx, end[1]), end])


def _center_right(rect: Rect) -> Point:
    x, y, w, h = rect
    return (x + w, y + h / 2)


def _center_left(rect: Rect) -> Point:
    x, y, _w, h = rect
    return (x, y + h / 2)


def _column_index(x: float, columns: list[Rect]) -> int:
    for index, (cx, _y, _w, _h) in enumerate(columns):
        if abs(x - cx) <= 2:
            return index
    return min(range(len(columns)), key=lambda index: abs(columns[index][0] - x))


def _gutter_between(columns: list[Rect], left_index: int) -> float:
    left = columns[left_index]
    right = columns[left_index + 1]
    left_edge = left[0] + left[2]
    return (left_edge + right[0]) / 2


def _gutter_after(columns: list[Rect], index: int) -> float:
    if index + 1 < len(columns):
        return _gutter_between(columns, index)
    col = columns[index]
    return col[0] + col[2] + 40


def _boxes(boxes_by_column: list[list[Rect]], index: int) -> list[Rect]:
    if 0 <= index < len(boxes_by_column):
        return boxes_by_column[index]
    return []


def _simplify(points: list[Point]) -> list[Point]:
    out: list[Point] = []
    for point in points:
        if out and abs(point[0] - out[-1][0]) < 0.1 and abs(point[1] - out[-1][1]) < 0.1:
            continue
        out.append(point)
    index = 1
    while index < len(out) - 1:
        prev, cur, nxt = out[index - 1], out[index], out[index + 1]
        same_x = abs(prev[0] - cur[0]) < 0.1 and abs(cur[0] - nxt[0]) < 0.1
        same_y = abs(prev[1] - cur[1]) < 0.1 and abs(cur[1] - nxt[1]) < 0.1
        if same_x or same_y:
            del out[index]
        else:
            index += 1
    return out
