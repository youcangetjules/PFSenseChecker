"""Animated NetCheck splash screen.

Renders A-Netcheck.svg on a white background and slides the three faint
rainbow bars behind the wordmark into place:

  * top bar    -> slides in from the left
  * middle bar -> slides in from the right
  * lower bar  -> slides in from the left

The solid bars, the A mark, and the word stay in place. Falls back to a
static render if the SVG can't be parsed into layers.
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from pathlib import Path

from PySide6.QtCore import QByteArray, QEasingCurve, QPointF, QRectF, Qt, QVariantAnimation
from PySide6.QtGui import QColor, QFont, QFontDatabase, QFontMetricsF, QPainter, QPainterPath
from PySide6.QtWidgets import QWidget

try:  # LOGO path lives in branding
    from pfsense_checker.branding import LOGO_SVG
except Exception:  # noqa: BLE001
    LOGO_SVG = Path(__file__).resolve().parent.parent / "A-Netcheck.svg"

_SVG_NS = "http://www.w3.org/2000/svg"

# Native page size of A-Netcheck.svg (updated when the file is prepared).
_VIEWBOX_W = 961.51826
_VIEWBOX_H = 277.40202

# Opening animation — previously 900ms.
ANIM_DURATION_MS = 2400

# The three faint gradient bars behind the word, top -> bottom.
_BAR_TOP = "path1-4-5-9"
_BAR_MID = "path1-4"
_BAR_LOW = "path1-4-5"
_SLIDING_BARS = (_BAR_TOP, _BAR_MID, _BAR_LOW)

# 1px light-grey box injected around the viewBox at prepare time, so
# Inkscape re-saves of A-Netcheck.svg cannot lose it.
_FRAME_ID = "logo-frame"
_FRAME_COLOR = "#cccccc"

# A mark + construction / dimension lines (stay behind the sliding bars).
_BACK_IDS = (
    "text4179-7",
    "g6",
    "g6-5",
    "path3",
    "path3-1",
    "path3-2",
    "path3-2-9",
    "path3-2-9-1",
    "path4",
    "path5",
    "path6",
    "path7",
    "path8",
    "path10",
    "path10-2",
    "path10-9",
    "path10-9-7",
    "path10-9-7-2",
    "path10-2-5",
    "path10-2-5-3",
    "path10-2-5-3-2",
    "path10-2-5-3-2-1",
    "path10-2-5-3-2-1-5",
)

# aliniant labs wordmark, i-halos, solid rainbow rules, outlined netcheck,
# baked copyright line, and the injected outer frame (drawn last so the
# bars slide beneath them).
_FRONT_IDS = (
    "text2",
    "path1",
    "path1-2",
    "path5053-0-6-8-5-4-0-3-4-0-4",
    "path5053-0-6-8-5-4-0-3-4-0-4-2",
    "netcheck-word",
    _FRAME_ID,
    "copyright-note",
)
# text1/tspan1 + text3: Qt cannot fill live <text>; we replace them with
# outlined paths. The rest are Inkscape working copies of the A scaffolding
# parked below the page — Qt paints outside the viewBox, so drop them.
_HIDE_IDS = (
    "text1",
    "tspan1",
    "text3",
    "text4179-7-5",
    "g1",
    "g2-4",
)
_NETCHECK_PATH_ID = "netcheck-word"
_NETCHECK_BAKED = False

# "© 2026 Aliniant Laboratories" lives in the SVG as Montserrat <text>
# (id text3) just below the page. Bake it to an outline and grow the
# prepared page so it shows, as in the Inkscape original.
_COPYRIGHT_SRC_ID = "text3"
_COPYRIGHT_ID = "copyright-note"
_COPYRIGHT_TEXT = "© 2026 Aliniant Laboratories"
# SVG x/y 99.611816 / 380.45047 after layer1 translate(-87.46,-88.14).
_COPYRIGHT_X = 12.148
_COPYRIGHT_BASELINE = 292.314
_COPYRIGHT_PIXEL_SIZE = 17

# Bottom horizontal stubs: arrow at the far end only — each pair of stubs
# converges on one leg of the A, like the Inkscape original.
_DIM_END_IDS = (
    "path10",
    "path10-2",
    "path10-9",
    "path10-2-5",
)
# Vertical gauges between the horizontal guides: arrows at both ends.
_DIM_BOTH_IDS = (
    "path10-2-5-3",
    "path10-2-5-3-2",
    "path10-2-5-3-2-1",
    "path10-2-5-3-2-1-5",
)
# Arc arrowhead stubs by the swoosh: small arrow at the far end only.
_POINTER_PATH_IDS = (
    "path10-9-7",
    "path10-9-7-2",
)


# "netcheck" lives in the SVG as <text id="text1"> but Qt's SVG renderer
# draws empty boxes instead of glyphs. Paint it in viewBox space instead.
# Layer-local x 371.94 after layer1 translate(-87.46,-88.14).
_NETCHECK_X = 284.48
_NETCHECK_COLOR = QColor("#5a5a5a")
# Solid rainbow rules (path1-2 top, path1 bottom) in viewBox Y after layer translate.
_BANNER_TOP_Y = 107.90
_BANNER_BOT_Y = 262.25
_BANNER_STROKE = 16.97
_NETCHECK_FONT_FAMILY = ""


def _ensure_netcheck_font() -> str:
    """Load a real TTF so Qt does not draw empty glyph boxes."""
    global _NETCHECK_FONT_FAMILY
    if _NETCHECK_FONT_FAMILY:
        return _NETCHECK_FONT_FAMILY
    windir = os.environ.get("WINDIR", r"C:\Windows")
    for name in ("arial.ttf", "segoeui.ttf", "calibri.ttf", "tahoma.ttf"):
        path = os.path.join(windir, "Fonts", name)
        if not os.path.isfile(path):
            continue
        font_id = QFontDatabase.addApplicationFont(path)
        if font_id == -1:
            continue
        families = QFontDatabase.applicationFontFamilies(font_id)
        if families:
            _NETCHECK_FONT_FAMILY = families[0]
            return _NETCHECK_FONT_FAMILY
    _NETCHECK_FONT_FAMILY = "Arial"
    return _NETCHECK_FONT_FAMILY


def _netcheck_font(pixel_size: int) -> QFont:
    font = QFont(_ensure_netcheck_font())
    font.setWeight(QFont.Weight.Normal)
    font.setHintingPreference(QFont.HintingPreference.PreferFullHinting)
    font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, -2.68125)
    font.setPixelSize(max(8, int(pixel_size)))
    return font


def _netcheck_layout(scale_x: float = 1.0, scale_y: float = 1.0) -> tuple[QFont, float, float]:
    """Return font + baseline origin for 'netcheck' inside the banner gap."""
    inner_top = _BANNER_TOP_Y + _BANNER_STROKE / 2.0
    inner_bot = _BANNER_BOT_Y - _BANNER_STROKE / 2.0
    pad = 8.0
    gap_vb = max(8.0, inner_bot - inner_top - 2.0 * pad)
    gap_px = gap_vb * scale_y
    pixel = max(8, int(gap_px / 0.78))
    font = _netcheck_font(pixel)
    metrics = QFontMetricsF(font)
    box = metrics.tightBoundingRect("netcheck")
    while box.height() > gap_px and pixel > 8:
        pixel -= 1
        font.setPixelSize(pixel)
        metrics = QFontMetricsF(font)
        box = metrics.tightBoundingRect("netcheck")
    x = _NETCHECK_X * scale_x
    band_top = (inner_top + pad) * scale_y
    baseline = band_top + (gap_px - box.height()) / 2.0 - box.top()
    return font, x, baseline


def _painter_path_to_svg_d(path: QPainterPath) -> str:
    parts: list[str] = []
    i = 0
    n = path.elementCount()
    move = QPainterPath.ElementType.MoveToElement
    line = QPainterPath.ElementType.LineToElement
    curve = QPainterPath.ElementType.CurveToElement
    while i < n:
        el = path.elementAt(i)
        if el.type == move:
            parts.append(f"M{el.x:.3f},{el.y:.3f}")
            i += 1
        elif el.type == line:
            parts.append(f"L{el.x:.3f},{el.y:.3f}")
            i += 1
        elif el.type == curve and i + 2 < n:
            c2 = path.elementAt(i + 1)
            c3 = path.elementAt(i + 2)
            parts.append(
                f"C{el.x:.3f},{el.y:.3f} {c2.x:.3f},{c2.y:.3f} {c3.x:.3f},{c3.y:.3f}"
            )
            i += 3
        else:
            i += 1
    return " ".join(parts)


def _inject_netcheck_outline(root: ET.Element) -> bool:
    """Replace live SVG <text> with an outlined path Qt can actually fill."""
    global _NETCHECK_BAKED
    from PySide6.QtWidgets import QApplication

    if QApplication.instance() is None:
        return False
    font, x, baseline = _netcheck_layout()
    path = QPainterPath()
    path.addText(QPointF(x, baseline), font, "netcheck")
    if path.isEmpty():
        return False
    d = _painter_path_to_svg_d(path)
    if not d:
        return False
    ns = f"{{{_SVG_NS}}}"
    el = ET.Element(f"{ns}path")
    el.set("id", _NETCHECK_PATH_ID)
    el.set("d", d)
    el.set("fill", _NETCHECK_COLOR.name())
    el.set("stroke", "none")
    el.set("fill-opacity", "1")
    root.append(el)
    _NETCHECK_BAKED = True
    return True


def _copyright_font() -> QFont:
    from PySide6.QtGui import QFontInfo

    font = QFont("Montserrat")
    font.setWeight(QFont.Weight.DemiBold)
    font.setPixelSize(_COPYRIGHT_PIXEL_SIZE)
    font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, -0.51)
    if QFontInfo(font).family().lower().startswith("montserrat"):
        return font
    fallback = QFont(_ensure_netcheck_font())
    fallback.setWeight(QFont.Weight.DemiBold)
    fallback.setPixelSize(_COPYRIGHT_PIXEL_SIZE)
    fallback.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, -0.51)
    return fallback


def _inject_copyright_outline(root: ET.Element) -> bool:
    """Replace the live Montserrat copyright <text> with an outlined path."""
    from PySide6.QtWidgets import QApplication

    if QApplication.instance() is None:
        return False
    path = QPainterPath()
    path.addText(
        QPointF(_COPYRIGHT_X, _COPYRIGHT_BASELINE), _copyright_font(), _COPYRIGHT_TEXT
    )
    if path.isEmpty():
        return False
    d = _painter_path_to_svg_d(path)
    if not d:
        return False
    ns = f"{{{_SVG_NS}}}"
    el = ET.Element(f"{ns}path")
    el.set("id", _COPYRIGHT_ID)
    el.set("d", d)
    el.set("fill", "#000000")
    el.set("fill-opacity", "0.57")
    el.set("stroke", "none")
    root.append(el)
    return True


def paint_netcheck_word(painter: QPainter, target: QRectF) -> None:
    """Draw regular-weight 'netcheck' inside the gap between the banner bars."""
    if _NETCHECK_BAKED:
        return
    if target.width() <= 0 or target.height() <= 0:
        return
    sx = target.width() / _VIEWBOX_W
    sy = target.height() / _VIEWBOX_H
    font, x, baseline = _netcheck_layout(sx, sy)
    painter.save()
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(_NETCHECK_COLOR)
    path = QPainterPath()
    path.addText(QPointF(target.x() + x, target.y() + baseline), font, "netcheck")
    painter.fillPath(path, _NETCHECK_COLOR)
    painter.restore()


def _register_namespaces() -> None:
    ET.register_namespace("", _SVG_NS)
    ET.register_namespace("xlink", "http://www.w3.org/1999/xlink")
    ET.register_namespace("inkscape", "http://www.inkscape.org/namespaces/inkscape")
    ET.register_namespace("sodipodi", "http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd")
    ET.register_namespace("rdf", "http://www.w3.org/1999/02/22-rdf-syntax-ns#")
    ET.register_namespace("cc", "http://creativecommons.org/ns#")
    ET.register_namespace("dc", "http://purl.org/dc/elements/1.1/")


def _remove_ids(root: ET.Element, ids: set[str]) -> None:
    """Remove every element whose id is in *ids* (searches the whole tree)."""
    parents = {child: parent for parent in root.iter() for child in parent}
    for el in list(root.iter()):
        if el.attrib.get("id") in ids:
            parent = parents.get(el)
            if parent is not None:
                parent.remove(el)


def _read_viewbox(root: ET.Element) -> tuple[float, float]:
    raw = (root.get("viewBox") or "").replace(",", " ").split()
    if len(raw) >= 4:
        return float(raw[2]), float(raw[3])
    return _VIEWBOX_W, _VIEWBOX_H


def _set_module_viewbox(width: float, height: float) -> None:
    global _VIEWBOX_W, _VIEWBOX_H
    if width > 1 and height > 1:
        _VIEWBOX_W = float(width)
        _VIEWBOX_H = float(height)


def _ensure_qt_arrow_markers(root: ET.Element) -> None:
    """Inkscape markers use context-stroke + auto-start-reverse; Qt draws them wrong."""
    defs = None
    for el in root.iter():
        if el.tag.split("}")[-1] == "defs":
            defs = el
            break
    if defs is None:
        return
    ns = f"{{{_SVG_NS}}}"
    existing = {el.get("id") for el in defs}
    # Inkscape's "Concave triangle" arrow. Sizes reproduce the original
    # markerUnits=strokeWidth scaling (markerWidth 3 x stroke 0.53 / 0.41).
    concave = "M -2,-4 9,0 -2,4 c 2,-2.33 2,-5.66 0,-8 z"
    specs = (
        # id, flip-x, viewBox, markerWidth, markerHeight
        ("nc-arrow-fwd", False, "-2 -4 11 8", "12.2", "8.9"),
        ("nc-arrow-rev", True, "-9 -4 11 8", "12.2", "8.9"),
        ("nc-arrow-fwd-sm", False, "-2 -4 11 8", "9.6", "7.0"),
    )
    if all(mid in existing for mid, _, _, _, _ in specs):
        return
    for mid, flip, viewbox, mw, mh in specs:
        if mid in existing:
            continue
        marker = ET.SubElement(defs, f"{ns}marker")
        marker.set("id", mid)
        marker.set("markerUnits", "userSpaceOnUse")
        marker.set("markerWidth", mw)
        marker.set("markerHeight", mh)
        marker.set("refX", "0")
        marker.set("refY", "0")
        marker.set("orient", "auto")
        marker.set("overflow", "visible")
        marker.set("viewBox", viewbox)
        path = ET.SubElement(marker, f"{ns}path")
        path.set("d", concave)
        if flip:
            path.set("transform", "scale(-1,1)")
        path.set("fill", "#666666")
        path.set("stroke", "none")


def _fix_dimension_arrows(root: ET.Element) -> None:
    """Replace Inkscape marker-mid arrows with start/end arrows Qt can render."""
    _ensure_qt_arrow_markers(root)
    for el in root.iter():
        el_id = el.get("id")
        if el_id in _DIM_END_IDS:
            el.set(
                "style",
                "fill:none;stroke:#666666;stroke-width:0.53;stroke-linecap:butt;"
                "marker-end:url(#nc-arrow-fwd)",
            )
        elif el_id in _DIM_BOTH_IDS:
            el.set(
                "style",
                "fill:none;stroke:#666666;stroke-width:0.53;stroke-linecap:butt;"
                "marker-start:url(#nc-arrow-rev);marker-end:url(#nc-arrow-fwd)",
            )
        elif el_id in _POINTER_PATH_IDS:
            el.set(
                "style",
                "opacity:0.57;fill:none;stroke:#666666;stroke-width:0.41;"
                "stroke-linecap:butt;marker-end:url(#nc-arrow-fwd-sm)",
            )


def _prepare_page(root: ET.Element) -> tuple[float, float]:
    """Keep the SVG's native proportions; drop fixed mm size so Qt follows viewBox."""
    width, height = _read_viewbox(root)
    if any(el.get("id") == _COPYRIGHT_SRC_ID for el in root.iter()):
        # Grow the page so the copyright line below the logo is visible.
        height = max(height, _COPYRIGHT_BASELINE + 6.0)
        root.set("viewBox", f"0 0 {width} {height}")
    root.set("overflow", "hidden")
    if "width" in root.attrib:
        del root.attrib["width"]
    if "height" in root.attrib:
        del root.attrib["height"]
    ns = f"{{{_SVG_NS}}}"
    spacer = ET.Element(f"{ns}rect")
    spacer.set("x", "0")
    spacer.set("y", "0")
    spacer.set("width", str(width))
    spacer.set("height", str(height))
    spacer.set("fill", "none")
    spacer.set("stroke", "none")
    spacer.set("id", "netcheck-viewbox-spacer")
    root.insert(0, spacer)
    if not any(el.get("id") == _FRAME_ID for el in root.iter()):
        frame = ET.SubElement(root, f"{ns}rect")
        frame.set("id", _FRAME_ID)
        frame.set("x", "0.5")
        frame.set("y", "0.5")
        frame.set("width", str(width - 1.0))
        frame.set("height", str(height - 1.0))
        frame.set("fill", "none")
        frame.set("stroke", _FRAME_COLOR)
        frame.set("stroke-width", "1")
    return width, height


def _prepared_logo_root(source: str) -> ET.Element:
    """Parse the logo SVG, show netcheck, and fix dimension arrows for Qt."""
    root = ET.fromstring(source)
    has_copyright = any(el.get("id") == _COPYRIGHT_SRC_ID for el in root.iter())
    width, height = _prepare_page(root)
    _set_module_viewbox(width, height)
    _fix_dimension_arrows(root)
    _remove_ids(root, set(_HIDE_IDS))
    _inject_netcheck_outline(root)
    if has_copyright:
        _inject_copyright_outline(root)
    return root


def prepare_logo_svg_bytes(svg_path: Path | None = None) -> QByteArray | None:
    """Full logo SVG bytes for splash / toolbar / login."""
    path = svg_path or LOGO_SVG
    key = str(path.resolve()) if path.is_file() else ""
    cached = getattr(prepare_logo_svg_bytes, "_cache", None)
    if isinstance(cached, dict) and key in cached:
        return cached[key]
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return None
    _register_namespaces()
    try:
        root = _prepared_logo_root(source)
        data = QByteArray(ET.tostring(root, encoding="unicode").encode("utf-8"))
    except ET.ParseError:
        return None
    if key:
        if not isinstance(cached, dict):
            cached = {}
            prepare_logo_svg_bytes._cache = cached  # type: ignore[attr-defined]
        cached[key] = data
    return data


def _variant_bytes_from_root(root: ET.Element, remove: set[str]) -> QByteArray:
    clone = ET.fromstring(ET.tostring(root, encoding="unicode"))
    _remove_ids(clone, remove)
    return QByteArray(ET.tostring(clone, encoding="unicode").encode("utf-8"))


def build_layer_bytes(svg_path: Path) -> dict[str, QByteArray] | None:
    """Return SVG byte-variants for back / front / each bar, or None on failure."""
    full = prepare_logo_svg_bytes(svg_path)
    if full is None:
        return None
    _register_namespaces()
    try:
        root = ET.fromstring(bytes(full.data()).decode("utf-8"))
        all_bars = set(_SLIDING_BARS)
        layers: dict[str, QByteArray] = {"full": full}
        layers["back"] = _variant_bytes_from_root(root, {"g10", *_FRONT_IDS})
        layers["front"] = _variant_bytes_from_root(root, {"g10", *_BACK_IDS})
        for bar in _SLIDING_BARS:
            remove = (all_bars - {bar}) | set(_BACK_IDS) | set(_FRONT_IDS)
            layers[bar] = _variant_bytes_from_root(root, remove)
        return layers
    except ET.ParseError:
        return None


class AnimatedSplash(QWidget):
    """Frameless white splash that slides the three rainbow bars into place."""

    def __init__(self, svg_path: Path | None = None, *, width: int = 960) -> None:
        super().__init__(None, Qt.WindowType.SplashScreen | Qt.WindowType.FramelessWindowHint)
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
        self.duration_ms = ANIM_DURATION_MS

        from PySide6.QtSvg import QSvgRenderer  # local import (optional dep)

        path = svg_path or LOGO_SVG
        layers = build_layer_bytes(path)
        self._renderers: dict[str, QSvgRenderer] = {}
        if layers is not None:
            for key, data in layers.items():
                r = QSvgRenderer(data)
                if r.isValid():
                    r.setViewBox(QRectF(0, 0, _VIEWBOX_W, _VIEWBOX_H))
                    self._renderers[key] = r
        self._valid = {"back", "front", *_SLIDING_BARS}.issubset(self._renderers)
        self._bar_align_dx = 0.0

        self._t = 0.0  # overall animation progress 0..1
        self._ease = QEasingCurve(QEasingCurve.Type.OutCubic)

        height = int(width * (_VIEWBOX_H / _VIEWBOX_W)) + 72
        self.resize(width, height)
        self._center_on_screen()

        self._anim = QVariantAnimation(self)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.setDuration(self.duration_ms)
        self._anim.valueChanged.connect(self._on_tick)

    # -- lifecycle -----------------------------------------------------

    def _center_on_screen(self) -> None:
        from PySide6.QtWidgets import QApplication

        screen = QApplication.primaryScreen()
        if screen is not None:
            geo = self.frameGeometry()
            geo.moveCenter(screen.availableGeometry().center())
            self.move(geo.topLeft())

    def start(self) -> None:
        # Warm the shared SVG prepare cache for toolbar/home logos.
        try:
            prepare_logo_svg_bytes(LOGO_SVG)
        except Exception:  # noqa: BLE001
            pass
        self.show()
        self.raise_()
        self._anim.start()

    def finish(self, window: QWidget) -> None:
        self._anim.stop()
        self.close()

    def _on_tick(self, value: float) -> None:
        self._t = float(value)
        self.update()

    # -- helpers -------------------------------------------------------

    def _seg(self, start: float, end: float) -> float:
        if self._t <= start:
            return 0.0
        if self._t >= end:
            return 1.0
        return self._ease.valueForProgress((self._t - start) / (end - start))

    def _target_rect(self) -> QRectF:
        margin_l, margin_t, margin_r, margin_b = 40, 36, 40, 36
        area = self.rect().adjusted(margin_l, margin_t, -margin_r, -margin_b)
        scale = min(area.width() / _VIEWBOX_W, area.height() / _VIEWBOX_H)
        w = _VIEWBOX_W * scale
        h = _VIEWBOX_H * scale
        x = area.x() + (area.width() - w) / 2
        y = area.y() + (area.height() - h) / 2
        return QRectF(x, y, w, h)

    def _render_layer(self, painter: QPainter, key: str, target: QRectF) -> None:
        """Render one SVG layer into *target*."""
        renderer = self._renderers.get(key)
        if renderer is not None:
            renderer.render(painter, target)

    # -- painting ------------------------------------------------------

    def paintEvent(self, event) -> None:  # noqa: N802, ANN001
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        painter.fillRect(self.rect(), QColor("#ffffff"))

        target = self._target_rect()
        if not self._valid:
            fallback = "full" if "full" in self._renderers else "front"
            self._render_layer(painter, fallback, target)
            paint_netcheck_word(painter, target)
            painter.end()
            return

        slide = target.width()
        align = self._bar_align_dx * (target.width() / _VIEWBOX_W)

        self._render_layer(painter, "back", target)

        bar_plan = (
            (_BAR_TOP, self._seg(0.00, 0.58), -1),
            (_BAR_MID, self._seg(0.18, 0.78), +1),
            (_BAR_LOW, self._seg(0.36, 1.00), -1),
        )
        for bar_id, prog, direction in bar_plan:
            offset = (1.0 - prog) * slide * direction + align
            painter.save()
            painter.translate(offset, 0.0)
            self._render_layer(painter, bar_id, target)
            painter.restore()

        self._render_layer(painter, "front", target)
        paint_netcheck_word(painter, target)
        painter.end()
