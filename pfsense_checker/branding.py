"""NetCheck branding helpers (logo pixmap for toolbar / home)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QPainter, QPixmap

from pfsense_checker.paths import PROJECT_ROOT

LOGO_SVG = PROJECT_ROOT / "A-Netcheck.svg"

# Status bar — very dark navy; chips use white / green / red.
STATUS_BAR_BG = "#061830"
STATUS_BAR_OK = "#00e676"  # strong green
STATUS_BAR_FAIL = "#ff5252"
STATUS_BAR_WARN = "#ffd740"  # connected, but not encrypted
STATUS_BAR_TEXT = "#ffffff"


# Left section nav (home hub + analysis workspace) — same chrome everywhere.
NAV_TREE_STYLE = (
    "QTreeWidget { border: 1px solid #cfd8dc; border-radius: 4px; "
    "background: #f7f9fa; outline: none; }"
    "QTreeWidget::item { padding: 8px 10px; border-radius: 3px; }"
    "QTreeWidget::item:selected { background: rgba(21, 101, 192, 160);"
    " color: white; font-weight: bold; }"
    "QTreeWidget::item:hover:!selected { background: #e3eef8; }"
)


def status_bar_stylesheet() -> str:
    """Shared QStatusBar look: very dark blue, semi-bold 9pt text."""
    return (
        "QStatusBar {"
        f" background: {STATUS_BAR_BG};"
        f" color: {STATUS_BAR_TEXT};"
        " border-top: 1px solid #123056;"
        " font-size: 9pt;"
        " font-weight: 600;"
        " padding: 2px 8px;"
        "}"
        "QStatusBar::item { border: none; background: transparent; }"
        "QStatusBar QLabel {"
        f" color: {STATUS_BAR_TEXT};"
        " background: transparent;"
        " font-size: 9pt;"
        " font-weight: 600;"
        "}"
        "QStatusBar QPushButton { font-size: 9pt; }"
        "QStatusBar QProgressBar {"
        " background: #0a2448;"
        " border: 1px solid #123056;"
        " border-radius: 2px;"
        " max-width: 25px;"
        " min-width: 25px;"
        " max-height: 16px;"
        " min-height: 16px;"
        " text-align: center;"
        "}"
        "QStatusBar QProgressBar::chunk {"
        f" background: {STATUS_BAR_OK};"
        " border-radius: 1px;"
        "}"
    )


def status_chip_style(color: str, *, extra_padding: str = "0 10px") -> str:
    """Semi-bold chip on the dark status bar (white / green / red)."""
    return (
        f"color: {color}; padding: {extra_padding}; font-weight: 600; "
        "background: transparent; font-size: 9pt;"
    )


# Cache prepared SVG bytes (XML rewrite is expensive) and rendered pixmaps.
_PREPARED_SVG: dict[str, object] = {}
_PIXMAP_CACHE: dict[tuple[str, int, str], QPixmap] = {}


def _prepared_svg_bytes(logo_path: Path):
    key = str(logo_path.resolve()) if logo_path.is_file() else ""
    if key in _PREPARED_SVG:
        return _PREPARED_SVG[key]
    try:
        from pfsense_checker.splash import prepare_logo_svg_bytes

        data = prepare_logo_svg_bytes(logo_path)
    except Exception:  # noqa: BLE001
        data = None
    if key:
        _PREPARED_SVG[key] = data
    return data


def _without_copyright(pix: QPixmap | None) -> QPixmap | None:
    """The logo with the copyright strip at the bottom cut off, frame closed."""
    if pix is None or pix.isNull():
        return pix
    from pfsense_checker import splash

    if splash._VIEWBOX_H <= splash._COPYRIGHT_BASELINE:  # noqa: SLF001 - no copyright strip
        return pix
    # The strip starts just above the copyright's capitals.
    cut = (splash._COPYRIGHT_BASELINE - splash._COPYRIGHT_PIXEL_SIZE) / splash._VIEWBOX_H  # noqa: SLF001
    height = max(1, int(round(pix.height() * cut)))
    out = pix.copy(0, 0, pix.width(), height)
    painter = QPainter(out)
    painter.setPen(QColor(splash._FRAME_COLOR))  # noqa: SLF001
    painter.drawLine(0, height - 1, out.width() - 1, height - 1)
    painter.end()
    return out


def render_logo_pixmap(
    *,
    width: int = 120,
    background: QColor | None = None,
    path: Path | None = None,
    copyright: bool = True,  # noqa: A002 - the copyright line under the logo
) -> QPixmap | None:
    """Render A-Netcheck.svg to a pixmap. Transparent background by default.

    Results are cached by path/width/background so toolbar + home share work
    after the first (expensive) SVG prepare pass. ``copyright=False`` cuts off
    the strip with "© 2026 Aliniant Laboratories" (the login screen shows it
    as its own line instead).
    """
    if not copyright:
        return _without_copyright(render_logo_pixmap(width=width, background=background, path=path))
    logo_path = path or LOGO_SVG
    if not logo_path.is_file():
        return None
    try:
        from PySide6.QtSvg import QSvgRenderer
    except ImportError:
        return None

    bg_key = (
        "transparent"
        if background is None
        else (
            f"{background.red():02x}{background.green():02x}"
            f"{background.blue():02x}{background.alpha():02x}"
        )
    )
    cache_key = (str(logo_path.resolve()), int(width), bg_key)
    cached = _PIXMAP_CACHE.get(cache_key)
    if cached is not None and not cached.isNull():
        return cached

    try:
        data = _prepared_svg_bytes(logo_path)
        if data is None:
            return None
        # Import after the prepare pass: it updates the module viewbox
        # (e.g. taller page when the copyright line is present).
        from pfsense_checker.splash import _VIEWBOX_H, _VIEWBOX_W

        renderer = QSvgRenderer(data)
        padded_w, padded_h = _VIEWBOX_W, _VIEWBOX_H
    except Exception:  # noqa: BLE001
        renderer = QSvgRenderer(str(logo_path))
        if not renderer.isValid():
            return None
        vb = renderer.viewBox()
        padded_w = max(float(vb.width()), 961.0)
        padded_h = float(vb.height()) if vb.height() else 277.0

    if not renderer.isValid():
        return None
    renderer.setViewBox(QRectF(0, 0, padded_w, padded_h))
    aspect = padded_w / padded_h if padded_h else 3.5
    height = max(1, int(width / aspect))
    pix = QPixmap(width, height)
    pix.fill(background if background is not None else Qt.GlobalColor.transparent)
    painter = QPainter(pix)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    painter.save()
    renderer.render(painter, QRectF(0, 0, width, height))
    painter.restore()
    from pfsense_checker.splash import paint_netcheck_word

    paint_netcheck_word(painter, QRectF(0, 0, width, height))
    painter.end()
    _PIXMAP_CACHE[cache_key] = pix
    return pix
