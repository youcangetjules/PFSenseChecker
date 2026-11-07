"""Vendor logo fills the chassis title bar, aspect kept, empty margins trimmed."""

from __future__ import annotations

from PySide6.QtCore import QRectF


def test_logo_takes_title_bar_height_with_aspect() -> None:
    from pfsense_checker import site_canvas as sc

    header = QRectF(0, 0, 900, sc.HEADER_H - 2)
    bar_h = header.height() - 2 * sc.LOGO_INSET
    r = sc.logo_target(header, 900, (300, 100))  # 3:1 logo
    assert abs(r.height() - bar_h) < 0.01
    assert abs(r.width() - 3 * bar_h) < 0.01
    assert abs(r.right() - (900 - 8)) < 0.01
    # very wide logo in a narrow box: capped width, still 3:1… here 20:1, shorter, centred
    wide = sc.logo_target(header, 300, (2000, 100))
    assert wide.width() <= 300 * sc.LOGO_MAX_SHARE + 0.01
    assert abs(wide.width() / wide.height() - 20) < 0.01
    assert abs((wide.top() + wide.height() / 2) - header.height() / 2) < 0.01


def test_trim_removes_transparent_and_white_margins() -> None:
    from PySide6.QtGui import QColor, QImage
    from PySide6.QtWidgets import QApplication

    from pfsense_checker import site_canvas as sc

    QApplication.instance() or QApplication([])
    img = QImage(320, 320, QImage.Format.Format_ARGB32)
    img.fill(QColor(0, 0, 0, 0))
    for y in range(135, 185):
        for x in range(16, 304):
            img.setPixelColor(x, y, QColor("#293c4a"))
    out = sc.trim_logo_margins(img)
    assert out.height() <= 52 and out.width() >= 288  # the band, not the square
    white = QImage(500, 280, QImage.Format.Format_RGB32)
    white.fill(QColor("white"))
    for y in range(80, 200):
        for x in range(11, 494):
            white.setPixelColor(x, y, QColor("black"))
    assert sc.trim_logo_margins(white).height() <= 122
    blank = QImage(10, 10, QImage.Format.Format_ARGB32)
    blank.fill(QColor(0, 0, 0, 0))
    assert sc.trim_logo_margins(blank).size() == blank.size()
