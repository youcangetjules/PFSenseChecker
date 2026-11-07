"""Login backdrop: subtle, slowly moving rainbow, different on each opening."""

from __future__ import annotations

from PySide6.QtWidgets import QApplication

from pfsense_checker import rainbow_backdrop as rb


def test_each_opening_differs_and_motion_is_slow() -> None:
    a, b = rb.RainbowParams(1), rb.RainbowParams(2)
    assert (a.hue0, a.angle) != (b.hue0, b.angle)
    h0 = rb.hue_at(a, 0.5, 0.5, 0.0)
    assert 0.0 <= h0 < 1.0
    # one frame later the colour has barely moved (slow undulation)
    step = abs(rb.hue_at(a, 0.5, 0.5, rb.FRAME_MS / 1000) - h0)
    assert min(step, 1 - step) < 0.002
    # over a minute it has visibly moved
    later = abs(rb.hue_at(a, 0.5, 0.5, 60.0) - h0)
    assert min(later, 1 - later) > 0.05


def test_grid_and_subtle_opacity() -> None:
    QApplication.instance() or QApplication([])
    img = rb.render_grid(rb.RainbowParams(3), 5.0)
    assert (img.width(), img.height()) == (rb.GRID_W, rb.GRID_H)
    assert 0 < rb.OPACITY <= 0.15  # "very subtle"


def test_animates_only_while_visible() -> None:
    QApplication.instance() or QApplication([])
    w = rb.RainbowBackdrop(seed=4)
    assert not w._timer.isActive()
    w.show()
    QApplication.processEvents()
    assert w._timer.isActive()
    w.hide()
    QApplication.processEvents()
    assert not w._timer.isActive()
    w.close()
