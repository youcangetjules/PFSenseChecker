"""A very subtle, slowly undulating rainbow behind the login screen.

A small grid of rainbow colours (hue sweeping across the window, bent by slow
sine waves) is drawn into a 64 x 40 image, scaled up smoothly — so there are
no hard edges — and laid over the normal window grey at about 10% strength.
Each instance starts from a random hue, direction and wave pattern, so the
screen looks a little different every time it opens. It animates only while
visible, 10 frames a second. (added 2026-11-07)
"""

from __future__ import annotations

import colorsys
import math
import random
import time

from PySide6.QtCore import QRectF, Qt, QTimer
from PySide6.QtGui import QImage, QPainter
from PySide6.QtWidgets import QWidget

GRID_W, GRID_H = 64, 40
OPACITY = 0.10  # how strongly the rainbow tints the grey (0 = off)
SATURATION = 0.55
FRAME_MS = 100


class RainbowParams:
    """The random choices that make each opening look different."""

    def __init__(self, seed: int | None = None) -> None:
        rng = random.Random(seed)
        self.hue0 = rng.random()  # starting colour, 0..1 round the wheel
        self.drift = rng.choice((-1, 1)) * rng.uniform(1 / 150, 1 / 90)  # hue turns per second
        self.angle = rng.uniform(0, math.pi)  # direction the rainbow runs across the window
        # Two slow waves bend the bands: (strength, spatial frequency, period s, phase)
        self.waves = [
            (rng.uniform(0.10, 0.18), rng.uniform(0.8, 1.6), rng.uniform(40, 70), rng.uniform(0, 2 * math.pi)),
            (rng.uniform(0.05, 0.10), rng.uniform(1.8, 3.0), rng.uniform(55, 90), rng.uniform(0, 2 * math.pi)),
        ]
        self.span = rng.uniform(0.7, 1.1)  # how much of the rainbow fits across the window


def hue_at(p: RainbowParams, x: float, y: float, t: float) -> float:
    """Hue (0..1) at normalised point (x, y) and time t seconds."""
    ca, sa = math.cos(p.angle), math.sin(p.angle)
    along = x * ca + y * sa  # position along the rainbow's direction
    across = -x * sa + y * ca
    bend = 0.0
    for strength, freq, period, phase in p.waves:
        bend += strength * math.sin(2 * math.pi * (freq * across + t / period) + phase)
    return (p.hue0 + p.drift * t + p.span * (along + bend)) % 1.0


def render_grid(p: RainbowParams, t: float, w: int = GRID_W, h: int = GRID_H) -> QImage:
    """The rainbow at time *t* as a small RGB image."""
    buf = bytearray(w * h * 4)
    i = 0
    for gy in range(h):
        y = gy / (h - 1)
        for gx in range(w):
            r, g, b = colorsys.hsv_to_rgb(hue_at(p, gx / (w - 1), y, t), SATURATION, 1.0)
            buf[i] = int(b * 255)
            buf[i + 1] = int(g * 255)
            buf[i + 2] = int(r * 255)
            buf[i + 3] = 255
            i += 4
    img = QImage(bytes(buf), w, h, w * 4, QImage.Format.Format_RGB32)
    return img.copy()  # own the pixels (the bytes object is temporary)


class RainbowBackdrop(QWidget):
    """Plain container widget whose background is the moving rainbow wash."""

    def __init__(self, parent: QWidget | None = None, *, seed: int | None = None,
                 opacity: float = OPACITY) -> None:
        super().__init__(parent)
        self.params = RainbowParams(seed if seed is not None else time.time_ns())
        self.opacity = opacity
        self._t0 = time.monotonic()
        self._frame: QImage | None = None
        self._timer = QTimer(self)
        self._timer.setInterval(FRAME_MS)
        self._timer.timeout.connect(self._tick)

    def elapsed(self) -> float:
        return time.monotonic() - self._t0

    def _tick(self) -> None:
        self._frame = render_grid(self.params, self.elapsed())
        self.update()

    def showEvent(self, event) -> None:  # noqa: N802, ANN001
        super().showEvent(event)
        self._tick()
        self._timer.start()

    def hideEvent(self, event) -> None:  # noqa: N802, ANN001
        self._timer.stop()  # no CPU while the login screen is hidden
        super().hideEvent(event)

    def paintEvent(self, _event) -> None:  # noqa: N802, ANN001
        painter = QPainter(self)
        painter.fillRect(self.rect(), self.palette().window())
        if self.opacity > 0:
            if self._frame is None:
                self._frame = render_grid(self.params, self.elapsed())
            painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
            painter.setOpacity(self.opacity)
            painter.drawImage(QRectF(self.rect()), self._frame, QRectF(self._frame.rect()))
        painter.end()
