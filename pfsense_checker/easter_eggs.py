"""Easter Egg me (login screen Tools): a random little cartoon, drawn live.

Original, hand-drawn (QPainter) homages, nothing copied from the films or shows:
  * John McClane in Harlem, having a very bad day;
  * Hunter S. Thompson swatting bats on the road to Las Vegas;
  * President Merkin Muffley breaking up a fight in the War Room;
  * Adrian Cronauer's good morning to Vietnam;
  * Basil Fawlty, the bandaged host, not mentioning the war;
  * a Roman official and his friend Biggus Dickus, guards not laughing;
  * Jack Torrance through the bathroom door;
  * Col. Jessup on the stand: the truth, and who can handle it;
  * Captain Jack Sparrow arriving in port as his boat sinks;
  * the Black Knight, losing limb after limb (a flesh wound);
  * King Arthur 'riding' to the clop of coconuts;
  * an airliner doctor who is serious, and not called Shirley;
  * a detective in front of an exploding fireworks factory: nothing to see here;
  * a male model who cannot turn left;
  * Brave Sir Robin meeting a three-headed knight, his minstrels singing as he runs.
Each scene loops; "Another!" picks a different one. (added 2026-11-08)
"""

from __future__ import annotations

import math
import random
import time
from collections.abc import Callable

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QRadialGradient,
)
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

W, H = 720.0, 405.0  # scene units; the canvas scales to fit
FRAME_MS = 33


def _caption(p: QPainter, text: str, sub: str = "") -> None:
    """Title band along the bottom: a soft dark gradient with a thin accent line."""
    band = QRectF(0, H - 50, W, 50)
    grad = QLinearGradient(0, band.top(), 0, H)
    grad.setColorAt(0, QColor(0, 0, 0, 70))
    grad.setColorAt(0.35, QColor(0, 0, 0, 165))
    grad.setColorAt(1, QColor(0, 0, 0, 200))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(grad)
    p.drawRect(band)
    p.setBrush(QColor(255, 193, 7, 220))
    p.drawRect(QRectF(14, H - 45, 36, 2.5))
    f = QFont()
    f.setBold(True)
    f.setPointSizeF(12.5)
    p.setFont(f)
    p.setPen(QColor(0, 0, 0, 160))
    p.drawText(QRectF(15, H - 41, W - 28, 24), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, text)
    p.setPen(QColor("#ffffff"))
    p.drawText(QRectF(14, H - 42, W - 28, 24), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, text)
    if sub:
        f.setBold(False)
        f.setItalic(True)
        f.setPointSizeF(9.5)
        p.setFont(f)
        p.setPen(QColor("#e0e0e0"))
        p.drawText(QRectF(14, H - 22, W - 28, 20), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, sub)


def _bubble(p: QPainter, rect: QRectF, tail: QPointF, text: str, size: float = 11.0) -> None:
    """Speech bubble with a tail to the speaker and a soft drop shadow."""
    path = QPainterPath()
    path.addRoundedRect(rect, 14, 14)
    tri = QPainterPath()
    cx = min(max(tail.x(), rect.left() + 22), rect.right() - 22)
    tri.moveTo(cx - 12, rect.bottom() - 2)
    tri.quadTo(cx - 2, rect.bottom() + (tail.y() - rect.bottom()) * 0.45, tail.x(), tail.y())
    tri.quadTo(cx + 4, rect.bottom() + (tail.y() - rect.bottom()) * 0.35, cx + 10, rect.bottom() - 2)
    tri.closeSubpath()
    shape = path.united(tri)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(0, 0, 0, 55))
    p.drawPath(shape.translated(3, 4))
    fill = QLinearGradient(0, rect.top(), 0, rect.bottom())
    fill.setColorAt(0, QColor("#ffffff"))
    fill.setColorAt(1, QColor("#f3f6f8"))
    p.setPen(QPen(QColor("#263238"), 2.2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
    p.setBrush(fill)
    p.drawPath(shape)
    f = QFont()
    f.setBold(True)
    f.setPointSizeF(size)
    p.setFont(f)
    p.setPen(QColor("#1c1c1c"))
    p.drawText(rect.adjusted(12, 6, -12, -6), Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap, text)


def _limb(p: QPainter, a: QPointF, b: QPointF, colour: QColor, width: float) -> None:
    """A limb with a darker outline, so figures read against any background."""
    p.setPen(QPen(colour.darker(170), width + 2.2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    p.drawLine(a, b)
    p.setPen(QPen(colour, width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    p.drawLine(a, b)


def _stick(p: QPainter, x: float, y: float, *, scale: float = 1.0, head: str = "#f1c27d",
           body: str = "#37474f", arm_l: float = -0.6, arm_r: float = 0.6, legs: float = 0.25,
           face: bool = True, shadow: bool = True) -> None:
    """A little cartoon figure standing with its feet at (x, y): shaded body, outlined
    limbs, hands, shoes, eyes and a shadow on the ground. Arm angles are radians from
    straight down (pi is straight up). Head centre is (x, y - 92 * scale)."""
    s = scale
    col = QColor(body)
    skin = QColor(head)
    p.setPen(Qt.PenStyle.NoPen)
    if shadow:
        p.setBrush(QColor(0, 0, 0, 45))
        p.drawEllipse(QPointF(x, y + 2 * s), 22 * s, 4.5 * s)
    hip = QPointF(x, y - 38 * s)
    neck = QPointF(x, y - 78 * s)
    feet = (QPointF(x - 14 * s * math.sin(legs * 2), y), QPointF(x + 14 * s * math.sin(legs * 2), y))
    for foot in feet:
        _limb(p, hip, foot, col, 6 * s)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#263238"))
    for foot in feet:
        p.drawEllipse(QPointF(foot.x() + 2 * s, foot.y() - 1 * s), 6 * s, 3.2 * s)
    # Torso: tapered, lit from the upper left.
    torso = QPainterPath(QPointF(x - 11 * s, neck.y() + 3 * s))
    torso.lineTo(x + 11 * s, neck.y() + 3 * s)
    torso.quadTo(x + 10 * s, hip.y() - 10 * s, x + 8 * s, hip.y() + 2 * s)
    torso.lineTo(x - 8 * s, hip.y() + 2 * s)
    torso.quadTo(x - 10 * s, hip.y() - 10 * s, x - 11 * s, neck.y() + 3 * s)
    torso.closeSubpath()
    shade = QLinearGradient(x - 12 * s, 0, x + 12 * s, 0)
    shade.setColorAt(0, col.lighter(125))
    shade.setColorAt(1, col.darker(120))
    p.setPen(QPen(col.darker(170), 1.2 * s))
    p.setBrush(shade)
    p.drawPath(torso)
    # Arms, then hands.
    shoulder = neck + QPointF(0, 6 * s)
    for side, ang in ((-1, arm_l), (1, arm_r)):
        start = shoulder + QPointF(side * 7 * s, 0)
        hand = start + QPointF(30 * s * math.sin(ang), 30 * s * math.cos(ang))
        _limb(p, start, hand, col, 5 * s)
        p.setPen(QPen(skin.darker(140), 1 * s))
        p.setBrush(skin)
        p.drawEllipse(hand, 3.4 * s, 3.4 * s)
    # Neck and head.
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(skin.darker(110))
    p.drawRect(QRectF(x - 3.5 * s, y - 82 * s, 7 * s, 6 * s))
    c = QPointF(x, y - 92 * s)
    lit = QRadialGradient(c + QPointF(-4 * s, -5 * s), 16 * s)
    lit.setColorAt(0, skin.lighter(112))
    lit.setColorAt(1, skin.darker(108))
    p.setBrush(skin)
    p.drawEllipse(c + QPointF(-12.5 * s, 1 * s), 2.6 * s, 3.6 * s)  # ears
    p.drawEllipse(c + QPointF(12.5 * s, 1 * s), 2.6 * s, 3.6 * s)
    p.setPen(QPen(skin.darker(150), 1.3 * s))
    p.setBrush(lit)
    p.drawEllipse(c, 13 * s, 14 * s)
    if face:
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#2b2b2b"))
        p.drawEllipse(c + QPointF(-4.5 * s, -1.5 * s), 1.5 * s, 1.8 * s)
        p.drawEllipse(c + QPointF(4.5 * s, -1.5 * s), 1.5 * s, 1.8 * s)
        p.setBrush(QColor(229, 115, 115, 70))
        p.drawEllipse(c + QPointF(-7.5 * s, 4 * s), 3 * s, 2 * s)
        p.drawEllipse(c + QPointF(7.5 * s, 4 * s), 3 * s, 2 * s)


def _vignette(p: QPainter) -> None:
    """Darken the corners a touch, like an old cartoon cel."""
    g = QRadialGradient(QPointF(W / 2, H * 0.45), W * 0.72)
    g.setColorAt(0.0, QColor(0, 0, 0, 0))
    g.setColorAt(0.7, QColor(0, 0, 0, 0))
    g.setColorAt(1.0, QColor(0, 0, 0, 85))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(g)
    p.drawRect(QRectF(0, 0, W, H))


# --------------------------------------------------------------------------- #
# 1. Harlem


def paint_harlem(p: QPainter, t: float) -> None:
    sky = QLinearGradient(0, 0, 0, H * 0.6)
    sky.setColorAt(0, QColor("#ffcc80"))
    sky.setColorAt(1, QColor("#90caf9"))
    p.fillRect(QRectF(0, 0, W, H), sky)
    # Brownstones with a clock on the corner building.
    rnd = random.Random(7)
    x = -10.0
    while x < W:
        bw = rnd.uniform(90, 140)
        bh = rnd.uniform(160, 240)
        col = QColor(rnd.choice(["#8d6e63", "#795548", "#a1887f", "#6d4c41"]))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(col)
        p.drawRect(QRectF(x, H * 0.62 - bh, bw, bh))
        p.setBrush(QColor("#fff59d") if rnd.random() < 0.3 else QColor("#4e342e"))
        for wy in range(int(H * 0.62 - bh + 18), int(H * 0.62 - 30), 34):
            for wx in range(int(x + 12), int(x + bw - 20), 28):
                p.setBrush(QColor("#fff59d") if rnd.random() < 0.25 else QColor("#3e2723"))
                p.drawRect(QRectF(wx, wy, 14, 20))
        x += bw + 4
    cx, cy = 600.0, 70.0
    p.setPen(QPen(QColor("#263238"), 3))
    p.setBrush(QColor("#fafafa"))
    p.drawEllipse(QPointF(cx, cy), 26, 26)
    minute = t * 2.0  # time is running out, fast
    p.drawLine(QPointF(cx, cy), QPointF(cx + 20 * math.sin(minute), cy - 20 * math.cos(minute)))
    p.drawLine(QPointF(cx, cy), QPointF(cx + 12 * math.sin(minute / 12), cy - 12 * math.cos(minute / 12)))
    # Street and pavement.
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#9e9e9e"))
    p.drawRect(QRectF(0, H * 0.62, W, 60))
    p.setBrush(QColor("#424242"))
    p.drawRect(QRectF(0, H * 0.62 + 60, W, H))
    p.setBrush(QColor("#fdd835"))
    for i in range(10):
        p.drawRect(QRectF(i * 90 - (t * 40) % 90, H * 0.62 + 100, 50, 5))
    # A taxi goes by now and then.
    tx = W + 60 - ((t * 260) % (W + 400))
    p.setBrush(QColor("#fbc02d"))
    p.drawRoundedRect(QRectF(tx, H * 0.62 + 70, 130, 34), 6, 6)
    p.drawRoundedRect(QRectF(tx + 28, H * 0.62 + 52, 70, 24), 6, 6)
    p.setBrush(QColor("#212121"))
    for wx in (tx + 26, tx + 104):
        p.drawEllipse(QPointF(wx, H * 0.62 + 104), 12, 12)
    # Our man: vest, sandwich board, shuffling, sweating under his own cloud.
    sway = math.sin(t * 5) * 6
    fx, fy = 330 + sway, H * 0.62 + 52
    _stick(p, fx, fy, scale=1.2, body="#eceff1", arm_l=-0.35 + math.sin(t * 7) * 0.2,
           arm_r=0.35 - math.sin(t * 7) * 0.2, legs=0.15 + 0.1 * math.sin(t * 5))
    p.setPen(QPen(QColor("#5d4037"), 2))
    p.setBrush(QColor("#fffde7"))
    board = QRectF(fx - 52, fy - 90, 104, 62)
    p.drawRect(board)
    p.drawLine(QPointF(fx - 40, fy - 90), QPointF(fx - 10, fy - 106))
    p.drawLine(QPointF(fx + 40, fy - 90), QPointF(fx + 10, fy - 106))
    f = QFont()
    f.setBold(True)
    f.setPointSizeF(10)
    p.setFont(f)
    p.setPen(QColor("#b71c1c"))
    p.drawText(board, Qt.AlignmentFlag.AlignCenter, "I AM HAVING\nA VERY\nBAD DAY")
    head = QPointF(fx, fy - 110 * 1.2 + 22)
    for i in range(3):
        k = (t * 1.6 + i / 3) % 1.0
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(100, 181, 246, int(255 * (1 - k))))
        p.drawEllipse(QPointF(head.x() + (i - 1) * 16, head.y() + 4 + k * 40), 3, 5)
    cloud_y = head.y() - 70 + math.sin(t * 2) * 3
    p.setBrush(QColor("#607d8b"))
    for dx, r in ((-26, 18), (0, 24), (26, 18)):
        p.drawEllipse(QPointF(fx + dx, cloud_y), r, r * 0.8)
    p.setPen(QPen(QColor("#64b5f6"), 2))
    for i in range(7):
        k = (t * 2.2 + i * 0.37) % 1.0
        rx = fx - 34 + i * 11
        p.drawLine(QPointF(rx, cloud_y + 18 + k * 30), QPointF(rx - 2, cloud_y + 26 + k * 30))
    if int(t * 1.2) % 4 == 3:  # a flash of lightning
        p.setPen(QPen(QColor("#ffee58"), 3))
        p.drawPolyline([QPointF(fx + 6, cloud_y + 16), QPointF(fx - 4, cloud_y + 32),
                        QPointF(fx + 6, cloud_y + 32), QPointF(fx - 6, cloud_y + 50)])
    if (t % 6) > 3:
        _bubble(p, QRectF(fx + 70, fy - 196, 210, 50), QPointF(fx + 18, fy - 128),
                "Yippee-ki… no. Not today.", 10.5)
    _caption(p, "John McClane, Harlem, 8:15 a.m.", "Having a very bad day.")


# --------------------------------------------------------------------------- #
# 2. Bat country


def _bat(p: QPainter, c: QPointF, size: float, flap: float) -> None:
    lift = math.sin(flap) * size * 0.7
    path = QPainterPath(QPointF(c.x(), c.y()))
    path.cubicTo(c.x() - size * 0.4, c.y() - lift - size * 0.3, c.x() - size * 0.8, c.y() - lift,
                 c.x() - size, c.y() - lift * 0.6)
    path.lineTo(c.x() - size * 0.6, c.y() + size * 0.15)
    path.lineTo(c.x() - size * 0.3, c.y() + size * 0.05)
    path.lineTo(c.x(), c.y() + size * 0.25)
    path.lineTo(c.x() + size * 0.3, c.y() + size * 0.05)
    path.lineTo(c.x() + size * 0.6, c.y() + size * 0.15)
    path.lineTo(c.x() + size, c.y() - lift * 0.6)
    path.cubicTo(c.x() + size * 0.8, c.y() - lift, c.x() + size * 0.4, c.y() - lift - size * 0.3,
                 c.x(), c.y())
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#1a1a1a"))
    p.drawPath(path)
    p.setBrush(QColor("#ff1744"))
    p.drawEllipse(QPointF(c.x() - size * 0.08, c.y() + size * 0.05), 1.5, 1.5)
    p.drawEllipse(QPointF(c.x() + size * 0.08, c.y() + size * 0.05), 1.5, 1.5)


def paint_bat_country(p: QPainter, t: float) -> None:
    sky = QLinearGradient(0, 0, 0, H * 0.6)
    sky.setColorAt(0, QColor("#1a0033"))
    sky.setColorAt(1, QColor("#ff7043"))
    p.fillRect(QRectF(0, 0, W, H), sky)
    rnd = random.Random(3)
    p.setPen(Qt.PenStyle.NoPen)
    for i in range(60):
        sx, sy = rnd.uniform(0, W), rnd.uniform(0, H * 0.4)
        a = int(140 + 110 * math.sin(t * 3 + i))
        p.setBrush(QColor(255, 255, 255, max(0, a)))
        p.drawEllipse(QPointF(sx, sy), 1.2, 1.2)
    # Mesas far away, scrolling slowly; desert; road.
    p.setBrush(QColor("#4a148c"))
    off = (t * 15) % 400
    for k in range(-1, 3):
        bx = k * 400 - off
        mesa = QPainterPath(QPointF(bx, H * 0.6))
        mesa.lineTo(bx + 60, H * 0.45)
        mesa.lineTo(bx + 170, H * 0.45)
        mesa.lineTo(bx + 230, H * 0.6)
        p.drawPath(mesa)
    p.setBrush(QColor("#bf8040"))
    p.drawRect(QRectF(0, H * 0.6, W, H))
    p.setBrush(QColor("#37474f"))
    p.drawRect(QRectF(0, H * 0.72, W, 70))
    p.setBrush(QColor("#ffeb3b"))
    for i in range(12):
        p.drawRect(QRectF(i * 80 - (t * 420) % 80, H * 0.72 + 33, 44, 4))
    # Cacti and a road sign whizz past.
    p.setBrush(QColor("#2e7d32"))
    for i in range(4):
        cx = W + 40 - ((t * 300 + i * 260) % (W + 160))
        p.drawRoundedRect(QRectF(cx, H * 0.6 - 4, 12, 40), 5, 5)
        p.drawRoundedRect(QRectF(cx - 12, H * 0.6 + 8, 8, 18), 4, 4)
        p.drawRoundedRect(QRectF(cx + 16, H * 0.6 + 4, 8, 16), 4, 4)
    sx = W + 80 - ((t * 300 + 120) % (W + 900))
    p.setBrush(QColor("#9e9e9e"))
    p.drawRect(QRectF(sx + 44, H * 0.6 - 20, 5, 60))
    p.setBrush(QColor("#2e7d32"))
    p.drawRoundedRect(QRectF(sx, H * 0.6 - 64, 96, 44), 4, 4)
    f = QFont()
    f.setBold(True)
    f.setPointSizeF(9)
    p.setFont(f)
    p.setPen(QColor("#ffffff"))
    p.drawText(QRectF(sx, H * 0.6 - 64, 96, 44), Qt.AlignmentFlag.AlignCenter, "LAS VEGAS\n112")
    # The red convertible, bouncing.
    bob = math.sin(t * 18) * 1.5
    car_x, car_y = 230.0, H * 0.72 + 18 + bob
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#c62828"))
    body = QPainterPath(QPointF(car_x, car_y + 30))
    body.lineTo(car_x + 10, car_y + 6)
    body.lineTo(car_x + 90, car_y)
    body.lineTo(car_x + 120, car_y - 14)
    body.lineTo(car_x + 150, car_y - 14)
    body.lineTo(car_x + 175, car_y + 2)
    body.lineTo(car_x + 250, car_y + 6)
    body.lineTo(car_x + 262, car_y + 30)
    body.closeSubpath()
    p.drawPath(body)
    p.setBrush(QColor("#b0bec5"))
    p.drawRect(QRectF(car_x + 120, car_y - 30, 4, 18))  # windscreen frame
    p.setBrush(QColor("#212121"))
    for wx in (car_x + 50, car_x + 210):
        p.drawEllipse(QPointF(wx, car_y + 30), 17, 17)
        p.setBrush(QColor("#cfd8dc"))
        p.drawEllipse(QPointF(wx, car_y + 30), 6, 6)
        p.setBrush(QColor("#212121"))
    # Driver: bucket hat, aviators, cigarette holder; one arm swatting.
    dx, dy = car_x + 150, car_y - 22
    p.setBrush(QColor("#f1c27d"))
    p.drawEllipse(QPointF(dx, dy - 18), 12, 13)
    p.setBrush(QColor("#d7ccc8"))
    p.drawEllipse(QRectF(dx - 18, dy - 30, 36, 8))
    p.drawRoundedRect(QRectF(dx - 11, dy - 40, 22, 14), 5, 5)
    p.setBrush(QColor("#ffb300"))
    p.drawRect(QRectF(dx + 1, dy - 21, 12, 5))
    p.setPen(QPen(QColor("#212121"), 2))
    p.drawLine(QPointF(dx + 8, dy - 9), QPointF(dx + 30, dy - 15))  # cigarette holder
    p.setPen(QPen(QColor(200, 200, 200, 120), 2))
    for i in range(3):
        k = (t * 0.8 + i / 3) % 1.0
        p.drawPoint(QPointF(dx + 32 - k * 60, dy - 18 - k * 30 + math.sin(k * 9) * 4))
    swing = math.sin(t * 9) * 1.1
    shoulder = QPointF(dx - 4, dy - 2)
    hand = shoulder + QPointF(40 * math.sin(swing - 2.4), 40 * math.cos(swing - 2.4))
    p.setPen(QPen(QColor("#f1c27d"), 5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    p.drawLine(shoulder, hand)
    p.setPen(QPen(QColor("#795548"), 3))
    tip = hand + QPointF(30 * math.sin(swing - 2.6), 30 * math.cos(swing - 2.6))
    p.drawLine(hand, tip)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#a1887f"))
    p.drawEllipse(tip, 9, 6)
    # His attorney, riding shotgun.
    p.setBrush(QColor("#c68642"))
    p.drawEllipse(QPointF(car_x + 95, car_y - 24), 15, 16)
    p.setBrush(QColor("#212121"))
    p.drawEllipse(QRectF(car_x + 80, car_y - 46, 30, 14))
    # The bats.
    rnd = random.Random(11)
    for i in range(9):
        ph = rnd.uniform(0, 6.28)
        rad = rnd.uniform(40, 120)
        spd = rnd.uniform(0.8, 1.6)
        bx = dx + math.cos(t * spd + ph) * rad
        by = dy - 70 + math.sin(t * spd * 1.3 + ph) * rad * 0.45
        _bat(p, QPointF(bx, by), rnd.uniform(9, 15), t * 14 + ph)
    if (t % 7) > 2:
        _bubble(p, QRectF(400, 30, 290, 54), QPointF(dx + 12, dy - 40),
                "We can't stop here. This is bat country!", 11)
    _caption(p, "Hunter S. Thompson, the desert road to Las Vegas", "Swatting bats. Again.")


# --------------------------------------------------------------------------- #
# 3. The War Room


def paint_war_room(p: QPainter, t: float) -> None:
    p.fillRect(QRectF(0, 0, W, H), QColor("#0d0d0d"))
    # The big board.
    board = QRectF(90, 24, 540, 150)
    p.setPen(QPen(QColor("#37474f"), 3))
    p.setBrush(QColor("#102027"))
    p.drawRect(board)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#1b5e20"))
    rnd = random.Random(5)
    for _ in range(9):
        p.drawEllipse(QPointF(rnd.uniform(board.left() + 30, board.right() - 30),
                              rnd.uniform(board.top() + 25, board.bottom() - 25)),
                      rnd.uniform(18, 50), rnd.uniform(10, 26))
    for i in range(7):
        k = ((t * 0.25) + i / 7) % 1.0
        sx = board.left() + 60 + i * 60
        ex = board.left() + 300 + math.sin(i) * 160
        x = sx + (ex - sx) * k
        y = board.bottom() - 20 - math.sin(k * math.pi) * 80
        p.setBrush(QColor(255, 82, 82, 220))
        p.drawEllipse(QPointF(x, y), 3, 3)
        if int(t * 3 + i) % 2:
            p.setBrush(QColor(255, 235, 59, 200))
            p.drawEllipse(QPointF(board.left() + 40 + i * 70, board.top() + 18 + (i % 3) * 30), 3, 3)
    # The ring of light above the round table.
    halo = QRadialGradient(QPointF(W / 2, 258), 260)
    halo.setColorAt(0, QColor(255, 255, 230, 70))
    halo.setColorAt(1, QColor(0, 0, 0, 0))
    p.setBrush(halo)
    p.drawEllipse(QPointF(W / 2, 258), 300, 120)
    p.setPen(QPen(QColor(255, 255, 210, 160), 6))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawEllipse(QPointF(W / 2, 196), 230, 26)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#424242"))
    p.drawEllipse(QPointF(W / 2, 286), 250, 58)
    p.setBrush(QColor("#2e7d32"))
    p.drawEllipse(QPointF(W / 2, 282), 236, 50)
    # Generals round the table (heads).
    for i in range(9):
        ang = math.pi * (0.15 + 0.7 * i / 8)
        hx = W / 2 - math.cos(ang) * 210
        hy = 246 - math.sin(ang) * 20
        p.setBrush(QColor("#455a64"))
        p.drawRoundedRect(QRectF(hx - 14, hy, 28, 26), 6, 6)
        p.setBrush(QColor("#e0ac69"))
        p.drawEllipse(QPointF(hx, hy - 6), 9, 10)
    # The scuffle, on the left.
    k = t % 4
    lunge = math.sin(t * 8) * 8 if k < 2.5 else 0
    _stick(p, 120 + lunge, 340, scale=0.9, body="#7cb342", arm_l=1.6 + math.sin(t * 9) * 0.6,
           arm_r=2.2, legs=0.3)  # a general in uniform
    p.setBrush(QColor("#7cb342"))
    p.drawRect(QRectF(106 + lunge, 240, 28, 6))  # cap brim
    _stick(p, 176 - lunge, 340, scale=0.9, body="#a1887f", arm_l=-2.2, arm_r=-1.6 - math.sin(t * 9) * 0.6,
           legs=0.3)  # the ambassador
    if k < 2.5:
        p.setPen(QPen(QColor("#ffeb3b"), 2))
        for i in range(6):
            a = t * 6 + i
            c = QPointF(148, 250)
            p.drawLine(c + QPointF(math.cos(a) * 10, math.sin(a) * 10),
                       c + QPointF(math.cos(a) * 22, math.sin(a) * 22))
    # The President: bald, glasses, both hands up.
    px, py = 560.0, 342.0
    up = 2.6 + math.sin(t * 3) * 0.15
    _stick(p, px, py, scale=1.0, body="#90a4ae", arm_l=-up, arm_r=up, legs=0.2)
    p.setPen(QPen(QColor("#212121"), 2))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawEllipse(QPointF(px - 6, py - 93), 5, 4)
    p.drawEllipse(QPointF(px + 6, py - 93), 5, 4)
    if k > 0.8:
        _bubble(p, QRectF(320, 150, 300, 58), QPointF(px - 6, py - 108),
                "Gentlemen, you can't fight in here! This is the War Room!", 10.5)
    _caption(p, "President Merkin Muffley, the War Room", "Peace is our profession.")


# --------------------------------------------------------------------------- #
# 4. Armed Forces Radio, Saigon


def paint_vietnam(p: QPainter, t: float) -> None:
    # Wood-panelled studio, a window onto the booth, ON AIR light.
    p.fillRect(QRectF(0, 0, W, H), QColor("#5d4037"))
    p.setPen(QPen(QColor("#4e342e"), 2))
    for i in range(0, int(W), 48):
        p.drawLine(QPointF(i, 0), QPointF(i, H))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#263238"))
    p.drawRect(QRectF(470, 112, 210, 108))
    p.setBrush(QColor("#80cbc4"))
    p.drawRect(QRectF(478, 120, 194, 92))
    _stick(p, 575, 212, scale=0.75, body="#33691e", arm_l=-2.6, arm_r=2.6)  # the producer, despairing
    lit = int(t * 2) % 2 == 0
    p.setBrush(QColor("#d50000") if lit else QColor("#5d1a1a"))
    p.drawRoundedRect(QRectF(540, 74, 110, 32), 6, 6)
    f = QFont()
    f.setBold(True)
    f.setPointSizeF(14)
    p.setFont(f)
    p.setPen(QColor("#ffffff") if lit else QColor("#9e9e9e"))
    p.drawText(QRectF(540, 74, 110, 32), Qt.AlignmentFlag.AlignCenter, "ON AIR")
    # Desk with reel-to-reel and faders.
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#37474f"))
    p.drawRect(QRectF(0, H * 0.7, W, H))
    p.setBrush(QColor("#546e7a"))
    p.drawRect(QRectF(20, H * 0.7 - 8, W - 40, 12))
    for cx in (530.0, 610.0):
        p.setBrush(QColor("#212121"))
        p.drawEllipse(QPointF(cx, H * 0.7 - 34), 24, 24)
        p.setPen(QPen(QColor("#90a4ae"), 3))
        for k in range(3):
            a = t * 6 + k * 2.094
            p.drawLine(QPointF(cx, H * 0.7 - 34), QPointF(cx + 18 * math.cos(a), H * 0.7 - 34 + 18 * math.sin(a)))
        p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#ffca28"))
    for i in range(8):
        p.drawRect(QRectF(60 + i * 26, H * 0.7 + 18 + 10 * math.sin(t * 4 + i), 14, 8))
    # The DJ: Hawaiian shirt, headphones, leaning in, arms flung wide on the big one.
    shout = (t % 6) / 6.0
    arms = 0.8 + 1.6 * min(1.0, shout * 2.2)
    fx, fy = 240.0, H * 0.7 + 4
    body = QRectF(fx - 34, fy - 96, 68, 80)
    p.setBrush(QColor("#00897b"))
    p.drawRoundedRect(body, 16, 16)
    rnd = random.Random(2)
    for _ in range(14):  # flowers on the shirt
        c = QPointF(rnd.uniform(body.left() + 8, body.right() - 8), rnd.uniform(body.top() + 8, body.bottom() - 8))
        p.setBrush(QColor(rnd.choice(["#ffeb3b", "#ff7043", "#f06292", "#ffffff"])))
        for k in range(5):
            a = k * 1.2566
            p.drawEllipse(c + QPointF(4 * math.cos(a), 4 * math.sin(a)), 2.4, 2.4)
    p.setPen(QPen(QColor("#00897b"), 12, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    shoulder_l, shoulder_r = QPointF(fx - 28, fy - 84), QPointF(fx + 28, fy - 84)
    p.drawLine(shoulder_l, shoulder_l + QPointF(-46 * math.sin(arms), 46 * math.cos(arms)))  # 0 = down, pi = up
    p.drawLine(shoulder_r, shoulder_r + QPointF(46 * math.sin(arms), 46 * math.cos(arms)))
    p.setPen(Qt.PenStyle.NoPen)
    head = QPointF(fx + 6, fy - 122)
    p.setBrush(QColor("#f1c27d"))
    p.drawEllipse(head, 24, 26)
    p.setBrush(QColor("#4e342e"))
    p.drawChord(QRectF(head.x() - 24, head.y() - 28, 48, 30), 0, 180 * 16)  # hair
    p.setPen(QPen(QColor("#212121"), 5))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawArc(QRectF(head.x() - 28, head.y() - 34, 56, 50), 0, 180 * 16)  # headphones
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#212121"))
    p.drawRoundedRect(QRectF(head.x() - 32, head.y() - 10, 10, 18), 3, 3)
    p.drawRoundedRect(QRectF(head.x() + 22, head.y() - 10, 10, 18), 3, 3)
    mouth = 4 + 12 * min(1.0, shout * 2.2)
    p.setBrush(QColor("#b71c1c"))
    p.drawEllipse(QPointF(head.x() + 10, head.y() + 10), 7, mouth / 2 + 2)
    p.setBrush(QColor("#212121"))
    p.drawEllipse(QPointF(head.x() + 2, head.y() - 6), 2.5, 3)
    p.drawEllipse(QPointF(head.x() + 14, head.y() - 6), 2.5, 3)
    # The microphone, and the sound coming out of it.
    mic = QPointF(fx + 70, fy - 116)
    p.setBrush(QColor("#9e9e9e"))
    p.drawRect(QRectF(mic.x() - 2, mic.y(), 4, fy - mic.y()))
    p.setBrush(QColor("#cfd8dc"))
    p.drawRoundedRect(QRectF(mic.x() - 10, mic.y() - 18, 20, 30), 9, 9)
    p.setBrush(Qt.BrushStyle.NoBrush)
    for i in range(4):
        k = (t * 1.5 + i / 4) % 1.0
        p.setPen(QPen(QColor(255, 235, 59, int(220 * (1 - k))), 3))
        r = 20 + k * 120
        p.drawArc(QRectF(mic.x() - r, mic.y() - r, 2 * r, 2 * r), -40 * 16, 80 * 16)
    # The big one, typed out, the O's getting longer and longer.
    n_o = 2 + int(min(1.0, shout * 1.6) * 12)
    text = "G" + "O" * n_o + "D MORNING, VIETNAM!"
    big = QFont()
    big.setBold(True)
    big.setPointSizeF(26)
    p.setFont(big)
    shake = math.sin(t * 40) * (2 if shout > 0.3 else 0)
    p.setPen(QColor(0, 0, 0, 120))
    p.drawText(QRectF(13 + shake, 23, W - 20, 50), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, text)
    p.setPen(QColor("#ffeb3b"))
    p.drawText(QRectF(10 + shake, 20, W - 20, 50), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, text)
    _caption(p, "Adrian Cronauer, Armed Forces Radio, Saigon, 1965", "Rise and shine. It's 0600 hours.")


# --------------------------------------------------------------------------- #
# 5. A hotel in Torquay


def paint_torquay(p: QPainter, t: float) -> None:
    # Dining room: striped wallpaper, a picture rail, a table of appalled guests.
    p.fillRect(QRectF(0, 0, W, H), QColor("#efebe9"))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#d7ccc8"))
    for i in range(0, int(W), 40):
        p.drawRect(QRectF(i, 0, 18, H * 0.64))
    p.setBrush(QColor("#6d4c41"))
    p.drawRect(QRectF(0, 60, W, 6))
    p.setBrush(QColor("#8d6e63"))
    p.drawRect(QRectF(0, H * 0.64, W, H))
    p.setBrush(QColor("#a1887f"))
    for i in range(0, int(W), 60):
        p.drawRect(QRectF(i, H * 0.64, 30, H))
    p.setPen(QPen(QColor("#4e342e"), 3))
    p.setBrush(QColor("#fff8e1"))
    p.drawRect(QRectF(300, 90, 120, 80))  # a seaside painting
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#81d4fa"))
    p.drawRect(QRectF(306, 96, 108, 40))
    p.setBrush(QColor("#ffe082"))
    p.drawRect(QRectF(306, 136, 108, 28))
    # The guests, round a table, mouths open.
    p.setBrush(QColor("#ffffff"))
    p.drawEllipse(QRectF(470, 230, 220, 50))
    p.setBrush(QColor("#5d4037"))
    p.drawRect(QRectF(570, 262, 20, 70))
    for i, (gx, col) in enumerate(((490, "#1565c0"), (545, "#ad1457"), (615, "#2e7d32"), (670, "#6a1b9a"))):
        p.setBrush(QColor(col))
        p.drawRoundedRect(QRectF(gx - 16, 190, 32, 46), 8, 8)
        p.setBrush(QColor("#f1c27d"))
        head = QPointF(gx, 176)
        p.drawEllipse(head, 13, 14)
        p.setBrush(QColor("#212121"))
        gape = 3 + 3 * abs(math.sin(t * 2 + i))
        p.drawEllipse(QPointF(gx, 183), 4, gape)
        p.drawEllipse(QPointF(gx - 5, 172), 1.8, 1.8)
        p.drawEllipse(QPointF(gx + 5, 172), 1.8, 1.8)
        if (t + i) % 3 < 1.2:
            p.setPen(QPen(QColor("#e53935"), 2))
            p.drawText(QRectF(gx - 6, 140, 12, 20), Qt.AlignmentFlag.AlignCenter, "!")
            p.setPen(Qt.PenStyle.NoPen)
    # Our host: tall, thin, black suit, bandaged head, marching about the room
    # with a finger for a moustache.
    lap = (t * 0.18) % 1.0
    fx = 40 + (lap * 2 if lap < 0.5 else (1 - lap) * 2) * 330
    facing = 1 if lap < 0.5 else -1
    fy = H * 0.64 + 50
    step = t * 5
    kick_l = max(0.0, math.sin(step)) * 1.3
    kick_r = max(0.0, -math.sin(step)) * 1.3
    hip = QPointF(fx, fy - 70)
    p.setPen(QPen(QColor("#212121"), 7, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    for kick in (kick_l, kick_r):  # straight-legged kicks, high as he can
        p.drawLine(hip, hip + QPointF(facing * 70 * math.sin(kick), 70 * math.cos(kick)))
    neck = QPointF(fx, fy - 150)
    p.drawLine(hip, neck)
    p.setPen(QPen(QColor("#212121"), 6, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    swing = math.sin(step) * 0.9
    p.drawLine(neck + QPointF(0, 8), neck + QPointF(-facing * 40 * math.sin(swing + 0.3), 8 + 40 * math.cos(swing + 0.3)))
    hand = neck + QPointF(facing * 6, -6)  # the finger moustache
    p.drawLine(neck + QPointF(0, 8), neck + QPointF(facing * 20, 6))
    p.drawLine(neck + QPointF(facing * 20, 6), hand)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#ffffff"))
    p.drawRect(QRectF(fx - 5, neck.y() - 2, 10, 10))  # shirt collar
    head = QPointF(fx, neck.y() - 22)
    p.setBrush(QColor("#f1c27d"))
    p.drawEllipse(head, 14, 18)
    p.setBrush(QColor("#fafafa"))
    p.drawRoundedRect(QRectF(head.x() - 16, head.y() - 20, 32, 14), 6, 6)  # bandage
    p.drawEllipse(QPointF(head.x() - facing * 14, head.y() - 12), 6, 6)
    p.setBrush(QColor("#212121"))
    p.drawRect(QRectF(head.x() + facing * 2 - 7, head.y() + 4, 14, 3))  # finger as moustache
    p.drawEllipse(QPointF(head.x() + facing * 6, head.y() - 2), 2, 2)
    if (t % 6) > 2:
        _bubble(p, QRectF(60, 20, 220, 48), QPointF(head.x(), head.y() - 26), "Don't mention the war!", 12)
    _caption(p, "Basil Fawlty, a hotel in Torquay", "He mentioned it once. He thinks he got away with it.")


# --------------------------------------------------------------------------- #
# 6. A Roman balcony

ROME_CYCLE = 7.5  # the three lines from the balcony, then round again


def paint_rome(p: QPainter, t: float) -> None:
    sky = QLinearGradient(0, 0, 0, H)
    sky.setColorAt(0, QColor("#ffe0b2"))
    sky.setColorAt(1, QColor("#ffcc80"))
    p.fillRect(QRectF(0, 0, W, H), sky)
    # Palace wall, columns, the balcony.
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#f5f5dc"))
    p.drawRect(QRectF(0, 0, 330, H))
    p.setBrush(QColor("#e0dccb"))
    for cx in (30, 130, 230):
        p.drawRect(QRectF(cx, 0, 34, H * 0.55))
        p.drawRect(QRectF(cx - 6, 0, 46, 10))
    p.setBrush(QColor("#d7cfb5"))
    p.drawRect(QRectF(0, H * 0.55, 340, 16))
    for i in range(12):
        p.drawRoundedRect(QRectF(10 + i * 27, H * 0.55 + 16, 14, 38), 6, 6)
    p.drawRect(QRectF(0, H * 0.55 + 54, 340, 12))
    # The official, on the balcony: toga, laurel, a lisp, a straight face.
    ox, oy = 180.0, H * 0.55
    p.setBrush(QColor("#fafafa"))
    toga = QPainterPath(QPointF(ox - 34, oy))
    toga.lineTo(ox - 26, oy - 80)
    toga.lineTo(ox + 26, oy - 80)
    toga.lineTo(ox + 34, oy)
    toga.closeSubpath()
    p.drawPath(toga)
    p.setPen(QPen(QColor("#8e24aa"), 6))
    p.drawLine(QPointF(ox - 24, oy - 78), QPointF(ox + 30, oy - 4))  # purple sash
    p.setPen(QPen(QColor("#fafafa"), 10, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    gesture = 0.4 * math.sin(t * 2.5)
    p.drawLine(QPointF(ox + 22, oy - 70), QPointF(ox + 62, oy - 90 + 18 * gesture))
    p.setPen(Qt.PenStyle.NoPen)
    head = QPointF(ox, oy - 100)
    p.setBrush(QColor("#f1c27d"))
    p.drawEllipse(head, 18, 20)
    p.setBrush(QColor("#558b2f"))
    for i in range(7):
        a = math.pi * (0.95 + 1.1 * i / 6)
        p.drawEllipse(QPointF(head.x() + 18 * math.cos(a), head.y() - 4 + 14 * math.sin(a)), 5, 3)
    p.setBrush(QColor("#212121"))
    p.drawEllipse(QPointF(head.x() + 6, head.y() - 4), 2, 2)
    p.drawRect(QRectF(head.x() + 2, head.y() + 8, 10, 2))  # a perfectly straight face
    # Guards below, trying very, very hard not to laugh; one cracks.
    for i, gx in enumerate((420.0, 500.0, 580.0, 660.0)):
        gy = H * 0.86
        phase = t % ROME_CYCLE
        # One guard cracks at the scolding; another goes at the titter line.
        cracking = (i == 2 and phase > 2.5) or (i == 0 and phase > 5.8)
        shake = math.sin(t * (30 if cracking else 14) + i) * (4 if cracking else 1.5)
        p.setBrush(QColor("#b71c1c"))
        p.drawRoundedRect(QRectF(gx - 18 + shake, gy - 90, 36, 56), 6, 6)
        p.setBrush(QColor("#9e9e9e"))
        p.drawRect(QRectF(gx - 18 + shake, gy - 90, 36, 22))  # armour
        p.setPen(QPen(QColor("#5d4037"), 6, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawLine(QPointF(gx - 10, gy), QPointF(gx - 8 + shake, gy - 34))
        p.drawLine(QPointF(gx + 10, gy), QPointF(gx + 8 + shake, gy - 34))
        tilt = 0.9 if i == 2 and phase > 3.6 else 0.0
        p.setPen(QPen(QColor("#795548"), 3))
        top = QPointF(gx + 28 + 70 * math.sin(tilt), gy - 140 + 70 * (1 - math.cos(tilt)))
        p.drawLine(QPointF(gx + 28, gy - 10), top)  # spear (dropping, for one)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#9e9e9e"))
        p.drawEllipse(top, 4, 7)
        h = QPointF(gx + shake, gy - 106)
        p.setBrush(QColor("#f1c27d"))
        p.drawEllipse(h, 14, 15)
        p.setBrush(QColor("#9e9e9e"))
        p.drawChord(QRectF(h.x() - 16, h.y() - 20, 32, 26), 0, 180 * 16)  # helmet
        p.setBrush(QColor("#c62828"))
        p.drawRect(QRectF(h.x() - 3, h.y() - 30, 6, 12))  # plume
        p.setBrush(QColor("#212121"))
        if cracking:
            p.drawEllipse(QPointF(h.x(), h.y() + 6), 6, 5)  # bursts out laughing
            p.setPen(QPen(QColor("#4fc3f7"), 2))
            p.drawLine(QPointF(h.x() - 8, h.y() - 2), QPointF(h.x() - 12, h.y() + 8))
            p.drawLine(QPointF(h.x() + 8, h.y() - 2), QPointF(h.x() + 12, h.y() + 8))
            p.setPen(Qt.PenStyle.NoPen)
        else:
            p.drawRect(QRectF(h.x() - 6, h.y() + 5, 12, 2))  # lips pressed tight
            p.drawEllipse(QPointF(h.x() - 5, h.y() - 3), 1.5, 1.0)  # eyes screwed shut
            p.drawEllipse(QPointF(h.x() + 5, h.y() - 3), 1.5, 1.0)
    phase = t % ROME_CYCLE
    if phase < 2.4:
        _bubble(p, QRectF(250, 30, 300, 54), QPointF(head.x() + 16, head.y() - 18),
                "My fwiend, Biggus Dickus, is not funny!", 11)
    elif phase < 5.0:
        _bubble(p, QRectF(300, 30, 300, 54), QPointF(head.x() + 16, head.y() - 18),
                "Thtop thniggering, tholdier!", 12)
    else:
        _bubble(p, QRectF(250, 22, 440, 70), QPointF(head.x() + 16, head.y() - 18),
                "Anyone else feel like a little titter when I mention the name "
                "“Biggggus… Diccckus”?", 11)
    _caption(p, "A balcony in Jerusalem, 33 A.D.", "Nobody laughs at Biggus Dickus. Nobody.")


# --------------------------------------------------------------------------- #
# 7. A hotel in the mountains, winter


def paint_overlook(p: QPainter, t: float) -> None:
    """An axe through a bathroom door, and a grinning face in the hole."""
    cycle = t % 8.0
    hits = min(4, int(cycle / 1.0))  # the hole grows with each blow
    p.fillRect(QRectF(0, 0, W, H), QColor("#eceff1"))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#cfd8dc"))
    for i in range(0, int(W), 30):  # bathroom tiles
        for j in range(0, int(H), 30):
            if (i // 30 + j // 30) % 2:
                p.drawRect(QRectF(i, j, 30, 30))
    door = QRectF(250, 30, 260, 330)
    p.setBrush(QColor("#8d6e63"))
    p.drawRect(door)
    p.setBrush(QColor("#795548"))
    for r in (QRectF(270, 50, 220, 130), QRectF(270, 200, 220, 140)):
        p.drawRect(r)
    p.setBrush(QColor("#ffd54f"))
    p.drawEllipse(QPointF(490, 210), 8, 8)  # handle
    # The hole, splintered, bigger each blow.
    hole_c = QPointF(380, 120)
    hr = 12 + hits * 14
    hole = QPainterPath()
    for k in range(14):
        a = k * math.pi * 2 / 14
        r = hr * (0.75 + 0.35 * ((k * 7) % 5) / 4)
        pt = hole_c + QPointF(math.cos(a) * r * 1.2, math.sin(a) * r * 0.9)
        if k == 0:
            hole.moveTo(pt)
        else:
            hole.lineTo(pt)
    hole.closeSubpath()
    p.setBrush(QColor("#1b1b1b"))
    p.drawPath(hole)
    if hits >= 3:  # the face, wild eyebrows, enormous grin
        p.save()
        p.setClipPath(hole)
        face = hole_c + QPointF(0, 6)
        p.setBrush(QColor("#f1c27d"))
        p.drawEllipse(face, 38, 44)
        p.setBrush(QColor("#4e342e"))
        p.drawChord(QRectF(face.x() - 40, face.y() - 50, 80, 40), 0, 180 * 16)
        p.setPen(QPen(QColor("#212121"), 4))
        p.drawLine(QPointF(face.x() - 22, face.y() - 18), QPointF(face.x() - 6, face.y() - 10))
        p.drawLine(QPointF(face.x() + 22, face.y() - 18), QPointF(face.x() + 6, face.y() - 10))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#ffffff"))
        p.drawEllipse(QPointF(face.x() - 13, face.y() - 4), 6, 5)
        p.drawEllipse(QPointF(face.x() + 13, face.y() - 4), 6, 5)
        p.setBrush(QColor("#212121"))
        p.drawEllipse(QPointF(face.x() - 13 + math.sin(t * 3) * 2, face.y() - 4), 2.5, 2.5)
        p.drawEllipse(QPointF(face.x() + 13 + math.sin(t * 3) * 2, face.y() - 4), 2.5, 2.5)
        grin = QPainterPath(QPointF(face.x() - 22, face.y() + 12))
        grin.quadTo(face.x(), face.y() + 34, face.x() + 22, face.y() + 12)
        grin.closeSubpath()
        p.setBrush(QColor("#ffffff"))
        p.drawPath(grin)
        p.restore()
    # Splinters round the hole.
    p.setPen(QPen(QColor("#d7ccc8"), 2))
    for k in range(10):
        a = k * 0.63
        p.drawLine(hole_c + QPointF(math.cos(a) * hr * 1.1, math.sin(a) * hr * 0.85),
                   hole_c + QPointF(math.cos(a) * (hr * 1.1 + 10), math.sin(a) * (hr * 0.85 + 8)))
    # The axe, swinging in.
    swing = (cycle % 1.0)
    # Pulled back out of the way once the face is through (so we can see him).
    ang = -1.2 + 1.2 * min(1.0, swing * 3) if hits < 3 else -1.15 + math.sin(t * 4) * 0.08
    pivot = QPointF(560, 40)
    head = pivot + QPointF(-170 * math.cos(ang), 170 * math.sin(ang) + 70)
    p.setPen(QPen(QColor("#8d6e63"), 8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    p.drawLine(pivot, head)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#b0bec5"))
    blade = QPainterPath(head + QPointF(0, -18))
    blade.lineTo(head + QPointF(-34, -26))
    blade.quadTo(head + QPointF(-44, 0), head + QPointF(-34, 26))
    blade.lineTo(head + QPointF(0, 18))
    blade.closeSubpath()
    p.drawPath(blade)
    # The woman in the corner with a knife.
    _stick(p, 110, 340, scale=1.0, head="#f1c27d", body="#90a4ae", arm_l=-2.4, arm_r=2.2 + math.sin(t * 12) * 0.1)
    p.setBrush(QColor("#4e342e"))
    p.drawEllipse(QPointF(110, 236), 15, 10)
    p.setPen(QPen(QColor("#cfd8dc"), 3))
    p.drawLine(QPointF(130, 228), QPointF(146, 210))
    p.setPen(Qt.PenStyle.NoPen)
    if hits >= 3:
        _bubble(p, QRectF(500, 160, 200, 48), QPointF(415, 150), "Heeere's Johnny!", 13)
    _caption(p, "Jack Torrance, a mountain hotel, out of season", "All work and no play.")


# --------------------------------------------------------------------------- #
# 8. A courtroom in Washington


def paint_truth(p: QPainter, t: float) -> None:
    """A colonel on the witness stand, on his feet, roaring."""
    cycle = t % 7.0
    roar = min(1.0, max(0.0, (cycle - 2.0) / 0.8))
    p.fillRect(QRectF(0, 0, W, H), QColor("#d7ccc8"))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#a1887f"))
    for i in range(0, int(W), 80):
        p.drawRect(QRectF(i + 8, 0, 64, H * 0.55))  # wood panels
    p.setBrush(QColor("#1565c0"))
    p.drawRect(QRectF(40, 20, 50, 80))  # a flag
    p.setBrush(QColor("#ffffff"))
    for k in range(4):
        p.drawRect(QRectF(40, 30 + k * 18, 50, 6))
    # Judge's bench, high, with a gavel.
    p.setBrush(QColor("#5d4037"))
    p.drawRect(QRectF(260, 120, 200, 130))
    p.setBrush(QColor("#212121"))
    p.drawRoundedRect(QRectF(335, 60, 50, 64), 10, 10)  # robe
    p.setBrush(QColor("#f1c27d"))
    p.drawEllipse(QPointF(360, 52), 14, 15)
    p.setBrush(QColor("#212121"))
    p.drawEllipse(QPointF(355, 50), 2, 2 + roar)
    p.drawEllipse(QPointF(365, 50), 2, 2 + roar)
    g = -0.6 + (0.9 * abs(math.sin(t * 6)) if roar >= 1 else 0)
    p.setPen(QPen(QColor("#6d4c41"), 5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    p.drawLine(QPointF(390, 100), QPointF(390 + 26 * math.cos(g), 100 - 26 * math.sin(g)))
    p.setPen(Qt.PenStyle.NoPen)
    # The witness box, and the colonel in it: dress blues, ribbons, rising.
    p.setBrush(QColor("#6d4c41"))
    p.drawRect(QRectF(480, 220, 160, 90))
    rise = roar * 30
    cx, cy = 560.0, 230.0 - rise
    p.setBrush(QColor("#1a237e"))
    p.drawRoundedRect(QRectF(cx - 34, cy - 60, 68, 70), 10, 10)
    p.setBrush(QColor("#fdd835"))
    for k in range(5):
        p.drawEllipse(QPointF(cx - 22 + k * 5, cy - 24), 2, 2)  # buttons / brass
    for row in range(3):  # ribbons
        for k in range(3):
            p.setBrush(QColor(["#c62828", "#2e7d32", "#fdd835"][(row + k) % 3]))
            p.drawRect(QRectF(cx + 4 + k * 8, cy - 46 + row * 6, 7, 5))
    p.setPen(QPen(QColor("#1a237e"), 11, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    jab = math.sin(t * 7) * 0.25 * roar
    p.drawLine(QPointF(cx - 28, cy - 50), QPointF(cx - 70 - 10 * roar, cy - 50 - 30 * roar + 20 * jab))  # pointing
    p.setPen(Qt.PenStyle.NoPen)
    head = QPointF(cx, cy - 82)
    p.setBrush(QColor("#f1c27d"))
    p.drawEllipse(head, 20, 23)
    p.setBrush(QColor("#5d4037"))
    p.drawChord(QRectF(head.x() - 20, head.y() - 24, 40, 18), 0, 180 * 16)
    p.setPen(QPen(QColor("#212121"), 3))
    p.drawLine(QPointF(head.x() - 14, head.y() - 10 + 3 * roar), QPointF(head.x() - 3, head.y() - 6))
    p.drawLine(QPointF(head.x() + 14, head.y() - 10 + 3 * roar), QPointF(head.x() + 3, head.y() - 6))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#b71c1c"))
    p.drawEllipse(QPointF(head.x(), head.y() + 10), 6 + 3 * roar, 2 + 7 * roar)
    # The young lawyer in navy whites, standing his ground.
    _stick(p, 190, 340, scale=1.0, body="#fafafa", arm_l=-0.3, arm_r=0.5)
    p.setBrush(QColor("#5d4037"))
    p.drawChord(QRectF(176, 234, 28, 18), 0, 180 * 16)
    if 0.6 < cycle < 2.0:
        _bubble(p, QRectF(20, 120, 200, 48), QPointF(190, 230), "I want the truth!", 12)
    if roar >= 1:
        _bubble(p, QRectF(250, 260, 230, 52), QPointF(head.x() - 20, head.y() + 10),
                "You can't handle the truth!", 12.5)
    _caption(p, "Col. Nathan R. Jessup, a courtroom in Washington", "Asked one question too many.")


# --------------------------------------------------------------------------- #
# 9. A harbour in the Caribbean


def paint_pirate(p: QPainter, t: float) -> None:
    """A captain arrives in port, standing tall on a dinghy that sinks under him."""
    cycle = t % 9.0
    sink = min(1.0, max(0.0, (cycle - 1.0) / 6.0))
    sky = QLinearGradient(0, 0, 0, H * 0.6)
    sky.setColorAt(0, QColor("#4fc3f7"))
    sky.setColorAt(1, QColor("#e1f5fe"))
    p.fillRect(QRectF(0, 0, W, H), sky)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#fff176"))
    p.drawEllipse(QPointF(620, 60), 34, 34)
    sea_y = H * 0.6
    # The dock on the right.
    p.setBrush(QColor("#6d4c41"))
    p.drawRect(QRectF(520, sea_y - 24, 220, 18))
    for px in (540, 600, 660, 720):
        p.drawRect(QRectF(px, sea_y - 24, 10, 90))
    _stick(p, 650, sea_y - 24, scale=0.8, body="#3949ab", arm_l=-0.4, arm_r=0.4)  # harbourmaster
    p.setBrush(QColor("#ffffff"))
    p.drawRoundedRect(QRectF(600, sea_y - 150, 120, 36), 8, 8)
    f = QFont()
    f.setBold(True)
    f.setPointSizeF(8.5)
    p.setFont(f)
    p.setPen(QColor("#212121"))
    p.drawText(QRectF(600, sea_y - 150, 120, 36), Qt.AlignmentFlag.AlignCenter, "Mooring: 1 shilling.\nAnd your name?")
    p.setPen(Qt.PenStyle.NoPen)
    # The dinghy drifts in as it sinks; the captain stays perfectly upright.
    bx = 90 + 340 * min(1.0, cycle / 7.0)
    hull_y = sea_y - 18 + sink * 46
    p.setBrush(QColor("#8d6e63"))
    hull = QPainterPath(QPointF(bx - 70, hull_y))
    hull.lineTo(bx + 70, hull_y)
    hull.lineTo(bx + 52, hull_y + 26)
    hull.lineTo(bx - 52, hull_y + 26)
    hull.closeSubpath()
    p.drawPath(hull)
    mast_top = hull_y - 120
    p.setBrush(QColor("#5d4037"))
    p.drawRect(QRectF(bx - 3, mast_top, 6, 120))
    p.setBrush(QColor("#efebe9"))
    sail = QPainterPath(QPointF(bx + 3, mast_top + 8))
    sail.quadTo(bx + 46 + math.sin(t * 2) * 4, mast_top + 50, bx + 3, mast_top + 92)
    sail.closeSubpath()
    p.drawPath(sail)
    # Captain on the mast's yard: tricorn, dreadlocks, beads, a little sway.
    sway = math.sin(t * 2.4) * 0.12
    cx, cy = bx - 26, hull_y - 2
    _stick(p, cx, cy, scale=0.95, body="#5d4037", arm_l=-0.9 + sway, arm_r=1.1 - sway, legs=0.15)
    head = QPointF(cx, cy - 87)
    p.setBrush(QColor("#3e2723"))
    for k, dx in enumerate((-19, -15, -11, 9, 13, 17)):  # dreadlocks, either side of the face
        p.drawRoundedRect(QRectF(head.x() + dx, head.y() - 4, 3, 24 + (k % 3) * 4), 1.5, 1.5)
    p.setBrush(QColor("#c62828"))
    p.drawRect(QRectF(head.x() - 13, head.y() - 14, 26, 6))  # bandana
    p.setBrush(QColor("#212121"))
    tri = QPainterPath(QPointF(head.x() - 24, head.y() - 12))
    tri.quadTo(head.x(), head.y() - 40, head.x() + 24, head.y() - 12)
    tri.quadTo(head.x(), head.y() - 20, head.x() - 24, head.y() - 12)
    p.drawPath(tri)  # tricorn
    p.drawRect(QRectF(head.x() - 6, head.y() + 8, 12, 2))  # moustache
    p.drawRect(QRectF(head.x() - 2, head.y() + 11, 4, 6))  # braided beard
    # The sea comes up over the hull.
    p.setBrush(QColor(2, 119, 189, 220))
    wave = QPainterPath(QPointF(0, sea_y))
    for x in range(0, int(W) + 20, 20):
        wave.lineTo(x, sea_y + math.sin(x / 40 + t * 2) * 4)
    wave.lineTo(W, H)
    wave.lineTo(0, H)
    wave.closeSubpath()
    p.drawPath(wave)
    if cycle > 6.8:  # steps off onto the dock just as the mast goes under
        _bubble(p, QRectF(200, 40, 280, 54), QPointF(head.x() + 8, head.y() - 30),
                "That's CAPTAIN Jack Sparrow, savvy?", 11.5)
    _caption(p, "Captain Jack Sparrow, arriving at Port Royal", "Never mind the boat.")


# --------------------------------------------------------------------------- #
# 10. A bridge in a forest, Britain, 932 A.D.


def _forest(p: QPainter) -> float:
    sky = QLinearGradient(0, 0, 0, H * 0.6)
    sky.setColorAt(0, QColor("#b3e5fc"))
    sky.setColorAt(1, QColor("#e8f5e9"))
    p.fillRect(QRectF(0, 0, W, H), sky)
    p.setPen(Qt.PenStyle.NoPen)
    rnd = random.Random(4)
    for _ in range(14):
        x = rnd.uniform(-20, W)
        p.setBrush(QColor("#5d4037"))
        p.drawRect(QRectF(x + 18, H * 0.3, 12, H * 0.35))
        p.setBrush(QColor(rnd.choice(["#2e7d32", "#388e3c", "#1b5e20"])))
        p.drawEllipse(QPointF(x + 24, H * 0.28), 40, 50)
    ground = H * 0.72
    p.setBrush(QColor("#7cb342"))
    p.drawRect(QRectF(0, ground, W, H))
    return ground


def paint_black_knight(p: QPainter, t: float) -> None:
    """The Black Knight loses a limb at a time and will not give up."""
    ground = _forest(p)
    cycle = t % 11.0
    lost = sum(cycle > k for k in (1.5, 3.5, 5.5, 7.5))  # left arm, right arm, left leg, right leg
    # Arthur: crown, white tunic with a red cross, sword swinging at each blow.
    ax, ay = 210.0, ground + 30
    blow = any(abs(cycle - k) < 0.35 for k in (1.5, 3.5, 5.5, 7.5))
    sword = -0.2 if blow else 1.2 + math.sin(t * 2) * 0.1
    _stick(p, ax, ay, scale=1.1, body="#eeeeee", arm_l=-0.5, arm_r=sword, legs=0.25)
    p.setBrush(QColor("#fafafa"))
    p.drawRoundedRect(QRectF(ax - 18, ay - 86, 36, 46), 6, 6)
    p.setBrush(QColor("#c62828"))
    p.drawRect(QRectF(ax - 3, ay - 84, 6, 42))
    p.drawRect(QRectF(ax - 15, ay - 70, 30, 6))
    p.setBrush(QColor("#fdd835"))
    crown = QPainterPath(QPointF(ax - 14, ay - 112))
    for i, dx in enumerate((-14, -9, -4, 0, 4, 9, 14)):
        crown.lineTo(ax + dx, ay - (126 if i % 2 else 112))
    crown.lineTo(ax + 14, ay - 108)
    crown.lineTo(ax - 14, ay - 108)
    crown.closeSubpath()
    p.drawPath(crown)
    hand = QPointF(ax, ay - 85) + QPointF(35 * math.sin(sword), 7 + 35 * math.cos(sword))
    tip = hand + QPointF(60 * math.sin(sword + 0.9), 60 * math.cos(sword + 0.9))
    p.setPen(QPen(QColor("#b0bec5"), 4))
    p.drawLine(hand, tip)
    p.setPen(Qt.PenStyle.NoPen)
    # The Black Knight. Without legs he sits on the ground and hops about.
    kx = 470.0 + (math.sin(t * 6) * 10 if lost == 4 else 0)
    ky = ground + 30 - (abs(math.sin(t * 6)) * 14 if lost == 4 else 0)
    hip_y = ky - (0 if lost == 4 else 48)
    torso = QRectF(kx - 22, hip_y - 62, 44, 62)
    black = QColor("#212121")
    p.setPen(QPen(black, 9, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    if lost < 3:
        p.drawLine(QPointF(kx - 10, hip_y), QPointF(kx - 16, ky))
    if lost < 4:
        p.drawLine(QPointF(kx + 10, hip_y), QPointF(kx + 16, ky))
    shoulder = QPointF(kx, hip_y - 56)
    if lost < 1:
        p.drawLine(shoulder + QPointF(-18, 0), shoulder + QPointF(-46, 24 + math.sin(t * 5) * 8))
    if lost < 2:
        p.drawLine(shoulder + QPointF(18, 0), shoulder + QPointF(50, -20 + math.sin(t * 5) * 10))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(black)
    p.drawRoundedRect(torso, 8, 8)
    p.setBrush(QColor("#424242"))
    p.drawRoundedRect(QRectF(kx - 16, hip_y - 92, 32, 32), 6, 6)  # helmet
    p.setBrush(QColor("#000000"))
    p.drawRect(QRectF(kx - 12, hip_y - 80, 24, 4))  # visor slit
    # Lost limbs lying about (no gore: it's only a flesh wound).
    p.setPen(QPen(black, 9, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    pieces = [((560, ground + 40), (600, ground + 34)), ((590, ground + 52), (630, ground + 58)),
              ((380, ground + 46), (410, ground + 62)), ((350, ground + 56), (390, ground + 50))]
    for (a, b) in pieces[:lost]:
        p.drawLine(QPointF(*a), QPointF(*b))
    p.setPen(Qt.PenStyle.NoPen)
    if blow:
        p.setPen(QPen(QColor("#ffeb3b"), 2))
        for i in range(6):
            a = i + t * 8
            c = QPointF(kx - 20, hip_y - 50)
            p.drawLine(c + QPointF(math.cos(a) * 8, math.sin(a) * 8), c + QPointF(math.cos(a) * 18, math.sin(a) * 18))
        p.setPen(Qt.PenStyle.NoPen)
    lines = {0: "None shall pass.", 1: "'Tis but a scratch!", 2: "It's just a flesh wound.",
             3: "I'm invincible!", 4: "All right, we'll call it a draw."}
    _bubble(p, QRectF(400, 40, 280, 50), QPointF(kx + 10, hip_y - 96), lines[lost], 12)
    _caption(p, "King Arthur meets the Black Knight", "None shall pass. Not even, it turns out, the Black Knight.")


# --------------------------------------------------------------------------- #
# 11. Riding (sort of) through Britain


def paint_coconuts(p: QPainter, t: float) -> None:
    """A king 'gallops' along on foot; his servant bangs two coconut halves behind him."""
    sky = QLinearGradient(0, 0, 0, H * 0.6)
    sky.setColorAt(0, QColor("#90a4ae"))
    sky.setColorAt(1, QColor("#eceff1"))
    p.fillRect(QRectF(0, 0, W, H), sky)
    p.setPen(Qt.PenStyle.NoPen)
    off = (t * 60) % 300
    p.setBrush(QColor("#8bc34a"))
    for k in range(-1, 4):  # rolling hills scrolling past
        p.drawEllipse(QPointF(k * 300 - off, H * 0.7), 220, 90)
    p.setBrush(QColor("#689f38"))
    p.drawRect(QRectF(0, H * 0.7, W, H))
    # A castle on the hill, with a sentry.
    p.setBrush(QColor("#9e9e9e"))
    p.drawRect(QRectF(560, 120, 120, 120))
    for i in range(5):
        p.drawRect(QRectF(560 + i * 26, 106, 16, 16))
    p.drawRect(QRectF(540, 90, 30, 150))
    p.drawRect(QRectF(670, 90, 30, 150))
    p.setBrush(QColor("#5d4037"))
    p.drawRoundedRect(QRectF(600, 190, 40, 50), 18, 18)
    p.setBrush(QColor("#f1c27d"))
    p.drawEllipse(QPointF(620, 96), 10, 11)
    p.setBrush(QColor("#9e9e9e"))
    p.drawChord(QRectF(608, 82, 24, 18), 0, 180 * 16)
    # The king, "riding": knees up, bobbing, holding imaginary reins.
    gal = t * 9
    kx = 230.0
    ky = H * 0.72 + 16 - abs(math.sin(gal)) * 16
    _stick(p, kx, ky, scale=1.05, body="#e0e0e0", arm_l=-1.9, arm_r=1.9, legs=0.55 * math.sin(gal))
    p.setBrush(QColor("#fafafa"))
    p.drawRoundedRect(QRectF(kx - 17, ky - 82, 34, 42), 6, 6)
    p.setBrush(QColor("#c62828"))
    p.drawRect(QRectF(kx - 3, ky - 80, 6, 38))
    p.setBrush(QColor("#fdd835"))
    p.drawRect(QRectF(kx - 13, ky - 112, 26, 8))
    for dx in (-12, -2, 8):
        p.drawRect(QRectF(kx + dx, ky - 120, 4, 8))
    # His servant behind, bent under the bags, clacking two coconut halves.
    sx = 130.0
    sy = H * 0.72 + 16 - abs(math.sin(gal + 0.6)) * 10
    clap = abs(math.sin(gal))
    _stick(p, sx, sy, scale=0.95, body="#795548", arm_l=-1.6 + clap * 0.4, arm_r=1.6 - clap * 0.4,
           legs=0.5 * math.sin(gal + 0.6))
    p.setBrush(QColor("#a1887f"))
    p.drawRoundedRect(QRectF(sx - 34, sy - 96, 26, 40), 6, 6)  # the luggage
    p.setBrush(QColor("#6d4c41"))
    neck = QPointF(sx, sy - 74)
    for side in (-1, 1):
        hand = neck + QPointF(side * 30 * (1 - clap * 0.5), -6)
        p.drawChord(QRectF(hand.x() - 9, hand.y() - 9, 18, 18), (0 if side < 0 else 180) * 16 + 90 * 16, 180 * 16)
    if clap < 0.2:
        f = QFont()
        f.setBold(True)
        f.setPointSizeF(13)
        p.setFont(f)
        p.setPen(QColor("#4e342e"))
        p.drawText(QPointF(sx - 30 + (int(t * 4) % 3) * 12, sy - 130), "clop!")
        p.setPen(Qt.PenStyle.NoPen)
    if (t % 8) > 3:
        _bubble(p, QRectF(330, 20, 300, 54), QPointF(620, 84), "Where'd you get the coconuts?", 12)
    _caption(p, "King Arthur, riding through Britain", "On a horse made entirely of coconuts.")


# --------------------------------------------------------------------------- #
# 12. Somewhere over the Rockies


def paint_shirley(p: QPainter, t: float) -> None:
    """In the aisle of an airliner: a doctor, a very serious face, and the inflatable autopilot."""
    p.fillRect(QRectF(0, 0, W, H), QColor("#eceff1"))
    p.setPen(Qt.PenStyle.NoPen)
    # Cabin wall with windows and clouds sliding by.
    p.setBrush(QColor("#cfd8dc"))
    p.drawRect(QRectF(0, 0, W, 150))
    for i in range(6):
        win = QRectF(30 + i * 115, 40, 54, 70)
        p.setBrush(QColor("#81d4fa"))
        p.drawRoundedRect(win, 22, 22)
        p.save()
        p.setClipRect(win)
        p.setBrush(QColor("#ffffff"))
        cx = win.left() + 80 - ((t * 90 + i * 37) % 140)
        p.drawEllipse(QPointF(cx, win.top() + 40), 20, 10)
        p.restore()
    # Seats in rows.
    for i in range(6):
        p.setBrush(QColor("#1565c0"))
        p.drawRoundedRect(QRectF(20 + i * 115, 170, 70, 90), 10, 10)
        p.setBrush(QColor("#0d47a1"))
        p.drawRect(QRectF(20 + i * 115, 250, 70, 14))
    p.setBrush(QColor("#b0bec5"))
    p.drawRect(QRectF(0, H * 0.72, W, H))
    # The cockpit door on the right; the inflatable autopilot waving through it.
    p.setBrush(QColor("#90a4ae"))
    p.drawRect(QRectF(640, 120, 80, 180))
    p.setBrush(QColor("#ffcc80"))
    otto = QPointF(680, 170 + math.sin(t * 2) * 3)
    p.drawEllipse(otto, 18, 20)
    p.setBrush(QColor("#d84315"))
    p.drawEllipse(QPointF(otto.x(), otto.y() + 8), 6, 6)  # round, astonished mouth
    p.setBrush(QColor("#212121"))
    p.drawEllipse(QPointF(otto.x() - 6, otto.y() - 4), 2, 2)
    p.drawEllipse(QPointF(otto.x() + 6, otto.y() - 4), 2, 2)
    p.setBrush(QColor("#1a237e"))
    p.drawRect(QRectF(otto.x() - 20, otto.y() - 24, 40, 6))  # pilot's cap
    # The worried passenger and the doctor, deadpan.
    _stick(p, 240, H * 0.72 + 30, scale=1.0, body="#6a1b9a", arm_l=-2.0, arm_r=2.0 + math.sin(t * 6) * 0.2)
    _stick(p, 420, H * 0.72 + 30, scale=1.05, body="#37474f", arm_l=-0.2, arm_r=0.2)
    p.setBrush(QColor("#eeeeee"))
    p.drawChord(QRectF(406, H * 0.72 + 30 - 112, 28, 18), 0, 180 * 16)  # white hair
    cycle = t % 7.0
    if 0.6 < cycle < 3.0:
        _bubble(p, QRectF(60, 40, 260, 50), QPointF(240, H * 0.72 - 74), "Surely you can't be serious.", 12)
    if cycle >= 3.0:
        _bubble(p, QRectF(280, 30, 340, 54), QPointF(420, H * 0.72 - 74),
                "I am serious. And don't call me Shirley.", 12)
    _caption(p, "Flight 209, somewhere over the Rockies", "Whatever you do, don't have the fish.")


# --------------------------------------------------------------------------- #
# 13. Police Squad!


def paint_nothing_to_see(p: QPainter, t: float) -> None:
    """A fireworks factory goes up behind a detective telling everyone to move along."""
    p.fillRect(QRectF(0, 0, W, H), QColor("#0d1b2a"))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#37474f"))
    p.drawRect(QRectF(380, 150, 300, 140))  # the factory
    p.drawRect(QRectF(420, 100, 30, 60))
    p.drawRect(QRectF(600, 90, 30, 70))
    f = QFont()
    f.setBold(True)
    f.setPointSizeF(10)
    p.setFont(f)
    p.setPen(QColor("#ffeb3b"))
    p.drawText(QRectF(380, 160, 300, 24), Qt.AlignmentFlag.AlignCenter, "ACME FIREWORKS — NO SMOKING")
    p.setPen(Qt.PenStyle.NoPen)
    for w in range(6):  # windows flashing
        lit = int(t * 8 + w * 3) % 3 == 0
        p.setBrush(QColor("#ff9100") if lit else QColor("#ffd54f"))
        p.drawRect(QRectF(400 + w * 46, 210, 26, 30))
    # Rockets, bursts, a Catherine wheel on the roof.
    rnd = random.Random(9)
    for i in range(10):
        period = rnd.uniform(1.6, 2.6)
        k = ((t + i * 0.37) % period) / period
        x0 = rnd.uniform(400, 660)
        peak = rnd.uniform(30, 120)
        col = QColor(rnd.choice(["#ff5252", "#69f0ae", "#40c4ff", "#ffd740", "#e040fb", "#ffffff"]))
        if k < 0.45:
            y = 150 - (150 - peak) * (k / 0.45)
            p.setBrush(col)
            p.drawEllipse(QPointF(x0, y), 2.5, 2.5)
        else:
            r = (k - 0.45) / 0.55 * 46
            col.setAlpha(int(255 * (1 - (k - 0.45) / 0.55)))
            p.setPen(QPen(col, 2))
            for j in range(12):
                a = j * math.pi / 6
                p.drawLine(QPointF(x0 + math.cos(a) * r * 0.4, peak + math.sin(a) * r * 0.4),
                           QPointF(x0 + math.cos(a) * r, peak + math.sin(a) * r))
            p.setPen(Qt.PenStyle.NoPen)
    wheel = QPointF(615, 90)
    for j in range(8):
        a = t * 10 + j * math.pi / 4
        p.setBrush(QColor(255, 200, 0, 200))
        p.drawEllipse(wheel + QPointF(math.cos(a) * 16, math.sin(a) * 16), 3, 3)
    # Crowd watching from behind the tape.
    p.setBrush(QColor("#263238"))
    p.drawRect(QRectF(0, H * 0.72, W, H))
    p.setPen(QPen(QColor("#ffeb3b"), 4))
    p.drawLine(QPointF(0, H * 0.72 + 6), QPointF(W, H * 0.72 + 6))  # police tape
    p.setPen(Qt.PenStyle.NoPen)
    for i in range(7):
        cx = 360 + i * 50
        p.setBrush(QColor("#546e7a"))
        p.drawEllipse(QPointF(cx, H * 0.72 + 30), 14, 18)
        p.setBrush(QColor("#f1c27d"))
        p.drawEllipse(QPointF(cx, H * 0.72 + 6), 9, 10)
    # The detective, arms out, utterly calm, lit by the explosions.
    dx = 190.0
    _stick(p, dx, H * 0.72 + 40, scale=1.15, body="#455a64",
           arm_l=-1.6 - math.sin(t * 3) * 0.15, arm_r=1.6 + math.sin(t * 3) * 0.15)
    p.setBrush(QColor("#eeeeee"))
    p.drawChord(QRectF(dx - 15, H * 0.72 + 40 - 124, 30, 20), 0, 180 * 16)
    _bubble(p, QRectF(30, 30, 300, 54), QPointF(dx, H * 0.72 - 84), "Nothing to see here! Please disperse!", 12)
    _caption(p, "Lt. Frank Drebin, Police Squad!", "Special crimes. Very special.")


# --------------------------------------------------------------------------- #
# 14. The catwalk


def paint_catwalk(p: QPainter, t: float) -> None:
    """A model reaches the end of the runway, can't turn left, and goes round to the right."""
    p.fillRect(QRectF(0, 0, W, H), QColor("#120d1e"))
    p.setPen(Qt.PenStyle.NoPen)
    for i, lx in enumerate((120, 360, 600)):  # spotlights
        sweep = math.sin(t * 1.2 + i) * 60
        beam = QPainterPath(QPointF(lx, 0))
        beam.lineTo(360 + sweep - 70, H * 0.8)
        beam.lineTo(360 + sweep + 70, H * 0.8)
        beam.closeSubpath()
        p.setBrush(QColor(255, 255, 255, 26))
        p.drawPath(beam)
    # The runway, in perspective, and flashing cameras either side.
    run = QPainterPath(QPointF(320, 120))
    run.lineTo(400, 120)
    run.lineTo(520, H * 0.86)
    run.lineTo(200, H * 0.86)
    run.closeSubpath()
    p.setBrush(QColor("#f5f5f5"))
    p.drawPath(run)
    rnd = random.Random(6)
    for i in range(12):
        side = -1 if i % 2 else 1
        x = 360 + side * rnd.uniform(200, 330)
        y = rnd.uniform(160, 330)
        p.setBrush(QColor("#424242"))
        p.drawEllipse(QPointF(x, y), 14, 16)
        if int(t * 5 + i * 1.7) % 6 == 0:
            p.setBrush(QColor(255, 255, 255, 230))
            p.drawEllipse(QPointF(x + side * -10, y - 10), 12, 12)
    # The model at the end of the runway: spins right, right, right…
    cycle = t % 6.0
    spin = 0.0 if cycle < 1.5 else (cycle - 1.5) / 4.5 * 3 * 2 * math.pi  # three turns to the right
    mx, my = 360.0, H * 0.8
    facing = math.cos(spin)
    width = max(0.25, abs(facing))
    p.save()
    p.translate(mx, my)
    p.scale(width, 1.0)
    _stick(p, 0, 0, scale=1.25, body="#9c27b0", arm_l=-0.3, arm_r=0.3, legs=0.15)
    p.setBrush(QColor("#ffca28"))
    p.drawChord(QRectF(-18, -134, 36, 26), 0, 180 * 16)  # hair, very done
    if facing > 0.2:  # the look: pout, eyebrow, smoulder
        p.setBrush(QColor("#212121"))
        p.drawRect(QRectF(-12, -122, 8, 2))
        p.drawRect(QRectF(4, -124, 8, 2))
        p.setBrush(QColor("#d81b60"))
        p.drawEllipse(QPointF(0, -106), 5, 3)
    p.restore()
    if cycle < 1.5:
        _bubble(p, QRectF(420, 40, 260, 50), QPointF(380, H * 0.8 - 150), "Blue Steel.", 13)
    else:
        _bubble(p, QRectF(420, 40, 260, 50), QPointF(380, H * 0.8 - 150), "I'm not an ambi-turner.", 12)
    _caption(p, "Derek Zoolander, end of the runway", "He can't turn left.")


# --------------------------------------------------------------------------- #
# 15. Brave Sir Robin


def _minstrel(p: QPainter, x: float, y: float, t: float, instrument: str) -> None:
    bob = abs(math.sin(t * 8 + x)) * 4
    _stick(p, x, y - bob, scale=0.85, body="#8e24aa", arm_l=-1.2 + math.sin(t * 10) * 0.3, arm_r=1.0, legs=0.3 * math.sin(t * 8))
    p.setBrush(QColor("#ab47bc"))
    p.drawChord(QRectF(x - 14, y - bob - 98, 28, 18), 0, 180 * 16)  # floppy hat
    if instrument == "lute":
        p.setBrush(QColor("#a1887f"))
        p.drawEllipse(QPointF(x + 16, y - bob - 46), 11, 14)
        p.setPen(QPen(QColor("#6d4c41"), 3))
        p.drawLine(QPointF(x + 16, y - bob - 58), QPointF(x + 34, y - bob - 80))
        p.setPen(Qt.PenStyle.NoPen)
    else:
        p.setBrush(QColor("#ef5350"))
        p.drawRect(QRectF(x + 6, y - bob - 54, 22, 16))
        p.setBrush(QColor("#fafafa"))
        p.drawEllipse(QRectF(x + 6, y - bob - 58, 22, 8))
    f = QFont()
    f.setPointSizeF(14)
    p.setFont(f)
    p.setPen(QColor("#6a1b9a"))
    for i in range(3):
        k = (t * 0.9 + i / 3) % 1.0
        c = QColor("#6a1b9a")
        c.setAlpha(int(255 * (1 - k)))
        p.setPen(c)
        p.drawText(QPointF(x + 10 + i * 10 + math.sin(k * 6) * 6, y - bob - 100 - k * 50), "♪")
    p.setPen(Qt.PenStyle.NoPen)


def paint_sir_robin(p: QPainter, t: float) -> None:
    """Sir Robin sets off bravely, meets a three-headed knight, and bravely runs away,
    his minstrels following, singing about it."""
    ground = _forest(p)
    cycle = t % 10.0
    gy = ground + 34
    # Sir Robin: marches right, freezes at the knight, then legs it left.
    if cycle < 3.0:
        rx, legs, arms = 200 + cycle * 50, 0.35 * math.sin(t * 6), (-0.3, 0.3)
    elif cycle < 4.2:
        rx, legs, arms = 350.0, 0.0, (-2.6, 2.6)  # aghast
    else:
        rx = 350 - (cycle - 4.2) * 160
        legs, arms = 0.8 * math.sin(t * 22), (-1.8, 1.8)
    p.setPen(Qt.PenStyle.NoPen)
    if cycle >= 4.2:  # a dust cloud behind the fleeing knight
        p.setBrush(QColor(161, 136, 127, 140))
        for i in range(5):
            p.drawEllipse(QPointF(rx + 30 + i * 18, gy - 8 - (i % 2) * 6), 14 - i, 10 - i)
    _stick(p, rx, gy, scale=1.0, body="#9e9e9e", arm_l=arms[0], arm_r=arms[1], legs=legs)
    p.setBrush(QColor("#bdbdbd"))
    p.drawRoundedRect(QRectF(rx - 16, gy - 80, 32, 40), 6, 6)  # armour
    p.setBrush(QColor("#1565c0"))
    p.drawRect(QRectF(rx - 4, gy - 78, 8, 36))
    p.setBrush(QColor("#9e9e9e"))
    p.drawChord(QRectF(rx - 15, gy - 108, 30, 26), 0, 180 * 16)  # helmet
    if 3.0 <= cycle < 4.2:  # jaw drops
        p.setBrush(QColor("#212121"))
        p.drawEllipse(QPointF(rx, gy - 86), 4, 5)
    # The three-headed knight, very large, arguing with himself.
    if cycle >= 2.6:
        kx, ky = 590.0, gy
        _stick(p, kx, ky, scale=1.5, body="#4e342e", arm_l=-0.8, arm_r=0.8 + math.sin(t * 3) * 0.2)
        p.setBrush(QColor("#5d4037"))
        p.drawRoundedRect(QRectF(kx - 30, ky - 126, 60, 66), 10, 10)
        for i, dx in enumerate((-30, 0, 30)):
            hy = ky - 152 - (6 if i == 1 else 0)
            p.setBrush(QColor("#f1c27d"))
            p.drawEllipse(QPointF(kx + dx, hy), 14, 15)
            p.setBrush(QColor("#212121"))
            p.drawEllipse(QPointF(kx + dx - 4, hy - 2), 2, 2)
            p.drawEllipse(QPointF(kx + dx + 4, hy - 2), 2, 2)
            mouth = 2 + 3 * abs(math.sin(t * 7 + i))
            p.drawEllipse(QPointF(kx + dx, hy + 7), 4, mouth)
        if 2.8 < cycle < 4.4:
            _bubble(p, QRectF(470, 20, 230, 46), QPointF(kx, ky - 170), "Shall we kill him? / No! / Yes!", 10.5)
    # The minstrels, a few paces behind Robin the whole time.
    behind = 1 if cycle < 4.2 else -1
    _minstrel(p, rx - behind * 90, gy, t, "lute")
    _minstrel(p, rx - behind * 150, gy, t + 0.4, "drum")
    if cycle < 2.6:
        _bubble(p, QRectF(30, 20, 300, 50), QPointF(rx - 90, gy - 120), "♪ Bravely bold Sir Robin rode forth… ♪", 11)
    elif cycle >= 4.4:
        _bubble(p, QRectF(140, 20, 360, 50), QPointF(max(40, rx + 90), gy - 120),
                "♪ …and bravely, bravely, he turned and ran! ♪", 11)
    _caption(p, "Brave Sir Robin, on the quest for the Grail", "Bravest of the brave. Briefly.")


SCENES: dict[str, Callable[[QPainter, float], None]] = {
    "harlem": paint_harlem,
    "bat country": paint_bat_country,
    "war room": paint_war_room,
    "vietnam": paint_vietnam,
    "torquay": paint_torquay,
    "rome": paint_rome,
    "overlook": paint_overlook,
    "truth": paint_truth,
    "port royal": paint_pirate,
    "black knight": paint_black_knight,
    "coconuts": paint_coconuts,
    "shirley": paint_shirley,
    "nothing to see": paint_nothing_to_see,
    "catwalk": paint_catwalk,
    "sir robin": paint_sir_robin,
}


class EggCanvas(QWidget):
    """Plays one scene, scaled to the widget, looping."""

    def __init__(self, scene: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(int(W), int(H))
        self.scene = scene
        self._t0 = time.monotonic()
        self.frozen_t: float | None = None  # tests and screenshots
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.update)
        self._timer.start(FRAME_MS)

    def set_scene(self, scene: str) -> None:
        self.scene = scene
        self._t0 = time.monotonic()
        self.update()

    def elapsed(self) -> float:
        return self.frozen_t if self.frozen_t is not None else time.monotonic() - self._t0

    def paintEvent(self, _event) -> None:  # noqa: ANN001, N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        scale = min(self.width() / W, self.height() / H)
        p.translate((self.width() - W * scale) / 2, (self.height() - H * scale) / 2)
        p.scale(scale, scale)
        p.setClipRect(QRectF(0, 0, W, H))
        SCENES[self.scene](p, self.elapsed())
        _vignette(p)
        p.end()

    def hideEvent(self, event) -> None:  # noqa: ANN001, N802
        self._timer.stop()
        super().hideEvent(event)

    def showEvent(self, event) -> None:  # noqa: ANN001, N802
        self._timer.start(FRAME_MS)
        super().showEvent(event)


def pick(last: str = "", rng: random.Random | None = None) -> str:
    """A random scene, never the same one twice in a row."""
    names = [n for n in SCENES if n != last] or list(SCENES)
    return (rng or random).choice(names)


class EasterEggDialog(QDialog):
    def __init__(self, parent: QWidget | None = None, scene: str | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Easter Egg")
        self.canvas = EggCanvas(scene or pick())
        root = QVBoxLayout(self)
        root.addWidget(self.canvas, 1)
        row = QHBoxLayout()
        note = QLabel("Cartoon homages, drawn by NetCheck.")
        note.setStyleSheet("color: #78909c;")
        row.addWidget(note)
        row.addStretch(1)
        self.another = QPushButton("Another!")
        self.another.clicked.connect(self.next_scene)
        row.addWidget(self.another)
        close = QPushButton("Close")  # rightmost
        close.clicked.connect(self.accept)
        row.addWidget(close)
        root.addLayout(row)
        self.resize(int(W) + 40, int(H) + 70)

    def next_scene(self) -> None:
        self.canvas.set_scene(pick(self.canvas.scene))
