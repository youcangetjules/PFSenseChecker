"""Easter Egg me: three looping cartoons, a random pick, never the same twice running."""

from __future__ import annotations

import os
import random

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QColor, QImage  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from pfsense_checker import easter_eggs as ee  # noqa: E402


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_every_scene_draws_and_moves() -> None:
    _app()
    assert set(ee.SCENES) == {"harlem", "bat country", "war room", "vietnam", "torquay", "rome",
                              "overlook", "truth", "port royal",
                              "black knight", "coconuts", "shirley", "nothing to see", "catwalk",
                              "sir robin"}
    for name in ee.SCENES:
        canvas = ee.EggCanvas(name)
        canvas.resize(int(ee.W), int(ee.H))
        frames = []
        for t in (0.5, 1.7):
            canvas.frozen_t = t
            frames.append(canvas.grab().toImage().convertToFormat(QImage.Format.Format_RGB32))
        img = frames[0]
        colours = {img.pixelColor(x, y).name() for x in range(0, img.width(), 37) for y in range(0, img.height(), 29)}
        assert len(colours) > 8, name  # a picture, not a blank
        assert frames[0] != frames[1], name  # animated
        canvas.close()


def test_pick_never_repeats() -> None:
    rng = random.Random(1)
    last = ""
    seen = set()
    for _ in range(60):
        nxt = ee.pick(last, rng)
        assert nxt != last
        seen.add(nxt)
        last = nxt
    assert seen == set(ee.SCENES)


def test_dialog_another_changes_scene() -> None:
    _app()
    dlg = ee.EasterEggDialog(scene="harlem")
    dlg.another.click()
    assert dlg.canvas.scene in set(ee.SCENES) - {"harlem"}
    dlg.close()


def test_login_tools_row_spans_with_equal_buttons(monkeypatch) -> None:
    _app()
    from pfsense_checker import easter_eggs
    from pfsense_checker.login_screen import LoginDialog

    monkeypatch.setattr(LoginDialog, "_prepare_mode", lambda self: None)
    monkeypatch.setattr(LoginDialog, "_refresh_db_status", lambda self: None)
    dlg = LoginDialog()
    dlg.resize(1194, 827)
    dlg.show()
    QApplication.processEvents()
    row = [dlg.btn_beacon, dlg.btn_collector, dlg.btn_check, dlg.btn_contact, dlg.btn_easter]
    assert dlg.btn_easter.text() == "Easter Egg me"
    assert row[-1].geometry().left() > row[-2].geometry().right()  # to the right of Get in Touch
    widths = [b.width() for b in row]
    assert max(widths) - min(widths) <= 1
    panel = row[0].parentWidget()
    assert row[0].geometry().left() < 30 and panel.width() - row[-1].geometry().right() < 30  # spans the panel
    assert abs(dlg.copyright.font().pointSizeF() - 11.25) < 0.01  # © line 3pt larger
    opened = []
    monkeypatch.setattr(easter_eggs.EasterEggDialog, "exec", lambda self: opened.append(self.canvas.scene) or 0)
    dlg.btn_easter.click()
    assert opened and opened[0] in ee.SCENES
    dlg.close()
