"""Enter in the password field activates Login, not the 1Password button."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def _app():
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_enter_on_password_activates_login(monkeypatch) -> None:
    _app()
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication

    from pfsense_checker.login_screen import LoginDialog

    monkeypatch.setattr(LoginDialog, "_prepare_mode", lambda self: None)
    monkeypatch.setattr(LoginDialog, "_refresh_db_status", lambda self: None)
    dlg = LoginDialog()
    dlg.show()
    QApplication.processEvents()
    assert dlg.submit.isDefault() is True
    assert dlg.btn_fill_op.autoDefault() is False
    assert dlg.btn_help.autoDefault() is False
    hits: list[str] = []
    dlg.submit.clicked.disconnect()
    dlg.submit.clicked.connect(lambda: hits.append("login"))
    dlg.btn_fill_op.clicked.connect(lambda: hits.append("op"))
    dlg.password.setFocus()
    QTest.keyClick(dlg.password, Qt.Key.Key_Return)
    QApplication.processEvents()
    dlg.close()
    assert hits == ["login"]


def test_panel_contents_sit_clear_of_the_title_pill(monkeypatch) -> None:
    _app()
    from PySide6.QtWidgets import QApplication, QGroupBox, QVBoxLayout

    from pfsense_checker import login_screen
    from pfsense_checker.login_screen import LoginDialog

    monkeypatch.setattr(LoginDialog, "_prepare_mode", lambda self: None)
    monkeypatch.setattr(LoginDialog, "_refresh_db_status", lambda self: None)
    dlg = LoginDialog()
    dlg.show()
    QApplication.processEvents()
    probe = QGroupBox("x")
    plain = QVBoxLayout(probe).contentsMargins().top()  # style default
    boxes = {b.title(): b for b in dlg.findChildren(QGroupBox)}
    for title in ("Login to main tool", "Tools (no sign-in required)"):
        top = boxes[title].layout().contentsMargins().top()
        assert top == plain + login_screen.PILL_CLEARANCE_PX
    dlg.close()


def test_copyright_moves_from_banner_to_the_bottom(monkeypatch) -> None:
    _app()
    from PySide6.QtWidgets import QApplication, QGroupBox

    from pfsense_checker.branding import render_logo_pixmap
    from pfsense_checker.login_screen import COPYRIGHT_LINE, LoginDialog

    full = render_logo_pixmap(width=800)
    bare = render_logo_pixmap(width=800, copyright=False)
    assert bare.width() == full.width() and full.height() - 30 < bare.height() < full.height()
    monkeypatch.setattr(LoginDialog, "_prepare_mode", lambda self: None)
    monkeypatch.setattr(LoginDialog, "_refresh_db_status", lambda self: None)
    dlg = LoginDialog()
    dlg.resize(1194, 800)
    dlg.show()
    QApplication.processEvents()
    tools = next(b for b in dlg.findChildren(QGroupBox) if b.title().startswith("Tools"))
    line = dlg.copyright
    assert line.text() == COPYRIGHT_LINE
    below_tools = line.mapTo(dlg, line.rect().topLeft()).y() >= tools.mapTo(dlg, tools.rect().bottomLeft()).y()
    above_bar = line.mapTo(dlg, line.rect().bottomLeft()).y() <= dlg.status_bar.mapTo(dlg, dlg.status_bar.rect().topLeft()).y()
    assert below_tools and above_bar
    dlg.close()


def test_intro_text_sits_between_login_and_tools(monkeypatch) -> None:
    _app()
    from PySide6.QtWidgets import QApplication, QGroupBox

    from pfsense_checker.login_screen import INTRO_TEXT, LoginDialog

    monkeypatch.setattr(LoginDialog, "_prepare_mode", lambda self: None)
    monkeypatch.setattr(LoginDialog, "_refresh_db_status", lambda self: None)
    dlg = LoginDialog()
    dlg.resize(1194, 827)
    dlg.show()
    QApplication.processEvents()
    boxes = {b.title(): b for b in dlg.findChildren(QGroupBox)}
    login, tools = boxes["Login to main tool"], boxes["Tools (no sign-in required)"]
    intro = dlg.intro
    assert intro.text() == INTRO_TEXT and INTRO_TEXT.endswith("\nEnjoy - it was made with weapons grade OCD and Caffeine by Aliniant UK Ltd.") and intro.wordWrap()
    top = intro.mapTo(dlg, intro.rect().topLeft()).y()
    bottom = intro.mapTo(dlg, intro.rect().bottomLeft()).y()
    assert login.mapTo(dlg, login.rect().bottomLeft()).y() < top
    assert bottom < tools.mapTo(dlg, tools.rect().topLeft()).y()
    dlg.close()


def test_cancel_lives_in_a_double_height_status_bar(monkeypatch) -> None:
    _app()
    from PySide6.QtWidgets import QApplication, QGroupBox, QStatusBar

    from pfsense_checker import login_screen
    from pfsense_checker.branding import status_bar_stylesheet
    from pfsense_checker.login_screen import LoginDialog

    monkeypatch.setattr(LoginDialog, "_prepare_mode", lambda self: None)
    monkeypatch.setattr(LoginDialog, "_refresh_db_status", lambda self: None)
    dlg = LoginDialog()
    dlg.resize(1194, 827)
    dlg.show()
    QApplication.processEvents()
    plain = QStatusBar()
    plain.setStyleSheet(status_bar_stylesheet())
    usual = plain.sizeHint().height()  # an empty bar; the DB chip adds a pixel or so
    assert login_screen.STATUS_BAR_SCALE * usual <= dlg.status_bar.height() <= login_screen.STATUS_BAR_SCALE * (usual + 2)
    assert dlg.cancel_btn.parentWidget() is dlg.status_bar
    bar = dlg.status_bar
    assert bar.width() - dlg.cancel_btn.geometry().right() <= 16  # on the right of the bar
    login = next(b for b in dlg.findChildren(QGroupBox) if b.title() == "Login to main tool")
    right_gap = login.width() - dlg.submit.geometry().right()
    assert dlg.submit.parentWidget() is login and right_gap <= 16  # Login on the right-hand side
    dlg.cancel_btn.click()
    assert not dlg.isVisible()  # still quits


def test_cancel_is_narrower_than_login(monkeypatch) -> None:
    _app()
    from pfsense_checker import login_screen
    from pfsense_checker.login_screen import LoginDialog

    monkeypatch.setattr(LoginDialog, "_prepare_mode", lambda self: None)
    monkeypatch.setattr(LoginDialog, "_refresh_db_status", lambda self: None)
    dlg = LoginDialog()
    assert dlg.cancel_btn.width() == login_screen.CANCEL_BAR_W < dlg.submit.width()
    dlg._set_bootstrap_ui(True)  # noqa: SLF001 - relabelling Login keeps Cancel narrow
    assert dlg.cancel_btn.width() == login_screen.CANCEL_BAR_W
    dlg.close()
