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
