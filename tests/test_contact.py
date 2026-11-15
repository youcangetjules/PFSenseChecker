"""Get in Touch: Outlook first, mailto as the fallback, nothing sent by itself."""

from __future__ import annotations

from pfsense_checker import contact


def test_outlook_gets_the_address_and_subject() -> None:
    calls = []
    how = contact.open_email(find_outlook=lambda: r"C:\Office\OUTLOOK.EXE", launch=calls.append,
                             open_url=lambda _u: (_ for _ in ()).throw(AssertionError("no mailto")))
    assert how == "outlook"
    assert calls == [[r"C:\Office\OUTLOOK.EXE", "/c", "ipm.note", "/m",
                      "administrator@aliniant.com?subject=Tell%20me%20about%20netcheck"]]


def test_falls_back_to_mailto_without_outlook() -> None:
    urls = []
    how = contact.open_email(find_outlook=lambda: "", launch=lambda _a: None,
                             open_url=lambda u: urls.append(u) or True)
    assert how == "mailto"
    assert urls == ["mailto:administrator@aliniant.com?subject=Tell%20me%20about%20netcheck"]


def test_outlook_that_will_not_start_falls_back() -> None:
    def broken(_args):  # noqa: ANN001, ANN202
        raise OSError("gone")

    urls = []
    assert contact.open_email(find_outlook=lambda: "x.exe", launch=broken,
                              open_url=lambda u: urls.append(u) or True) == "mailto"
    assert contact.open_email(find_outlook=lambda: "", launch=broken, open_url=lambda _u: False) == ""


def test_login_tools_row_has_get_in_touch(monkeypatch) -> None:
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication, QMessageBox

    from pfsense_checker import login_screen
    from pfsense_checker.login_screen import LoginDialog

    QApplication.instance() or QApplication([])
    monkeypatch.setattr(LoginDialog, "_prepare_mode", lambda self: None)
    monkeypatch.setattr(LoginDialog, "_refresh_db_status", lambda self: None)
    dlg = LoginDialog()
    assert dlg.btn_contact.text() == "Get in Touch"
    assert dlg.btn_contact.height() == dlg.btn_check.height()
    opened = []
    monkeypatch.setattr(login_screen.contact, "open_email", lambda: opened.append(1) or "outlook")
    dlg.btn_contact.click()
    assert opened == [1]
    shown = []
    monkeypatch.setattr(login_screen.contact, "open_email", lambda: "")
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: shown.append(a[2]))
    dlg.btn_contact.click()
    assert "administrator@aliniant.com" in shown[0]
    dlg.close()
