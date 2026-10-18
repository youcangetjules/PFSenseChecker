"""Companion console receives app logs and library warnings."""

from __future__ import annotations

import logging
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def _app():
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_root_warnings_reach_the_hub() -> None:
    from pfsense_checker import app_log

    marker = "root-marker-companion-1842"
    logging.getLogger("external.demo").warning(marker)
    assert any(marker in event.message for event in app_log.get_hub().recent())


def test_companion_appends_log_line() -> None:
    _app()
    from PySide6.QtWidgets import QApplication

    from pfsense_checker import app_log
    from pfsense_checker.console_window import close_companion, open_companion

    window = open_companion(show=True, activate=False)
    try:
        marker = "companion-marker-1842"
        app_log.get_logger("console-test").warning(marker)
        QApplication.processEvents()
        assert marker in window.view.toPlainText()
    finally:
        close_companion()
        QApplication.processEvents()
