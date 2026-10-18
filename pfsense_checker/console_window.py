"""Companion console window: live log beside the rest of NetCheck.

One window for the process. Home → Console → Pop out raises it. Closing the
window hides it; quitting NetCheck destroys it. Log listeners may run off the
GUI thread, so lines arrive through a queued signal.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from pfsense_checker import app_log

_VIEW_STYLE = (
    "QPlainTextEdit {"
    " background: #111111; color: #e0e0e0;"
    " border: 1px solid #333; border-radius: 4px;"
    " padding: 6px;"
    "}"
)

_window: "CompanionConsole | None" = None


class CompanionConsole(QDialog):
    """Top-level log window. Not an OS console."""

    line_ready = Signal(str)

    def __init__(self) -> None:
        super().__init__(None)
        self.setWindowTitle("NetCheck — Console")
        self.setModal(False)
        self.setWindowModality(Qt.WindowModality.NonModal)
        self.setWindowFlag(Qt.WindowType.Window, True)
        self.setAttribute(Qt.WidgetAttribute.WA_QuitOnClose, False)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, False)
        self.resize(720, 480)
        self._placed = False
        self._shutting_down = False

        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        tip = QLabel(
            "Live log for this NetCheck process. Closes when NetCheck quits. "
            "Hiding this window does not stop logging."
        )
        tip.setStyleSheet("color: #666;")
        tip.setWordWrap(True)
        root.addWidget(tip)

        self.view = QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.view.setFont(QFont("Consolas", 10))
        self.view.setStyleSheet(_VIEW_STYLE)
        root.addWidget(self.view, stretch=1)

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setTextFormat(Qt.TextFormat.RichText)
        self.status_label.setStyleSheet(
            "QLabel { background: #eceff1; border: 1px solid #cfd8dc; "
            "border-radius: 4px; padding: 6px 10px; color: #37474f; }"
        )
        root.addWidget(self.status_label)

        row = QHBoxLayout()
        reload_btn = QPushButton("Reload")
        reload_btn.clicked.connect(self.reload_from_hub)
        clear_btn = QPushButton("Clear view")
        clear_btn.clicked.connect(self.view.clear)
        close_btn = QPushButton("Hide")
        close_btn.clicked.connect(self.hide)
        for button in (reload_btn, clear_btn, close_btn):
            button.setAutoDefault(False)
            button.setDefault(False)
        row.addWidget(reload_btn)
        row.addWidget(clear_btn)
        row.addStretch(1)
        row.addWidget(close_btn)
        root.addLayout(row)

        self.line_ready.connect(self._append_line)
        self._listener = self._on_log_event
        app_log.get_hub().subscribe(self._listener)
        self.reload_from_hub()

    def reload_from_hub(self) -> None:
        text = "\n".join(event.format_line() for event in app_log.get_hub().recent())
        self.view.setPlainText(text)
        self.view.moveCursor(QTextCursor.MoveOperation.End)
        self.status_label.setText(app_log.logging_status_html())

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        if not self._placed:
            _place(self)
            self._placed = True
        self.status_label.setText(app_log.logging_status_html())

    def closeEvent(self, event) -> None:  # noqa: N802
        if self._shutting_down:
            self._unsubscribe()
            event.accept()
            return
        event.ignore()
        self.hide()

    def shutdown(self) -> None:
        self._shutting_down = True
        self._unsubscribe()
        self.close()

    def _unsubscribe(self) -> None:
        listener = getattr(self, "_listener", None)
        if listener is None:
            return
        try:
            app_log.get_hub().unsubscribe(listener)
        except Exception:  # noqa: BLE001
            pass
        self._listener = None

    def _on_log_event(self, event: app_log.LogEvent) -> None:
        try:
            self.line_ready.emit(event.format_line())
        except RuntimeError:
            return

    def _append_line(self, line: str) -> None:
        try:
            bar = self.view.verticalScrollBar()
        except RuntimeError:
            return
        follow = bar.maximum() - bar.value() <= 8
        self.view.appendPlainText(line)
        cap = max(50, app_log.get_hub().settings.memory_lines)
        if self.view.document().blockCount() > cap + 1:
            text = "\n".join(event.format_line() for event in app_log.get_hub().recent())
            self.view.setPlainText(text)
        if follow:
            self.view.moveCursor(QTextCursor.MoveOperation.End)


def _place(window: QWidget) -> None:
    """Sit in the free strip to the right of the 1200px login window."""
    screen = QApplication.primaryScreen()
    if screen is None:
        return
    avail = screen.availableGeometry()
    gap = 12
    free_right = avail.width() - 1200
    if free_right > 280:
        width = min(640, max(280, free_right - gap * 2))
        x = avail.right() - width - 8 + 1
    else:
        width = min(720, max(320, avail.width() - 24))
        x = avail.left() + 8
    height = min(720, max(240, avail.height() - 24))
    y = avail.top() + 8
    window.setGeometry(x, y, width, height)


def open_companion(*, show: bool = True, activate: bool = False) -> CompanionConsole:
    """Return the process console, creating it on first use."""
    global _window
    if QApplication.instance() is None:
        raise RuntimeError("Companion console requires QApplication")
    if _window is None:
        _window = CompanionConsole()
    if show:
        _window.setAttribute(
            Qt.WidgetAttribute.WA_ShowWithoutActivating,
            not activate,
        )
        _window.show()
        if activate:
            _window.raise_()
            _window.activateWindow()
    return _window


def close_companion() -> None:
    """Unsubscribe and destroy the companion, if it exists."""
    global _window
    window = _window
    _window = None
    if window is None:
        return
    try:
        window.shutdown()
        window.deleteLater()
    except RuntimeError:
        return
