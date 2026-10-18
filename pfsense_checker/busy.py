"""Application-wide busy (wait) cursor while NetCheck is working."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtWidgets import QApplication

class BusyHub(QObject):
    """GUI-thread bridge: ``busy_changed(True)`` while the wait cursor is showing."""

    busy_changed = Signal(bool)
    busy_message = Signal(str)

    def end_busy(self) -> None:
        """Slot so worker ``QThread.finished`` can restore busy state on the GUI thread."""
        end_busy()


# Nested user actions share one override; refcount avoids premature restore.
_BUSY_DEPTH = 0
_BUSY_MESSAGE = ""
_HUB: BusyHub | None = None


def _app() -> QApplication | None:
    inst = QApplication.instance()
    return inst if isinstance(inst, QApplication) else None


def busy_hub() -> BusyHub:
    """Singleton hub. Create from the GUI thread (main window status bar)."""
    global _HUB
    if _HUB is None:
        _HUB = BusyHub()
        app = _app()
        if app is not None and _HUB.thread() is not app.thread():
            _HUB.moveToThread(app.thread())
    return _HUB


def is_busy() -> bool:
    return _BUSY_DEPTH > 0


def busy_message() -> str:
    return _BUSY_MESSAGE


def _set_busy_active(active: bool) -> None:
    if _app() is None:
        return
    if active:
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
    else:
        QApplication.restoreOverrideCursor()
    busy_hub().busy_changed.emit(active)
    busy_hub().busy_message.emit(_BUSY_MESSAGE if active else "")


def begin_busy(message: str = "") -> None:
    """Show the system wait/spinner cursor (nestable)."""
    global _BUSY_DEPTH, _BUSY_MESSAGE
    if _app() is None:
        return
    if message:
        _BUSY_MESSAGE = message.strip()
    if _BUSY_DEPTH == 0:
        _set_busy_active(True)
    elif message:
        busy_hub().busy_message.emit(_BUSY_MESSAGE)
    _BUSY_DEPTH += 1


def end_busy() -> None:
    """Restore the previous cursor when the outermost busy ends."""
    global _BUSY_DEPTH, _BUSY_MESSAGE
    if _BUSY_DEPTH <= 0:
        return
    _BUSY_DEPTH -= 1
    if _BUSY_DEPTH == 0:
        _BUSY_MESSAGE = ""
        _set_busy_active(False)


def set_busy_message(message: str) -> None:
    """Update status-bar text while already busy (does not change depth)."""
    global _BUSY_MESSAGE
    if not is_busy():
        return
    _BUSY_MESSAGE = (message or "").strip()
    busy_hub().busy_message.emit(_BUSY_MESSAGE)


@contextmanager
def busy_cursor(message: str = "") -> Iterator[None]:
    """Wait cursor for a synchronous block of work."""
    begin_busy(message)
    try:
        yield
    finally:
        end_busy()


def show_busy_while(thread: QThread, *, message: str = "") -> QThread:
    """Keep the wait cursor up until *thread* finishes (success or fail)."""
    begin_busy(message)
    thread.finished.connect(
        busy_hub().end_busy, Qt.ConnectionType.QueuedConnection
    )
    return thread
