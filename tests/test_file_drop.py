"""File drag-and-drop accepts Explorer formats, not only hasUrls()."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from pfsense_checker.file_drop import (
    FileDropRouter,
    accept_file_drag,
    hdrop_from_paths,
    mime_has_files,
    paths_from_hdrop,
    paths_from_mime,
)


def _app():
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_filenamew_counts_as_a_file_drag_before_urls_exist() -> None:
    _app()
    from PySide6.QtCore import QMimeData

    mime = QMimeData()
    mime.setData(
        'application/x-qt-windows-mime;value="FileNameW"',
        "C:\\lab\\edge.xml".encode("utf-16-le"),
    )
    assert mime.hasUrls() is False
    assert mime_has_files(mime)
    assert paths_from_mime(mime)[0].name == "edge.xml"


def test_router_accepts_explorer_drag_onto_a_child_label(tmp_path) -> None:
    _app()
    from PySide6.QtCore import QMimeData, QPoint, Qt, QUrl
    from PySide6.QtGui import QDragEnterEvent, QDropEvent
    from PySide6.QtWidgets import QApplication, QLabel, QMainWindow, QWidget

    window = QMainWindow()
    window.setAcceptDrops(True)
    page = QWidget()
    window.setCentralWidget(page)
    label = QLabel("drop here", page)
    dropped: list[Path] = []
    router = FileDropRouter(window, dropped.extend)
    assert router.parent() is window

    mime = QMimeData()
    mime.setData(
        'application/x-qt-windows-mime;value="FileNameW"',
        "C:\\lab\\fw.xml\0".encode("utf-16-le"),
    )
    enter = QDragEnterEvent(
        QPoint(4, 4),
        Qt.DropAction.CopyAction,
        mime,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    QApplication.sendEvent(label, enter)
    assert enter.isAccepted()
    assert enter.dropAction() == Qt.DropAction.CopyAction

    plain = QMimeData()
    plain.setText("not a file")
    rejected = QDragEnterEvent(
        QPoint(4, 4),
        Qt.DropAction.CopyAction,
        plain,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    assert accept_file_drag(rejected) is False

    target = tmp_path / "router.rsc"
    target.write_text("/export\n", encoding="utf-8")
    urls = QMimeData()
    urls.setUrls([QUrl.fromLocalFile(str(target))])
    drop = QDropEvent(
        QPoint(4, 4),
        Qt.DropAction.CopyAction,
        urls,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    QApplication.sendEvent(label, drop)
    assert dropped == [target]
    window.close()


def test_config_page_drop_zone_accepts_drops() -> None:
    _app()
    from PySide6.QtWidgets import QFrame, QLabel

    from pfsense_checker.home_screen import HomeScreen

    page = HomeScreen()._build_config()
    texts = [label.text() for label in page.findChildren(QLabel)]
    assert any(text.startswith("Drop a config.xml") for text in texts)
    zone = page.findChild(QFrame, "configDrop")
    assert zone is not None
    assert zone.acceptDrops()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows drop target")
def test_elevated_window_accepts_wm_dropfiles(monkeypatch) -> None:
    app = _app()
    from PySide6.QtWidgets import QMainWindow

    from pfsense_checker.file_drop import enable_os_file_drop

    monkeypatch.setattr(
        "pfsense_checker.file_drop._is_process_elevated", lambda: True
    )
    window = QMainWindow()
    window.resize(200, 100)
    window.show()
    app.processEvents()
    enable_os_file_drop(window, lambda paths: None)
    assert window._wm_drop_filter is not None  # type: ignore[attr-defined]
    window.close()
    app.processEvents()


@pytest.mark.skipif(sys.platform != "win32", reason="HDROP is a Windows handle")
def test_hdrop_round_trip() -> None:
    import ctypes

    handle = hdrop_from_paths([r"C:\lab\fw.xml", r"C:\lab\edge.rsc"])
    try:
        assert paths_from_hdrop(handle) == [
            Path(r"C:\lab\fw.xml"),
            Path(r"C:\lab\edge.rsc"),
        ]
    finally:
        kernel32 = ctypes.windll.kernel32
        kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
        kernel32.GlobalFree.restype = ctypes.c_void_p
        kernel32.GlobalFree(handle)
