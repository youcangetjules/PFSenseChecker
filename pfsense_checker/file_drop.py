"""Route file drag-and-drop from Explorer/Finder into the application.

Windows Explorer often offers ``FileNameW`` / ``CF_HDROP`` during drag-enter
and only fills ``text/uri-list`` on drop. Accepting only ``hasUrls()`` makes
the cursor a stop sign, so the drop never lands.

An elevated NetCheck process cannot receive OLE drops from Explorer (UIPI).
In that case the main window switches to ``WM_DROPFILES``, which Windows will
deliver after the drop messages are allowed through.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QEvent, QObject, QUrl, Qt
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget

_FILE_FORMAT_HINTS = ("uri-list", "filename", "cf_hdrop", "hdrop")


def mime_has_files(mime: object) -> bool:
    """True when *mime* looks like a file drag, including Explorer's formats."""
    has_urls = getattr(mime, "hasUrls", None)
    if callable(has_urls):
        try:
            if has_urls():
                return True
        except Exception:  # noqa: BLE001
            pass
    formats = getattr(mime, "formats", None)
    if not callable(formats):
        return False
    try:
        names = formats()
    except Exception:  # noqa: BLE001
        return False
    for name in names:
        low = str(name).lower()
        if any(hint in low for hint in _FILE_FORMAT_HINTS):
            return True
    return False


def accept_file_drag(event: object) -> bool:
    """Accept a file drag as a copy. Returns False when it is not a file drag."""
    mime_of = getattr(event, "mimeData", None)
    if not callable(mime_of) or not mime_has_files(mime_of()):
        return False
    event.setDropAction(Qt.DropAction.CopyAction)  # type: ignore[attr-defined]
    event.accept()  # type: ignore[attr-defined]
    return True


def paths_from_mime(mime: object) -> list[Path]:
    """Local paths from a drop. Explorer may only fill these on the drop itself."""
    paths: list[Path] = []
    urls = getattr(mime, "urls", None)
    if callable(urls):
        try:
            for url in urls():
                local = url.toLocalFile()
                if local:
                    paths.append(Path(local))
        except Exception:  # noqa: BLE001
            paths = []
    if paths:
        return paths

    data_of = getattr(mime, "data", None)
    formats = getattr(mime, "formats", None)
    if not callable(data_of) or not callable(formats):
        return []
    try:
        names = list(formats())
    except Exception:  # noqa: BLE001
        return []

    for name in names:
        low = str(name).lower()
        if "filenamew" in low:
            paths.extend(_paths_from_filename_w(bytes(data_of(name))))
        elif low == "text/uri-list" or low.endswith("filename"):
            paths.extend(_paths_from_filename(bytes(data_of(name))))
    # De-duplicate, keep order.
    seen: set[str] = set()
    unique: list[Path] = []
    for path in paths:
        key = str(path)
        if not key or key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def _paths_from_filename_w(raw: bytes) -> list[Path]:
    if not raw:
        return []
    text = raw.decode("utf-16-le", errors="replace").replace("\x00", "\n")
    return [Path(part.strip()) for part in text.splitlines() if part.strip()]


def _paths_from_filename(raw: bytes) -> list[Path]:
    if not raw:
        return []
    text = raw.decode("utf-8", errors="replace").replace("\x00", "\n")
    paths: list[Path] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("file:"):
            local = QUrl(line).toLocalFile()
            if local:
                paths.append(Path(local))
            continue
        paths.append(Path(line))
    return paths


class FileDropRouter(QObject):
    """Accept file drags on any widget inside *window* and invoke *on_drop*."""

    def __init__(
        self,
        window: QMainWindow,
        on_drop: Callable[[list[Path]], None],
        *,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent or window)
        # State lives on the window. Qt may rebuild the Python wrapper for this
        # filter, and a rebuilt wrapper does not keep attributes set in __init__.
        host = parent or window
        host._netcheck_drop_state = {  # type: ignore[attr-defined]
            "window": window,
            "on_drop": on_drop,
            "armed": False,
        }
        window.destroyed.connect(self._uninstall)
        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self)

    def _uninstall(self, *_args: object) -> None:
        app = QApplication.instance()
        if app is None:
            return
        try:
            app.removeEventFilter(self)
        except RuntimeError:
            pass

    def _state(self) -> dict | None:
        host = self.parent()
        if host is None:
            return None
        state = getattr(host, "_netcheck_drop_state", None)
        return state if isinstance(state, dict) else None

    def _in_window(self, obj: QObject, window: QObject) -> bool:
        w: QObject | None = obj
        while w is not None:
            if w is window:
                return True
            w = w.parent()
        return False

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:  # noqa: N802
        try:
            return self._filter_event(watched, event)
        except RuntimeError:
            return False

    def _filter_event(self, watched: QObject, event: QEvent) -> bool:
        state = self._state()
        if state is None:
            return False
        window = state.get("window")
        on_drop = state.get("on_drop")
        if window is None or not callable(on_drop):
            return False
        if not isinstance(watched, QWidget) or not self._in_window(watched, window):
            return False
        et = event.type()
        if et == QEvent.Type.DragEnter:
            if accept_file_drag(event):
                state["armed"] = True
                return True
            state["armed"] = False
            return False
        if et == QEvent.Type.DragMove:
            if state.get("armed") or accept_file_drag(event):
                event.setDropAction(Qt.DropAction.CopyAction)
                event.accept()
                state["armed"] = True
                return True
            return False
        if et == QEvent.Type.DragLeave:
            state["armed"] = False
            return False
        if et == QEvent.Type.Drop:
            was_armed = bool(state.get("armed"))
            state["armed"] = False
            mime_of = getattr(event, "mimeData", None)
            if not callable(mime_of):
                return False
            if not was_armed and not mime_has_files(mime_of()):
                return False
            paths = paths_from_mime(mime_of())
            if paths:
                on_drop(paths)
            event.setDropAction(Qt.DropAction.CopyAction)
            event.accept()
            return True
        return False


def paths_from_hdrop(hdrop: int) -> list[Path]:
    """Read file paths from a Windows ``HDROP`` handle."""
    if sys.platform != "win32" or not hdrop:
        return []
    import ctypes
    from ctypes import wintypes

    shell32 = ctypes.windll.shell32
    shell32.DragQueryFileW.argtypes = [
        wintypes.HANDLE,
        wintypes.UINT,
        wintypes.LPWSTR,
        wintypes.UINT,
    ]
    shell32.DragQueryFileW.restype = wintypes.UINT
    count = int(shell32.DragQueryFileW(hdrop, 0xFFFFFFFF, None, 0))
    paths: list[Path] = []
    for index in range(count):
        length = int(shell32.DragQueryFileW(hdrop, index, None, 0))
        if length <= 0:
            continue
        buf = ctypes.create_unicode_buffer(length + 1)
        shell32.DragQueryFileW(hdrop, index, buf, length + 1)
        if buf.value:
            paths.append(Path(buf.value))
    return paths


def hdrop_from_paths(paths: list[str]) -> int:
    """Build an ``HDROP`` (``HGLOBAL``) for tests and the elevated drop path."""
    if sys.platform != "win32":
        raise OSError("HDROP is only available on Windows")
    import ctypes
    from ctypes import wintypes

    class _DropFiles(ctypes.Structure):
        _fields_ = [
            ("pFiles", wintypes.DWORD),
            ("x", wintypes.LONG),
            ("y", wintypes.LONG),
            ("fNC", wintypes.BOOL),
            ("fWide", wintypes.BOOL),
        ]

    payload = ("\0".join(paths) + "\0\0").encode("utf-16-le")
    header = _DropFiles()
    header.pFiles = ctypes.sizeof(_DropFiles)
    header.fWide = True
    raw = bytes(header) + payload
    kernel32 = ctypes.windll.kernel32
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.restype = wintypes.BOOL
    handle = kernel32.GlobalAlloc(0x0002, len(raw))  # GMEM_MOVEABLE
    if not handle:
        raise OSError("GlobalAlloc failed")
    ptr = kernel32.GlobalLock(handle)
    if not ptr:
        raise OSError("GlobalLock failed")
    ctypes.memmove(ptr, raw, len(raw))
    kernel32.GlobalUnlock(handle)
    return int(handle)


def _is_process_elevated() -> bool:
    if sys.platform != "win32":
        return False
    import ctypes
    from ctypes import wintypes

    shell32 = ctypes.windll.shell32
    shell32.IsUserAnAdmin.restype = wintypes.BOOL
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


class _WmDropFilter:
    """Deliver ``WM_DROPFILES`` into *on_drop*. Kept alive by the window."""

    def __init__(self, on_drop: Callable[[list[Path]], None]) -> None:
        from PySide6.QtCore import QAbstractNativeEventFilter

        class _Filter(QAbstractNativeEventFilter):
            def nativeEventFilter(self, eventType, message):  # noqa: N802
                if bytes(eventType) != b"windows_generic_MSG":
                    return False, 0
                return _handle_wm_dropfiles(message, on_drop)

        self.filter = _Filter()


def _win32():
    """Bind pointer-sized Windows prototypes once (64-bit HWND is not a c_int)."""
    import ctypes
    from ctypes import wintypes

    if getattr(_win32, "_ready", False):
        return ctypes
    user32 = ctypes.windll.user32
    shell32 = ctypes.windll.shell32
    ole32 = ctypes.windll.ole32
    user32.ChangeWindowMessageFilterEx.argtypes = [
        wintypes.HWND,
        wintypes.UINT,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    user32.ChangeWindowMessageFilterEx.restype = wintypes.BOOL
    user32.ChangeWindowMessageFilter.argtypes = [wintypes.UINT, wintypes.DWORD]
    user32.ChangeWindowMessageFilter.restype = wintypes.BOOL
    ole32.RevokeDragDrop.argtypes = [wintypes.HWND]
    ole32.RevokeDragDrop.restype = ctypes.c_long
    shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
    shell32.DragAcceptFiles.restype = None
    shell32.DragFinish.argtypes = [wintypes.HANDLE]
    shell32.DragFinish.restype = None
    _win32._ready = True  # type: ignore[attr-defined]
    return ctypes


def _handle_wm_dropfiles(message: object, on_drop: Callable[[list[Path]], None]):
    import ctypes
    from ctypes import wintypes

    WM_DROPFILES = 0x0233
    try:
        msg = wintypes.MSG.from_address(int(message))  # type: ignore[arg-type]
    except (TypeError, ValueError, OSError):
        return False, 0
    if int(msg.message) != WM_DROPFILES:
        return False, 0
    hdrop = int(msg.wParam)
    try:
        paths = paths_from_hdrop(hdrop)
    finally:
        try:
            _win32()
            ctypes.windll.shell32.DragFinish(hdrop)
        except Exception:  # noqa: BLE001
            pass
    if paths:
        on_drop(paths)
    return True, 0


def enable_os_file_drop(
    window: QMainWindow,
    on_drop: Callable[[list[Path]], None],
) -> None:
    """Let Explorer drop files onto an elevated window.

    Unelevated processes keep Qt's OLE target. Elevated processes cannot
    receive those drops, so the HWND is switched to ``WM_DROPFILES``.
    """
    if sys.platform != "win32" or not _is_process_elevated():
        return
    import ctypes
    from ctypes import wintypes

    hwnd = int(window.winId())
    if hwnd == 0:
        return
    _win32()
    user32 = ctypes.windll.user32
    MSGFLT_ALLOW = 1
    for message_id in (0x0233, 0x004A, 0x0049):  # DROPFILES, COPYDATA, COPYGLOBALDATA
        user32.ChangeWindowMessageFilterEx(hwnd, message_id, MSGFLT_ALLOW, None)
        user32.ChangeWindowMessageFilter(message_id, MSGFLT_ALLOW)
    # Drop Qt's OLE target so Explorer falls back to WM_DROPFILES.
    ctypes.windll.ole32.RevokeDragDrop(wintypes.HWND(hwnd))
    ctypes.windll.shell32.DragAcceptFiles(wintypes.HWND(hwnd), True)

    holder = getattr(window, "_wm_drop_filter", None)
    if holder is None:
        holder = _WmDropFilter(on_drop)
        window._wm_drop_filter = holder  # type: ignore[attr-defined]
        app = QApplication.instance()
        if app is not None:
            app.installNativeEventFilter(holder.filter)

        def _remove(*_args: object, _holder: _WmDropFilter = holder) -> None:
            application = QApplication.instance()
            if application is not None:
                try:
                    application.removeNativeEventFilter(_holder.filter)
                except RuntimeError:
                    pass

        window.destroyed.connect(_remove)
