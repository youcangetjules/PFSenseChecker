"""Application logging with an in-memory ring buffer and FIFO log file.

Settings live in ``data/logging.json``. The Console UI reads the memory ring;
optional file logging appends to a single file and, when it exceeds
``max_bytes``, keeps only the newest bytes (FIFO / ring truncate).
"""

from __future__ import annotations

import json
import logging
import threading
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from pfsense_checker.paths import PROJECT_ROOT, ensure_data_dir

LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
_LEVEL_MAP = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
}

# Third-party loggers wired into the Console ring when level is DEBUG.
_VERBOSE_LOGGER_NAMES = (
    "paramiko",
    "paramiko.transport",
    "paramiko.client",
    "paramiko.sftp",
    "paramiko.ec2keys",
)

DEFAULT_LOG_DIR = PROJECT_ROOT / "data" / "logs"
DEFAULT_LOG_FILENAME = "netcheck.log"
DEFAULT_MAX_BYTES = 1_048_576  # 1 MiB
DEFAULT_MEMORY_LINES = 2000
SETTINGS_PATH = PROJECT_ROOT / "data" / "logging.json"

Listener = Callable[["LogEvent"], None]


@dataclass
class LogSettings:
    level: str = "INFO"
    file_enabled: bool = True
    log_dir: str = ""
    log_filename: str = DEFAULT_LOG_FILENAME
    max_bytes: int = DEFAULT_MAX_BYTES
    memory_lines: int = DEFAULT_MEMORY_LINES

    def resolved_dir(self) -> Path:
        raw = (self.log_dir or "").strip()
        return Path(raw) if raw else DEFAULT_LOG_DIR

    def log_path(self) -> Path:
        return self.resolved_dir() / (self.log_filename or DEFAULT_LOG_FILENAME)


@dataclass(frozen=True)
class LogEvent:
    ts: str
    level: str
    logger: str
    message: str

    def format_line(self) -> str:
        return f"{self.ts} [{self.level}] {self.logger}: {self.message}"


class _RingFileHandler(logging.Handler):
    """Append-only handler that truncates the head of the file when oversized."""

    def __init__(self, path: Path, max_bytes: int) -> None:
        super().__init__()
        self.path = path
        self.max_bytes = max(512, int(max_bytes))
        self._lock_file = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            line = self.format(record) + "\n"
            with self._lock_file:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
                self._trim_if_needed()
        except Exception:  # noqa: BLE001
            self.handleError(record)

    def _trim_if_needed(self) -> None:
        try:
            size = self.path.stat().st_size
        except OSError:
            return
        if size <= self.max_bytes:
            return
        try:
            data = self.path.read_bytes()
        except OSError:
            return
        keep = data[-self.max_bytes :]
        # Align to next newline so we don't keep a partial first line.
        nl = keep.find(b"\n")
        if nl >= 0 and nl + 1 < len(keep):
            keep = keep[nl + 1 :]
        try:
            self.path.write_bytes(keep)
        except OSError:
            pass


class _HubHandler(logging.Handler):
    def __init__(self, hub: "LogHub") -> None:
        super().__init__()
        self._hub = hub

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._hub._ingest_record(record)
        except Exception:  # noqa: BLE001
            self.handleError(record)


class LogHub:
    """Process-wide log fan-out: memory ring + optional FIFO file + listeners."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._settings = load_settings()
        self._memory: deque[LogEvent] = deque(maxlen=self._settings.memory_lines)
        self._listeners: list[Listener] = []
        self._file_handler: _RingFileHandler | None = None
        self._verbose_handlers: dict[str, _HubHandler] = {}
        self._hub_handler = _HubHandler(self)
        self._hub_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        self._root = logging.getLogger("netcheck")
        self._root.handlers.clear()
        self._root.addHandler(self._hub_handler)
        self._root.propagate = False
        # Warnings and errors from libraries (not the netcheck tree, which
        # does not propagate) land in the same ring and companion console.
        root_logger = logging.getLogger()
        if self._hub_handler not in root_logger.handlers:
            root_logger.addHandler(self._hub_handler)
        self.apply_settings(self._settings, persist=False)

    @property
    def settings(self) -> LogSettings:
        with self._lock:
            return LogSettings(**asdict(self._settings))

    def subscribe(self, listener: Listener) -> None:
        with self._lock:
            if listener not in self._listeners:
                self._listeners.append(listener)

    def unsubscribe(self, listener: Listener) -> None:
        with self._lock:
            if listener in self._listeners:
                self._listeners.remove(listener)

    def recent(self, limit: int | None = None) -> list[LogEvent]:
        with self._lock:
            events = list(self._memory)
        if limit is not None:
            return events[-limit:]
        return events

    def clear_memory(self) -> None:
        with self._lock:
            self._memory.clear()

    def apply_settings(self, settings: LogSettings, *, persist: bool = True) -> None:
        level_name = (settings.level or "INFO").upper()
        if level_name not in _LEVEL_MAP:
            level_name = "INFO"
        settings.level = level_name
        settings.max_bytes = max(512, int(settings.max_bytes or DEFAULT_MAX_BYTES))
        settings.memory_lines = max(10, int(settings.memory_lines or DEFAULT_MEMORY_LINES))
        settings.log_filename = (
            (settings.log_filename or DEFAULT_LOG_FILENAME).strip()
            or DEFAULT_LOG_FILENAME
        )

        with self._lock:
            self._settings = settings
            self._memory = deque(self._memory, maxlen=settings.memory_lines)
            self._root.setLevel(_LEVEL_MAP[level_name])
            self._hub_handler.setLevel(_LEVEL_MAP[level_name])
            if self._file_handler is not None:
                self._root.removeHandler(self._file_handler)
                self._file_handler.close()
                self._file_handler = None
            if settings.file_enabled:
                path = settings.log_path()
                handler = _RingFileHandler(path, settings.max_bytes)
                handler.setLevel(_LEVEL_MAP[level_name])
                handler.setFormatter(
                    logging.Formatter(
                        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
                    )
                )
                self._root.addHandler(handler)
                self._file_handler = handler
            self._sync_verbose_loggers(level_name)
        if persist:
            save_settings(settings)

    def _sync_verbose_loggers(self, level_name: str) -> None:
        """At DEBUG, fan paramiko transport trace into the Console memory ring."""
        want = level_name == "DEBUG"
        for name in _VERBOSE_LOGGER_NAMES:
            lg = logging.getLogger(name)
            handler = self._verbose_handlers.get(name)
            if want and handler is None:
                h = _HubHandler(self)
                h.setLevel(logging.DEBUG)
                lg.addHandler(h)
                lg.setLevel(logging.DEBUG)
                lg.propagate = False
                self._verbose_handlers[name] = h
            elif not want and handler is not None:
                lg.removeHandler(handler)
                del self._verbose_handlers[name]
                lg.setLevel(logging.WARNING)
                lg.propagate = True

    def _ingest_record(self, record: logging.LogRecord) -> None:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        event = LogEvent(
            ts=ts,
            level=record.levelname,
            logger=record.name,
            message=record.getMessage(),
        )
        listeners: list[Listener]
        with self._lock:
            self._memory.append(event)
            listeners = list(self._listeners)
        for listener in listeners:
            try:
                listener(event)
            except Exception:  # noqa: BLE001
                pass

    def get_logger(self, name: str = "netcheck") -> logging.Logger:
        if name == "netcheck" or name.startswith("netcheck."):
            return logging.getLogger(name)
        return logging.getLogger(f"netcheck.{name}")


_hub: LogHub | None = None
_hub_lock = threading.Lock()


def get_hub() -> LogHub:
    global _hub
    with _hub_lock:
        if _hub is None:
            ensure_data_dir()
            _hub = LogHub()
        return _hub


def configure() -> LogHub:
    """Ensure the hub is initialised (call once at app startup)."""
    return get_hub()


_hooks_installed = False


def install_crash_hooks() -> None:
    """Route uncaught exceptions, thread crashes, and Qt messages to the hub.

    Without this, tracebacks vanish when running under pythonw.exe (no
    console), which makes DEBUG sessions look silent even when things break.
    """
    global _hooks_installed
    if _hooks_installed:
        return
    _hooks_installed = True

    import sys
    import threading
    import traceback

    log = get_logger("crash")

    prev_excepthook = sys.excepthook

    def _excepthook(exc_type, exc, tb) -> None:
        text = "".join(traceback.format_exception(exc_type, exc, tb)).rstrip()
        log.error("Uncaught exception:\n%s", text)
        if prev_excepthook is not None:
            prev_excepthook(exc_type, exc, tb)

    sys.excepthook = _excepthook

    def _threadhook(args: threading.ExceptHookArgs) -> None:
        text = "".join(
            traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)
        ).rstrip()
        name = args.thread.name if args.thread is not None else "?"
        log.error("Uncaught exception in thread %s:\n%s", name, text)

    threading.excepthook = _threadhook

    try:
        from PySide6.QtCore import QtMsgType, qInstallMessageHandler

        qt_log = get_logger("qt")
        _QT_LEVELS = {
            QtMsgType.QtDebugMsg: logging.DEBUG,
            QtMsgType.QtInfoMsg: logging.INFO,
            QtMsgType.QtWarningMsg: logging.WARNING,
            QtMsgType.QtCriticalMsg: logging.ERROR,
            QtMsgType.QtFatalMsg: logging.CRITICAL,
        }

        def _qt_handler(msg_type, context, message) -> None:
            qt_log.log(_QT_LEVELS.get(msg_type, logging.WARNING), "%s", message)

        qInstallMessageHandler(_qt_handler)
    except Exception:  # noqa: BLE001
        pass


def get_logger(name: str = "app") -> logging.Logger:
    return get_hub().get_logger(name)


def _normalize_log_dir(raw: str) -> str:
    """Return *raw*, or "" when it is this project's default log folder.

    An older build saved ``DEFAULT_LOG_DIR`` as an absolute path. After the
    project moved (C: → E:), logs kept going to the old copy's ``data/logs``.
    A saved ``<…>/<project name>/data/logs`` that is not this project's
    folder is treated as that stale default.
    """
    text = (raw or "").strip()
    if not text:
        return ""
    path = Path(text)
    try:
        if path.resolve() == DEFAULT_LOG_DIR.resolve():
            return ""
    except OSError:
        pass
    parts = [p.lower() for p in path.parts]
    if (
        len(parts) >= 3
        and parts[-2:] == ["data", "logs"]
        and parts[-3] == PROJECT_ROOT.name.lower()
    ):
        return ""
    return text


def load_settings() -> LogSettings:
    ensure_data_dir()
    defaults = LogSettings()
    if not SETTINGS_PATH.is_file():
        return defaults
    try:
        data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return defaults
    if not isinstance(data, dict):
        return defaults
    return LogSettings(
        level=str(data.get("level", defaults.level)),
        file_enabled=bool(data.get("file_enabled", defaults.file_enabled)),
        log_dir=_normalize_log_dir(str(data.get("log_dir") or "")),
        log_filename=str(
            data.get("log_filename", defaults.log_filename) or defaults.log_filename
        ),
        max_bytes=int(data.get("max_bytes", defaults.max_bytes) or defaults.max_bytes),
        memory_lines=int(
            data.get("memory_lines", defaults.memory_lines) or defaults.memory_lines
        ),
    )


def save_settings(settings: LogSettings) -> None:
    ensure_data_dir()
    data = asdict(settings)
    data["log_dir"] = _normalize_log_dir(settings.log_dir)
    SETTINGS_PATH.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )


def logging_status_html(settings: LogSettings | None = None) -> str:
    """HTML summary for Console — level, file path, disk logging on/off."""
    s = settings or get_hub().settings
    path = str(s.log_path()) if s.file_enabled else "—"
    disk = "Active" if s.file_enabled else "Off"
    disk_color = "#2e7d32" if s.file_enabled else "#757575"
    return (
        f"Log level: <b>{s.level}</b> &nbsp;·&nbsp; "
        f"Log file: <code>{path}</code> &nbsp;·&nbsp; "
        f'Log to disk: <span style="color:{disk_color}; font-weight:bold;">'
        f"{disk}</span>"
    )
