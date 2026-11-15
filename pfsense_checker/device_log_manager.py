"""Runs device log downloads in the background: on a timer and after Connect.

One device at a time, one SSH login per device per run. A device downloaded in
the last two minutes is not fetched again for a Connect (Connect and Load Config
often come together). (added 2026-11-09)
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from datetime import datetime

from PySide6.QtCore import QObject, QThread, QTimer, Signal

from pfsense_checker import app_log
from pfsense_checker import device_logs as dl

CHECK_MS = 5 * 60 * 1000  # how often to look whether a scheduled run is due
FIRST_CHECK_MS = 60 * 1000  # a minute after NetCheck opens
CONNECT_DELAY_MS = 20 * 1000  # let Connect's own inventory finish first
RECENT_S = 120
SCHEDULE_KEY = "_schedule"


class _LogWorker(QThread):
    done = Signal(object, str)  # DeviceLogResult, index message

    def __init__(self, device, source: str) -> None:  # noqa: ANN001
        super().__init__()
        self._device = device
        self._source = source

    def run(self) -> None:  # noqa: D102
        res = dl.download_device_logs(self._device, source=self._source)
        ok, msg = dl.record_index([res]) if res.ok else (True, "")
        self.done.emit(res, msg if ok else f"index not written: {msg}")


class DeviceLogManager(QObject):
    status = Signal(str)  # one line for the status bar / page
    device_done = Signal(object)  # DeviceLogResult

    def __init__(self, site_getter: Callable[[], object], parent: QObject | None = None,
                 *, autostart: bool = True) -> None:
        super().__init__(parent)
        self._site_getter = site_getter
        self.settings = dl.load_settings()
        self._queue: deque[tuple[str, str]] = deque()
        self._worker: _LogWorker | None = None
        self._recent: dict[str, float] = {}
        self.history: list[dl.DeviceLogResult] = []
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.check_schedule)
        if autostart:
            self._timer.start(CHECK_MS)
            QTimer.singleShot(FIRST_CHECK_MS, self.check_schedule)

    # -- settings ----------------------------------------------------------- #

    def apply_settings(self, settings: dl.LogSettings) -> None:
        self.settings = settings.normalised()
        dl.save_settings(self.settings)

    def last_scheduled_run(self) -> str:
        return str((dl.load_state().get(SCHEDULE_KEY) or {}).get("last_run", ""))

    # -- triggers ----------------------------------------------------------- #

    def check_schedule(self) -> None:
        if not self.settings.enabled or not dl.due(self.last_scheduled_run(), self.settings.hours):
            return
        state = dl.load_state()
        state[SCHEDULE_KEY] = {"last_run": datetime.now().isoformat(timespec="seconds")}
        dl.save_state(state)
        self.run_all("schedule")

    def run_all(self, source: str = "manual") -> int:
        names = [d.name for d in self._devices() if dl.eligible(d)]
        for name in names:
            self.enqueue(name, source)
        if not names:
            self.status.emit("Device logs: no pfSense / MikroTik device has SSH set up")
        return len(names)

    def on_device_logged_in(self, name: str) -> None:
        """Connect / Load Config succeeded: fetch that device's logs shortly."""
        if self.settings.enabled and self.settings.on_connect:
            QTimer.singleShot(CONNECT_DELAY_MS, lambda: self.enqueue(name, "connect"))

    def enqueue(self, name: str, source: str) -> bool:
        if any(n == name for n, _s in self._queue):
            return False
        if source == "connect" and time.time() - self._recent.get(name, 0) < RECENT_S:
            return False
        self._queue.append((name, source))
        self._next()
        return True

    def busy(self) -> bool:
        return self._worker is not None or bool(self._queue)

    # -- running ------------------------------------------------------------ #

    def _devices(self) -> list:
        site = self._site_getter()
        return list(getattr(site, "devices", []) or [])

    def _next(self) -> None:
        if self._worker is not None or not self._queue:
            return
        name, source = self._queue.popleft()
        device = next((d for d in self._devices() if d.name == name), None)
        if device is None or not dl.eligible(device):
            self._next()
            return
        self.status.emit(f"Device logs: downloading from {name}…")
        worker = _LogWorker(device, source)
        self._worker = worker
        worker.done.connect(self._on_done)
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def _on_done(self, res: dl.DeviceLogResult, index_msg: str) -> None:
        self._worker = None
        self._recent[res.device] = time.time()
        self.history.insert(0, res)
        del self.history[200:]
        line = f"Device logs: {res.summary()}" + (f" ({index_msg})" if "not written" in index_msg else "")
        log = app_log.get_logger("device_logs")
        (log.info if res.ok else log.warning)("%s source=%s", res.summary(), res.source)
        self.status.emit(line)
        self.device_done.emit(res)
        self._next()
