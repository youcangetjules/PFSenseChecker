"""Device log manager: schedule, after-Connect runs, one device at a time, no double fetches."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from pfsense_checker import device_log_manager as dlm  # noqa: E402
from pfsense_checker import device_logs as dl  # noqa: E402
from pfsense_checker.topology_site import Device, SiteTopology, SshAccess  # noqa: E402


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _site() -> SiteTopology:
    return SiteTopology(devices=[
        Device(name="guardian", kind="pfsense", ssh=SshAccess(host="10.0.0.1", username="admin")),
        Device(name="crs328", kind="mikrotik", ssh=SshAccess(host="10.0.0.5", username="admin")),
        Device(name="nas", kind="other", ssh=SshAccess(host="10.0.0.9", username="admin")),
        Device(name="crs109", kind="mikrotik"),  # no SSH yet
    ])


def _wait(mgr: dlm.DeviceLogManager, ms: int = 3000) -> None:
    import time

    end = time.time() + ms / 1000
    while mgr.busy() and time.time() < end:
        QCoreApplication.processEvents()
        time.sleep(0.01)
    QCoreApplication.processEvents()


def _fake(monkeypatch, tmp_path, calls: list) -> None:  # noqa: ANN001
    def fake_download(device, *, source="schedule", **_k):  # noqa: ANN001, ANN003, ANN202
        calls.append((device.name, source))
        return dl.DeviceLogResult(device=device.name, kind=dl.kind_of(device), ok=True, source=source)

    monkeypatch.setattr(dl, "download_device_logs", fake_download)
    monkeypatch.setattr(dl, "record_index", lambda results: (True, "ok"))
    monkeypatch.setattr(dl, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(dl, "SETTINGS_FILE", tmp_path / "settings.json")
    orig_load, orig_save = dl.load_state, dl.save_state
    monkeypatch.setattr(dl, "load_state", lambda path=None: orig_load(tmp_path / "state.json"))
    monkeypatch.setattr(dl, "save_state", lambda state, path=None: orig_save(state, tmp_path / "state.json"))
    monkeypatch.setattr(dl, "load_settings", lambda path=None: dl.LogSettings())
    monkeypatch.setattr(dl, "save_settings", lambda s, path=None: None)


def test_run_all_fetches_each_eligible_device_once(monkeypatch, tmp_path) -> None:
    _app()
    calls: list = []
    _fake(monkeypatch, tmp_path, calls)
    site = _site()
    mgr = dlm.DeviceLogManager(lambda: site, autostart=False)
    assert mgr.run_all("manual") == 2
    _wait(mgr)
    assert calls == [("guardian", "manual"), ("crs328", "manual")]
    assert [r.device for r in mgr.history] == ["crs328", "guardian"]


def test_connect_soon_after_a_download_is_skipped(monkeypatch, tmp_path) -> None:
    _app()
    calls: list = []
    _fake(monkeypatch, tmp_path, calls)
    site = _site()
    mgr = dlm.DeviceLogManager(lambda: site, autostart=False)
    assert mgr.enqueue("guardian", "connect")
    _wait(mgr)
    assert not mgr.enqueue("guardian", "connect")  # Load Config right after Connect
    assert mgr.enqueue("guardian", "manual")  # but Download now always goes
    _wait(mgr)
    assert calls == [("guardian", "connect"), ("guardian", "manual")]


def test_schedule_runs_when_due_and_records_it(monkeypatch, tmp_path) -> None:
    _app()
    calls: list = []
    _fake(monkeypatch, tmp_path, calls)
    site = _site()
    mgr = dlm.DeviceLogManager(lambda: site, autostart=False)
    mgr.check_schedule()
    _wait(mgr)
    assert len(calls) == 2 and mgr.last_scheduled_run()
    mgr.check_schedule()  # just ran: not due again for six hours
    _wait(mgr)
    assert len(calls) == 2
    mgr.settings = dl.LogSettings(enabled=False)
    state = dl.load_state()
    state.pop(dlm.SCHEDULE_KEY)
    dl.save_state(state)
    mgr.check_schedule()  # switched off
    assert len(calls) == 2


def test_device_logs_page_builds(monkeypatch, tmp_path) -> None:
    _app()
    _fake(monkeypatch, tmp_path, [])
    monkeypatch.setattr(dl, "recent_index", lambda limit=200: [])
    from pfsense_checker.home_screen import HomeScreen

    home = HomeScreen()
    home.set_sites(live=_site())
    home._ensure_page("logs.devices")  # noqa: SLF001
    assert home.dlog_hours.value() == dl.DEFAULT_HOURS and home.dlog_enabled.isChecked()
    assert "guardian, crs328" in home.dlog_status.text()
