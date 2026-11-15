"""Login to Routers → Load All: every ticked device with SSH, one summary at the end."""

from __future__ import annotations

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication  # noqa: E402
from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from pfsense_checker import session_screen as ss  # noqa: E402
from pfsense_checker.ssh_session import SshExportResult  # noqa: E402
from pfsense_checker.topology_site import Device, SiteTopology, SshAccess  # noqa: E402


def _site() -> SiteTopology:
    return SiteTopology(devices=[
        Device(name="guardian", kind="pfsense", mgmt_ip="10.0.0.1", ssh=SshAccess(host="10.0.0.1", username="admin")),
        Device(name="crs328", kind="mikrotik", mgmt_ip="10.0.0.5", ssh=SshAccess(host="10.0.0.5", username="admin")),
        Device(name="crs109", kind="mikrotik", mgmt_ip="10.0.0.6", ssh=SshAccess(host="10.0.0.6", username="admin")),
        Device(name="off", kind="mikrotik", mgmt_ip="10.0.0.7", ssh=SshAccess(host="10.0.0.7", username="admin"),
               ignored=True),
        Device(name="nossh", kind="mikrotik", mgmt_ip="10.0.0.8"),
    ])


def test_load_all_pulls_each_eligible_device_and_reports_once(monkeypatch) -> None:
    QApplication.instance() or QApplication([])
    calls: list[str] = []

    def pf(dev, **_k):  # noqa: ANN001, ANN003, ANN202
        calls.append(f"pf:{dev.name}")
        return SshExportResult(ok=True, path="x.xml", bytes_written=10)

    def mt(dev, **_k):  # noqa: ANN001, ANN003, ANN202
        calls.append(f"mt:{dev.name}")
        return SshExportResult(ok=dev.name != "crs109", error="Authentication failed")

    monkeypatch.setattr(ss, "export_pfsense_config_ssh", pf)
    monkeypatch.setattr(ss, "export_mikrotik_verbose_ssh", mt)
    monkeypatch.setattr("pfsense_checker.module_required.ensure_feature", lambda *a, **k: True)
    shown: list[str] = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: shown.append(a[2]))
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: shown.append(a[2]))
    screen = ss.SessionScreen()
    monkeypatch.setattr(screen, "_sync_topology_from_config", lambda dev: None)
    screen.set_site(_site())
    assert [d.name for d in screen.load_all_devices()] == ["guardian", "crs328", "crs109"]
    assert screen.btn_load_all.text() == "Load All"
    logged_in: list[str] = []
    screen.device_logged_in.connect(logged_in.append)
    screen._load_all_configs()  # noqa: SLF001
    end = time.time() + 5
    while screen._load_all_worker is not None and time.time() < end:  # noqa: SLF001
        QCoreApplication.processEvents()
        time.sleep(0.01)
    assert calls == ["pf:guardian", "mt:crs328", "mt:crs109"]  # in order, one at a time
    assert logged_in == ["guardian", "crs328"]
    assert len(shown) == 1  # one summary, not a box per device
    assert "Loaded 2 of 3" in shown[0] and "crs109: Authentication failed" in shown[0]
    assert screen.btn_load_all.text() == "Load All" and screen.btn_load_all.isEnabled()
    screen.close()
