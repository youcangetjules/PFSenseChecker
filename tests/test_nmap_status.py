"""nmap status on Python Modules: found, version, test run, Npcap, and the panel row."""

from __future__ import annotations

import os
import subprocess

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pfsense_checker import nmap_status as ns  # noqa: E402


def _fake_run(outputs: dict[str, subprocess.CompletedProcess]):  # noqa: ANN202
    def run(args, **_kw):  # noqa: ANN001, ANN003, ANN202
        key = "sc" if args[0] == "sc" else ("version" if "--version" in args else "scan")
        return outputs[key]
    return run


def _cp(out: str = "", err: str = "", code: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], code, out, err)


def test_installed_and_working(monkeypatch) -> None:
    monkeypatch.setattr(ns.device_scan, "nmap_path", lambda: r"C:\Program Files (x86)\Nmap\nmap.exe")
    monkeypatch.setattr("shutil.which", lambda name: None)
    monkeypatch.setattr(ns.winproc, "run", _fake_run({
        "sc": _cp("SERVICE_NAME: npcap\n STATE : 4 RUNNING"),
        "version": _cp("Nmap version 7.95 ( https://nmap.org )\nPlatform: i686-pc-windows-windows"),
        "scan": _cp("Nmap scan report for 127.0.0.1\nHost is up (0.0010s latency).\nNmap done"),
    }))
    st = ns.check()
    assert st.installed and st.works and st.version == "Nmap 7.95" and st.npcap == "running"
    assert st.summary == "Installed and working" and not st.on_path
    assert any("not on PATH" in n for n in st.notes)


def test_without_npcap_and_not_installed(monkeypatch) -> None:
    monkeypatch.setattr(ns.device_scan, "nmap_path", lambda: "nmap")
    monkeypatch.setattr(ns.winproc, "run", _fake_run({
        "sc": _cp("[SC] EnumQueryServicesStatus:OpenService FAILED 1060"),
        "version": _cp("Nmap version 7.95"),
        "scan": _cp("Host is up"),
    }))
    st = ns.check()
    assert st.npcap == "not installed" and st.summary == "Installed and working (no Npcap)"
    monkeypatch.setattr(ns.device_scan, "nmap_path", lambda: "")
    st2 = ns.check()
    assert st2.summary == "Not installed" and ns.DOWNLOAD_URL in st2.notes[0]


def test_failed_test_run(monkeypatch) -> None:
    monkeypatch.setattr(ns.device_scan, "nmap_path", lambda: "nmap")
    monkeypatch.setattr(ns.winproc, "run", _fake_run({
        "sc": _cp("RUNNING"), "version": _cp("Nmap version 7.95"),
        "scan": _cp("", "dnet: Failed to open device eth0", 1),
    }))
    st = ns.check()
    assert not st.works and st.summary == "Installed, but a test run failed" and "eth0" in st.error


def test_programs_panel_has_graphviz_and_nmap_rows(monkeypatch) -> None:
    from PySide6.QtWidgets import QApplication, QGroupBox

    from pfsense_checker.home_screen import HomeScreen

    QApplication.instance() or QApplication([])
    monkeypatch.setattr(ns, "check", lambda: ns.NmapStatus(error="nmap was not found", npcap="running",
                                                           notes=["Install nmap"]))
    home = HomeScreen()
    home._ensure_page("modules")  # noqa: SLF001
    home._nmap_refresh()  # noqa: SLF001
    titles = [b.title() for b in home.findChildren(QGroupBox)]
    assert "Programs (not Python modules)" in titles
    assert home.nmap_badge.text() == "Not installed"
    assert "Npcap driver: running" in home.nmap_detail.text()
    assert home.graphviz_badge is not home.nmap_badge
