"""Unit tests for speed_check helpers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from pfsense_checker.speed_check import (
    SpeedSample,
    measure_download,
    measure_ping,
    measure_traceroute,
)


def test_measure_download_empty_url() -> None:
    sample = measure_download("")
    assert sample.kind == "download"
    assert sample.status == "error"
    assert "no URL" in sample.message


def test_measure_ping_maps_probe_result() -> None:
    fake = MagicMock()
    fake.status = "ok"
    fake.message = "reachable"
    fake.latency_ms = 12.3
    with patch("pfsense_checker.speed_check.ping_host", return_value=fake):
        sample = measure_ping("8.8.8.8", count=1)
    assert isinstance(sample, SpeedSample)
    assert sample.kind == "ping"
    assert sample.status == "ok"
    assert sample.latency_ms == 12.3
    assert sample.target == "8.8.8.8"


def test_measure_traceroute_empty_target() -> None:
    sample = measure_traceroute("")
    assert sample.kind == "traceroute"
    assert sample.status == "error"
    assert "no target" in sample.message


def test_measure_traceroute_maps_output() -> None:
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = (
        "Tracing route to 8.8.8.8\n"
        "  1    <1 ms    <1 ms    <1 ms  192.168.1.1\n"
        "  2    12 ms    11 ms    10 ms  8.8.8.8\n"
    )
    fake.stderr = ""
    with patch("pfsense_checker.speed_check.winproc.run", return_value=fake):
        sample = measure_traceroute("8.8.8.8")
    assert sample.kind == "traceroute"
    assert sample.status == "ok"
    assert sample.target == "8.8.8.8"
    assert "2 hop" in sample.message
    assert sample.latency_ms == 10.0


def test_home_sections_defined() -> None:
    from pfsense_checker.home_screen import SECTIONS

    keys = [k for k, _ in SECTIONS]
    assert keys == [
        "login",
        "files",
        "beaconing",
        "subnet_health",
        "config",
        "security_holes",
        "pentesting",
        "dns_leakage",
        "speed",
        "topology",
        "database",
        "users",
        "modules",
        "tests",
        "ollama",
        "problems",
        "wireshark",
        "logs",
        "setup",
        "about",
    ]


def test_log_pages_sit_under_the_one_logs_entry() -> None:
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from pfsense_checker.home_screen import LOGS_SUBSECTIONS, SECTIONS, HomeScreen, section_title

    assert [k for k, _ in LOGS_SUBSECTIONS] == [
        "logs.analysis", "logs.devices", "syslog", "console", "logs.logins"]
    top = [k for k, _ in SECTIONS]
    assert not {"console", "syslog", "log_pipeline"} & set(top)  # one Logs entry, not four
    assert "Log Pipeline" not in [label for _k, label in LOGS_SUBSECTIONS]  # it is part of Syslog
    assert top.count("logs") == 1
    assert section_title("console") == "Console" and section_title("syslog") == "Syslog"

    QApplication.instance() or QApplication([])
    home = HomeScreen()
    for key in ("console", "syslog"):
        assert home.nav.parent_of(key) == "logs"
        home.show_section(key)  # the old keys still open their pages, now inside Logs
        assert home.current_section_key() == key and home.nav.open_parent() == "logs"
        assert home.stack.currentWidget() is home._pages[key]  # noqa: SLF001
    home.nav.select("login", animate=False)
    home.show_section("logs")
    assert home.current_section_key() in {k for k, _ in LOGS_SUBSECTIONS}


def test_setup_subsections_defined() -> None:
    from pfsense_checker.home_screen import SETUP_SUBSECTIONS

    keys = [k for k, _ in SETUP_SUBSECTIONS]
    assert keys == [
        "setup.oui",
        "setup.logging",
        "setup.openobserve",
        "setup.snmp",
        "setup.mibs",
        "setup.version",
    ]
