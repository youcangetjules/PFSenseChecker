"""Log Pipeline listen port and line formatting."""

from __future__ import annotations

import os
from pathlib import Path

from pfsense_checker import log_pipeline
from pfsense_checker.syslog_recv import SyslogMessage


def test_default_port_is_59000(tmp_path) -> None:
    settings = log_pipeline.load_settings(tmp_path / "missing.json")
    assert settings.port == 59000
    recv = log_pipeline.receiver_settings(settings)
    assert recv.udp_port == 59000
    assert recv.tcp_port == 59000
    assert recv.attached_only is False
    assert recv.file_enabled is False


def test_port_round_trip_and_reject_invalid(tmp_path) -> None:
    path = tmp_path / "log_pipeline.json"
    log_pipeline.save_settings(log_pipeline.LogPipelineSettings(port=5514), path)
    assert log_pipeline.load_settings(path).port == 5514
    log_pipeline.save_settings(log_pipeline.LogPipelineSettings(port=0), path)
    assert log_pipeline.load_settings(path).port == 59000
    assert log_pipeline.clamp_port("nope") == 59000
    assert log_pipeline.clamp_port(70000) == 59000
    assert log_pipeline.clamp_port(59000) == 59000


def test_filterlog_line_is_decoded() -> None:
    raw = (
        "<134>Oct 18 19:00:00 fw filterlog[123]: "
        "5,,,1000000103,igb0,match,block,in,4,0x0,,64,1,0,DF,6,tcp,60,"
        "192.0.2.10,198.51.100.20,44321,443,0,S,1,0,,"
    )
    msg = SyslogMessage(
        received_at="2026-10-18T19:00:00+00:00",
        source_ip="10.1.1.1",
        source_port=514,
        device_name="",
        pri=134,
        facility=16,
        severity=6,
        facility_name="local0",
        severity_name="info",
        timestamp="Oct 18 19:00:00",
        hostname="fw",
        app_name="filterlog",
        message=raw,
        raw=raw,
        accepted=True,
    )
    line = log_pipeline.format_message(msg)
    assert "block in igb0" in line
    assert "tcp" in line
    assert "192.0.2.10:44321 -> 198.51.100.20:443" in line


def test_pipeline_page_port_defaults_to_59000(tmp_path) -> None:
    """Construct the page in a child process so Qt does not leak into other tests."""
    import subprocess
    import sys

    settings = tmp_path / "missing.json"
    script = tmp_path / "check_port.py"
    script.write_text(
        "\n".join(
            [
                "import os",
                "os.environ['QT_QPA_PLATFORM'] = 'offscreen'",
                "from pathlib import Path",
                "from pfsense_checker import log_pipeline",
                f"log_pipeline.SETTINGS_PATH = Path({str(settings)!r})",
                "from PySide6.QtWidgets import QApplication",
                "QApplication([])",
                "from pfsense_checker.log_pipeline_screen import LogPipelinePage",
                "page = LogPipelinePage()",
                "assert page.port.value() == 59000",
                "assert page.port.minimum() == 1",
                "assert page.port.maximum() == 65535",
                "page.port.setValue(514)",
                "assert page.port.value() == 514",
            ]
        ),
        encoding="utf-8",
    )
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        check=False,
        cwd=root,
        env=env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
