"""Application logging / FIFO ring-file tests."""

from __future__ import annotations

from pathlib import Path

from pfsense_checker import app_log


def test_memory_ring_and_listener(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(app_log, "SETTINGS_PATH", tmp_path / "logging.json")
    monkeypatch.setattr(app_log, "DEFAULT_LOG_DIR", tmp_path / "logs")
    app_log._hub = None  # noqa: SLF001 — reset singleton for isolated test

    hub = app_log.configure()
    hub.apply_settings(
        app_log.LogSettings(
            level="DEBUG",
            file_enabled=False,
            log_dir=str(tmp_path / "logs"),
            memory_lines=10,
            max_bytes=512,
        ),
        persist=True,
    )
    seen: list[str] = []
    hub.subscribe(lambda e: seen.append(e.message))
    log = app_log.get_logger("test")
    for i in range(12):
        log.info("msg-%s", i)
    recent = hub.recent()
    assert len(recent) == 10
    assert recent[0].message == "msg-2"
    assert recent[-1].message == "msg-11"
    assert seen[-1] == "msg-11"


def test_ring_file_trims_oldest(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(app_log, "SETTINGS_PATH", tmp_path / "logging.json")
    monkeypatch.setattr(app_log, "DEFAULT_LOG_DIR", tmp_path / "logs")
    app_log._hub = None  # noqa: SLF001

    hub = app_log.configure()
    log_dir = tmp_path / "logs"
    hub.apply_settings(
        app_log.LogSettings(
            level="INFO",
            file_enabled=True,
            log_dir=str(log_dir),
            log_filename="ring.log",
            max_bytes=600,
            memory_lines=100,
        ),
        persist=True,
    )
    log = app_log.get_logger("ring")
    for i in range(80):
        log.info("line-%03d %s", i, "x" * 40)
    path = Path(log_dir) / "ring.log"
    assert path.is_file()
    size = path.stat().st_size
    assert size <= 600
    text = path.read_text(encoding="utf-8")
    assert "line-079" in text
    assert "line-000" not in text
