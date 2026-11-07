"""Shared test isolation.

Tests must not write into the operator's real log (``data/logs``) or its
``data/logging.json``. Before this fixture, test runs appended lines such
as "1Password login item saved user=julian" to the production log, which
read like real events.
"""

from __future__ import annotations

import logging

import pytest

from pfsense_checker import app_log, auth


def _detach_hub() -> None:
    hub = app_log._hub  # noqa: SLF001
    if hub is not None:
        logging.getLogger().removeHandler(hub._hub_handler)  # noqa: SLF001
    app_log._hub = None  # noqa: SLF001


@pytest.fixture(autouse=True)
def _isolate_app_log(tmp_path, monkeypatch):
    monkeypatch.setattr(app_log, "SETTINGS_PATH", tmp_path / "logging.json")
    monkeypatch.setattr(app_log, "DEFAULT_LOG_DIR", tmp_path / "logs")
    _detach_hub()
    # Build the hub now so the root logger feeds it before the test logs.
    app_log.configure()
    yield
    _detach_hub()


@pytest.fixture(autouse=True)
def _fresh_login_throttle(monkeypatch):
    monkeypatch.setattr(auth, "LOGIN_THROTTLE", auth.LoginThrottle())
