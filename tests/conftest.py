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
def _isolate_receiver_settings(tmp_path, monkeypatch):
    # Opening Logs → Syslog moves the old Log Pipeline port into the Syslog
    # settings (once). A test that builds the page must not do that to the
    # operator's data/log_pipeline.json and data/syslog.json.
    from pfsense_checker import log_pipeline, syslog_recv

    monkeypatch.setattr(log_pipeline, "SETTINGS_PATH", tmp_path / "log_pipeline.json")
    from pfsense_checker import security_holes

    monkeypatch.setattr(security_holes, "SETTINGS_PATH", tmp_path / "security_holes.json")
    real_load, real_save = syslog_recv.load_settings, syslog_recv.save_settings
    monkeypatch.setattr(syslog_recv, "load_settings",
                        lambda path=None: real_load(path or tmp_path / "syslog.json"))
    monkeypatch.setattr(syslog_recv, "save_settings",
                        lambda settings, path=None: real_save(settings, path or tmp_path / "syslog.json"))


@pytest.fixture(autouse=True)
def _fresh_login_throttle(monkeypatch):
    monkeypatch.setattr(auth, "LOGIN_THROTTLE", auth.LoginThrottle())


@pytest.fixture(autouse=True)
def _no_cached_adapters(monkeypatch):
    # discover_local_subnets caches for 30 s; a test's fake adapters must
    # not leak into the next test.
    from pfsense_checker import subnet_health

    monkeypatch.setattr(subnet_health, "_cache", None)


@pytest.fixture(autouse=True)
def _no_cached_identification():
    from pfsense_checker import net_discovery

    net_discovery.clear_ident_cache()
    yield
    net_discovery.clear_ident_cache()
