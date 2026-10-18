"""Mocked RouterOS REST collection tests."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from pfsense_checker.routeros_rest import (
    CollectResult,
    RouterOSRestError,
    _extract_file_chunk,
    _looks_like_export,
    collect_export,
    probe_connection,
)
from pfsense_checker.topology_site import CONFIG_SOURCE_MIKROTIK_REST, ConfigSource, Device

SAMPLE_EXPORT = """# by RouterOS 7.14.2
/interface bridge
add name=bridge1
/system identity
set name=TestRouter
"""


def test_looks_like_export() -> None:
    assert _looks_like_export(SAMPLE_EXPORT)
    assert not _looks_like_export("hello world")


def test_extract_file_chunk_json() -> None:
    raw = json.dumps({"data": "abc"}).encode("utf-8")
    assert _extract_file_chunk(raw) == "abc"


def _device() -> Device:
    d = Device(name="mt1", kind="mikrotik")
    d.config_source = ConfigSource(
        source_type=CONFIG_SOURCE_MIKROTIK_REST,
        host="192.0.2.1",
        port=443,
        username="admin",
        credential_ref="mt-testref",
        allow_insecure_tls=True,
        verify_tls=False,
    )
    return d


def test_probe_connection_auth_failure() -> None:
    d = _device()

    def boom(*_a, **_k):
        raise RouterOSRestError("Authentication failed (HTTP 401).")

    with patch("pfsense_checker.routeros_rest._resolve_password", return_value="x"), patch(
        "pfsense_checker.routeros_rest._request", side_effect=boom
    ):
        ok, msg = probe_connection(d.config_source)  # type: ignore[arg-type]
        assert ok is False
        assert "401" in msg or "Authentication" in msg


def test_collect_export_success(tmp_path: Path) -> None:
    d = _device()
    calls: list[str] = []

    def fake_request(method, url, **kwargs):  # noqa: ANN001
        calls.append(f"{method} {url}")
        if url.endswith("/rest/export"):
            return 200, b"{}", {}
        if url.endswith("/rest/file/read"):
            # First chunk returns full export, second empty to stop
            if any("file/read" in c and "POST" in c for c in calls[:-1]):
                return 200, json.dumps({"data": ""}).encode(), {}
            return 200, json.dumps({"data": SAMPLE_EXPORT}).encode(), {}
        if "file/remove" in url or method == "DELETE":
            return 200, b"{}", {}
        return 200, b"{}", {}

    with patch("pfsense_checker.routeros_rest._resolve_password", return_value="secret"), patch(
        "pfsense_checker.routeros_rest._request", side_effect=fake_request
    ):
        res = collect_export(d, cache_base=tmp_path)
    assert isinstance(res, CollectResult)
    assert res.ok, res.error
    assert Path(res.path).is_file()
    assert "TestRouter" in Path(res.path).read_text(encoding="utf-8")
    assert d.config_source is not None
    assert d.config_source.last_status == "ok"
    assert d.config_source.export_hash
    assert any("export" in c for c in calls)


def test_collect_export_empty_fails(tmp_path: Path) -> None:
    d = _device()

    def fake_request(method, url, **kwargs):  # noqa: ANN001
        if url.endswith("/rest/file/read"):
            return 200, json.dumps({"data": ""}).encode(), {}
        return 200, b"{}", {}

    with patch("pfsense_checker.routeros_rest._resolve_password", return_value="secret"), patch(
        "pfsense_checker.routeros_rest._request", side_effect=fake_request
    ), patch(
        "pfsense_checker.routeros_rest._try_file_contents", return_value=""
    ):
        res = collect_export(d, cache_base=tmp_path)
    assert res.ok is False
    assert "empty" in res.error.lower()
