"""OUI / MAC vendor lookup tests."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from pfsense_checker import oui


class _Response:
    def __init__(self, payload: dict | str) -> None:
        if isinstance(payload, dict):
            self._raw = json.dumps(payload).encode("utf-8")
        else:
            self._raw = payload.encode("utf-8")
        self.status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self, _limit: int = -1) -> bytes:
        return self._raw


def test_oui_key_roundtrip(tmp_path, monkeypatch) -> None:
    secrets = tmp_path / "secrets.local.json"
    monkeypatch.setattr(oui, "_SECRETS_FILE", secrets)
    monkeypatch.delenv("OUI_API_KEY", raising=False)
    monkeypatch.delenv("RAPIDAPI_KEY", raising=False)
    monkeypatch.delenv("MACADDRESS_IO_API_KEY", raising=False)
    assert oui.has_oui_api_key() is False
    oui.save_oui_api_key("test-key-123")
    assert oui.load_oui_api_key() == "test-key-123"
    assert oui.has_oui_api_key() is True


def test_lookup_vendor_without_key_returns_empty(tmp_path, monkeypatch) -> None:
    secrets = tmp_path / "secrets.local.json"
    monkeypatch.setattr(oui, "_SECRETS_FILE", secrets)
    monkeypatch.delenv("OUI_API_KEY", raising=False)
    monkeypatch.delenv("RAPIDAPI_KEY", raising=False)
    monkeypatch.delenv("MACADDRESS_IO_API_KEY", raising=False)
    oui.clear_vendor_cache()
    assert oui.lookup_vendor("00:1B:44:11:3A:B7") == ""


def test_lookup_vendor_parses_company(tmp_path, monkeypatch) -> None:
    secrets = tmp_path / "secrets.local.json"
    monkeypatch.setattr(oui, "_SECRETS_FILE", secrets)
    monkeypatch.delenv("OUI_API_KEY", raising=False)
    monkeypatch.delenv("RAPIDAPI_KEY", raising=False)
    monkeypatch.delenv("MACADDRESS_IO_API_KEY", raising=False)
    oui.clear_vendor_cache()
    payload = {
        "errors": [],
        "result": [
            {
                "hex": "00:1b:44",
                "b16": "001b44",
                "name": "sandisk corporation",
                "address": "somewhere",
            }
        ],
    }
    with patch("urllib.request.urlopen", return_value=_Response(payload)):
        name = oui.lookup_vendor("00:1B:44:11:3A:B7", api_key="k")
    assert name == "Sandisk Corporation"
    # cached — second call must not hit the network
    with patch("urllib.request.urlopen", side_effect=AssertionError("cache miss")):
        assert oui.lookup_vendor("00:1B:44:aa:bb:cc", api_key="k") == "Sandisk Corporation"


def test_lookup_sends_rapidapi_headers(tmp_path, monkeypatch) -> None:
    secrets = tmp_path / "secrets.local.json"
    monkeypatch.setattr(oui, "_SECRETS_FILE", secrets)
    monkeypatch.delenv("OUI_API_KEY", raising=False)
    monkeypatch.delenv("RAPIDAPI_KEY", raising=False)
    monkeypatch.delenv("MACADDRESS_IO_API_KEY", raising=False)
    oui.clear_vendor_cache()
    captured = {}

    def fake_open(request, timeout=0):  # noqa: ANN001
        captured["url"] = request.full_url
        captured["host"] = request.get_header("X-rapidapi-host")
        captured["key"] = request.get_header("X-rapidapi-key")
        return _Response({"result": [{"name": "Acme"}]})

    with patch("urllib.request.urlopen", side_effect=fake_open):
        assert oui.lookup_vendor("00:15:5d:86:eb:5f", api_key="secret-key") == "Acme"
    assert "mac-address-lookup1.p.rapidapi.com" in captured["url"]
    assert "query=00" in captured["url"] or "query=00%3A15%3A5d" in captured["url"]
    assert captured["host"] == "mac-address-lookup1.p.rapidapi.com"
    assert captured["key"] == "secret-key"


@pytest.mark.parametrize("mac", ["not-a-mac", "11:22"])
def test_lookup_rejects_bad_mac(mac: str) -> None:
    with pytest.raises(ValueError):
        oui.lookup_vendor(mac, api_key="k")
