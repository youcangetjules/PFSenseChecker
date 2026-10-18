"""Local Ollama advisor tests."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from pfsense_checker import ai


class _Response:
    def __init__(self, payload: dict) -> None:
        self._raw = json.dumps(payload).encode("utf-8")
        self.status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self, _limit: int = -1) -> bytes:
        return self._raw


def test_list_ollama_models() -> None:
    payload = {"models": [{"name": "llama3.2:latest"}, {"name": "qwen3:8b"}]}
    with patch("urllib.request.urlopen", return_value=_Response(payload)):
        assert ai.list_ollama_models() == ["llama3.2:latest", "qwen3:8b"]


def test_ask_ollama_redacts_and_returns_reply() -> None:
    captured = {}

    def fake_open(request, timeout=0):  # noqa: ANN001
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return _Response({"message": {"role": "assistant", "content": "Fix VLAN 10."}})

    with patch("urllib.request.urlopen", side_effect=fake_open):
        reply = ai.ask_ollama(
            "Finding token=sk-poe-secret123",
            "Prioritise it",
            model="llama3.2:latest",
        )
    assert reply == "Fix VLAN 10."
    assert captured["url"].endswith("/api/chat")
    assert captured["body"]["stream"] is False
    assert captured["body"]["model"] == "llama3.2:latest"
    sent = json.dumps(captured["body"])
    assert "sk-poe-secret123" not in sent
    assert "[REDACTED-KEY]" in sent


def test_ask_ollama_sends_bearer_when_keyed() -> None:
    captured = {}

    def fake_open(request, timeout=0):  # noqa: ANN001
        captured["auth"] = request.get_header("Authorization")
        return _Response({"message": {"role": "assistant", "content": "ok"}})

    with patch("urllib.request.urlopen", side_effect=fake_open):
        ai.ask_ollama("context", "q", model="llama3.2", api_key="test-secret-key")
    assert captured["auth"] == "Bearer test-secret-key"


@pytest.mark.parametrize("url", ["file:///tmp/ollama", "localhost:11434", "ftp://host"])
def test_ollama_url_rejects_unsupported_schemes(url: str) -> None:
    with pytest.raises(ValueError):
        ai.list_ollama_models(url)


def test_ollama_enabled_defaults_true(tmp_path, monkeypatch) -> None:
    secrets = tmp_path / "secrets.local.json"
    monkeypatch.setattr(ai, "_SECRETS_FILE", secrets)
    monkeypatch.delenv("OLLAMA_ENABLED", raising=False)
    assert ai.is_ollama_enabled() is True


def test_ollama_enabled_persists(tmp_path, monkeypatch) -> None:
    secrets = tmp_path / "secrets.local.json"
    monkeypatch.setattr(ai, "_SECRETS_FILE", secrets)
    monkeypatch.delenv("OLLAMA_ENABLED", raising=False)
    ai.save_ollama_settings(
        "http://127.0.0.1:11434",
        "llama3.2",
        enabled=False,
    )
    assert ai.is_ollama_enabled() is False
    data = json.loads(secrets.read_text(encoding="utf-8"))
    assert data["ollama_enabled"] is False
    ai.save_ollama_settings(
        "http://127.0.0.1:11434",
        "llama3.2",
        enabled=True,
    )
    assert ai.is_ollama_enabled() is True
