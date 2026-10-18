"""Optional LLM advisor via Poe or a local Ollama instance.

Security posture:
- Poe's API key is loaded from the POE_API_KEY environment variable or the
  gitignored ``secrets.local.json``. It is never logged or embedded in source.
- Ollama defaults to ``http://127.0.0.1:11434``. A local instance needs no key;
  cloud / protected endpoints may use ``OLLAMA_API_KEY`` or ``ollama_api_key``
  in ``secrets.local.json`` (sent as ``Authorization: Bearer …``).
- Only a minimal, redacted summary of *findings* is ever sent to the LLM.
  Raw config bytes and known-secret fields (password hashes, PSKs, private
  keys, sshdata, tokens, certificates) are stripped before anything leaves
  the machine.
- Network calls are opt-in (user clicks a button); nothing is sent automatically.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

_SECRETS_FILE = Path(__file__).resolve().parent.parent / "secrets.local.json"

DEFAULT_BOT = "GPT-4o-mini"
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_OLLAMA_MODEL = "llama3.2"
MAX_OLLAMA_RESPONSE = 4 * 1024 * 1024

# Tag/field names whose *values* must never be transmitted.
SECRET_FIELD_HINTS = (
    "password",
    "bcrypt-hash",
    "bcrypt_hash",
    "md5-hash",
    "secret",
    "psk",
    "pre-shared",
    "preshared",
    "privatekey",
    "private_key",
    "prv",
    "apikey",
    "api_key",
    "api-key",
    "token",
    "sshdata",
    "rrddata",
    "crypto",
    "tls",
    "cert",
    "ca",
    "crl",
    "radius",
    "authkey",
    "serverauthkey",
    "lighttpd",
    "wpa",
)

# Patterns for secret-looking blobs in free text.
_PEM_RE = re.compile(r"-----BEGIN[\s\S]*?END[^-]*-----", re.MULTILINE)
_BCRYPT_RE = re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")
_POE_KEY_RE = re.compile(r"sk-poe-[A-Za-z0-9]+")
_LONG_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
_HEXBLOB_RE = re.compile(r"\b[0-9a-fA-F]{40,}\b")


def is_available() -> bool:
    try:
        import fastapi_poe  # noqa: F401
    except ImportError:
        return False
    return True


def load_api_key() -> str:
    """Load the Poe API key from env or the gitignored secrets file."""
    env = os.environ.get("POE_API_KEY", "").strip()
    if env:
        return env
    try:
        data = json.loads(_SECRETS_FILE.read_text(encoding="utf-8"))
        return str(data.get("poe_api_key", "")).strip()
    except (OSError, json.JSONDecodeError):
        return ""


def save_api_key(key: str) -> None:
    """Persist the key to the gitignored secrets file."""
    data = {}
    if _SECRETS_FILE.is_file():
        try:
            data = json.loads(_SECRETS_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
    data["poe_api_key"] = key.strip()
    _SECRETS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_ollama_settings() -> tuple[str, str]:
    """Load Ollama URL/model from environment or local settings."""
    url = os.environ.get("OLLAMA_HOST", "").strip()
    model = os.environ.get("OLLAMA_MODEL", "").strip()
    try:
        data = json.loads(_SECRETS_FILE.read_text(encoding="utf-8"))
        url = url or str(data.get("ollama_url", "")).strip()
        model = model or str(data.get("ollama_model", "")).strip()
    except (OSError, json.JSONDecodeError):
        pass
    return url or DEFAULT_OLLAMA_URL, model or DEFAULT_OLLAMA_MODEL


def is_ollama_enabled() -> bool:
    """Whether the tool should use a local Ollama instance.

    Defaults to True when unset so an installed local Ollama works out of the
    box. Override with ``OLLAMA_ENABLED=0`` / ``false`` or ``ollama_enabled``
    in ``secrets.local.json``.
    """
    env = os.environ.get("OLLAMA_ENABLED", "").strip().lower()
    if env in {"0", "false", "no", "off"}:
        return False
    if env in {"1", "true", "yes", "on"}:
        return True
    try:
        data = json.loads(_SECRETS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return True
    if "ollama_enabled" not in data:
        return True
    return bool(data.get("ollama_enabled"))


def load_ollama_api_key() -> str:
    """Load optional Ollama API key from env or secrets.local.json."""
    env = os.environ.get("OLLAMA_API_KEY", "").strip()
    if env:
        return env
    try:
        data = json.loads(_SECRETS_FILE.read_text(encoding="utf-8"))
        return str(data.get("ollama_api_key", "")).strip()
    except (OSError, json.JSONDecodeError):
        return ""


def save_ollama_settings(
    url: str,
    model: str,
    *,
    api_key: str | None = None,
    enabled: bool | None = None,
) -> None:
    """Persist Ollama URL/model and optionally the API key (gitignored file)."""
    data = {}
    if _SECRETS_FILE.is_file():
        try:
            data = json.loads(_SECRETS_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
    data["ollama_url"] = _normalise_ollama_url(url)
    data["ollama_model"] = model.strip()
    if api_key is not None:
        data["ollama_api_key"] = api_key.strip()
    if enabled is not None:
        data["ollama_enabled"] = bool(enabled)
    _SECRETS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _normalise_ollama_url(url: str) -> str:
    value = (url or DEFAULT_OLLAMA_URL).strip().rstrip("/")
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Ollama URL must be an http:// or https:// URL")
    if parsed.username or parsed.password:
        raise ValueError("Do not embed credentials in the Ollama URL")
    return value


def _ollama_json(
    url: str,
    *,
    method: str = "GET",
    body: dict | None = None,
    timeout: float = 120,
    api_key: str = "",
) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {
        "Accept": "application/json",
        "User-Agent": "PFSenseChecker/1.x",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            raw = response.read(MAX_OLLAMA_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        detail = exc.read(512).decode("utf-8", errors="replace")
        raise RuntimeError(f"Ollama HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Cannot reach Ollama at {url}: {exc.reason}. "
            "Check that Ollama is running."
        ) from exc
    if len(raw) > MAX_OLLAMA_RESPONSE:
        raise RuntimeError("Ollama response exceeded the 4 MiB safety limit")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Ollama returned an invalid JSON response") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("Ollama returned an unexpected response")
    return payload


def list_ollama_models(
    base_url: str = DEFAULT_OLLAMA_URL,
    *,
    api_key: str = "",
    timeout: float = 5,
) -> list[str]:
    """Return model names exposed by a local Ollama server."""
    root = _normalise_ollama_url(base_url)
    payload = _ollama_json(
        f"{root}/api/tags",
        timeout=timeout,
        api_key=api_key or load_ollama_api_key(),
    )
    models = payload.get("models", [])
    if not isinstance(models, list):
        return []
    names = []
    for item in models:
        if isinstance(item, dict) and item.get("name"):
            names.append(str(item["name"]))
    return names


def redact_text(text: str) -> str:
    """Strip secret-looking blobs from arbitrary text before transmission."""
    if not text:
        return text
    text = _PEM_RE.sub("[REDACTED-PEM]", text)
    text = _BCRYPT_RE.sub("[REDACTED-HASH]", text)
    text = _POE_KEY_RE.sub("[REDACTED-KEY]", text)
    text = _HEXBLOB_RE.sub("[REDACTED-HEX]", text)
    text = _LONG_B64_RE.sub("[REDACTED-BLOB]", text)
    return text


def _is_secret_field(name: str) -> bool:
    n = name.lower()
    return any(hint in n for hint in SECRET_FIELD_HINTS)


def redact_config_snippet(snippet: str) -> str:
    """Redact values inside <secret-ish> XML tags, then blob-redact the rest.

    Use this if a user ever chooses to include a raw config section. It keeps
    the tag *structure* (useful for advice) but removes secret values.
    """
    def _replace(match: re.Match) -> str:
        tag = match.group("tag")
        inner = match.group("inner")
        if _is_secret_field(tag):
            return f"<{tag}>[REDACTED]</{tag}>"
        return match.group(0)

    tag_re = re.compile(
        r"<(?P<tag>[A-Za-z0-9_\-]+)>(?P<inner>[\s\S]*?)</(?P=tag)>"
    )
    snippet = tag_re.sub(_replace, snippet)
    return redact_text(snippet)


def build_findings_context(result, *, include_hostname: bool = False) -> str:
    """Produce a SAFE, minimal context string from a CheckResult.

    Only high-level counts and our own finding descriptions/paths are included —
    never raw config values.
    """
    s = result.summary
    device = (
        "MikroTik RouterOS"
        if getattr(result, "source_type", "") == "mikrotik"
        else "pfSense/OPNsense"
    )
    lines: list[str] = []
    lines.append(f"{device} configuration check summary:")
    if include_hostname and result.hostname:
        lines.append(f"- hostname: {result.hostname}")
    lines.append(f"- config version: {result.version or 'unknown'}")
    lines.append(
        f"- result: {'PASS' if result.ok else 'FAIL'} "
        f"({result.error_count} errors, {result.warning_count} warnings, "
        f"{result.info_count} info)"
    )
    lines.append(
        f"- interfaces: {s.get('interfaces_total', 0)} "
        f"({s.get('interfaces_enabled', 0)} enabled, "
        f"{s.get('interfaces_disabled', 0)} disabled); "
        f"bridges={s.get('bridges', 0)}, vlans={s.get('vlans', 0)}, laggs={s.get('laggs', 0)}"
    )
    lines.append(
        f"- firewall rules: {s.get('filter_rules', 0)}, nat: {s.get('nat_rules', 0)}, "
        f"vpn: {s.get('vpn', 0)}, packages: {s.get('packages', 0)} "
        f"({s.get('packages_disabled', 0)} disabled)"
    )
    lines.append("")
    lines.append("Findings (severity | category | path | message):")
    for f in result.findings:
        line = (
            f"- {f.severity.value.upper()} | {f.category} | {f.path or '-'} | {f.message}"
        )
        lines.append(redact_text(line))
    return "\n".join(lines)


_SYSTEM_PROMPT = (
    "You are a senior network and security engineer who specialises in pfSense, "
    "OPNsense and MikroTik RouterOS devices. You are given the output of an automated config "
    "checker (findings only, no secrets). Give concise, prioritised, actionable "
    "advice: call out the most important risks first, explain why each matters, "
    "and give concrete remediation steps referencing pfSense UI locations where "
    "helpful. If there are no serious issues, say so briefly."
)


def _make_session(verify: bool | str = True):
    """Build an httpx.AsyncClient that trusts the OS cert store when possible.

    Networks that intercept TLS (corporate proxies) present a private root CA
    that certifi does not know about. ``truststore`` bridges to the OS trust
    store (which does contain that CA), avoiding the need to disable verification.
    """
    import httpx

    if verify is False:
        return httpx.AsyncClient(verify=False, timeout=120)
    if isinstance(verify, str):
        return httpx.AsyncClient(verify=verify, timeout=120)
    try:
        import ssl

        import truststore

        ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        return httpx.AsyncClient(verify=ctx, timeout=120)
    except ImportError:
        # Fall back to certifi's default bundle.
        return httpx.AsyncClient(timeout=120)


def ask_advisor(
    context: str,
    question: str,
    *,
    api_key: str,
    bot_name: str = DEFAULT_BOT,
    temperature: float | None = 0.2,
    verify: bool | str = True,
) -> str:
    """Send a redacted context + question to the Poe bot and return the reply.

    ``verify`` may be True (OS trust store / certifi), a path to a CA bundle,
    or False (opt-in insecure — only for isolated test networks).

    Raises RuntimeError on any failure (missing lib, auth, network).
    """
    if not is_available():
        raise RuntimeError(
            "fastapi-poe is not installed. Run: pip install fastapi-poe"
        )
    if not api_key:
        raise RuntimeError("No Poe API key configured.")

    import fastapi_poe as fp

    # Defensive: redact both context and question one more time.
    safe_context = redact_text(context)
    safe_question = redact_text(question or "Summarise and prioritise the issues.")

    user_content = f"{safe_context}\n\nQuestion: {safe_question}"

    messages = [
        fp.ProtocolMessage(role="system", content=_SYSTEM_PROMPT),
        fp.ProtocolMessage(role="user", content=user_content),
    ]

    session = _make_session(verify)
    chunks: list[str] = []
    try:
        for partial in fp.get_bot_response_sync(
            messages=messages,
            bot_name=bot_name,
            api_key=api_key,
            temperature=temperature,
            session=session,
        ):
            text = getattr(partial, "text", "")
            if text:
                chunks.append(text)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"Poe request failed: {exc}") from exc

    reply = "".join(chunks).strip()
    return reply or "(empty response from bot)"


def ask_ollama(
    context: str,
    question: str,
    *,
    model: str = DEFAULT_OLLAMA_MODEL,
    base_url: str = DEFAULT_OLLAMA_URL,
    api_key: str = "",
    temperature: float = 0.2,
    timeout: float = 180,
) -> str:
    """Ask a local Ollama model using its native non-streaming chat API."""
    model = model.strip()
    if not model:
        raise RuntimeError("Select or enter an Ollama model.")

    safe_context = redact_text(context)
    safe_question = redact_text(
        question or "Summarise and prioritise the issues."
    )
    payload = _ollama_json(
        f"{_normalise_ollama_url(base_url)}/api/chat",
        method="POST",
        timeout=timeout,
        api_key=api_key or load_ollama_api_key(),
        body={
            "model": model,
            "stream": False,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": f"{safe_context}\n\nQuestion: {safe_question}",
                },
            ],
            "options": {"temperature": temperature},
        },
    )
    message = payload.get("message")
    if not isinstance(message, dict):
        error = payload.get("error")
        if error:
            raise RuntimeError(f"Ollama request failed: {error}")
        raise RuntimeError("Ollama response did not contain a message")
    reply = str(message.get("content", "")).strip()
    return reply or "(empty response from Ollama)"
