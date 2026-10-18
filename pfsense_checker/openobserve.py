"""OpenObserve ingest and search client.

Talks to an OpenObserve HTTP API:

- ``GET /healthz``
- ``GET /api/{org}/streams``
- ``POST /api/{org}/{stream}/_json``
- ``POST /api/{org}/_search``

The password or ingestion token is read from the environment or the OS
keyring. It is never written to the settings file or to PostgreSQL.

Nothing is sent until Setup → OpenObserve is enabled and a credential is
present. App-log shipping skips this module's own logger so a failed ingest
cannot loop.
"""

from __future__ import annotations

import base64
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import asdict, dataclass
from typing import Any, Callable

from pfsense_checker.paths import PROJECT_ROOT, ensure_data_dir

SETTINGS_PATH = PROJECT_ROOT / "data" / "openobserve.json"
DEFAULT_URL = "http://127.0.0.1:5080"
DEFAULT_ORG = "default"
DEFAULT_STREAM = "netcheck"
_KEYRING_SERVICE = "PFSenseChecker.OpenObserve"
_MAX_RESPONSE = 2 * 1024 * 1024
_MAX_RECORDS = 100
_MAX_QUEUE = 5000
_FIELD_CHARS = 8000
_SQL_CHARS = 4000
_SECRET_KEYS = {
    "password",
    "secret",
    "token",
    "authorization",
    "api_key",
    "apikey",
    "passwd",
}
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_WRITE_SQL_RE = re.compile(
    r"\b(insert|update|delete|drop|alter|create|grant|revoke|truncate|copy|into|call|execute)\b",
    re.IGNORECASE,
)
_LOOPBACKS = {"localhost", "127.0.0.1", "::1"}

SendFunc = Callable[[urllib.request.Request, float], tuple[int, bytes]]

_lock = threading.RLock()
_cached: "OpenObserveSettings | None" = None
_queue: deque[dict[str, Any]] = deque()
_shipper: threading.Thread | None = None
_stop = threading.Event()
_wake = threading.Event()
_listener_installed = False
_last_error = ""
_hostname = ""


class OpenObserveError(RuntimeError):
    """OpenObserve rejected a call or could not be reached."""

    def __init__(self, message: str, *, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class OpenObserveSettings:
    enabled: bool = False
    base_url: str = DEFAULT_URL
    organization: str = DEFAULT_ORG
    stream: str = DEFAULT_STREAM
    username: str = ""
    ship_app_logs: bool = True
    ship_syslog: bool = True
    timeout_sec: float = 10.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def credential_transport_warning(base_url: str) -> str:
    """Warn when Basic auth would cross a non-loopback network in cleartext."""
    parsed = urllib.parse.urlparse(base_url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "https" or host in _LOOPBACKS:
        return ""
    return (
        "This URL is http:// to a remote host. The OpenObserve password is sent "
        "on every request and can be read on the path. Use https:// unless this "
        "is an isolated lab network."
    )


def normalise_base_url(url: str) -> str:
    value = (url or "").strip().rstrip("/")
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise OpenObserveError("OpenObserve URL must be http:// or https://host[:port]")
    if parsed.username or parsed.password:
        raise OpenObserveError(
            "Put the OpenObserve user and password in the credential fields, not the URL"
        )
    if parsed.query or parsed.fragment or (parsed.path not in {"", "/"}):
        raise OpenObserveError(
            "OpenObserve URL should be the server root, for example http://127.0.0.1:5080"
        )
    return f"{parsed.scheme}://{parsed.netloc}"


def normalise_name(value: str, *, label: str) -> str:
    text = (value or "").strip()
    if not _NAME_RE.fullmatch(text):
        raise OpenObserveError(
            f"{label} must be 1–128 characters: letters, digits, '.', '_' or '-'"
        )
    return text


def validate_search_sql(sql: str) -> str:
    """Allow one read-only SELECT. OpenObserve runs this on the server."""
    text = (sql or "").strip().rstrip(";").strip()
    if not text.lower().startswith("select"):
        raise OpenObserveError("OpenObserve search accepts a single SELECT")
    if ";" in text:
        raise OpenObserveError("Only one SELECT statement is allowed")
    if _WRITE_SQL_RE.search(text):
        raise OpenObserveError("Only read-only SELECT queries are sent to OpenObserve")
    if len(text) > _SQL_CHARS:
        raise OpenObserveError("Query is too long")
    return text


def load_settings(path: Any = None) -> OpenObserveSettings:
    """Load non-secret settings. Environment variables override the file."""
    global _cached
    target = path or SETTINGS_PATH
    data: dict[str, Any] = {}
    try:
        loaded = json.loads(target.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            data = loaded
    except (OSError, json.JSONDecodeError):
        data = {}
    try:
        timeout = float(data.get("timeout_sec") or 10.0)
    except (TypeError, ValueError):
        timeout = 10.0
    settings = OpenObserveSettings(
        enabled=bool(data.get("enabled", False)),
        base_url=str(data.get("base_url") or DEFAULT_URL),
        organization=str(data.get("organization") or DEFAULT_ORG),
        stream=str(data.get("stream") or DEFAULT_STREAM),
        username=str(data.get("username") or ""),
        ship_app_logs=bool(data.get("ship_app_logs", True)),
        ship_syslog=bool(data.get("ship_syslog", True)),
        timeout_sec=timeout,
    )
    settings.base_url = _env("OPENOBSERVE_URL") or settings.base_url
    settings.organization = _env("OPENOBSERVE_ORG") or settings.organization
    settings.stream = _env("OPENOBSERVE_STREAM") or settings.stream
    settings.username = _env("OPENOBSERVE_USER") or settings.username
    enabled_env = _env("OPENOBSERVE_ENABLED").lower()
    if enabled_env in {"1", "true", "yes", "on"}:
        settings.enabled = True
    elif enabled_env in {"0", "false", "no", "off"}:
        settings.enabled = False
    settings.timeout_sec = min(60.0, max(2.0, float(settings.timeout_sec)))
    if path is None:
        with _lock:
            _cached = settings
    return settings


def current_settings() -> OpenObserveSettings:
    with _lock:
        cached = _cached
    if cached is None:
        return load_settings()
    return cached


def save_settings(settings: OpenObserveSettings, path: Any = None) -> Any:
    """Persist non-secret settings. Never include a password."""
    global _cached
    cleaned = OpenObserveSettings(
        enabled=bool(settings.enabled),
        base_url=normalise_base_url(settings.base_url),
        organization=normalise_name(settings.organization, label="Organization"),
        stream=normalise_name(settings.stream, label="Stream"),
        username=(settings.username or "").strip(),
        ship_app_logs=bool(settings.ship_app_logs),
        ship_syslog=bool(settings.ship_syslog),
        timeout_sec=min(60.0, max(2.0, float(settings.timeout_sec or 10))),
    )
    target = path or SETTINGS_PATH
    ensure_data_dir()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = cleaned.to_dict()
    for secret in ("password", "token", "api_key"):
        payload.pop(secret, None)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if path is None:
        with _lock:
            _cached = cleaned
        _wake.set()
    return target


def load_password(username: str) -> str:
    """Environment first, then OS keyring. Empty string if nothing is stored."""
    env = _env("OPENOBSERVE_PASSWORD") or _env("OPENOBSERVE_TOKEN")
    if env:
        return env
    account = (username or "").strip() or "token"
    try:
        import keyring
    except ImportError:
        return ""
    try:
        stored = keyring.get_password(_KEYRING_SERVICE, account)
    except Exception:  # noqa: BLE001
        return ""
    return (stored or "").strip()


def store_password(username: str, password: str) -> None:
    """Save the credential in the OS keyring."""
    account = (username or "").strip() or "token"
    try:
        import keyring
    except ImportError as exc:
        raise OpenObserveError(
            "The keyring package is required to store the OpenObserve password"
        ) from exc
    try:
        keyring.set_password(_KEYRING_SERVICE, account, password)
    except Exception as exc:  # noqa: BLE001
        raise OpenObserveError(f"Could not store the OpenObserve password: {exc}") from exc


def clear_password(username: str) -> None:
    account = (username or "").strip() or "token"
    try:
        import keyring
    except ImportError:
        return
    try:
        keyring.delete_password(_KEYRING_SERVICE, account)
    except Exception:  # noqa: BLE001
        pass


def password_is_stored(username: str) -> bool:
    return bool(load_password(username))


def _bound(settings: OpenObserveSettings) -> OpenObserveSettings:
    """Copy settings with a safe URL, organization, and stream."""
    return OpenObserveSettings(
        enabled=bool(settings.enabled),
        base_url=normalise_base_url(settings.base_url),
        organization=normalise_name(settings.organization, label="Organization"),
        stream=normalise_name(settings.stream, label="Stream"),
        username=(settings.username or "").strip(),
        ship_app_logs=bool(settings.ship_app_logs),
        ship_syslog=bool(settings.ship_syslog),
        timeout_sec=min(60.0, max(2.0, float(settings.timeout_sec or 10))),
    )


def health(settings: OpenObserveSettings | None = None, *, send: SendFunc | None = None) -> str:
    cfg = _bound(settings or current_settings())
    status, body = _request("GET", "/healthz", settings=cfg, send=send, auth=False)
    text = body.decode("utf-8", errors="replace").strip()
    if status >= 400:
        raise OpenObserveError(f"OpenObserve health failed (HTTP {status})", status=status)
    return text or "ok"


def list_streams(
    settings: OpenObserveSettings | None = None,
    *,
    password: str | None = None,
    send: SendFunc | None = None,
) -> list[str]:
    cfg = _bound(settings or current_settings())
    _status, payload = _request_json(
        "GET",
        f"/api/{_quote(cfg.organization)}/streams?type=logs",
        settings=cfg,
        password=password,
        send=send,
    )
    names: list[str] = []
    rows = payload.get("list") if isinstance(payload, dict) else payload
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, str):
                names.append(row)
            elif isinstance(row, dict):
                name = str(row.get("name") or row.get("stream") or "")
                if name:
                    names.append(name)
    return names


def ingest(
    records: list[dict[str, Any]],
    settings: OpenObserveSettings | None = None,
    *,
    password: str | None = None,
    send: SendFunc | None = None,
) -> dict[str, Any]:
    """POST a JSON array to ``/{org}/{stream}/_json``."""
    cfg = _bound(settings or current_settings())
    cleaned = [_clean_record(row) for row in records[:_MAX_RECORDS] if isinstance(row, dict)]
    if not cleaned:
        return {"skipped": 0}
    _status, payload = _request_json(
        "POST",
        f"/api/{_quote(cfg.organization)}/{_quote(cfg.stream)}/_json",
        settings=cfg,
        body=cleaned,
        password=password,
        send=send,
    )
    if isinstance(payload, dict):
        failed = 0
        for item in payload.get("status") or []:
            if isinstance(item, dict):
                failed += int(item.get("failed") or 0)
        if failed:
            raise OpenObserveError(f"OpenObserve rejected {failed} record(s)")
        return payload
    return {"status": payload}


def search(
    sql: str,
    settings: OpenObserveSettings | None = None,
    *,
    minutes: int = 15,
    size: int = 100,
    password: str | None = None,
    send: SendFunc | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Run one read-only SQL search. Times are microseconds, as OpenObserve expects."""
    cfg = _bound(settings or current_settings())
    statement = validate_search_sql(sql)
    end_sec = time.time() if now is None else float(now)
    span = max(1, min(int(minutes), 60 * 24 * 30)) * 60
    body = {
        "query": {
            "sql": statement,
            "start_time": int((end_sec - span) * 1_000_000),
            "end_time": int(end_sec * 1_000_000),
            "from": 0,
            "size": max(1, min(int(size), 500)),
        }
    }
    _status, payload = _request_json(
        "POST",
        f"/api/{_quote(cfg.organization)}/_search?type=logs",
        settings=cfg,
        body=body,
        password=password,
        send=send,
    )
    if not isinstance(payload, dict):
        raise OpenObserveError("OpenObserve search returned an unexpected response")
    return payload


def format_search_result(payload: dict[str, Any]) -> str:
    """Compact text for the Setup query pane."""
    hits = payload.get("hits")
    rows = hits if isinstance(hits, list) else []
    total = payload.get("total", len(rows))
    lines = [f"{total} hit(s), showing {min(len(rows), 100)}"]
    for row in rows[:100]:
        if not isinstance(row, dict):
            lines.append(str(row)[:500])
            continue
        stamp = row.get("_timestamp", "")
        level = row.get("level") or row.get("severity") or ""
        message = row.get("message") or row.get("log") or ""
        lines.append(" ".join(str(part) for part in (stamp, level, message) if part)[:500])
    return "\n".join(lines)


def test_connection(
    settings: OpenObserveSettings | None = None,
    *,
    password: str | None = None,
    send: SendFunc | None = None,
) -> str:
    cfg = _bound(settings or current_settings())
    alive = health(cfg, send=send)
    names = list_streams(cfg, password=password, send=send)
    stream = cfg.stream
    present = stream in names
    listed = ", ".join(names[:8]) if names else "(none)"
    extra = f" Stream {stream} exists." if present else f" Stream {stream} is not created yet; the first ingest creates it."
    warning = credential_transport_warning(cfg.base_url)
    text = f"OpenObserve is up ({alive}). Log streams: {listed}.{extra}"
    if warning:
        text = f"{text}\n{warning}"
    return text


def offer_syslog(message: Any) -> None:
    """Queue an accepted syslog line. Dropped sources are not shipped."""
    if not getattr(message, "accepted", False):
        return
    cfg = current_settings()
    if not cfg.enabled or not cfg.ship_syslog:
        return
    body = str(getattr(message, "message", "") or "")
    if not body:
        body = str(getattr(message, "raw", "") or "")
    offer(
        {
            "log_type": "syslog",
            "source_ip": getattr(message, "source_ip", ""),
            "source_port": int(getattr(message, "source_port", 0) or 0),
            "device": getattr(message, "device_name", ""),
            "facility": getattr(message, "facility_name", ""),
            "severity": getattr(message, "severity_name", ""),
            "hostname": getattr(message, "hostname", ""),
            "app_name": getattr(message, "app_name", ""),
            "message": body,
        }
    )


def offer(record: dict[str, Any]) -> None:
    """Queue one record. No HTTP on the caller's thread."""
    cfg = current_settings()
    if not cfg.enabled:
        return
    cleaned = _clean_record(record)
    cleaned.setdefault("host", _host())
    with _lock:
        if len(_queue) >= _MAX_QUEUE:
            _queue.popleft()
        _queue.append(cleaned)
    _wake.set()


def last_error() -> str:
    with _lock:
        return _last_error


def start_shipper() -> None:
    """Start the background ingest thread and subscribe to app logs once."""
    global _shipper, _listener_installed
    load_settings()
    with _lock:
        if not _listener_installed:
            from pfsense_checker import app_log

            app_log.get_hub().subscribe(_on_app_log)
            _listener_installed = True
        if _shipper is None or not _shipper.is_alive():
            _stop.clear()
            _shipper = threading.Thread(
                target=_ship_loop, name="openobserve-shipper", daemon=True
            )
            _shipper.start()


def _on_app_log(event: Any) -> None:
    logger_name = str(getattr(event, "logger", "") or "")
    if logger_name.startswith("netcheck.openobserve"):
        return
    cfg = current_settings()
    if not cfg.enabled or not cfg.ship_app_logs:
        return
    offer(
        {
            "log_type": "app",
            "level": getattr(event, "level", ""),
            "logger": logger_name,
            "message": getattr(event, "message", ""),
        }
    )


def _ship_loop() -> None:
    while not _stop.is_set():
        _wake.wait(2.0)
        _wake.clear()
        if _stop.is_set():
            break
        _flush()


def _flush() -> None:
    global _last_error
    cfg = current_settings()
    if not cfg.enabled:
        return
    if not load_password(cfg.username):
        with _lock:
            if _queue:
                _last_error = "OpenObserve password is not stored"
        return
    with _lock:
        if not _queue:
            return
        batch: list[dict[str, Any]] = []
        while _queue and len(batch) < _MAX_RECORDS:
            batch.append(_queue.popleft())
    if not batch:
        return
    try:
        ingest(batch, cfg)
    except Exception as exc:  # noqa: BLE001
        with _lock:
            _last_error = str(exc)
        _log().warning("OpenObserve ingest failed: %s", exc)
        return
    with _lock:
        _last_error = ""


def _log():
    import logging

    return logging.getLogger("netcheck.openobserve")


def _host() -> str:
    global _hostname
    if not _hostname:
        try:
            _hostname = socket.gethostname()
        except OSError:
            _hostname = ""
    return _hostname


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def _quote(part: str) -> str:
    return urllib.parse.quote(part, safe="")


def _clean_record(record: dict[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for key, value in record.items():
        name = str(key)[:64]
        if name.lower() in _SECRET_KEYS:
            continue
        if isinstance(value, str):
            cleaned[name] = value[:_FIELD_CHARS]
        elif isinstance(value, (int, float, bool)) or value is None:
            cleaned[name] = value
        else:
            cleaned[name] = str(value)[:_FIELD_CHARS]
    cleaned.setdefault("_timestamp", int(time.time() * 1_000_000))
    return cleaned


def _auth_header(settings: OpenObserveSettings, password: str) -> str:
    user = (settings.username or "").strip()
    if user:
        token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        return f"Basic {token}"
    return f"Bearer {password}"


def _request_json(
    method: str,
    path: str,
    *,
    settings: OpenObserveSettings,
    body: Any = None,
    password: str | None = None,
    send: SendFunc | None = None,
) -> tuple[int, Any]:
    status, raw = _request(
        method, path, settings=settings, body=body, password=password, send=send
    )
    if not raw:
        return status, {}
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OpenObserveError("OpenObserve returned invalid JSON", status=status) from exc
    return status, payload


def _request(
    method: str,
    path: str,
    *,
    settings: OpenObserveSettings,
    body: Any = None,
    password: str | None = None,
    send: SendFunc | None = None,
    auth: bool = True,
) -> tuple[int, bytes]:
    base = normalise_base_url(settings.base_url)
    if auth:
        secret = password if password is not None and password != "" else load_password(
            settings.username
        )
        if not secret:
            raise OpenObserveError("OpenObserve password is not stored")
    else:
        secret = ""
    data = None
    headers = {
        "Accept": "application/json, text/plain",
        "User-Agent": "NetCheck-OpenObserve",
    }
    if secret:
        headers["Authorization"] = _auth_header(settings, secret)
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    sender = send or _http_send
    try:
        status, raw = sender(request, settings.timeout_sec)
    except OpenObserveError:
        raise
    except urllib.error.HTTPError as exc:
        detail = exc.read(400).decode("utf-8", errors="replace")
        raise OpenObserveError(
            f"OpenObserve HTTP {exc.code}: {_one_line(detail)}", status=exc.code
        ) from exc
    except urllib.error.URLError as exc:
        raise OpenObserveError(f"Cannot reach OpenObserve at {base}: {exc.reason}") from exc
    if len(raw) > _MAX_RESPONSE:
        raise OpenObserveError("OpenObserve response exceeded the 2 MiB limit")
    if status >= 400:
        detail = raw[:400].decode("utf-8", errors="replace")
        raise OpenObserveError(
            f"OpenObserve HTTP {status}: {_one_line(detail)}", status=status
        )
    return status, raw


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise OpenObserveError(
            f"OpenObserve redirected (HTTP {code}); redirects are not followed"
        )


def _http_send(request: urllib.request.Request, timeout: float) -> tuple[int, bytes]:
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(request, timeout=timeout) as response:  # noqa: S310
        return int(response.status), response.read(_MAX_RESPONSE + 1)


def _one_line(text: str) -> str:
    return " ".join(text.split())[:300]
