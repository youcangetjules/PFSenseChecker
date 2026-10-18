"""RouterOS 7 REST API client for sanitized configuration export.

Collects a hide-sensitive text export via HTTPS REST, reads it in chunks,
caches it locally, and cleans up the temporary router-side file.

Passwords come from the OS keyring — never logged or written to site JSON.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from pfsense_checker.credentials import (
    CredentialRef,
    get_password,
    make_credential_ref,
    store_password,
)
from pfsense_checker.topology_site import CONFIG_SOURCE_MIKROTIK_REST, ConfigSource, Device

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SEC = 30
MAX_EXPORT_BYTES = 8 * 1024 * 1024  # 8 MiB hard cap
CHUNK_SIZE = 16384


@dataclass
class CollectResult:
    ok: bool
    path: str = ""
    export_hash: str = ""
    collected_at: str = ""
    error: str = ""
    bytes_read: int = 0
    cleaned_remote: bool = False


class RouterOSRestError(RuntimeError):
    """Raised for REST transport / authentication / protocol failures."""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _safe_filename(device_name: str, host: str) -> str:
    raw = f"{device_name}_{host}".lower()
    cleaned = re.sub(r"[^a-z0-9._-]+", "_", raw).strip("_") or "device"
    return cleaned[:80]


def cache_dir(base: Path | None = None) -> Path:
    root = base or Path.cwd() / "data"
    path = root / "mikrotik_exports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _ssl_context(src: ConfigSource) -> ssl.SSLContext:
    if src.allow_insecure_tls or not src.verify_tls:
        ctx = ssl._create_unverified_context()  # noqa: S323 — explicit user opt-in
        return ctx
    ctx = ssl.create_default_context()
    if src.ca_path:
        ca = Path(src.ca_path)
        if not ca.is_file():
            raise RouterOSRestError(f"CA certificate not found: {src.ca_path}")
        ctx.load_verify_locations(cafile=str(ca))
    return ctx


def _auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _request(
    method: str,
    url: str,
    *,
    username: str,
    password: str,
    ctx: ssl.SSLContext,
    body: dict[str, Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT_SEC,
    accept_json: bool = True,
) -> tuple[int, bytes, dict[str, str]]:
    data = None
    headers = {
        "Authorization": _auth_header(username, password),
        "User-Agent": "PFSenseChecker/1.x",
    }
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if accept_json:
        headers["Accept"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:  # noqa: S310
            status = getattr(resp, "status", 200) or 200
            raw = resp.read(MAX_EXPORT_BYTES + 1)
            if len(raw) > MAX_EXPORT_BYTES:
                raise RouterOSRestError(
                    f"Response exceeds {MAX_EXPORT_BYTES} byte limit"
                )
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return status, raw, hdrs
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read(512).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
        if exc.code in (401, 403):
            raise RouterOSRestError(
                f"Authentication failed (HTTP {exc.code}). "
                "Check username/password and REST permissions."
            ) from exc
        raise RouterOSRestError(
            f"HTTP {exc.code} from {url}: {detail[:200]}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RouterOSRestError(f"Connection failed: {exc.reason}") from exc
    except TimeoutError as exc:
        raise RouterOSRestError(f"Timed out after {timeout}s contacting {url}") from exc


def base_url(src: ConfigSource) -> str:
    host = (src.host or "").strip()
    if not host:
        raise RouterOSRestError("MikroTik REST host is not set")
    # Allow host to already include scheme
    if host.startswith("http://") or host.startswith("https://"):
        return host.rstrip("/")
    scheme = "https"
    port = int(src.port or 443)
    if port in (80, 443):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def probe_connection(
    src: ConfigSource,
    *,
    password: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SEC,
) -> tuple[bool, str]:
    """Probe REST with /system/identity/print. Returns (ok, message)."""
    try:
        pwd = password if password is not None else _resolve_password(src)
        ctx = _ssl_context(src)
        url = f"{base_url(src)}/rest/system/identity"
        status, raw, _ = _request(
            "GET", url, username=src.username, password=pwd, ctx=ctx, timeout=timeout
        )
        if status >= 400:
            return False, f"HTTP {status}"
        try:
            data = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return True, "REST reachable (non-JSON identity response)"
        name = ""
        if isinstance(data, dict):
            name = data.get("name", "")
        elif isinstance(data, list) and data:
            name = data[0].get("name", "") if isinstance(data[0], dict) else ""
        return True, f"Connected — identity: {name or '(unknown)'}"
    except RouterOSRestError as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001
        return False, f"Unexpected error: {exc}"


def _resolve_password(src: ConfigSource) -> str:
    if not src.username:
        raise RouterOSRestError("REST username is required")
    if not src.credential_ref:
        raise RouterOSRestError(
            "No credential reference — save credentials via Windows Credential Manager first"
        )
    ref = CredentialRef(
        ref_id=src.credential_ref,
        username=src.username,
        service=f"PFSenseChecker.MikroTik.{src.credential_ref}"
        if not src.credential_ref.startswith("PFSenseChecker")
        else src.credential_ref,
    )
    # Accept either bare ref_id or full service name
    if src.credential_ref.startswith("PFSenseChecker"):
        ref = CredentialRef(
            ref_id=src.credential_ref.rsplit(".", 1)[-1],
            username=src.username,
            service=src.credential_ref,
        )
    else:
        ref = CredentialRef(
            ref_id=src.credential_ref,
            username=src.username,
            service=f"PFSenseChecker.MikroTik.{src.credential_ref}",
        )
    pwd = get_password(ref)
    if pwd is None:
        raise RouterOSRestError(
            "Password not found in Windows Credential Manager for this device"
        )
    return pwd


def save_device_credentials(
    device: Device,
    *,
    host: str,
    username: str,
    password: str,
    port: int = 443,
    verify_tls: bool = True,
    allow_insecure_tls: bool = False,
    ca_path: str = "",
) -> ConfigSource:
    """Store password in keyring and update device.config_source metadata."""
    src = device.config_source or ConfigSource(source_type=CONFIG_SOURCE_MIKROTIK_REST)
    src.source_type = CONFIG_SOURCE_MIKROTIK_REST
    src.host = host
    src.port = port
    src.username = username
    src.verify_tls = verify_tls
    src.allow_insecure_tls = allow_insecure_tls
    src.ca_path = ca_path
    ref = make_credential_ref(device.name, host, username)
    if password:
        store_password(ref, password)
    src.credential_ref = ref.ref_id
    device.config_source = src
    if device.mgmt_ip == "" and host:
        # Convenience only — host may be a name
        device.mgmt_ip = host
    return src


def collect_export(
    device: Device,
    *,
    password: str | None = None,
    cache_base: Path | None = None,
    timeout: float = DEFAULT_TIMEOUT_SEC,
) -> CollectResult:
    """Export sanitized config from the router and cache it locally."""
    src = device.ensure_config_source()
    if src is None:
        return CollectResult(ok=False, error="Device has no config source")
    if not src.host:
        return CollectResult(
            ok=False,
            error="MikroTik REST host not configured (attach .backup and set REST endpoint)",
        )

    remote_name = f"pfsensechecker_{_safe_filename(device.name, src.host)}.rsc"
    collected_at = _utc_now_iso()
    cleaned = False
    try:
        pwd = password if password is not None else _resolve_password(src)
        ctx = _ssl_context(src)
        root = base_url(src)

        # 1) Trigger export (hide sensitive by default — omit show-sensitive)
        export_url = f"{root}/rest/export"
        _request(
            "POST",
            export_url,
            username=src.username,
            password=pwd,
            ctx=ctx,
            body={"file": remote_name, "terse": ""},
            timeout=timeout,
        )

        # 2) Read file in chunks via /rest/file/read
        text_parts: list[str] = []
        offset = 0
        total = 0
        while True:
            status, raw, _ = _request(
                "POST",
                f"{root}/rest/file/read",
                username=src.username,
                password=pwd,
                ctx=ctx,
                body={
                    "file": remote_name,
                    "offset": str(offset),
                    "chunk-size": str(CHUNK_SIZE),
                },
                timeout=timeout,
            )
            chunk = _extract_file_chunk(raw)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_EXPORT_BYTES:
                raise RouterOSRestError(
                    f"Export exceeds {MAX_EXPORT_BYTES} byte limit"
                )
            text_parts.append(chunk)
            if len(chunk) < CHUNK_SIZE:
                break
            offset += len(chunk)

        export_text = "".join(text_parts)
        if not export_text.strip():
            # Fallback: try /file/get contents for small exports
            export_text = _try_file_contents(
                root, remote_name, src.username, pwd, ctx, timeout
            )
        if not export_text.strip():
            raise RouterOSRestError(
                "Export file is empty — ensure RouterOS 7 REST is enabled "
                "and the account can run /export"
            )
        if not _looks_like_export(export_text):
            raise RouterOSRestError(
                "Downloaded content does not look like a RouterOS export"
            )

        digest = hashlib.sha256(export_text.encode("utf-8", errors="replace")).hexdigest()
        out_dir = cache_dir(cache_base)
        out_path = out_dir / f"{_safe_filename(device.name, src.host)}.rsc"
        out_path.write_text(export_text, encoding="utf-8")

        # 3) Cleanup remote file
        cleaned = _cleanup_remote(root, remote_name, src.username, pwd, ctx, timeout)

        src.source_type = CONFIG_SOURCE_MIKROTIK_REST
        src.path = str(out_path)
        src.export_hash = digest
        src.last_collected_at = collected_at
        src.last_status = "ok"
        src.last_error = ""
        device.config_file = str(out_path)
        device.config_source = src

        return CollectResult(
            ok=True,
            path=str(out_path),
            export_hash=digest,
            collected_at=collected_at,
            bytes_read=total or len(export_text.encode("utf-8")),
            cleaned_remote=cleaned,
        )
    except RouterOSRestError as exc:
        if src:
            src.last_status = "error"
            src.last_error = str(exc)
            src.last_collected_at = collected_at
        return CollectResult(
            ok=False, error=str(exc), collected_at=collected_at, cleaned_remote=cleaned
        )
    except Exception as exc:  # noqa: BLE001
        msg = f"Collection failed: {exc}"
        if src:
            src.last_status = "error"
            src.last_error = msg
            src.last_collected_at = collected_at
        return CollectResult(
            ok=False, error=msg, collected_at=collected_at, cleaned_remote=cleaned
        )


def _extract_file_chunk(raw: bytes) -> str:
    """Best-effort decode of /file/read JSON (or latin-1 quirks)."""
    if not raw:
        return ""
    # Prefer UTF-8 JSON
    for encoding in ("utf-8", "latin-1"):
        try:
            text = raw.decode(encoding)
            data = json.loads(text)
            if isinstance(data, dict):
                return str(data.get("data") or data.get("contents") or "")
            if isinstance(data, list) and data and isinstance(data[0], dict):
                return str(data[0].get("data") or data[0].get("contents") or "")
            if isinstance(data, str):
                return data
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
    # Last resort: treat body as raw text
    return raw.decode("utf-8", errors="replace")


def _try_file_contents(
    root: str,
    name: str,
    username: str,
    password: str,
    ctx: ssl.SSLContext,
    timeout: float,
) -> str:
    try:
        # GET /rest/file/<name> — works for small files
        url = f"{root}/rest/file/{quote(name)}"
        _, raw, _ = _request(
            "GET", url, username=username, password=password, ctx=ctx, timeout=timeout
        )
        data = json.loads(raw.decode("utf-8", errors="replace"))
        if isinstance(data, dict):
            return str(data.get("contents") or "")
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return str(data[0].get("contents") or "")
    except Exception:  # noqa: BLE001
        return ""
    return ""


def _looks_like_export(text: str) -> bool:
    head = text.lstrip()[:2000]
    if "RouterOS" in head:
        return True
    return bool(re.search(r"^\s*/(interface|ip|system)\b", text, re.M))


def _cleanup_remote(
    root: str,
    name: str,
    username: str,
    password: str,
    ctx: ssl.SSLContext,
    timeout: float,
) -> bool:
    try:
        # Prefer remove by name
        _request(
            "POST",
            f"{root}/rest/file/remove",
            username=username,
            password=password,
            ctx=ctx,
            body={"numbers": name},
            timeout=timeout,
        )
        return True
    except RouterOSRestError:
        try:
            _request(
                "DELETE",
                f"{root}/rest/file/{quote(name)}",
                username=username,
                password=password,
                ctx=ctx,
                timeout=timeout,
            )
            return True
        except RouterOSRestError as exc:
            log.warning("Could not remove remote export %s: %s", name, exc)
            return False


def collect_all(
    devices: list[Device],
    *,
    cache_base: Path | None = None,
    timeout: float = DEFAULT_TIMEOUT_SEC,
) -> dict[str, CollectResult]:
    """Collect exports for every device with a MikroTik REST source."""
    out: dict[str, CollectResult] = {}
    for dev in devices:
        src = dev.ensure_config_source()
        if src is None:
            continue
        if src.source_type == CONFIG_SOURCE_MIKROTIK_REST or bool(
            src.host and (src.backup_artifact or src.credential_ref)
        ):
            out[dev.name] = collect_export(
                dev, cache_base=cache_base, timeout=timeout
            )
    return out
