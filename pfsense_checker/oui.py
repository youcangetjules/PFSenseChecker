"""OUI / MAC vendor lookup via RapidAPI (mac-address-lookup1).

The RapidAPI key is stored in gitignored ``secrets.local.json``
(``oui_api_key`` / ``rapidapi_key``) or ``OUI_API_KEY`` /
``RAPIDAPI_KEY`` environment variables. Lookups are cached in-process by
OUI prefix so device scans do not burn the quota on every refresh.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from pfsense_checker.lan_scan import normalize_mac

_SECRETS_FILE = Path(__file__).resolve().parent.parent / "secrets.local.json"
DEFAULT_API_HOST = "mac-address-lookup1.p.rapidapi.com"
DEFAULT_API_BASE = f"https://{DEFAULT_API_HOST}/static_rapid/mac_lookup/"
_VENDOR_CACHE: dict[str, str] = {}


def _read_secrets() -> dict:
    if not _SECRETS_FILE.is_file():
        return {}
    try:
        data = json.loads(_SECRETS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def load_oui_api_key() -> str:
    env = (
        os.environ.get("OUI_API_KEY", "").strip()
        or os.environ.get("RAPIDAPI_KEY", "").strip()
        or os.environ.get("MACADDRESS_IO_API_KEY", "").strip()
    )
    if env:
        return env
    data = _read_secrets()
    return str(
        data.get("oui_api_key")
        or data.get("rapidapi_key")
        or ""
    ).strip()


def save_oui_api_key(key: str) -> None:
    data = _read_secrets()
    value = key.strip()
    data["oui_api_key"] = value
    data["rapidapi_key"] = value
    _SECRETS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def has_oui_api_key() -> bool:
    return bool(load_oui_api_key())


def oui_prefix(mac: str) -> str:
    """Return the 24-bit OUI (first three octets) for cache keys."""
    return normalize_mac(mac)[:8]


def clear_vendor_cache() -> None:
    _VENDOR_CACHE.clear()


def _vendor_from_payload(payload: object) -> str:
    """Extract a manufacturer name from the RapidAPI JSON body."""
    if isinstance(payload, list) and payload:
        return _vendor_from_payload(payload[0])
    if not isinstance(payload, dict):
        return ""

    result = payload.get("result")
    if isinstance(result, list) and result:
        first = result[0]
        if isinstance(first, dict):
            name = str(first.get("name") or first.get("vendor") or "").strip()
            if name:
                return name
    if isinstance(result, dict):
        name = str(result.get("name") or result.get("vendor") or "").strip()
        if name:
            return name

    details = payload.get("vendorDetails")
    if isinstance(details, dict):
        name = str(details.get("companyName") or "").strip()
        if name:
            return name
    elif isinstance(details, str) and details.strip():
        return details.strip()

    return str(
        payload.get("companyName") or payload.get("vendor") or payload.get("name") or ""
    ).strip()


def lookup_vendor(
    mac: str,
    *,
    api_key: str | None = None,
    timeout: float = 8,
    use_cache: bool = True,
) -> str:
    """Return the manufacturer name for *mac*, or ``\"\"`` if unknown/unavailable.

    Raises ``ValueError`` for a bad MAC, ``RuntimeError`` for API/HTTP failures
    when a key is configured. Without a key, returns ``\"\"`` (no network call).
    """
    mac_n = normalize_mac(mac)
    prefix = mac_n[:8]
    if use_cache and prefix in _VENDOR_CACHE:
        return _VENDOR_CACHE[prefix]

    key = (api_key if api_key is not None else load_oui_api_key()).strip()
    if not key:
        return ""

    params = urllib.parse.urlencode({"query": mac_n})
    url = f"{DEFAULT_API_BASE}?{params}"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "NetCheck/1.0",
            "x-rapidapi-host": DEFAULT_API_HOST,
            "x-rapidapi-key": key,
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(256 * 1024)
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")[:200]
        except OSError:
            pass
        raise RuntimeError(
            f"OUI lookup failed (HTTP {exc.code})"
            + (f": {body}" if body else "")
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"OUI lookup unreachable: {exc.reason}") from exc

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("OUI lookup returned invalid JSON") from exc

    vendor = _vendor_from_payload(payload)
    if vendor:
        vendor = vendor.title() if vendor.islower() else vendor

    if use_cache:
        _VENDOR_CACHE[prefix] = vendor
    return vendor
