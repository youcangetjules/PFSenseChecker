"""Local and beacon subnets: which IPv4 networks this machine can reach.

Rebuilt 2026-11-07. This file was committed empty in 115b08d and no copy
survived. This part covers what the tests and callers define: the
``SubnetAccess`` record, link-type / duplex helpers, local adapter
discovery, the adapter description, beacon rows, then settings
(token in the OS keyring), gateway ping / speed checks and collector polling.

No Qt imports: beacon bundles ship this module (``beacon_builder``).
"""

from __future__ import annotations

import ipaddress
import json
import platform
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Any

from pfsense_checker import winproc

_CACHE_TTL_S = 30.0
_cache: tuple[float, list["SubnetAccess"]] | None = None


@dataclass
class SubnetAccess:
    """One IPv4 subnet reachable from a local adapter or a beacon."""

    cidr: str
    ip: str = ""
    interface: str = ""
    mac: str = ""
    gateway: str = ""
    link_type: str = "unknown"  # wired | wlan | vpn | virtual | unknown
    link_speed: str = ""
    duplex: str = ""
    mtu: int | None = None
    source: str = "local"  # local | beacon:<id>
    hostname: str = ""
    ping_status: str = ""
    ping_ms: float | None = None
    speed_mbps: float | None = None
    speed_status: str = ""
    last_check: str = ""
    message: str = ""


def normalize_link_type(text: str) -> str:
    low = (text or "").strip().lower()
    if not low:
        return "unknown"
    if any(k in low for k in ("wi-fi", "wifi", "wlan", "wireless", "802.11")):
        return "wlan"
    # Before "wired": Hyper-V's "vEthernet" / "Virtual Ethernet" contain "ethernet".
    if any(k in low for k in ("virtual", "hyper-v", "vethernet", "docker", "loopback")):
        return "virtual"
    if any(k in low for k in ("vpn", "tailscale", "wireguard")):
        return "vpn"
    if any(k in low for k in ("ethernet", "wired", "802.3", "lan")):
        return "wired"
    return low if low in {"wired", "wlan", "vpn", "virtual"} else "unknown"


def link_type_label(kind: str) -> str:
    return {
        "wired": "Wired",
        "wlan": "WLAN",
        "vpn": "VPN",
        "virtual": "Virtual",
    }.get((kind or "").lower(), "Unknown")


def _normalize_duplex(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "full" if value else "half"
    low = str(value).strip().lower()
    if "full" in low:
        return "full"
    if "half" in low:
        return "half"
    return ""


def _kind_for(name: str, media: str, ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        if addr in ipaddress.ip_network("100.64.0.0/10"):
            return "vpn"
    except ValueError:
        pass
    kind = normalize_link_type(media)
    if kind == "unknown":
        kind = normalize_link_type(name)
    return kind


def _windows_rows() -> list[SubnetAccess]:
    """Get-NetIPAddress + Get-NetAdapter + default routes, as JSON."""
    script = (
        "$ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.IPAddress -notlike '127.*' -and $_.AddressState -eq 'Preferred' } | "
        "Select-Object InterfaceIndex, InterfaceAlias, IPAddress, PrefixLength;"
        "$ads = Get-NetAdapter -ErrorAction SilentlyContinue | "
        "Select-Object ifIndex, Name, MacAddress, LinkSpeed, FullDuplex, MediaType, "
        "PhysicalMediaType, InterfaceDescription, Status;"
        "$mtu = Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Select-Object InterfaceIndex, NlMtu;"
        "$gw = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
        "-ErrorAction SilentlyContinue | Select-Object InterfaceIndex, NextHop;"
        "@{ips=@($ips); ads=@($ads); mtu=@($mtu); gw=@($gw)} | ConvertTo-Json -Depth 4 -Compress"
    )
    out = winproc.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    data = json.loads(out.stdout or "{}")
    ads = {int(a["ifIndex"]): a for a in data.get("ads") or [] if a.get("ifIndex") is not None}
    mtus = {int(m["InterfaceIndex"]): m.get("NlMtu") for m in data.get("mtu") or []}
    gws: dict[int, str] = {}
    for g in data.get("gw") or []:
        hop = str(g.get("NextHop") or "")
        if hop and hop != "0.0.0.0":
            gws.setdefault(int(g["InterfaceIndex"]), hop)
    rows: list[SubnetAccess] = []
    for entry in data.get("ips") or []:
        ip = str(entry.get("IPAddress") or "")
        idx = int(entry.get("InterfaceIndex") or 0)
        try:
            net = ipaddress.ip_network(f"{ip}/{int(entry.get('PrefixLength'))}", strict=False)
        except (TypeError, ValueError):
            continue
        ad = ads.get(idx, {})
        name = str(entry.get("InterfaceAlias") or ad.get("Name") or "")
        media = " ".join(
            str(ad.get(k) or "")
            for k in ("PhysicalMediaType", "MediaType", "InterfaceDescription")
        )
        mtu = mtus.get(idx)
        rows.append(
            SubnetAccess(
                cidr=str(net),
                ip=ip,
                interface=name,
                mac=str(ad.get("MacAddress") or "").replace("-", ":").lower(),
                gateway=gws.get(idx, ""),
                link_type=_kind_for(name, media, ip),
                link_speed=str(ad.get("LinkSpeed") or ""),
                duplex=_normalize_duplex(ad.get("FullDuplex")),
                mtu=int(mtu) if mtu not in (None, "") else None,
            )
        )
    return rows


def _linux_rows() -> list[SubnetAccess]:
    out = winproc.run(
        ["ip", "-j", "-4", "addr"], capture_output=True, text=True, timeout=8, check=False
    )
    routes = winproc.run(
        ["ip", "-j", "-4", "route", "show", "default"],
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
    )
    gws: dict[str, str] = {}
    try:
        for r in json.loads(routes.stdout or "[]"):
            if r.get("dev") and r.get("gateway"):
                gws.setdefault(r["dev"], r["gateway"])
    except json.JSONDecodeError:
        pass
    rows: list[SubnetAccess] = []
    for link in json.loads(out.stdout or "[]"):
        name = str(link.get("ifname") or "")
        for info in link.get("addr_info") or []:
            ip = str(info.get("local") or "")
            if not ip or ip.startswith("127."):
                continue
            net = ipaddress.ip_network(f"{ip}/{info.get('prefixlen')}", strict=False)
            rows.append(
                SubnetAccess(
                    cidr=str(net),
                    ip=ip,
                    interface=name,
                    mac=str(link.get("address") or ""),
                    gateway=gws.get(name, ""),
                    link_type=_kind_for(name, "wlan" if name.startswith("wl") else "", ip),
                    mtu=link.get("mtu"),
                )
            )
    return rows


def discover_local_subnets(*, force_refresh: bool = False) -> list[SubnetAccess]:
    """IPv4 subnets on this machine's adapters (cached for 30 s)."""
    global _cache
    now = time.monotonic()
    if not force_refresh and _cache is not None and now - _cache[0] < _CACHE_TTL_S:
        return list(_cache[1])
    try:
        if platform.system().lower() == "windows":
            rows = _windows_rows()
        else:
            rows = _linux_rows()
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        rows = []
    _cache = (now, rows)
    return list(rows)


def describe_local_adapter(cidr_or_ip: str) -> str:
    """One line for the adapter on *cidr_or_ip*: type, speed, duplex, MTU."""
    seed = (cidr_or_ip or "").strip()
    try:
        net = ipaddress.ip_network(seed, strict=False)
    except ValueError:
        return "Local adapter: unavailable"
    for row in discover_local_subnets():
        try:
            mine = ipaddress.ip_network(row.cidr, strict=False)
        except ValueError:
            continue
        if not (mine.overlaps(net)):
            continue
        parts = [f"{row.interface or '?'} {row.ip}".strip()]
        parts.append(f"type {link_type_label(row.link_type)}")
        if row.link_speed:
            parts.append(f"speed {row.link_speed}")
        if row.duplex:
            parts.append(f"duplex {row.duplex}")
        if row.mtu:
            parts.append(f"MTU {row.mtu}")
        return "Local adapter: " + " · ".join(parts)
    return f"Local adapter: none on {net} (reached by routing)"


def subnet_rows_from_beacon(beacon: dict) -> list[SubnetAccess]:
    """Rows for the ``accessible_subnets`` a beacon reported."""
    bid = str(beacon.get("beacon_id") or "?")
    meta = beacon.get("meta") or {}
    rows: list[SubnetAccess] = []
    for item in meta.get("accessible_subnets") or []:
        if not isinstance(item, dict) or not item.get("cidr"):
            continue
        ms = item.get("ping_ms")
        rows.append(
            SubnetAccess(
                cidr=str(item["cidr"]),
                ip=str(item.get("ip") or ""),
                interface=str(item.get("interface") or ""),
                gateway=str(item.get("gateway") or ""),
                link_type=normalize_link_type(str(item.get("link_type") or "")),
                source=f"beacon:{bid}",
                hostname=str(beacon.get("hostname") or ""),
                ping_status=str(item.get("ping_status") or ""),
                ping_ms=float(ms) if ms is not None else None,
                last_check=str(beacon.get("last_seen") or ""),
            )
        )
    return rows


# --------------------------------------------------------------------------- #
# Settings, local ping/speed checks and collector beacons (rebuilt, BUG-024).
# The collector token lives in the OS keyring, never in the JSON file.
# --------------------------------------------------------------------------- #

DEFAULT_SPEED_URL = "https://speed.cloudflare.com/__down?bytes=10000000"
_SETTINGS_FILE = "subnet_health.json"
_TOKEN_SERVICE = "PFSenseChecker.Collector"
_TOKEN_USER = "collector-token"


@dataclass
class SubnetHealthSettings:
    interval_sec: int = 60
    speed_url: str = DEFAULT_SPEED_URL
    run_speed: bool = False
    collector_url: str = ""
    collector_token: str = ""
    auto_refresh: bool = False
    ping_count: int = 3


def _settings_path():  # noqa: ANN202
    from pfsense_checker.paths import PROJECT_ROOT

    return PROJECT_ROOT / "data" / _SETTINGS_FILE


def _keyring():  # noqa: ANN202
    try:
        import keyring  # noqa: PLC0415

        return keyring
    except Exception:  # noqa: BLE001
        return None


def _as_int(value: Any, default: int, low: int) -> int:
    try:
        return max(low, int(value))
    except (TypeError, ValueError):
        return default


def load_settings() -> SubnetHealthSettings:
    path = _settings_path()
    data: dict[str, Any] = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            data = loaded if isinstance(loaded, dict) else {}
        except (OSError, ValueError):
            data = {}
    s = SubnetHealthSettings()
    s.interval_sec = _as_int(data.get("interval_sec"), s.interval_sec, 10)
    s.speed_url = str(data.get("speed_url") or s.speed_url)
    s.run_speed = bool(data.get("run_speed", s.run_speed))
    s.collector_url = str(data.get("collector_url") or "")
    s.auto_refresh = bool(data.get("auto_refresh", s.auto_refresh))
    s.ping_count = _as_int(data.get("ping_count"), s.ping_count, 1)
    kr = _keyring()
    if kr is not None:
        try:
            s.collector_token = kr.get_password(_TOKEN_SERVICE, _TOKEN_USER) or ""
        except Exception:  # noqa: BLE001
            s.collector_token = ""
    return s


def save_settings(settings: SubnetHealthSettings) -> None:
    path = _settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "interval_sec": int(settings.interval_sec),
        "speed_url": settings.speed_url,
        "run_speed": bool(settings.run_speed),
        "collector_url": settings.collector_url,
        "auto_refresh": bool(settings.auto_refresh),
        "ping_count": int(settings.ping_count),
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    kr = _keyring()
    if kr is None:
        return
    try:
        if settings.collector_token:
            kr.set_password(_TOKEN_SERVICE, _TOKEN_USER, settings.collector_token)
        else:
            kr.delete_password(_TOKEN_SERVICE, _TOKEN_USER)
    except Exception:  # noqa: BLE001 - nothing stored to delete, or no backend
        pass


_PING_MS = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)


def ping_host(host: str, count: int = 3, timeout_sec: float = 1.0) -> tuple[str, float | None]:
    """('ok' | 'loss' | 'fail', average ms) from the system ping."""
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(int(timeout_sec * 1000)), host]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(max(1, int(timeout_sec))), host]
    try:
        out = winproc.run(cmd, capture_output=True, text=True,
                          timeout=count * (timeout_sec + 1) + 3, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "fail", None
    times = [float(m) for m in _PING_MS.findall(out.stdout or "")]
    if not times:
        return "fail", None
    avg = round(sum(times) / len(times), 1)
    return ("ok" if len(times) >= count else "loss"), avg


def download_speed_mbps(url: str, max_bytes: int = 10_000_000, timeout: float = 20.0) -> float | None:
    import urllib.request  # noqa: PLC0415

    req = urllib.request.Request(url, headers={"User-Agent": "NetCheck-subnet-health"})
    start = time.monotonic()
    got = 0
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-set URL
            while got < max_bytes:
                chunk = resp.read(65536)
                if not chunk:
                    break
                got += len(chunk)
    except OSError:
        return None
    elapsed = time.monotonic() - start
    if elapsed <= 0 or got == 0:
        return None
    return round(got * 8 / elapsed / 1_000_000, 1)


def check_all_local(*, ping_count: int = 3, speed_url: str = DEFAULT_SPEED_URL,
                    run_speed: bool = False) -> list[SubnetAccess]:
    """Ping each local subnet's gateway (else its own address); one speed sample."""
    from datetime import datetime, timezone  # noqa: PLC0415

    rows = [r for r in discover_local_subnets(force_refresh=True) if r.link_type != "virtual"]
    stamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    speed_done = False
    for row in rows:
        target = row.gateway or row.ip
        if target:
            row.ping_status, row.ping_ms = ping_host(target, ping_count)
            row.message = f"ping {target}"
        else:
            row.ping_status, row.ping_ms = "fail", None
            row.message = "no address to ping"
        row.last_check = stamp
        if run_speed and row.gateway and not speed_done:
            row.speed_mbps = download_speed_mbps(speed_url)
            row.speed_status = "ok" if row.speed_mbps else "fail"
            speed_done = True
    return rows


def fetch_collector_beacons(url: str, *, token: str = "", offline_after: int = 180) -> list[dict]:
    """Beacons known to the NetCheck collector (GET /api/beacons)."""
    import urllib.request  # noqa: PLC0415

    base = (url or "").strip().rstrip("/")
    if not base:
        return []
    req = urllib.request.Request(f"{base}/api/beacons?offline_after={int(offline_after)}",
                                 headers={"User-Agent": "NetCheck"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 - operator-set URL
        data = json.loads(resp.read().decode("utf-8") or "{}")
    beacons = data.get("beacons") if isinstance(data, dict) else None
    return [b for b in beacons or [] if isinstance(b, dict)]
