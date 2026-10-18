"""Receive syslog (RFC 3164 / RFC 5424) from attached routers.

UDP is the usual transport (pfSense / MikroTik remote logging). TCP is optional
(newline- or octet-counted frames). Packets are never executed; they are parsed
and buffered for the Syslog home section.

Port 514 typically needs administrator rights on Windows — default is 5514.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import select
import socket
import threading
from collections import deque
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from PySide6.QtCore import QThread, Signal

from pfsense_checker.paths import PROJECT_ROOT, ensure_data_dir

_LOG = logging.getLogger("netcheck.syslog")

SETTINGS_PATH = PROJECT_ROOT / "data" / "syslog.json"
DEFAULT_UDP_PORT = 5514
DEFAULT_BIND_HOST = "0.0.0.0"
MAX_DATAGRAM = 8192
MAX_MEMORY_LINES = 50_000
DEFAULT_MEMORY_LINES = 2000
DEFAULT_MAX_FILE_BYTES = 2_097_152

_PRI_RE = re.compile(r"^<(\d{1,3})>")
_RFC3164_TS = re.compile(
    r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
)

FACILITY_NAMES: tuple[str, ...] = (
    "kern",
    "user",
    "mail",
    "daemon",
    "auth",
    "syslog",
    "lpr",
    "news",
    "uucp",
    "cron",
    "authpriv",
    "ftp",
    "ntp",
    "audit",
    "alert",
    "clock",
    "local0",
    "local1",
    "local2",
    "local3",
    "local4",
    "local5",
    "local6",
    "local7",
)

SEVERITY_NAMES: tuple[str, ...] = (
    "emerg",
    "alert",
    "crit",
    "err",
    "warning",
    "notice",
    "info",
    "debug",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def canon_ip(host: str) -> str:
    """Normalise a source address (strip IPv4-mapped IPv6)."""
    text = (host or "").strip()
    if not text:
        return ""
    if "%" in text:
        text = text.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return text
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return str(mapped)
    return str(ip)


@dataclass
class SyslogSettings:
    bind_host: str = DEFAULT_BIND_HOST
    udp_port: int = DEFAULT_UDP_PORT
    tcp_port: int = 0  # 0 = TCP disabled
    attached_only: bool = True
    file_enabled: bool = True
    memory_lines: int = DEFAULT_MEMORY_LINES
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    auto_start: bool = False
    extra_allow: str = ""  # extra IPs/CIDRs, e.g. 222.10.50.0/24

    def log_path(self) -> Path:
        return PROJECT_ROOT / "data" / "logs" / "syslog.jsonl"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> SyslogSettings:
        data = data or {}
        port = int(data.get("udp_port", DEFAULT_UDP_PORT) or DEFAULT_UDP_PORT)
        tcp = int(data.get("tcp_port", 0) or 0)
        mem = int(data.get("memory_lines", DEFAULT_MEMORY_LINES) or DEFAULT_MEMORY_LINES)
        size = int(data.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES) or DEFAULT_MAX_FILE_BYTES)
        host = str(data.get("bind_host", DEFAULT_BIND_HOST) or DEFAULT_BIND_HOST).strip()
        return cls(
            bind_host=host or DEFAULT_BIND_HOST,
            udp_port=max(1, min(65535, port)),
            tcp_port=max(0, min(65535, tcp)),
            attached_only=bool(data.get("attached_only", True)),
            file_enabled=bool(data.get("file_enabled", True)),
            memory_lines=max(10, min(MAX_MEMORY_LINES, mem)),
            max_file_bytes=max(4096, size),
            auto_start=bool(data.get("auto_start", False)),
            extra_allow=str(data.get("extra_allow", "") or "").strip(),
        )


def looks_like_cidr(text: str) -> bool:
    raw = (text or "").strip()
    if "/" not in raw:
        return False
    try:
        ipaddress.ip_network(raw, strict=False)
        return True
    except ValueError:
        return False


def normalize_bind_settings(settings: SyslogSettings) -> tuple[SyslogSettings, str]:
    """CIDR belongs in extra_allow, not bind. Bind is 0.0.0.0 or one IP."""
    host = (settings.bind_host or "").strip() or DEFAULT_BIND_HOST
    note = ""
    extra = (settings.extra_allow or "").strip()
    if looks_like_cidr(host):
        cidr = host
        if cidr not in extra:
            extra = f"{extra} {cidr}".strip() if extra else cidr
        host = DEFAULT_BIND_HOST
        note = (
            f"{cidr} is a network, not a bind address. "
            f"Listening on {host}; also-accept includes {cidr}."
        )
    elif host not in {DEFAULT_BIND_HOST, "::", "*"}:
        try:
            ipaddress.ip_address(canon_ip(host.split("%", 1)[0]))
        except ValueError:
            note = (
                f"Invalid bind address {host!r}. Use 0.0.0.0 or a single IP "
                "(e.g. 222.10.50.25). Networks like 222.10.50.0/24 go in "
                "Also accept from."
            )
            host = DEFAULT_BIND_HOST
    return replace(settings, bind_host=host, extra_allow=extra), note


def load_settings(path: Path | None = None) -> SyslogSettings:
    target = path or SETTINGS_PATH
    if not target.is_file():
        return SyslogSettings()
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return SyslogSettings()
    if not isinstance(raw, dict):
        return SyslogSettings()
    settings = SyslogSettings.from_dict(raw)
    before = settings.to_dict()
    normalized, note = normalize_bind_settings(settings)
    if normalized.to_dict() != before:
        try:
            save_settings(normalized, target)
        except OSError:
            pass
        if note:
            logging.getLogger("netcheck.syslog").info(
                "Syslog settings migrated: %s", note
            )
    return normalized


def save_settings(settings: SyslogSettings, path: Path | None = None) -> Path:
    target = path or SETTINGS_PATH
    ensure_data_dir()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(settings.to_dict(), indent=2) + "\n",
        encoding="utf-8",
    )
    return target


@dataclass(frozen=True)
class SyslogMessage:
    received_at: str
    source_ip: str
    source_port: int
    device_name: str
    pri: int
    facility: int
    severity: int
    facility_name: str
    severity_name: str
    timestamp: str
    hostname: str
    app_name: str
    message: str
    raw: str
    accepted: bool
    drop_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def facility_name(facility: int) -> str:
    if 0 <= facility < len(FACILITY_NAMES):
        return FACILITY_NAMES[facility]
    return f"facility{facility}"


def severity_name(severity: int) -> str:
    if 0 <= severity < len(SEVERITY_NAMES):
        return SEVERITY_NAMES[severity]
    return f"severity{severity}"


def parse_syslog(raw: bytes | str, *, source_ip: str = "", source_port: int = 0) -> SyslogMessage:
    """Parse a syslog datagram. Unknown layouts still yield a usable message."""
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace")
    else:
        text = raw
    text = text.replace("\x00", "").strip("\r\n")
    # Cap stored raw so a huge payload cannot blow the ring.
    stored_raw = text if len(text) <= MAX_DATAGRAM else text[:MAX_DATAGRAM] + "…"

    pri = 13
    rest = text
    match = _PRI_RE.match(text)
    if match:
        pri = min(191, int(match.group(1)))
        rest = text[match.end() :]

    facility, severity = divmod(pri, 8)
    hostname = ""
    app_name = ""
    timestamp = ""
    body = rest

    if rest.startswith("1 "):
        hostname, app_name, timestamp, body = _parse_rfc5424(rest[2:])
    else:
        hostname, app_name, timestamp, body = _parse_rfc3164(rest)

    return SyslogMessage(
        received_at=utc_now(),
        source_ip=canon_ip(source_ip),
        source_port=int(source_port or 0),
        device_name="",
        pri=pri,
        facility=facility,
        severity=severity,
        facility_name=facility_name(facility),
        severity_name=severity_name(severity),
        timestamp=timestamp,
        hostname=hostname,
        app_name=app_name,
        message=body.strip(),
        raw=stored_raw,
        accepted=True,
    )


def _parse_rfc5424(rest: str) -> tuple[str, str, str, str]:
    # TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    parts = rest.split(" ", 5)
    if len(parts) < 6:
        return "", "", "", rest
    timestamp, hostname, app_name, _procid, _msgid, remainder = parts
    if remainder.startswith("["):
        # Skip structured data until unquoted '] ' then message.
        idx = remainder.find("] ")
        if idx >= 0:
            remainder = remainder[idx + 2 :]
        elif remainder == "-":
            remainder = ""
        elif remainder.startswith("- "):
            remainder = remainder[2:]
    elif remainder.startswith("- "):
        remainder = remainder[2:]
    elif remainder == "-":
        remainder = ""
    hostname = "" if hostname == "-" else hostname
    app_name = "" if app_name == "-" else app_name
    timestamp = "" if timestamp == "-" else timestamp
    return hostname, app_name, timestamp, remainder


def _parse_rfc3164(rest: str) -> tuple[str, str, str, str]:
    ts_match = _RFC3164_TS.match(rest)
    timestamp = ""
    body = rest
    if ts_match:
        timestamp = ts_match.group(0).strip()
        body = rest[ts_match.end() :]
    hostname = ""
    app_name = ""
    # Hostname is only present after a BSD timestamp.
    if ts_match and body:
        bits = body.split(None, 1)
        if len(bits) == 2 and ":" not in bits[0] and "/" not in bits[0]:
            hostname, body = bits[0], bits[1]
    if ":" in body:
        tag, _, msg = body.partition(":")
        if tag and " " not in tag.strip() and len(tag) <= 48:
            app_name = tag.strip()
            body = msg.lstrip()
    return hostname, app_name, timestamp, body


def _resolve_host_ips(host: str) -> list[str]:
    """Resolve a hostname to IPv4 addresses for allowlist matching."""
    text = (host or "").strip()
    if not text:
        return []
    try:
        ipaddress.ip_address(canon_ip(text.split("%", 1)[0]))
        return [canon_ip(text)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(text, None, socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for info in infos:
        ip = canon_ip(info[4][0])
        if ip and ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def _ip_from_component_address(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        return ""
    if "/" in text:
        text = text.split("/", 1)[0].strip()
    try:
        ipaddress.ip_address(canon_ip(text))
        return canon_ip(text)
    except ValueError:
        return ""


def attached_sources(site: Any) -> dict[str, str]:
    """Map canon IP → device name from a live topology / login site."""
    out: dict[str, str] = {}
    devices = getattr(site, "devices", None) or []
    for dev in devices:
        name = str(getattr(dev, "name", "") or "").strip() or "device"
        candidates: list[str] = []
        mgmt = str(getattr(dev, "mgmt_ip", "") or "").strip()
        if mgmt:
            candidates.append(mgmt)
        ssh = getattr(dev, "ssh", None)
        host = str(getattr(ssh, "host", "") or "").strip() if ssh is not None else ""
        if host:
            candidates.append(host)
            candidates.extend(_resolve_host_ips(host))
        for comp in getattr(dev, "components", None) or []:
            addr = _ip_from_component_address(str(getattr(comp, "address", "") or ""))
            if addr:
                candidates.append(addr)
        for raw in candidates:
            ip = canon_ip(raw.split("%", 1)[0])
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            out.setdefault(ip, name)
    return out


def parse_allow_networks(text: str) -> list[ipaddress._BaseNetwork]:
    """Parse extra allow IPs/CIDRs (comma/space/semicolon separated)."""
    nets: list[ipaddress._BaseNetwork] = []
    for part in re.split(r"[\s,;]+", (text or "").strip()):
        if not part:
            continue
        try:
            if "/" in part:
                nets.append(ipaddress.ip_network(part, strict=False))
            else:
                ip = ipaddress.ip_address(canon_ip(part))
                nets.append(ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}"))
        except ValueError:
            continue
    return nets


def site_allow_networks(site: Any, settings: SyslogSettings) -> list[ipaddress._BaseNetwork]:
    """Configured extra_allow CIDRs plus site subnet list from Login."""
    parts = [(settings.extra_allow or "").strip()]
    for cidr in getattr(site, "subnets", None) or []:
        text = str(cidr or "").strip()
        if text:
            parts.append(text)
    return parse_allow_networks(" ".join(parts))


def source_permitted(
    ip: str,
    attached: dict[str, str],
    extra_networks: list[ipaddress._BaseNetwork],
    *,
    attached_only: bool,
) -> tuple[bool, str]:
    """Return (allowed, device_label). extra_networks apply even with attached_only."""
    key = canon_ip(ip)
    if key in attached:
        return True, attached[key]
    try:
        addr = ipaddress.ip_address(key)
    except ValueError:
        return (not attached_only), ""
    for net in extra_networks:
        if addr in net:
            return True, f"allow {net}"
    if attached_only:
        return False, ""
    return True, ""


def prefer_listen_ips(
    ips: list[str], extra_allow: str
) -> list[str]:
    """Put addresses in extra_allow CIDRs first (e.g. 222.10.50.0/24 fiber)."""
    nets = parse_allow_networks(extra_allow)
    if not nets:
        return list(ips)
    preferred: list[str] = []
    rest: list[str] = []
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            rest.append(ip)
            continue
        if any(addr in net for net in nets):
            preferred.append(ip)
        else:
            rest.append(ip)
    return preferred + rest


def order_listen_nics(nics: list[Any], extra_allow: str) -> list[Any]:
    """Fiber / extra-allow NICs first, then other LAN, then VPN / virtual."""
    nets = parse_allow_networks(extra_allow)
    preferred: list[Any] = []
    lan: list[Any] = []
    rest: list[Any] = []
    for nic in nics:
        ip = str(getattr(nic, "ip", "") or "").strip()
        kind = str(getattr(nic, "kind", "") or "lan")
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            rest.append(nic)
            continue
        if nets and any(addr in net for net in nets):
            preferred.append(nic)
        elif kind == "lan":
            lan.append(nic)
        else:
            rest.append(nic)
    return preferred + lan + rest


def pick_listen_bind(nics: list[Any], saved_bind: str, extra_allow: str) -> str:
    """Choose 0.0.0.0 or a NIC IP from saved settings.

    A saved CIDR or empty bind picks the first LAN NIC (fiber), not Hyper-V.
    An explicit 0.0.0.0 is kept as all-interfaces.
    """
    raw = (saved_bind or "").strip()
    cidr_saved = looks_like_cidr(raw)
    host = DEFAULT_BIND_HOST if (not raw or cidr_saved) else raw
    ordered = order_listen_nics(nics, extra_allow)
    ips = {str(getattr(n, "ip", "") or "") for n in ordered}
    if host != DEFAULT_BIND_HOST and host in ips:
        return host
    if host != DEFAULT_BIND_HOST:
        try:
            ipaddress.ip_address(canon_ip(host))
            return host
        except ValueError:
            host = DEFAULT_BIND_HOST
    if not raw or cidr_saved:
        for nic in ordered:
            if str(getattr(nic, "kind", "")) == "lan":
                return str(nic.ip)
    return host or DEFAULT_BIND_HOST


class _RingJsonl:
    def __init__(self, path: Path, max_bytes: int) -> None:
        self.path = path
        self.max_bytes = max(4096, int(max_bytes))
        self._lock = threading.Lock()

    def append(self, payload: dict[str, Any]) -> None:
        line = json.dumps(payload, ensure_ascii=False) + "\n"
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)
            try:
                size = self.path.stat().st_size
            except OSError:
                return
            if size <= self.max_bytes:
                return
            try:
                data = self.path.read_bytes()
            except OSError:
                return
            keep = data[-(self.max_bytes // 2) :]
            cut = keep.find(b"\n")
            if cut >= 0:
                keep = keep[cut + 1 :]
            self.path.write_bytes(keep)


class SyslogReceiver(QThread):
    """UDP (and optional TCP) syslog listener."""

    received = Signal(object)  # SyslogMessage
    status = Signal(str)
    failed = Signal(str)

    def __init__(self, settings: SyslogSettings, parent=None) -> None:
        super().__init__(parent)
        self.settings = settings
        self._stop = threading.Event()
        self._allow_lock = threading.Lock()
        self._allow: dict[str, str] = {}
        self._extra_networks: list[ipaddress._BaseNetwork] = []
        self._dropped = 0
        self._accepted = 0
        self._file: _RingJsonl | None = None
        if settings.file_enabled:
            self._file = _RingJsonl(settings.log_path(), settings.max_file_bytes)
        self._extra_networks = site_allow_networks(None, settings)

    def set_allowlist(
        self,
        sources: dict[str, str],
        *,
        site: Any = None,
        settings: SyslogSettings | None = None,
    ) -> None:
        with self._allow_lock:
            self._allow = dict(sources)
            cfg = settings or self.settings
            self._extra_networks = site_allow_networks(site, cfg)
            _LOG.debug(
                "Allowlist updated: %d attached IP(s) %s · %d extra network(s) %s",
                len(self._allow),
                sorted(self._allow),
                len(self._extra_networks),
                [str(n) for n in self._extra_networks],
            )

    def stop(self) -> None:
        self._stop.set()

    @property
    def accepted_count(self) -> int:
        return self._accepted

    @property
    def dropped_count(self) -> int:
        return self._dropped

    def run(self) -> None:
        sockets: list[socket.socket] = []
        tcp_listen: socket.socket | None = None
        clients: dict[socket.socket, bytearray] = {}
        try:
            udp = self._bind_udp()
            sockets.append(udp)
            if self.settings.tcp_port:
                tcp_listen = self._bind_tcp()
                sockets.append(tcp_listen)
            where = f"{self.settings.bind_host}:{self.settings.udp_port}/udp"
            if self.settings.tcp_port:
                where += f" and :{self.settings.tcp_port}/tcp"
            _LOG.info("Syslog listener started on %s", where)
            self.status.emit(f"Listening on {where}")
            while not self._stop.is_set():
                readable, _, _ = select.select(sockets, [], [], 0.4)
                for sock in readable:
                    if sock is tcp_listen:
                        self._accept_tcp(sock, sockets, clients)
                    elif sock in clients:
                        self._read_tcp(sock, sockets, clients)
                    else:
                        self._read_udp(sock)
        except OSError as exc:
            _LOG.error("Syslog listener failed: %s", exc)
            self.failed.emit(str(exc))
        finally:
            for sock in list(clients) + sockets:
                try:
                    sock.close()
                except OSError:
                    pass
            _LOG.info(
                "Syslog listener stopped (accepted %d, dropped %d)",
                self._accepted,
                self._dropped,
            )
            self.status.emit("Stopped")

    def _bind_udp(self) -> socket.socket:
        host = self.settings.bind_host.strip() or DEFAULT_BIND_HOST
        if host in {DEFAULT_BIND_HOST, "*"}:
            host = DEFAULT_BIND_HOST
        family = socket.AF_INET6 if ":" in host and host != DEFAULT_BIND_HOST else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, self.settings.udp_port))
        except OSError as exc:
            sock.close()
            if host != DEFAULT_BIND_HOST:
                # Fall back to all interfaces if the saved NIC IP is stale.
                _LOG.warning(
                    "UDP bind to %s:%d failed (%s) — falling back to 0.0.0.0",
                    host,
                    self.settings.udp_port,
                    exc,
                )
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((DEFAULT_BIND_HOST, self.settings.udp_port))
                self.settings = replace(self.settings, bind_host=DEFAULT_BIND_HOST)
            else:
                raise
        sock.setblocking(False)
        return sock

    def _bind_tcp(self) -> socket.socket:
        host = self.settings.bind_host.strip() or DEFAULT_BIND_HOST
        family = socket.AF_INET6 if ":" in host and host != DEFAULT_BIND_HOST else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, self.settings.tcp_port))
        sock.listen(8)
        sock.setblocking(False)
        return sock

    def _read_udp(self, sock: socket.socket) -> None:
        try:
            data, addr = sock.recvfrom(MAX_DATAGRAM)
        except BlockingIOError:
            return
        except OSError:
            return
        if not data:
            return
        host, port = addr[0], int(addr[1]) if len(addr) > 1 else 0
        self._ingest(data, host, port)

    def _accept_tcp(
        self,
        listen: socket.socket,
        sockets: list[socket.socket],
        clients: dict[socket.socket, bytearray],
    ) -> None:
        try:
            conn, _addr = listen.accept()
        except OSError:
            return
        conn.setblocking(False)
        sockets.append(conn)
        clients[conn] = bytearray()

    def _read_tcp(
        self,
        sock: socket.socket,
        sockets: list[socket.socket],
        clients: dict[socket.socket, bytearray],
    ) -> None:
        try:
            chunk = sock.recv(MAX_DATAGRAM)
        except BlockingIOError:
            return
        except OSError:
            chunk = b""
        buf = clients.get(sock)
        if not chunk:
            sockets.remove(sock)
            clients.pop(sock, None)
            try:
                sock.close()
            except OSError:
                pass
            return
        if buf is None:
            return
        buf.extend(chunk)
        try:
            peer = sock.getpeername()
        except OSError:
            peer = ("", 0)
        host = peer[0] if peer else ""
        port = int(peer[1]) if peer and len(peer) > 1 else 0
        while True:
            frame, rest = _pop_tcp_frame(bytes(buf))
            if frame is None:
                if len(buf) > MAX_DATAGRAM * 2:
                    buf.clear()
                break
            buf.clear()
            buf.extend(rest)
            if frame:
                self._ingest(frame, host, port)

    def _ingest(self, data: bytes, host: str, port: int) -> None:
        msg = parse_syslog(data, source_ip=host, source_port=port)
        ip = msg.source_ip
        with self._allow_lock:
            allow = dict(self._allow)
            attached_only = self.settings.attached_only
            extra = list(self._extra_networks)
        accepted, device = source_permitted(
            ip, allow, extra, attached_only=attached_only
        )
        reason = ""
        if not accepted:
            reason = "source is not an attached router or extra-allow network"
            self._dropped += 1
            _LOG.debug(
                "Dropped syslog from %s:%d (%s): %.120s",
                ip,
                port,
                reason,
                msg.message,
            )
        else:
            self._accepted += 1
            _LOG.debug(
                "Accepted syslog from %s:%d [%s/%s] %.120s",
                ip,
                port,
                msg.facility_name,
                msg.severity_name,
                msg.message,
            )
        if not device:
            device = allow.get(ip, "")
        msg = replace(
            msg,
            device_name=device,
            accepted=accepted,
            drop_reason=reason,
        )
        if accepted and self._file is not None:
            try:
                self._file.append(msg.to_dict())
            except OSError:
                pass
        if accepted:
            try:
                from pfsense_checker import openobserve

                openobserve.offer_syslog(msg)
            except Exception:  # noqa: BLE001
                _LOG.debug("OpenObserve syslog handoff failed", exc_info=True)
        self.received.emit(msg)


def _pop_tcp_frame(buf: bytes) -> tuple[bytes | None, bytes]:
    """Return (frame, remainder). None frame means incomplete."""
    if not buf:
        return None, buf
    # Octet-counting: "123 <PRI>..."
    if buf[0:1].isdigit():
        sp = buf.find(b" ")
        if sp <= 0:
            return None, buf
        try:
            length = int(buf[:sp].decode("ascii"))
        except ValueError:
            length = -1
        if 0 < length <= MAX_DATAGRAM:
            start = sp + 1
            if len(buf) < start + length:
                return None, buf
            return buf[start : start + length], buf[start + length :]
    nl = buf.find(b"\n")
    if nl < 0:
        return None, buf
    return buf[:nl], buf[nl + 1 :]


# In-memory ring used by the UI (GUI thread).
class SyslogBuffer:
    def __init__(self, maxlen: int = DEFAULT_MEMORY_LINES) -> None:
        self.lines: deque[SyslogMessage] = deque(maxlen=max(10, int(maxlen)))

    def resize(self, maxlen: int) -> None:
        items = list(self.lines)
        self.lines = deque(items, maxlen=max(10, int(maxlen)))

    def append(self, msg: SyslogMessage) -> None:
        self.lines.append(msg)

    def clear(self) -> None:
        self.lines.clear()
