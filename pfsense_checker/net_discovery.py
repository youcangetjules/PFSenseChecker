"""Find routers, switches, gateways and firewalls on the operator's subnets.

Scope and footprint (this is network discovery, so it is kept narrow):

* Only subnets the operator listed are swept, and only up to
  ``MAX_SWEEP_HOSTS`` addresses each. Larger subnets are refused, not
  silently truncated.
* Liveness is ping + ARP (``lan_scan.scan_subnet``). Live hosts then get a
  TCP connect on ``NETWORK_PORTS`` only — management ports, no range scan.
* One read per service to identify the box: the SSH greeting line, and the
  HTTP(S) ``<title>``. An HTTP redirect is followed once, and only to the
  same IP. TLS certificates are not verified (self-signed admin GUIs);
  nothing is sent but ``GET /``, and no credentials are ever used.
* Vendors come from a local OUI table. MACs are not sent to any lookup
  service.
"""

from __future__ import annotations

import ipaddress
import logging
import platform
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

from pfsense_checker import winproc
from pfsense_checker.lan_scan import LanHost, _tcp_probe, scan_subnet

_LOG = logging.getLogger("netcheck.discovery")

# SSH, Telnet, HTTP, HTTPS, NETCONF (Juniper and others), Winbox, RouterOS API.
NETWORK_PORTS: tuple[int, ...] = (22, 23, 80, 443, 830, 8291, 8728)
MAX_SWEEP_HOSTS = 1024  # a /22
_PROBE_TIMEOUT = 1.5
_READ_LIMIT = 32_768

ROLE_ROUTER = "router"
ROLE_SWITCH = "switch"
ROLE_GATEWAY = "gateway"
ROLE_FIREWALL = "firewall"

# First three octets → vendor. Network gear only; a miss is not evidence.
_VENDOR_OUI: dict[str, str] = {
    # MikroTik
    "000c42": "MikroTik",
    "085531": "MikroTik",
    "18fd74": "MikroTik",
    "2cc81b": "MikroTik",
    "488f5a": "MikroTik",
    "4c5e0c": "MikroTik",
    "64d154": "MikroTik",
    "6c3b6b": "MikroTik",
    "744d28": "MikroTik",
    "b869f4": "MikroTik",
    "c4ad34": "MikroTik",
    "cc2de0": "MikroTik",
    "d4ca6d": "MikroTik",
    "dc2c6e": "MikroTik",
    "e48d8c": "MikroTik",
    # Juniper
    "000585": "Juniper",
    # Netgate (ADI Engineering) pfSense appliances
    "0008a2": "Netgate",
    # Ubiquiti
    "24a43c": "Ubiquiti",
    "687251": "Ubiquiti",
    "802aa8": "Ubiquiti",
    "f09fc2": "Ubiquiti",
    "fcecda": "Ubiquiti",
}


class SweepTooLarge(ValueError):
    """The subnet has more addresses than ``MAX_SWEEP_HOSTS``."""


@dataclass(frozen=True)
class SeenDevice:
    ip: str
    role: str
    vendor: str = ""
    mac: str = ""
    open_ports: tuple[int, ...] = ()
    ssh_banner: str = ""
    http_title: str = ""
    evidence: tuple[str, ...] = field(default_factory=tuple)

    def label(self) -> str:
        what = f"{self.vendor} {self.role}".strip() if self.vendor else self.role
        return f"{self.ip}  {what}"


def vendor_from_mac(mac: str) -> str:
    key = re.sub(r"[^0-9a-f]", "", (mac or "").lower())[:6]
    return _VENDOR_OUI.get(key, "")


def sweep_size(cidr: str) -> int:
    net = ipaddress.ip_network(cidr, strict=False)
    return max(0, net.num_addresses - 2) if net.prefixlen < 31 else net.num_addresses


def read_ssh_banner(ip: str, port: int = 22, timeout: float = _PROBE_TIMEOUT) -> str:
    """Return the server's SSH greeting line (``SSH-2.0-…``), or ""."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(255)
    except OSError:
        return ""
    line = data.split(b"\n", 1)[0].strip().decode("ascii", "replace")
    return line if line.startswith("SSH-") else ""


def _http_get(
    ip: str, port: int, tls: bool, timeout: float
) -> tuple[str, str, bytes]:
    """``GET /`` → (status line, Location header, body prefix)."""
    sock = socket.create_connection((ip, port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # identification only, see module doc
            sock = ctx.wrap_socket(sock, server_hostname=ip)
        sock.sendall(
            f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetCheck-discovery\r\n"
            "Connection: close\r\n\r\n".encode("ascii")
        )
        data = b""
        while len(data) < _READ_LIMIT:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", "replace").splitlines()
    status = lines[0] if lines else ""
    location = ""
    for line in lines[1:]:
        if line.lower().startswith("location:"):
            location = line.split(":", 1)[1].strip()
    return status, location, body


def _title_of(body: bytes) -> str:
    m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if not m:
        return ""
    return " ".join(m.group(1).decode("utf-8", "replace").split())[:120]


def read_http_title(
    ip: str, open_ports: tuple[int, ...] | set[int], timeout: float = _PROBE_TIMEOUT
) -> str:
    """Page title of the admin GUI on 443 or 80 (one same-host redirect)."""
    attempts = [(443, True)] if 443 in open_ports else []
    if 80 in open_ports:
        attempts.append((80, False))
    for port, tls in attempts:
        try:
            status, location, body = _http_get(ip, port, tls, timeout)
        except (OSError, ssl.SSLError):
            continue
        title = _title_of(body)
        if status.split(" ")[1:2] and status.split(" ")[1].startswith("3") and location:
            target = urlsplit(location)
            if target.hostname == ip:
                next_tls = target.scheme == "https"
                next_port = target.port or (443 if next_tls else 80)
                try:
                    _s, _l, body2 = _http_get(ip, next_port, next_tls, timeout)
                    title = _title_of(body2) or title
                except (OSError, ssl.SSLError):
                    pass
        if title:
            return title
    return ""


_ROUTE_WIN = re.compile(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s", re.M)
_ROUTE_UNIX = re.compile(r"^default\s+via\s+(\d+\.\d+\.\d+\.\d+)", re.M)


def parse_default_gateways(text: str) -> set[str]:
    found = set(_ROUTE_WIN.findall(text or "")) | set(_ROUTE_UNIX.findall(text or ""))
    return {ip for ip in found if ip != "0.0.0.0"}


def default_gateways() -> set[str]:
    """This PC's IPv4 default gateways (``route print`` / ``ip route``)."""
    if platform.system().lower() == "windows":
        cmd = ["route", "print", "-4"]
    else:
        cmd = ["ip", "-4", "route"]
    try:
        out = winproc.run(cmd, capture_output=True, text=True, timeout=8, check=False)
    except (OSError, ValueError):
        return set()
    return parse_default_gateways(out.stdout or "")


def classify(
    ip: str,
    *,
    mac: str = "",
    open_ports: tuple[int, ...] = (),
    ssh_banner: str = "",
    http_title: str = "",
    gateways: set[str] | frozenset[str] = frozenset(),
) -> SeenDevice | None:
    """Return a :class:`SeenDevice` for network gear, or None for other hosts."""
    evidence: list[str] = []
    vendor = vendor_from_mac(mac)
    if vendor:
        evidence.append(f"MAC {mac[:8]} is {vendor}")
    ports = set(open_ports)
    banner = ssh_banner.lower()
    title = http_title.lower()

    firewall = False
    switch = False
    network = False
    if "pfsense" in title:
        vendor, firewall = "pfSense", True
        evidence.append(f"web GUI: {http_title}")
    elif "opnsense" in title:
        vendor, firewall = "OPNsense", True
        evidence.append(f"web GUI: {http_title}")
    if "rosssh" in banner:
        vendor, network = "MikroTik", True
        evidence.append("SSH banner ROSSSH (RouterOS)")
    if ports & {8291, 8728}:
        vendor = vendor or "MikroTik"
        network = True
        evidence.append(
            "MikroTik service port open: "
            + ", ".join(str(p) for p in sorted(ports & {8291, 8728}))
        )
    if "routeros" in title:
        vendor, network = "MikroTik", True
        evidence.append("web GUI: RouterOS")
    if "swos" in title or re.search(r"\bswitch\b", title):
        switch = network = True
        evidence.append(f"web GUI: {http_title}")
    if "cisco" in banner:
        vendor, network = vendor or "Cisco", True
        evidence.append(f"SSH banner: {ssh_banner}")
    if 830 in ports:
        network = True
        evidence.append("NETCONF (830) open")
    if vendor in {"MikroTik", "Juniper", "Ubiquiti", "Netgate"}:
        network = True
    gateway = ip in gateways
    if gateway:
        evidence.append("default gateway of this PC")
    if 23 in ports:
        evidence.append("Telnet (23) open")

    if firewall:
        role = ROLE_FIREWALL
    elif gateway:
        role = ROLE_GATEWAY
    elif switch:
        role = ROLE_SWITCH
    elif network:
        role = ROLE_ROUTER
    else:
        return None
    return SeenDevice(
        ip=ip,
        role=role,
        vendor=vendor,
        mac=mac,
        open_ports=tuple(sorted(ports)),
        ssh_banner=ssh_banner,
        http_title=http_title,
        evidence=tuple(evidence),
    )


def discover(
    cidr: str,
    *,
    scan: Callable[..., list[LanHost]] = scan_subnet,
    probe: Callable[[str, int, float], bool | None] = _tcp_probe,
    banner: Callable[[str], str] = read_ssh_banner,
    title: Callable[[str, tuple[int, ...]], str] = read_http_title,
    gateways: set[str] | None = None,
    should_stop: Callable[[], bool] = lambda: False,
) -> list[SeenDevice]:
    """Sweep *cidr* and return the network devices seen on it."""
    net = ipaddress.ip_network(cidr, strict=False)
    size = sweep_size(str(net))
    if size > MAX_SWEEP_HOSTS:
        raise SweepTooLarge(
            f"{net} has {size} addresses; NetCheck sweeps at most "
            f"{MAX_SWEEP_HOSTS} (a /22). Add the /24s you want swept."
        )
    gws = default_gateways() if gateways is None else set(gateways)
    hosts = scan(
        str(net),
        ping=True,
        check_ssh=False,
        check_http=False,
        max_hosts=MAX_SWEEP_HOSTS,
    )
    hosts = [h for h in hosts if _in(h.ip, net)]

    def _look(host: LanHost) -> SeenDevice | None:
        if should_stop():
            return None
        open_ports = tuple(
            p for p in NETWORK_PORTS if probe(host.ip, p, _PROBE_TIMEOUT) is True
        )
        ssh = banner(host.ip) if 22 in open_ports else ""
        page = title(host.ip, open_ports) if {80, 443} & set(open_ports) else ""
        return classify(
            host.ip,
            mac=host.mac,
            open_ports=open_ports,
            ssh_banner=ssh,
            http_title=page,
            gateways=gws,
        )

    with ThreadPoolExecutor(max_workers=16) as pool:
        seen = [d for d in pool.map(_look, hosts) if d is not None]
    seen.sort(key=lambda d: ipaddress.ip_address(d.ip))
    _LOG.info(
        "Discovery %s: %d live host(s), %d network device(s)", net, len(hosts), len(seen)
    )
    return seen


def _in(ip: str, net) -> bool:  # noqa: ANN001
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


# ---- Subnets panel text (pure, so it is testable without Qt) ----

SEEN_COLOR = "#1565c0"
CONNECTED_COLOR = "#2e7d32"
IDLE_COLOR = "#78909c"
WARN_COLOR = "#e65100"


def seen_summary(state: str, devices: list[SeenDevice], error: str = "") -> tuple[str, str, str]:
    """(text, colour, tooltip) for the Seen column.

    *state* is ``pending``, ``scanning``, ``done``, ``too_large`` or ``error``.
    """
    if state == "scanning":
        return "scanning…", IDLE_COLOR, "Looking for routers, switches and gateways"
    if state == "too_large":
        return "too large", WARN_COLOR, error
    if state == "error":
        return "scan failed", WARN_COLOR, error
    if state != "done":
        return "not swept", IDLE_COLOR, "Click Rescan subnets to look for network devices"
    n = len(devices)
    if n == 0:
        return "none seen", IDLE_COLOR, "No routers, switches or gateways answered"
    lines = [d.label() + ("  — " + "; ".join(d.evidence) if d.evidence else "") for d in devices]
    return f"{n} seen", SEEN_COLOR, "Network devices seen:\n" + "\n".join(lines)


def connected_summary(names: list[str]) -> tuple[str, str]:
    """(text, colour) for the Connected column."""
    n = len(names)
    if n == 0:
        return "none connected", IDLE_COLOR
    return f"{n} connected", CONNECTED_COLOR
