"""LAN helpers: classify IP/MAC, read ARP, and light subnet discovery."""

from __future__ import annotations

import ipaddress
import logging
import platform
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from pfsense_checker import winproc

_LOG = logging.getLogger("netcheck.lan")

_MAC_RE = re.compile(
    r"^(?:"
    r"(?:[0-9A-Fa-f]{2}([:\-]))(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}"
    r"|"
    r"[0-9A-Fa-f]{12}"
    r")$"
)
_ARP_LINE_WIN = re.compile(
    r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})\s+(\S+)",
    re.M,
)
_ARP_LINE_UNIX = re.compile(
    r"^(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{11,17})",
    re.M,
)


@dataclass(frozen=True)
class AddressKind:
    kind: str  # ip | mac | empty | invalid
    value: str  # normalized IP or MAC (colon form) or ""
    detail: str = ""


@dataclass
class LanHost:
    ip: str
    mac: str = ""
    ssh_open: bool | None = None  # TCP/22
    http_open: bool | None = None  # TCP/80
    https_open: bool | None = None  # TCP/443
    source: str = ""  # arp | ping | ssh


def classify_address(text: str) -> AddressKind:
    """Return whether *text* is an IPv4 address, a MAC, empty, or invalid."""
    raw = (text or "").strip()
    if not raw:
        return AddressKind("empty", "")
    # MAC first (avoid treating hex-like junk as IP)
    if _MAC_RE.match(raw):
        return AddressKind("mac", normalize_mac(raw))
    try:
        ip = ipaddress.ip_address(raw)
        if isinstance(ip, ipaddress.IPv4Address):
            return AddressKind("ip", str(ip))
        return AddressKind("invalid", "", "IPv6 is not supported here — use IPv4")
    except ValueError:
        pass
    return AddressKind("invalid", "", "Enter an IPv4 address or MAC address")


def normalize_mac(text: str) -> str:
    hexes = re.findall(r"[0-9A-Fa-f]{2}", text)
    if len(hexes) != 6:
        raise ValueError(f"not a MAC address: {text!r}")
    return ":".join(h.lower() for h in hexes)


def mac_key(text: str) -> str:
    return normalize_mac(text).replace(":", "")


def parse_arp_table(text: str | None = None) -> list[LanHost]:
    """Parse `arp -a` output (Windows or Unix)."""
    import subprocess

    if text is None:
        try:
            completed = winproc.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            text = completed.stdout or ""
        except (OSError, subprocess.TimeoutExpired):
            return []
    hosts: dict[str, LanHost] = {}
    for m in _ARP_LINE_WIN.finditer(text):
        ip, mac, _iface = m.group(1), m.group(2), m.group(3)
        if mac.replace("-", "").lower() in ("ffffffffffff", "000000000000"):
            continue
        try:
            mac_n = normalize_mac(mac)
        except ValueError:
            continue
        hosts[ip] = LanHost(ip=ip, mac=mac_n, source="arp")
    for m in _ARP_LINE_UNIX.finditer(text):
        ip, mac = m.group(2), m.group(3)
        try:
            mac_n = normalize_mac(mac)
        except ValueError:
            continue
        hosts[ip] = LanHost(ip=ip, mac=mac_n, source="arp")
    return list(hosts.values())


def resolve_mac_to_ip(mac: str, arp_hosts: list[LanHost] | None = None) -> str | None:
    key = mac_key(mac)
    for h in arp_hosts if arp_hosts is not None else parse_arp_table():
        if h.mac and mac_key(h.mac) == key:
            return h.ip
    return None


@dataclass(frozen=True)
class LocalIpv4Nic:
    """One IPv4 address on a named adapter (syslog listen-on list)."""

    ip: str
    name: str
    cidr: str = ""
    kind: str = "lan"  # lan | vpn | virtual | link-local

    def label(self) -> str:
        title = (self.name or "").strip() or self.ip
        base = f"{title}  —  {self.ip}" if title != self.ip else self.ip
        tag = {
            "virtual": "virtual",
            "link-local": "link-local",
            "vpn": "VPN / Tailscale",
        }.get(self.kind, "")
        return f"{base}  ({tag})" if tag else base


def nic_kind(ip: str, name: str = "") -> str:
    """Classify a NIC so syslog can prefer fiber LAN over Hyper-V / APIPA."""
    text = (ip or "").strip()
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return "lan"
    if addr.is_link_local:
        return "link-local"
    if addr in ipaddress.ip_network("100.64.0.0/10"):
        return "vpn"
    label = (name or "").lower()
    virtual_bits = (
        "vethernet",
        "hyper-v",
        "default switch",
        "docker",
        "vbox",
        "virtualbox",
        "vmware",
        "wsl",
        "loopback",
    )
    if any(bit in label for bit in virtual_bits):
        return "virtual"
    return "lan"


def local_ipv4_nics() -> list[LocalIpv4Nic]:
    """Named IPv4 adapters (PowerShell / ip) with a hostname fallback."""
    nics: list[LocalIpv4Nic] = []
    seen: set[str] = set()
    try:
        from pfsense_checker.subnet_health import discover_local_subnets

        rows = discover_local_subnets()
    except (ImportError, OSError):
        rows = []
    for row in rows:
        ip = str(getattr(row, "ip", "") or "").strip()
        if not ip or ip in seen:
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.version != 4 or addr.is_loopback or addr.is_unspecified:
            continue
        seen.add(ip)
        name = str(getattr(row, "interface", "") or "").strip()
        nics.append(
            LocalIpv4Nic(
                ip=ip,
                name=name or ip,
                cidr=str(getattr(row, "cidr", "") or ""),
                kind=nic_kind(ip, name),
            )
        )
    if nics:
        return nics
    for ip in local_ipv4_addresses():
        nics.append(LocalIpv4Nic(ip=ip, name=ip, kind=nic_kind(ip, "")))
    return nics


def local_ipv4_addresses() -> list[str]:
    """This PC's non-loopback IPv4 addresses (for syslog / bind hints)."""
    found: list[str] = []
    seen: set[str] = set()

    def _add(ip: str) -> None:
        ip = (ip or "").strip()
        if not ip or ip.startswith("127.") or ip in seen:
            return
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return
        if addr.version != 4 or addr.is_loopback or addr.is_unspecified:
            return
        seen.add(ip)
        found.append(ip)

    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            _add(info[4][0])
    except OSError:
        pass
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        primary = sock.getsockname()[0]
        sock.close()
        if primary in seen:
            found.remove(primary)
        _add(primary)
        if primary in found:
            found.remove(primary)
            found.insert(0, primary)
    except OSError:
        pass
    return found


def local_ipv4_cidrs() -> list[str]:
    """Best-effort local /24 (or interface prefix) suggestions for scanning."""
    cidrs: list[str] = []
    seen: set[str] = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip.startswith("127."):
                continue
            net = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            if net not in seen:
                seen.add(net)
                cidrs.append(net)
    except OSError:
        pass
    # Also try UDP connect trick for the outbound interface
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        if not ip.startswith("127."):
            net = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            if net not in seen:
                cidrs.insert(0, net)
    except OSError:
        pass
    return cidrs


def _ping_one(ip: str, timeout_sec: float = 0.6) -> bool:
    import subprocess

    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_sec * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_sec))), ip]
    try:
        return (
            winproc.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec + 2,
                check=False,
            ).returncode
            == 0
        )
    except (OSError, subprocess.TimeoutExpired):
        return False


def _tcp_probe(
    ip: str, port: int, timeout_sec: float = 2.0
) -> bool | None:
    """TCP connect to *port*.

    Returns:
      True  — port accepted a TCP connection
      False — connection refused (port closed / nothing listening)
      None  — timeout / unreachable / filtered (unknown; not proof of closed)
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout_sec):
            return True
    except ConnectionRefusedError:
        return False
    except TimeoutError:
        return None
    except OSError as exc:
        # Windows often maps refuse/timeout to WinError variants.
        err = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        # 10061 WSAECONNREFUSED, 111 ECONNREFUSED
        if err in {10061, 111}:
            return False
        # 10060 WSAETIMEDOUT, 110 ETIMEDOUT, 101 ENETUNREACH-ish
        if err in {10060, 110, 101}:
            return None
        # Network unreachable / no route — treat as unknown, not closed
        return None


def _ssh_probe(
    ip: str, port: int = 22, timeout_sec: float = 2.0
) -> bool | None:
    """Backward-compatible alias for :func:`_tcp_probe`."""
    return _tcp_probe(ip, port, timeout_sec)


def _ssh_open(ip: str, port: int = 22, timeout_sec: float = 2.0) -> bool:
    """Backward-compatible bool: True only when TCP connect succeeded."""
    return _tcp_probe(ip, port=port, timeout_sec=timeout_sec) is True


def scan_subnet(
    cidr: str,
    *,
    ping: bool = True,
    check_ssh: bool = True,
    check_http: bool = True,
    max_hosts: int = 254,
    workers: int = 64,
    ssh_timeout_sec: float = 2.0,
) -> list[LanHost]:
    """Ping-sweep (optional) + ARP merge + optional TCP probes (22 / 80 / 443).

    Returns hosts found via ARP and/or successful ping. Does not attack —
    only ICMP echo and TCP connects to common management ports.

    Port fields on :class:`LanHost` are True / False / None
    (open / refused / no reply).
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid subnet: {cidr}") from exc
    _LOG.debug(
        "Subnet scan start: %s (ping=%s ssh=%s http=%s workers=%d)",
        network,
        ping,
        check_ssh,
        check_http,
        workers,
    )
    scan_started = time.perf_counter()
    if network.num_addresses > max_hosts + 2:
        # Cap oversized nets to first max_hosts usable addresses
        hosts_iter = list(network.hosts())[:max_hosts]
    else:
        hosts_iter = list(network.hosts())

    def _in_net(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in network
        except ValueError:
            return False

    # Only ARP entries inside the scanned subnet (not the whole table).
    found: dict[str, LanHost] = {
        h.ip: h for h in parse_arp_table() if _in_net(h.ip)
    }

    if ping and hosts_iter:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_ping_one, str(ip)): str(ip) for ip in hosts_iter}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    ok = fut.result()
                except Exception:  # noqa: BLE001
                    ok = False
                if ok:
                    if ip in found:
                        found[ip].source = (
                            "ping+arp" if found[ip].source == "arp" else "ping"
                        )
                    else:
                        found[ip] = LanHost(ip=ip, source="ping")

        # Re-read ARP after pings to pick up MACs
        for h in parse_arp_table():
            if not _in_net(h.ip):
                continue
            if h.ip in found:
                if h.mac:
                    found[h.ip].mac = h.mac
            else:
                found[h.ip] = h

    ports: list[tuple[int, str]] = []
    if check_ssh:
        ports.append((22, "ssh_open"))
    if check_http:
        ports.extend([(80, "http_open"), (443, "https_open")])
    if ports and found:
        # Fewer parallel probes + longer timeout → fewer false "closed" results.
        probe_workers = min(24, max(4, workers // 3))
        with ThreadPoolExecutor(max_workers=probe_workers) as pool:
            futures = {
                pool.submit(_tcp_probe, ip, port, ssh_timeout_sec): (ip, attr)
                for ip in list(found)
                for port, attr in ports
            }
            for fut in as_completed(futures):
                ip, attr = futures[fut]
                try:
                    setattr(found[ip], attr, fut.result())
                except Exception:  # noqa: BLE001
                    setattr(found[ip], attr, None)

    _LOG.debug(
        "Subnet scan done: %s → %d host(s) in %.1fs",
        network,
        len(found),
        time.perf_counter() - scan_started,
    )
    return sorted(found.values(), key=lambda h: ipaddress.ip_address(h.ip))
