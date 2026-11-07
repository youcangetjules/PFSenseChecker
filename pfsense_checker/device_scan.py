"""Subnet Health device scan: who is on each subnet, how they got their
address, how long they have been around, and anything that looks wrong.

Sources, merged per subnet:

* **nmap** (main source) - ``nmap -sV -O`` by default, XML on stdout.
  Firewalls (pfSense / OPNsense) are excluded unless the operator unticks
  that, because repeated probes make sshguard ban the scanning machine.
  Without nmap installed, the existing ping sweep + ARP merge
  (``lan_scan.scan_subnet``) stands in and the result says so.
* **Router tables** - live ARP and DHCP leases over SSH (saved logins only),
  to fill the gaps nmap leaves (sleeping phones, hosts that drop ICMP).
* **Loaded configs** - DHCP pools and static mappings / static leases.
* **Beacons** - what the collector knows; a beacon's own address marks the
  device it runs on.

Device age (first seen / last seen) lives in PostgreSQL ``subnet_devices``.

No Qt imports; the GUI runs :func:`scan` on a worker thread.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET  # noqa: S405 - parses nmap's own output
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from pfsense_checker import winproc

# Connection types
CONN_ROUTER = "Router / gateway"
CONN_DHCP = "DHCP"
CONN_STATIC_DHCP = "Static DHCP"
CONN_STATIC = "Static"
CONN_DHCP_INFERRED = "DHCP (inferred)"  # inside a pool whose lease table was not read
CONN_MACVLAN = "MACVLAN"
CONN_UNKNOWN = "Unknown"

# Problem severities
SEV_FAIL = "fail"
SEV_WARN = "warn"
SEV_INFO = "info"

FIREWALL_KINDS = frozenset({"pfsense", "opnsense", "firewall"})
ROUTER_KINDS = FIREWALL_KINDS | {"mikrotik", "router", "switch", "gateway"}
STALE_LEASE_AFTER = timedelta(days=7)
POOL_WARN_RATIO = 0.9
BEACON_OFFLINE_AFTER = timedelta(minutes=3)

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #


@dataclass
class Sighting:
    """One source saying 'this IP has this MAC'."""

    ip: str
    mac: str = ""
    source: str = ""  # nmap | arp | router-arp:<dev> | lease:<dev> | beacon:<id> | local
    hostname: str = ""
    vendor: str = ""
    os_guess: str = ""
    services: list[str] = field(default_factory=list)
    lease: str = ""  # dynamic | static | ""
    lease_expires: str = ""
    lease_last_seen: str = ""
    incomplete: bool = False
    interface: str = ""


@dataclass
class Device:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    os_guess: str = ""
    services: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    conn_type: str = CONN_UNKNOWN
    beacon_id: str = ""
    known_name: str = ""  # topology device name, when it is one
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    answered: bool = False  # seen live by nmap / ping, not only in a table

    @property
    def key(self) -> str:
        return self.mac or f"ip:{self.ip}"


@dataclass
class Problem:
    severity: str
    kind: str
    subject: str
    detail: str
    fix: str = ""


@dataclass
class Pool:
    start: ipaddress.IPv4Address
    end: ipaddress.IPv4Address
    owner: str = ""

    @property
    def size(self) -> int:
        return int(self.end) - int(self.start) + 1

    def __contains__(self, ip: ipaddress.IPv4Address) -> bool:
        return self.start <= ip <= self.end


@dataclass
class StaticMap:
    ip: str
    mac: str
    owner: str = ""


@dataclass
class ScanResult:
    cidr: str
    devices: list[Device] = field(default_factory=list)
    problems: list[Problem] = field(default_factory=list)
    engine: str = ""  # "nmap" | "ping sweep"
    notes: list[str] = field(default_factory=list)
    gateway: str = ""


# --------------------------------------------------------------------------- #
# MAC helpers
# --------------------------------------------------------------------------- #


def norm_mac(text: str) -> str:
    raw = re.sub(r"[^0-9a-fA-F]", "", text or "").lower()
    if len(raw) != 12:
        return ""
    mac = ":".join(raw[i:i + 2] for i in range(0, 12, 2))
    return "" if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") else mac


def is_locally_administered(mac: str) -> bool:
    mac = norm_mac(mac)
    return bool(mac) and bool(int(mac[:2], 16) & 0x02)


def is_macvlan_mac(mac: str) -> bool:
    """Docker / Podman macvlan and ipvlan endpoints default to 02:42:xx."""
    return norm_mac(mac).startswith("02:42:")


def is_random_mac(mac: str) -> bool:
    """Locally administered and not a container default: phone/laptop privacy MAC."""
    return is_locally_administered(mac) and not is_macvlan_mac(mac)


def _ip(text: str) -> ipaddress.IPv4Address | None:
    try:
        return ipaddress.IPv4Address((text or "").strip())
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# nmap
# --------------------------------------------------------------------------- #

_NMAP_CANDIDATES = (
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
)


def nmap_path() -> str:
    found = shutil.which("nmap")
    if found:
        return found
    for cand in _NMAP_CANDIDATES:
        if Path(cand).is_file():
            return cand
    return ""


def nmap_args(cidr: str, *, aggressive: bool = True, exclude: Iterable[str] = ()) -> list[str]:
    """nmap arguments (without the executable) for one subnet, XML to stdout."""
    args = ["-oX", "-", "-T4", "--host-timeout", "90s"]
    if aggressive:
        args += ["-sV", "-O", "--osscan-limit", "--version-light", "--top-ports", "100"]
    else:
        args += ["-sn"]
    ex = sorted({e for e in exclude if _ip(e)})
    if ex:
        args += ["--exclude", ",".join(ex)]
    args.append(cidr)
    return args


def run_nmap(cidr: str, *, aggressive: bool = True, exclude: Iterable[str] = (),
             timeout: float = 900.0) -> tuple[list[Sighting], str]:
    """(sightings, error). An empty error with no sightings means nobody answered."""
    exe = nmap_path()
    if not exe:
        return [], "nmap is not installed"
    try:
        out = winproc.run([exe, *nmap_args(cidr, aggressive=aggressive, exclude=exclude)],
                          capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return [], f"nmap took longer than {int(timeout)} s"
    except OSError as exc:
        return [], f"nmap could not start: {exc}"
    text = out.stdout or ""
    if "<nmaprun" not in text:
        err = (out.stderr or "").strip().splitlines()
        return [], err[-1] if err else f"nmap exited with {out.returncode}"
    hosts = parse_nmap_xml(text)
    if aggressive and not hosts and "requires root" in (out.stderr or "").lower():
        return [], "OS detection needs NetCheck to run as administrator"
    return hosts, ""


def parse_nmap_xml(text: str) -> list[Sighting]:
    root = ET.fromstring(text)  # noqa: S314 - nmap's own output
    rows: list[Sighting] = []
    for host in root.iter("host"):
        status = host.find("status")
        if status is not None and status.get("state") not in (None, "up"):
            continue
        ip = mac = vendor = ""
        for addr in host.findall("address"):
            kind = addr.get("addrtype")
            if kind == "ipv4":
                ip = addr.get("addr", "")
            elif kind == "mac":
                mac = norm_mac(addr.get("addr", ""))
                vendor = addr.get("vendor", "") or ""
        if not ip:
            continue
        name_el = host.find("hostnames/hostname")
        hostname = name_el.get("name", "") if name_el is not None else ""
        os_el = host.find("os/osmatch")
        os_guess = ""
        if os_el is not None:
            os_guess = f"{os_el.get('name', '')} ({os_el.get('accuracy', '?')}%)"
        services = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            label = f"{port.get('portid')}/{port.get('protocol')}"
            if svc is not None:
                name = " ".join(x for x in (svc.get("name"), svc.get("product"), svc.get("version")) if x)
                if name:
                    label += f" {name}"
            services.append(label)
        rows.append(Sighting(ip=ip, mac=mac, source="nmap", hostname=hostname,
                             vendor=vendor, os_guess=os_guess, services=services))
    return rows


def ping_sweep(cidr: str) -> list[Sighting]:
    """Fallback without nmap: the existing ping sweep + local ARP merge."""
    from pfsense_checker import lan_scan  # noqa: PLC0415

    rows = []
    for h in lan_scan.scan_subnet(cidr, check_ssh=False, check_http=False):
        rows.append(Sighting(ip=h.ip, mac=norm_mac(h.mac), source="ping" if h.source.startswith("ping") else "arp"))
    return rows


def local_sightings(net: ipaddress.IPv4Network) -> list[Sighting]:
    """This PC's own address(es) on *net* (no scan reports the scanner itself)."""
    import socket  # noqa: PLC0415

    from pfsense_checker import subnet_health  # noqa: PLC0415

    try:
        rows = subnet_health.discover_local_subnets()
    except Exception:  # noqa: BLE001
        return []
    host = socket.gethostname()
    return [Sighting(ip=r.ip, mac=norm_mac(r.mac), source="local", hostname=f"{host} (this PC)")
            for r in rows if _in(net, r.ip)]


# --------------------------------------------------------------------------- #
# Router tables (live, over SSH)
# --------------------------------------------------------------------------- #

MIKROTIK_TABLE_COMMANDS = (
    ":put \"##ARP\"",
    "/ip arp print terse without-paging",
    ":put \"##LEASE\"",
    "/ip dhcp-server lease print terse without-paging",
    ":put \"##POOL\"",
    "/ip pool print terse without-paging",
)

PFSENSE_TABLE_COMMANDS = (
    "/bin/sh -c " + shlex.quote(
        "echo '##ARP'; arp -an; "
        "echo '##LEASE'; cat /var/dhcpd/var/db/dhcpd.leases 2>/dev/null; "
        "echo '##KEA'; cat /var/lib/kea/dhcp4.leases 2>/dev/null; true"
    ),
)


def _terse_rows(text: str) -> list[tuple[str, dict[str, str]]]:
    """RouterOS ``print terse``: (flags, key=value dict) per line."""
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        try:
            parts = shlex.split(line, posix=True)
        except ValueError:
            parts = line.split()
        flags = ""
        pairs: dict[str, str] = {}
        for part in parts:
            if "=" in part:
                k, _, v = part.partition("=")
                pairs[k] = v
            elif not pairs and not part.isdigit():
                flags += part
        rows.append((flags.upper(), pairs))
    return rows


def _sections(text: str) -> dict[str, str]:
    out: dict[str, list[str]] = defaultdict(list)
    current = ""
    for line in (text or "").splitlines():
        if line.strip().startswith("##"):
            current = line.strip()[2:]
            continue
        out[current].append(line)
    return {k: "\n".join(v) for k, v in out.items()}


def parse_mikrotik_tables(text: str, owner: str) -> tuple[list[Sighting], list[Pool]]:
    parts = _sections(text)
    rows: list[Sighting] = []
    for flags, kv in _terse_rows(parts.get("ARP", "")):
        ip = kv.get("address", "")
        if not _ip(ip) or "X" in flags:
            continue
        mac = norm_mac(kv.get("mac-address", ""))
        status = kv.get("status", "").lower()
        rows.append(Sighting(ip=ip, mac=mac, source=f"router-arp:{owner}", interface=kv.get("interface", ""),
                             incomplete=not mac or status in ("incomplete", "failed") or "I" in flags))
    for flags, kv in _terse_rows(parts.get("LEASE", "")):
        ip = kv.get("address", "") or kv.get("active-address", "")
        if not _ip(ip) or "X" in flags:
            continue
        mac = norm_mac(kv.get("mac-address", "") or kv.get("active-mac-address", ""))
        rows.append(Sighting(ip=ip, mac=mac, source=f"lease:{owner}",
                             hostname=kv.get("host-name", ""),
                             lease="dynamic" if "D" in flags else "static",
                             lease_expires=kv.get("expires-after", "") or kv.get("status", ""),
                             lease_last_seen=kv.get("last-seen", "")))
    pools = []
    for _flags, kv in _terse_rows(parts.get("POOL", "")):
        pools += _pool_ranges(kv.get("ranges", ""), owner)
    return rows, pools


_ISC_LEASE = re.compile(r"lease\s+([\d.]+)\s*\{(.*?)\}", re.S)


def parse_pfsense_tables(text: str, owner: str, now: datetime | None = None) -> list[Sighting]:
    now = now or datetime.now(timezone.utc)
    parts = _sections(text)
    rows: list[Sighting] = []
    for line in parts.get("ARP", "").splitlines():
        m = re.search(r"\(([\d.]+)\)\s+at\s+(\S+)(?:\s+on\s+(\S+))?", line)
        if not m:
            continue
        mac = norm_mac(m.group(2))
        rows.append(Sighting(ip=m.group(1), mac=mac, source=f"router-arp:{owner}", interface=m.group(3) or "",
                             incomplete="incomplete" in line or not mac,
                             hostname="" if line.startswith("?") else line.split(" ", 1)[0]))
    latest: dict[str, Sighting] = {}
    for m in _ISC_LEASE.finditer(parts.get("LEASE", "")):
        body = m.group(2)
        state = re.search(r"binding state (\w+);", body)
        if state and state.group(1) not in ("active",):
            continue
        mac = re.search(r"hardware ethernet ([0-9a-fA-F:]+);", body)
        host = re.search(r'client-hostname "([^"]*)";', body)
        ends = re.search(r"ends \d+ ([\d/]+ [\d:]+);", body)
        latest[m.group(1)] = Sighting(ip=m.group(1), mac=norm_mac(mac.group(1)) if mac else "",
                                      source=f"lease:{owner}", hostname=host.group(1) if host else "",
                                      lease="dynamic", lease_expires=ends.group(1) if ends else "")
    rows += latest.values()
    kea = parts.get("KEA", "").splitlines()
    if kea and kea[0].startswith("address,"):
        cols = kea[0].split(",")
        for line in kea[1:]:
            vals = line.split(",")
            if len(vals) < len(cols):
                continue
            rec = dict(zip(cols, vals))
            try:
                expire = datetime.fromtimestamp(int(rec.get("expire", "0")), timezone.utc)
            except ValueError:
                expire = None
            if expire is not None and expire < now:
                continue
            latest_k = Sighting(ip=rec.get("address", ""), mac=norm_mac(rec.get("hwaddr", "")),
                                source=f"lease:{owner}", hostname=rec.get("hostname", ""), lease="dynamic",
                                lease_expires=expire.isoformat() if expire else "")
            rows.append(latest_k)
    return rows


def _pool_ranges(text: str, owner: str) -> list[Pool]:
    out = []
    for part in (text or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            try:
                net = ipaddress.IPv4Network(part, strict=False)
            except ValueError:
                continue
            out.append(Pool(net.network_address, net.broadcast_address, owner))
            continue
        lo, _, hi = part.partition("-")
        a, b = _ip(lo), _ip(hi or lo)
        if a and b:
            out.append(Pool(a, b, owner))
    return out


def fetch_router_tables(device: Any) -> tuple[list[Sighting], list[Pool], str]:
    """Live ARP / leases / pools from one topology device over SSH (saved login)."""
    from pfsense_checker.ssh_session import run_ssh_commands  # noqa: PLC0415

    kind = (getattr(device, "kind", "") or "").lower()
    name = getattr(device, "name", "") or "router"
    if kind == "mikrotik":
        res = run_ssh_commands(device, list(MIKROTIK_TABLE_COMMANDS), timeout=20)
        if not res.ok:
            return [], [], res.error or "SSH failed"
        rows, pools = parse_mikrotik_tables(res.output, name)
        return rows, pools, ""
    if kind in FIREWALL_KINDS:
        res = run_ssh_commands(device, list(PFSENSE_TABLE_COMMANDS), timeout=20)
        if not res.ok:
            return [], [], res.error or "SSH failed"
        return parse_pfsense_tables(res.output, name), [], ""
    return [], [], ""


# --------------------------------------------------------------------------- #
# Loaded configs: pools and static mappings
# --------------------------------------------------------------------------- #


def config_dhcp_facts(path: str, owner: str) -> tuple[list[Pool], list[StaticMap]]:
    from pfsense_checker.checker import check_file  # noqa: PLC0415

    try:
        result = check_file(path)
    except Exception:  # noqa: BLE001 - unreadable config: no facts from it
        return [], []
    pools: list[Pool] = []
    statics: list[StaticMap] = []
    if result.source_type == "mikrotik":
        raw = result.summary.get("raw", {})
        for p in raw.get("ip pool", []):
            pools += _pool_ranges(p.get("ranges", ""), owner)
        for lease in raw.get("ip dhcp-server lease", []):
            if lease.get("disabled") == "yes":
                continue
            mac = norm_mac(lease.get("mac-address", ""))
            if _ip(lease.get("address", "")) and mac:
                statics.append(StaticMap(lease["address"], mac, owner))
    else:
        for scope in result.dhcp_scopes:
            if scope.get("family") != "v4":
                continue
            if scope.get("enabled") == "yes":
                a, b = _ip(scope.get("from", "")), _ip(scope.get("to", ""))
                if a and b:
                    pools.append(Pool(a, b, owner))
            for item in (scope.get("staticmap_list") or "").split(";"):
                ip, _, mac = item.partition("|")
                if _ip(ip) and norm_mac(mac):
                    statics.append(StaticMap(ip, norm_mac(mac), owner))
    return pools, statics


# --------------------------------------------------------------------------- #
# Merge, classify, problems
# --------------------------------------------------------------------------- #


def _in(cidr: ipaddress.IPv4Network, ip: str) -> bool:
    addr = _ip(ip)
    return addr is not None and addr in cidr


def merge(cidr: str, sightings: Iterable[Sighting]) -> list[Device]:
    """One device per (MAC, IP); sightings without a MAC fold into the IP's device."""
    net = ipaddress.IPv4Network(cidr, strict=False)
    by_key: dict[tuple[str, str], Device] = {}
    no_mac: list[Sighting] = []
    for s in sightings:
        if not _in(net, s.ip):
            continue
        if not s.mac:
            no_mac.append(s)
            continue
        dev = by_key.setdefault((s.mac, s.ip), Device(ip=s.ip, mac=s.mac))
        _absorb(dev, s)
    for s in no_mac:
        target = next((d for (m, ip), d in by_key.items() if ip == s.ip), None)
        if target is None:
            target = by_key.setdefault(("", s.ip), Device(ip=s.ip))
        _absorb(target, s)
    return sorted(by_key.values(), key=lambda d: (int(ipaddress.IPv4Address(d.ip)), d.mac))


def _absorb(dev: Device, s: Sighting) -> None:
    if s.source not in dev.sources:
        dev.sources.append(s.source)
    dev.hostname = dev.hostname or s.hostname
    dev.vendor = dev.vendor or s.vendor
    dev.os_guess = dev.os_guess or s.os_guess
    for svc in s.services:
        if svc not in dev.services:
            dev.services.append(svc)
    if s.source in ("nmap", "ping", "arp", "local"):  # "arp": this PC's ARP right after the sweep
        dev.answered = True


def _pool_unread(addr: ipaddress.IPv4Address | None, pools: list[Pool], leases_read: set[str]) -> bool:
    return addr is not None and any(addr in p and p.owner not in leases_read for p in pools)


def classify(devices: list[Device], *, gateways: set[str], router_ips: dict[str, str],
             statics: list[StaticMap], leases: list[Sighting], beacons: list[dict],
             pools: list[Pool] = (), leases_read: set[str] = frozenset()) -> None:  # type: ignore[assignment]
    """Connection type per device. *leases_read* names the routers whose lease
    table was read; a pool owned by any other router cannot prove 'Static'."""
    static_mac = {(m.mac, m.ip) for m in statics}
    lease_by = {(norm_mac(s.mac), s.ip): s for s in leases if s.mac}
    beacon_ips: dict[str, str] = {}
    beacon_macs: dict[str, str] = {}
    for b in beacons:
        bid = str(b.get("beacon_id") or "")
        for item in (b.get("meta") or {}).get("accessible_subnets") or []:
            if isinstance(item, dict):
                if item.get("ip"):
                    beacon_ips[str(item["ip"])] = bid
                if norm_mac(str(item.get("mac") or "")):
                    beacon_macs[norm_mac(str(item["mac"]))] = bid
    for d in devices:
        d.known_name = router_ips.get(d.ip, "")
        d.beacon_id = beacon_macs.get(d.mac, "") or beacon_ips.get(d.ip, "")
        lease = lease_by.get((d.mac, d.ip))
        if d.ip in gateways or d.known_name:
            d.conn_type = CONN_ROUTER
        elif is_macvlan_mac(d.mac):
            d.conn_type = CONN_MACVLAN
        elif (d.mac, d.ip) in static_mac or (lease is not None and lease.lease == "static"):
            d.conn_type = CONN_STATIC_DHCP
        elif lease is not None:
            d.conn_type = CONN_DHCP
        elif _pool_unread(_ip(d.ip), list(pools), leases_read):
            d.conn_type = CONN_DHCP_INFERRED
        elif any(src.startswith(("nmap", "ping", "arp", "router-arp", "local")) for src in d.sources):
            d.conn_type = CONN_STATIC
        if lease is not None and lease.hostname and not d.hostname:
            d.hostname = lease.hostname


def find_problems(result: ScanResult, *, sightings: list[Sighting], pools: list[Pool],
                  statics: list[StaticMap], beacons: list[dict], previous_gateway_mac: str = "",
                  now: datetime | None = None) -> list[Problem]:
    now = now or datetime.now(timezone.utc)
    net = ipaddress.IPv4Network(result.cidr, strict=False)
    devs = result.devices
    probs: list[Problem] = []

    def add(sev: str, kind: str, subject: str, detail: str, fix: str = "") -> None:
        probs.append(Problem(sev, kind, subject, detail, fix))

    # Same IP, several MACs
    by_ip: dict[str, set[str]] = defaultdict(set)
    for d in devs:
        if d.mac:
            by_ip[d.ip].add(d.mac)
    for ip, macs in by_ip.items():
        if len(macs) > 1:
            add(SEV_FAIL, "IP clash", ip, f"{len(macs)} devices claim {ip}: {', '.join(sorted(macs))}.",
                "Give one of them another address, or a DHCP reservation.")

    # One MAC on many IPs (routers with aliases are expected)
    by_mac: dict[str, list[Device]] = defaultdict(list)
    for d in devs:
        if d.mac:
            by_mac[d.mac].append(d)
    for mac, group in by_mac.items():
        if len(group) > 1 and not any(g.conn_type == CONN_ROUTER for g in group):
            ips = ", ".join(g.ip for g in group)
            add(SEV_WARN, "One MAC, many IPs", mac, f"{mac} answers on {ips}.",
                "Check for a proxy-ARP device, a bridge, or a host with extra addresses.")

    # Gateway MAC changed since the last scan
    gw = result.gateway
    gw_now = next((d.mac for d in devs if d.ip == gw and d.mac), "")
    if gw and gw_now and previous_gateway_mac and gw_now != previous_gateway_mac:
        add(SEV_FAIL, "Gateway MAC changed", gw,
            f"The gateway {gw} was {previous_gateway_mac}, now {gw_now}.",
            "Expected after replacing the router or a CARP failover; otherwise suspect ARP spoofing.")

    # Static addresses inside a DHCP pool
    local_pools = [p for p in pools if p.start in net]
    for d in devs:
        addr = _ip(d.ip)
        if d.conn_type == CONN_STATIC and addr is not None and any(addr in p for p in local_pools):
            add(SEV_WARN, "Static IP in DHCP pool", d.ip,
                f"{d.ip} ({d.mac or 'no MAC'}) has no lease but sits inside the DHCP pool; "
                "the server can hand the same address to someone else.",
                "Move it outside the pool or make it a DHCP reservation.")
    for m in statics:
        addr = _ip(m.ip)
        if addr is not None and addr in net and any(addr in p for p in local_pools):
            add(SEV_INFO, "Reservation in pool", m.ip,
                f"Reservation {m.ip} for {m.mac} on {m.owner} is inside the dynamic pool.",
                "Usually fine, but reservations outside the pool are clearer.")

    # Wrong subnet: a router interface that serves this subnet also sees an
    # address from a network that interface has no other neighbours in.
    groups: dict[tuple[str, str], list[Sighting]] = defaultdict(list)
    for s in sightings:
        if s.source.startswith("router-arp:") and s.interface:
            groups[(s.source, s.interface)].append(s)
    for (src, iface), group in groups.items():
        inside = [s for s in group if _in(net, s.ip)]
        if len(inside) < 2:
            continue
        nets_seen: dict[str, int] = defaultdict(int)
        for s in group:
            if (a := _ip(s.ip)) is not None:
                nets_seen[str(ipaddress.IPv4Network(f"{a}/24", strict=False))] += 1
        for s in group:
            addr = _ip(s.ip)
            if addr is None or addr in net or addr.is_multicast or addr.is_link_local:
                continue
            if nets_seen[str(ipaddress.IPv4Network(f"{addr}/24", strict=False))] > 1:
                continue  # several neighbours there: a second subnet on the same wire
            add(SEV_WARN, "Wrong subnet", s.ip,
                f"{src.split(':', 1)[-1]} sees {s.ip} ({s.mac or 'no MAC'}) on {iface}, which serves "
                f"{result.cidr}.", "Check that device's address and mask (unless the router has a "
                "second address on that interface).")

    # Incomplete ARP
    for s in sightings:
        if s.incomplete and _in(net, s.ip):
            add(SEV_WARN, "Incomplete ARP", s.ip, f"{s.source.split(':', 1)[-1]} asked for {s.ip} "
                "and got no answer.", "A device left, is off, or is filtering ARP.")

    # Stale leases: lease holder never answered live
    for s in sightings:
        if not s.source.startswith("lease:") or s.lease != "dynamic" or not _in(net, s.ip):
            continue
        dev = next((d for d in devs if d.ip == s.ip and d.mac == s.mac), None)
        ref = (dev.last_seen or dev.first_seen) if dev is not None else None
        if dev is not None and not dev.answered and ref and now - ref > STALE_LEASE_AFTER:
            since = f"since {dev.last_seen:%Y-%m-%d}" if dev.last_seen else f"at all since {ref:%Y-%m-%d}"
            add(SEV_INFO, "Stale lease", s.ip, f"Lease for {s.mac} ({s.hostname or 'no name'}) but the device "
                f"has not answered {since}.", "Release the lease if the device is gone.")

    # Pool exhaustion
    leased = {s.ip for s in sightings if s.source.startswith("lease:") and s.lease == "dynamic"}
    for p in local_pools:
        used = sum(1 for ip in leased if (a := _ip(ip)) is not None and a in p)
        if p.size and used / p.size >= POOL_WARN_RATIO:
            add(SEV_FAIL if used >= p.size else SEV_WARN, "Pool nearly full", f"{p.start}-{p.end}",
                f"{used} of {p.size} addresses leased on {p.owner}.", "Widen the pool or shorten the lease time.")

    # Duplicate hostnames
    by_name: dict[str, set[str]] = defaultdict(set)
    for d in devs:
        if d.hostname and d.mac:
            by_name[d.hostname.lower()].add(d.mac)
    for name, macs in by_name.items():
        if len(macs) > 1:
            add(SEV_WARN, "Duplicate hostname", name, f"{len(macs)} devices call themselves {name}.",
                "Rename one, or DNS / DHCP registration will flap between them.")

    # Random (privacy) MACs
    rnd = [d for d in devs if is_random_mac(d.mac)]
    for d in rnd:
        add(SEV_INFO, "Random MAC", d.ip, f"{d.mac} is a randomised (privacy) address; this device's "
            "age and reservations reset when it changes.", "Turn off private address for this network if it matters.")

    # Beacons
    seen_ips = {d.ip for d in devs if d.answered}
    for b in beacons:
        bid = str(b.get("beacon_id") or "?")
        mine = [i for i in (b.get("meta") or {}).get("accessible_subnets") or []
                if isinstance(i, dict) and _in(net, str(i.get("ip") or ""))]
        if not mine:
            continue
        last = _parse_time(str(b.get("last_seen") or ""))
        offline = str(b.get("status") or "").lower() == "offline" or (last is not None and now - last > BEACON_OFFLINE_AFTER)
        ip = str(mine[0].get("ip"))
        if offline:
            when = f" since {last:%Y-%m-%d %H:%M} UTC" if last else ""
            add(SEV_WARN, "Beacon offline", ip, f"Beacon {bid} ({b.get('hostname') or ip}) has not reported{when}.",
                "Check the beacon's host and its route to the collector.")
        if ip not in seen_ips:
            add(SEV_WARN, "Beacon not seen", ip, f"Beacon {bid} says it is at {ip}, but the scan did not find it.",
                "The host may block probes, or the beacon's address changed.")
    return probs


def _parse_time(text: str) -> datetime | None:
    if not text:
        return None
    try:
        t = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# Device age in PostgreSQL
# --------------------------------------------------------------------------- #


def _connect():  # noqa: ANN202
    from pfsense_checker import postgres_db as pg  # noqa: PLC0415

    return pg.connect()


def previous_gateway_mac(cidr: str, gateway: str, *, connect: Callable = _connect) -> str:
    if not gateway:
        return ""
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT mac FROM subnet_devices WHERE cidr = %s AND ip = %s AND mac <> '' "
            "ORDER BY last_seen DESC LIMIT 1",
            (cidr, gateway),
        )
        row = cur.fetchone()
    return str(row[0]) if row else ""


def record_sightings(result: ScanResult, *, connect: Callable = _connect) -> None:
    """Upsert every device; fills first_seen / last_seen back into the result."""
    if not result.devices:
        return
    with connect() as conn, conn.cursor() as cur:
        for d in result.devices:
            cur.execute(
                "INSERT INTO subnet_devices (cidr, device_key, ip, mac, hostname, vendor, conn_type, "
                "os_guess, sources, beacon_id, answered, last_seen) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CASE WHEN %s THEN NOW() END) "
                "ON CONFLICT (cidr, device_key) DO UPDATE SET ip = EXCLUDED.ip, "
                "hostname = COALESCE(NULLIF(EXCLUDED.hostname, ''), subnet_devices.hostname), "
                "vendor = COALESCE(NULLIF(EXCLUDED.vendor, ''), subnet_devices.vendor), "
                "conn_type = EXCLUDED.conn_type, "
                "os_guess = COALESCE(NULLIF(EXCLUDED.os_guess, ''), subnet_devices.os_guess), "
                "sources = EXCLUDED.sources, beacon_id = EXCLUDED.beacon_id, "
                "answered = EXCLUDED.answered, "
                "last_seen = CASE WHEN EXCLUDED.answered THEN NOW() ELSE subnet_devices.last_seen END, "
                "last_listed = NOW() "
                "RETURNING first_seen, last_seen",
                (result.cidr, d.key, d.ip, d.mac, d.hostname, d.vendor, d.conn_type, d.os_guess,
                 ",".join(d.sources), d.beacon_id, d.answered, d.answered),
            )
            row = cur.fetchone()
            if row:
                d.first_seen, d.last_seen = row[0], row[1]


# --------------------------------------------------------------------------- #
# Whole scan
# --------------------------------------------------------------------------- #


@dataclass
class ScanOptions:
    aggressive: bool = True
    include_firewalls: bool = False
    router_tables: bool = True
    use_db: bool = True


def scan(cidr: str, *, gateway: str = "", site: Any = None, beacons: list[dict] | None = None,
         options: ScanOptions | None = None, progress: Callable[[str], None] | None = None) -> ScanResult:
    opts = options or ScanOptions()
    beacons = beacons or []
    say = progress or (lambda _m: None)
    net = ipaddress.IPv4Network(cidr, strict=False)
    result = ScanResult(cidr=str(net), gateway=gateway)

    devices_in_site = [d for d in (getattr(site, "devices", None) or []) if not getattr(d, "ignored", False)]
    router_ips: dict[str, str] = {}
    firewall_ips: set[str] = set()
    for d in devices_in_site:
        kind = (d.kind or "").lower()
        ip = (getattr(d, "mgmt_ip", "") or (d.ssh.host if getattr(d, "ssh", None) else "") or "").strip()
        if kind in ROUTER_KINDS and ip:
            router_ips[ip] = d.name
        if kind in FIREWALL_KINDS and ip:
            firewall_ips.add(ip)
        for comp in getattr(d, "components", []) or []:
            addr = (getattr(comp, "address", "") or "").split("/")[0]
            if kind in ROUTER_KINDS and _ip(addr):
                router_ips.setdefault(addr, d.name)
                if kind in FIREWALL_KINDS:
                    firewall_ips.add(addr)

    sightings: list[Sighting] = []
    exclude = set() if opts.include_firewalls else {ip for ip in firewall_ips if _in(net, ip)}
    if nmap_path():
        say(f"nmap {'-sV -O' if opts.aggressive else '-sn'} {cidr}")
        rows, err = run_nmap(str(net), aggressive=opts.aggressive, exclude=exclude)
        result.engine = "nmap"
        if err:
            result.notes.append(f"nmap: {err}")
        sightings += rows
    else:
        say(f"ping sweep {cidr} (nmap not installed)")
        result.engine = "ping sweep"
        result.notes.append("nmap is not installed: using a ping sweep and the ARP table. Install Nmap "
                            "from nmap.org for OS / service detection.")
        sightings += ping_sweep(str(net))
    sightings += local_sightings(net)
    if exclude:
        result.notes.append(f"Firewalls not probed (sshguard): {', '.join(sorted(exclude))}.")
        for ip in exclude:
            sightings.append(Sighting(ip=ip, source="topology", hostname=router_ips.get(ip, "")))

    pools: list[Pool] = []
    statics: list[StaticMap] = []
    leases: list[Sighting] = []
    leases_read: set[str] = set()
    unread: dict[str, list[str]] = defaultdict(list)
    if opts.router_tables:
        for d in devices_in_site:
            kind = (d.kind or "").lower()
            if kind not in ROUTER_KINDS or (kind in FIREWALL_KINDS and not opts.include_firewalls):
                continue
            ssh = getattr(d, "ssh", None)
            if ssh is None or not (ssh.username or "").strip():
                continue
            if not _router_serves(d, net):
                continue
            say(f"ARP / DHCP tables from {d.name}")
            rows, more_pools, err = fetch_router_tables(d)
            if err:
                unread[err].append(d.name)
            else:
                leases_read.add(d.name)
            sightings += rows
            pools += more_pools
            leases += [r for r in rows if r.source.startswith("lease:")]
    for err, names in unread.items():
        result.notes.append(f"Router tables not read from {', '.join(names)}: {err}.")
    for d in devices_in_site:
        src = d.ensure_config_source() if hasattr(d, "ensure_config_source") else None

        path = (src.analyzable_path() if src is not None else "") or getattr(d, "config_file", "") or ""
        if path and Path(path).is_file():
            p, s = config_dhcp_facts(path, d.name)
            pools += p
            statics += s

    for b in beacons:
        bid = str(b.get("beacon_id") or "?")
        for item in (b.get("meta") or {}).get("accessible_subnets") or []:
            if isinstance(item, dict) and _in(net, str(item.get("ip") or "")):
                sightings.append(Sighting(ip=str(item["ip"]), mac=norm_mac(str(item.get("mac") or "")),
                                          source=f"beacon:{bid}", hostname=str(b.get("hostname") or "")))

    result.devices = merge(str(net), sightings)
    _fill_vendors(result.devices)
    pools = _dedupe_pools(pools)
    classify(result.devices, gateways={gateway} if gateway else set(), router_ips=router_ips,
             statics=statics, leases=leases, beacons=beacons, pools=pools, leases_read=leases_read)

    prev_gw = ""
    if opts.use_db:
        try:
            prev_gw = previous_gateway_mac(result.cidr, gateway)
            record_sightings(result)
        except Exception as exc:  # noqa: BLE001 - scan still useful without the database
            result.notes.append(f"Device age not recorded: {type(exc).__name__}: {exc}")
    result.problems = find_problems(result, sightings=sightings, pools=pools, statics=statics,
                                    beacons=beacons, previous_gateway_mac=prev_gw)
    order = {SEV_FAIL: 0, SEV_WARN: 1, SEV_INFO: 2}
    result.problems.sort(key=lambda p: (order.get(p.severity, 3), p.kind, p.subject))
    return result


def _fill_vendors(devices: list[Device]) -> None:
    """Vendor from the OUI lookup (cached; online only when an API key is saved)."""
    try:
        from pfsense_checker import oui  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return
    for d in devices:
        if d.vendor or not d.mac or is_locally_administered(d.mac):
            continue
        try:
            d.vendor = oui.lookup_vendor(d.mac, timeout=4) or ""
        except Exception:  # noqa: BLE001 - lookup failures leave the column blank
            continue


def _dedupe_pools(pools: list[Pool]) -> list[Pool]:
    seen: dict[tuple[int, int], Pool] = {}
    for p in pools:
        seen.setdefault((int(p.start), int(p.end)), p)
    return list(seen.values())


def _router_serves(device: Any, net: ipaddress.IPv4Network) -> bool:
    """True when the router has an address in *net*, or we cannot tell."""
    addrs = []
    for comp in getattr(device, "components", []) or []:
        text = (getattr(comp, "address", "") or "").split("/")[0]
        if _ip(text):
            addrs.append(_ip(text))
    mgmt = _ip(getattr(device, "mgmt_ip", "") or "")
    if mgmt:
        addrs.append(mgmt)
    return not addrs or any(a in net for a in addrs if a is not None)


def age_text(first: datetime | None, now: datetime | None = None) -> str:
    if first is None:
        return ""
    now = now or datetime.now(timezone.utc)
    delta = now - first
    if delta < timedelta(hours=1):
        return "new"
    if delta < timedelta(days=1):
        return f"{int(delta.total_seconds() // 3600)} h"
    if delta < timedelta(days=60):
        return f"{delta.days} d"
    return f"{delta.days // 30} mo"
