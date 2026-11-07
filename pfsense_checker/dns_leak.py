"""NetCheck DNS leak test — standard library only.

Runs inside the DNS Leakage test package (copied there as-is) and inside
NetCheck ("Run on this PC"). It answers: where do this machine's DNS queries
really go?

Checks
------
* Resolvers the operating system uses (IPv4 and IPv6) against the expected
  resolver for this VLAN.
* The expected resolver answers.
* Plain DNS (UDP and TCP port 53) to public resolvers: blocked, redirected to
  your resolver, or straight out to the Internet (a leak path for devices with
  hard-coded DNS).
* DNS-over-TLS (853) and DNS-over-HTTPS reachability (encrypted bypass).
* The Firefox DoH canary domain (use-application-dns.net).
* Which public address DNS leaves from (whoami.akamai.net), optionally against
  the expected egress (for example a VPN).

Usage::

    python dns_leak.py                       # uses dnsleak.json next to this file
    python dns_leak.py --expected 192.168.1.1 --label "LAN"
    python dns_leak.py --out results --json
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import ipaddress
import json
import os
import platform
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

VERSION = "1.0"
TOOL = "netcheck-dns-leak"

PUBLIC_V4 = {"Cloudflare": "1.1.1.1", "Google": "8.8.8.8", "Quad9": "9.9.9.9"}
PUBLIC_V6 = {"Cloudflare": "2606:4700:4700::1111", "Google": "2001:4860:4860::8888"}
DOT = {"Cloudflare": ("1.1.1.1", "cloudflare-dns.com"), "Google": ("8.8.8.8", "dns.google"),
       "Quad9": ("9.9.9.9", "dns.quad9.net")}
DOH = {"Cloudflare": "https://cloudflare-dns.com/dns-query", "Google": "https://dns.google/resolve"}
CANARY = "use-application-dns.net"
WHOAMI = "whoami.akamai.net"  # A record = address of the resolver that asked Akamai
TEST_NAME = "example.com"

PASS, WARN, FAIL, INFO, SKIP = "pass", "warn", "fail", "info", "skip"

T_A, T_AAAA, T_TXT, T_CNAME = 1, 28, 16, 5
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


# --------------------------------------------------------------------------- #
# DNS wire format
# --------------------------------------------------------------------------- #


@dataclasses.dataclass
class Answer:
    rcode: int = 0
    records: list = dataclasses.field(default_factory=list)  # [(type, value)]
    via: str = ""

    @property
    def rcode_name(self) -> str:
        return RCODES.get(self.rcode, str(self.rcode))

    def values(self, rtype: int = T_A) -> list[str]:
        return [v for t, v in self.records if t == rtype]


def build_query(name: str, qtype: int = T_A, txid: int | None = None) -> tuple[int, bytes]:
    txid = random.randint(0, 0xFFFF) if txid is None else txid
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # recursion desired
    qname = b"".join(bytes([len(p)]) + p.encode("idna") for p in name.strip(".").split(".") if p) + b"\0"
    return txid, header + qname + struct.pack(">HH", qtype, 1)


def _read_name(data: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    labels: list[str] = []
    while True:
        if pos >= len(data) or depth > 20:
            raise ValueError("bad name")
        n = data[pos]
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", data[pos:pos + 2])[0] & 0x3FFF
            rest, _ = _read_name(data, ptr, depth + 1)
            if rest:
                labels.append(rest)
            return ".".join(labels), pos + 2
        if n == 0:
            return ".".join(labels), pos + 1
        labels.append(data[pos + 1:pos + 1 + n].decode("ascii", "replace"))
        pos += 1 + n


def parse_response(data: bytes, txid: int | None = None) -> Answer:
    if len(data) < 12:
        raise ValueError("short DNS response")
    rid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if txid is not None and rid != txid:
        raise ValueError("DNS transaction id mismatch")
    ans = Answer(rcode=flags & 0x0F)
    pos = 12
    for _ in range(qd):
        _, pos = _read_name(data, pos)
        pos += 4
    for _ in range(an):
        _, pos = _read_name(data, pos)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        rdata = data[pos:pos + rdlen]
        if rtype == T_A and rdlen == 4:
            ans.records.append((T_A, socket.inet_ntoa(rdata)))
        elif rtype == T_AAAA and rdlen == 16:
            ans.records.append((T_AAAA, socket.inet_ntop(socket.AF_INET6, rdata)))
        elif rtype == T_TXT:
            parts, i = [], 0
            while i < len(rdata):
                ln = rdata[i]
                parts.append(rdata[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                i += 1 + ln
            ans.records.append((T_TXT, "".join(parts)))
        elif rtype == T_CNAME:
            ans.records.append((T_CNAME, _read_name(data, pos)[0]))
        pos += rdlen
    return ans


def _family(server: str) -> int:
    return socket.AF_INET6 if ":" in server else socket.AF_INET


def query_udp(server: str, name: str, qtype: int = T_A, timeout: float = 2.0) -> Answer:
    txid, q = build_query(name, qtype)
    with socket.socket(_family(server), socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(q, (server, 53))
        while True:
            data, _addr = s.recvfrom(4096)
            try:
                ans = parse_response(data, txid)
            except ValueError:
                continue
            ans.via = f"udp {server}"
            return ans


def _tcp_exchange(sock, q: bytes, txid: int) -> Answer:
    sock.sendall(struct.pack(">H", len(q)) + q)
    head = _recv_exact(sock, 2)
    return parse_response(_recv_exact(sock, struct.unpack(">H", head)[0]), txid)


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def query_tcp(server: str, name: str, qtype: int = T_A, timeout: float = 3.0) -> Answer:
    txid, q = build_query(name, qtype)
    with socket.create_connection((server, 53), timeout=timeout) as s:
        ans = _tcp_exchange(s, q, txid)
    ans.via = f"tcp {server}"
    return ans


def query_dot(server: str, hostname: str, name: str, qtype: int = T_A, timeout: float = 4.0) -> Answer:
    txid, q = build_query(name, qtype)
    ctx = ssl.create_default_context()
    with socket.create_connection((server, 853), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=hostname) as s:
            ans = _tcp_exchange(s, q, txid)
    ans.via = f"dot {hostname}"
    return ans


def query_doh(url: str, name: str, qtype: int = T_A, timeout: float = 5.0) -> Answer:
    full = f"{url}?{urllib.parse.urlencode({'name': name, 'type': qtype})}"
    req = urllib.request.Request(full, headers={"Accept": "application/dns-json",
                                                "User-Agent": f"{TOOL}/{VERSION}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed public endpoints
        payload = json.loads(resp.read(65536).decode("utf-8"))
    ans = Answer(rcode=int(payload.get("Status", 0)), via=f"doh {urllib.parse.urlparse(url).hostname}")
    for rec in payload.get("Answer", []) or []:
        rtype = int(rec.get("type", 0))
        ans.records.append((rtype, str(rec.get("data", "")).strip('"')))
    return ans


# --------------------------------------------------------------------------- #
# This machine
# --------------------------------------------------------------------------- #


def _run(cmd: list[str], timeout: float = 10) -> str:
    flags = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=flags, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.decode("utf-8", "replace")


def _valid_ip(text: str) -> str:
    text = text.strip().split("%")[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def system_resolvers() -> list[str]:
    """DNS servers configured on the interfaces that are up."""
    found: list[str] = []
    system = platform.system()
    if system == "Windows":
        ps = ("Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' } | "
              "ForEach-Object { $_.DNSServer.ServerAddresses } | ConvertTo-Json -Compress")
        raw = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps])
        try:
            data = json.loads(raw) if raw.strip() else []
        except json.JSONDecodeError:
            data = []
        if isinstance(data, str):
            data = [data]
        found = [_valid_ip(str(x)) for x in data]
    elif system == "Darwin":
        found = [_valid_ip(m) for m in re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", _run(["scutil", "--dns"]))]
    else:
        text = _run(["resolvectl", "dns"])
        found = [_valid_ip(x) for line in text.splitlines() for x in line.split(":", 1)[-1].split()]
        try:
            conf = Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="replace")
            found += [_valid_ip(m) for m in re.findall(r"^\s*nameserver\s+(\S+)", conf, re.M)]
        except OSError:
            pass
    out: list[str] = []
    for ip in found:
        if ip and ip not in out and not ip.startswith("127.0.0.53") and ip not in WINDOWS_PLACEHOLDERS:
            out.append(ip)
    return out


# Windows lists these deprecated site-local addresses as IPv6 DNS servers when
# nothing real is configured; they are not servers and not a leak.
WINDOWS_PLACEHOLDERS = frozenset({"fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3"})


def local_addresses() -> list[str]:
    addrs: list[str] = []
    for target, fam in (("192.0.2.1", socket.AF_INET), ("2001:db8::1", socket.AF_INET6)):
        try:
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.connect((target, 9))  # no packet is sent
                addrs.append(s.getsockname()[0])
        except OSError:
            pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = _valid_ip(info[4][0])
            if ip and ip not in addrs and not ip.startswith(("127.", "::1", "fe80")):
                addrs.append(ip)
    except OSError:
        pass
    return addrs


def pick_profile(profiles: list[dict], addrs: list[str]) -> dict:
    """The VLAN profile whose subnet holds one of this machine's addresses."""
    for prof in profiles:
        try:
            net = ipaddress.ip_network(prof.get("subnet", ""), strict=False)
        except ValueError:
            continue
        for a in addrs:
            try:
                if ipaddress.ip_address(a) in net:
                    return prof
            except ValueError:
                continue
    return {}


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #


@dataclasses.dataclass
class Check:
    id: str
    title: str
    status: str
    detail: str
    fix: str = ""


def _egress(server: str, timeout: float) -> str:
    try:
        vals = query_udp(server, WHOAMI, T_A, timeout).values(T_A)
    except (OSError, ValueError):
        return ""
    return vals[0] if vals else ""


def _err(exc: BaseException) -> str:
    text = str(exc) or exc.__class__.__name__
    return "timed out" if isinstance(exc, (socket.timeout, TimeoutError)) else text


def run_checks(expected: list[str], *, expected_egress: list[str] | None = None,
               timeout: float = 2.0, public: bool = True, ipv6: bool = True,
               resolvers: list[str] | None = None) -> list[Check]:
    checks: list[Check] = []
    expected = [e for e in (_valid_ip(x) for x in expected) if e]
    resolvers = system_resolvers() if resolvers is None else resolvers

    # 1. What the OS uses
    v4 = [r for r in resolvers if ":" not in r]
    v6 = [r for r in resolvers if ":" in r]
    if not resolvers:
        checks.append(Check("system", "Resolvers this machine uses", WARN,
                            "Could not read the DNS servers from the operating system."))
    elif expected:
        odd4 = [r for r in v4 if r not in expected]
        checks.append(Check(
            "system", "Resolvers this machine uses (IPv4)",
            FAIL if odd4 else PASS,
            f"Uses {', '.join(v4) or 'none'}; expected {', '.join(expected)}."
            + (f" {', '.join(odd4)} {'is' if len(odd4) == 1 else 'are'} not your resolver." if odd4 else ""),
            "Hand out only your resolver in DHCP (DNS servers) and remove static DNS on this "
            "machine." if odd4 else ""))
        if v6:
            odd6 = [r for r in v6 if r not in expected]
            checks.append(Check(
                "system6", "Resolvers this machine uses (IPv6)",
                FAIL if odd6 else PASS,
                f"IPv6 DNS servers: {', '.join(v6)}."
                + (" These bypass your IPv4 resolver — usually handed out by router "
                   "advertisements (RDNSS) or DHCPv6." if odd6 else ""),
                "Advertise your own resolver in RA / DHCPv6, or turn off IPv6 DNS on this "
                "VLAN." if odd6 else ""))
    else:
        checks.append(Check("system", "Resolvers this machine uses", INFO,
                            f"Uses {', '.join(resolvers)} (no expected resolver set for this VLAN)."))

    # 2. Expected resolver answers
    exp_egress = ""
    for e in expected:
        try:
            ans = query_udp(e, TEST_NAME, T_A, timeout)
            ok = ans.rcode == 0 and ans.values(T_A)
            checks.append(Check(f"expected:{e}", f"Your resolver {e} answers",
                                PASS if ok else FAIL, f"{TEST_NAME}: {ans.rcode_name} "
                                f"{', '.join(ans.values(T_A))}".strip()))
            exp_egress = exp_egress or _egress(e, timeout)
        except (OSError, ValueError) as exc:
            checks.append(Check(f"expected:{e}", f"Your resolver {e} answers", FAIL,
                                f"No answer: {_err(exc)}.",
                                "Check the resolver is enabled on this interface and the firewall "
                                "passes DNS to it."))
    sys_egress = ""
    for r in resolvers:
        sys_egress = _egress(r, timeout)
        if sys_egress:
            break

    # 3. Egress
    egress = exp_egress or sys_egress
    if egress:
        want = [x for x in (expected_egress or []) if x]
        status = INFO
        detail = f"DNS from here reaches the Internet from {egress} (whoami.akamai.net)."
        if want:
            status = PASS if egress in want else FAIL
            if status == FAIL:
                detail += f" Expected {', '.join(want)}: DNS is leaving outside the intended path (VPN?)."
        checks.append(Check("egress", "Where DNS leaves from", status, detail,
                            "Route the resolver's outbound queries through the intended "
                            "gateway / VPN." if status == FAIL else ""))
    else:
        checks.append(Check("egress", "Where DNS leaves from", SKIP,
                            "whoami.akamai.net did not answer through your resolver."))

    if not public:
        return checks

    # 4. Plain DNS straight to public resolvers
    def direct(fam: str, name: str, server: str, proto: str) -> None:
        cid = f"direct-{proto}:{server}"
        title = f"Plain DNS ({proto.upper()}/53) to {name} {server}"
        try:
            ans = (query_udp if proto == "udp" else query_tcp)(server, TEST_NAME, T_A, timeout)
        except (OSError, ValueError) as exc:
            checks.append(Check(cid, title, PASS, f"Blocked ({_err(exc)}).", ""))
            return
        if not (ans.rcode == 0 and ans.values(T_A)):
            checks.append(Check(cid, title, PASS, f"Answered {ans.rcode_name} with no address — "
                                "filtered.", ""))
            return
        via = _egress(server, timeout) if proto == "udp" else ""
        if via and egress and via == egress:
            checks.append(Check(cid, title, PASS,
                                f"Answered, but by your own resolver path (egress {via}): port 53 is "
                                "redirected to your resolver.", ""))
            return
        checks.append(Check(
            cid, title, FAIL,
            f"Answered directly{f' (egress {via})' if via else ''}: devices with a hard-coded "
            "DNS server bypass your resolver and its filtering.",
            "Block outbound port 53 (TCP and UDP) from this VLAN except to your resolver, or add "
            "a NAT port forward that redirects port 53 to it."))

    for name, server in PUBLIC_V4.items():
        direct("v4", name, server, "udp")
    direct("v4", "Cloudflare", PUBLIC_V4["Cloudflare"], "tcp")
    has_v6 = any(":" in a and not a.startswith("fe80") for a in local_addresses())
    if ipv6 and has_v6:
        for name, server in PUBLIC_V6.items():
            direct("v6", name, server, "udp")
    elif ipv6:
        checks.append(Check("direct-v6", "Plain DNS over IPv6", SKIP, "This machine has no global IPv6 address."))

    # 5. DNS-over-TLS
    for name, (server, host) in DOT.items():
        cid = f"dot:{server}"
        title = f"DNS-over-TLS (853) to {name}"
        try:
            ans = query_dot(server, host, TEST_NAME, T_A, timeout + 2)
            ok = ans.rcode == 0 and bool(ans.values(T_A))
            checks.append(Check(cid, title, WARN if ok else PASS,
                                "Reachable: encrypted DNS can bypass your resolver." if ok
                                else f"Connected but answered {ans.rcode_name}.",
                                "Block outbound TCP 853 from this VLAN unless clients are meant to use "
                                "DoT." if ok else ""))
        except (OSError, ValueError, ssl.SSLError) as exc:
            checks.append(Check(cid, title, PASS, f"Blocked ({_err(exc)})."))

    # 6. DNS-over-HTTPS
    for name, url in DOH.items():
        cid = f"doh:{name.lower()}"
        title = f"DNS-over-HTTPS to {name}"
        try:
            ans = query_doh(url, TEST_NAME, T_A, timeout + 3)
            ok = ans.rcode == 0 and bool(ans.values(T_A))
            checks.append(Check(cid, title, WARN if ok else PASS,
                                "Reachable: browsers and apps can resolve over HTTPS and bypass your "
                                "resolver." if ok else f"Answered {ans.rcode_name}.",
                                "Block known DoH servers (pfBlockerNG → DNSBL → DoH/DoT/DoQ blocking), "
                                "and answer the Firefox canary with NXDOMAIN." if ok else ""))
        except Exception as exc:  # noqa: BLE001 - network, TLS, JSON
            checks.append(Check(cid, title, PASS, f"Blocked ({_err(exc)})."))

    # 7. Firefox canary
    try:
        infos = socket.getaddrinfo(CANARY, None)
        addrs = sorted({i[4][0] for i in infos})
        checks.append(Check("canary", f"Firefox DoH canary ({CANARY})", WARN,
                            f"Resolves ({', '.join(addrs)}): Firefox may switch itself to DoH and "
                            "bypass your resolver.",
                            "Make your resolver answer NXDOMAIN for use-application-dns.net "
                            "(pfBlockerNG / Unbound local zone)."))
    except socket.gaierror:
        checks.append(Check("canary", f"Firefox DoH canary ({CANARY})", PASS,
                            "NXDOMAIN: Firefox keeps using the system resolver."))
    return checks


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


def run(config: dict, *, resolvers: list[str] | None = None) -> dict:
    addrs = local_addresses()
    profile = pick_profile(config.get("profiles", []), addrs)
    expected = list(config.get("expected_resolvers") or profile.get("expected_resolvers") or [])
    label = config.get("label") or profile.get("label") or "unknown VLAN"
    started = _dt.datetime.now(_dt.timezone.utc)
    resolvers = system_resolvers() if resolvers is None else resolvers
    checks = run_checks(
        expected,
        expected_egress=config.get("expected_egress") or profile.get("expected_egress") or [],
        timeout=float(config.get("timeout", 2.0)),
        public=bool(config.get("public", True)),
        ipv6=bool(config.get("ipv6", True)),
        resolvers=resolvers,
    )
    worst = FAIL if any(c.status == FAIL for c in checks) else WARN if any(
        c.status == WARN for c in checks) else PASS
    return {
        "tool": TOOL,
        "version": VERSION,
        "site": config.get("site", ""),
        "host": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "label": label,
        "subnet": profile.get("subnet", ""),
        "addresses": addrs,
        "expected_resolvers": expected,
        "resolvers": resolvers,
        "started": started.isoformat(timespec="seconds"),
        "seconds": round((_dt.datetime.now(_dt.timezone.utc) - started).total_seconds(), 1),
        "result": worst,
        "checks": [dataclasses.asdict(c) for c in checks],
    }


def summary_text(report: dict) -> str:
    mark = {PASS: "OK  ", WARN: "WARN", FAIL: "FAIL", INFO: "info", SKIP: "skip"}
    lines = [
        f"NetCheck DNS leak test {report.get('version')} — {report.get('host')} "
        f"({', '.join(report.get('addresses', []))})",
        f"VLAN: {report.get('label')} {report.get('subnet', '')}".rstrip(),
        f"Result: {str(report.get('result', '')).upper()}",
        "",
    ]
    for c in report.get("checks", []):
        lines.append(f"[{mark.get(c['status'], c['status'])}] {c['title']}: {c['detail']}")
        if c.get("fix"):
            lines.append(f"       Fix: {c['fix']}")
    return "\n".join(lines)


def _safe(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_")[:60] or "x"


def save_report(report: dict, folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = folder / f"dnsleak_{_safe(report.get('label', ''))}_{_safe(report.get('host', ''))}_{stamp}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent
    for stream in (sys.stdout, sys.stderr):
        try:  # Windows consoles are often cp1252: never die on a dash or arrow
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="NetCheck DNS leak test")
    ap.add_argument("--config", default=str(here / "dnsleak.json"))
    ap.add_argument("--expected", action="append", default=[], help="expected resolver IP (repeat)")
    ap.add_argument("--label", default="")
    ap.add_argument("--out", default=str(here / "results"))
    ap.add_argument("--json", action="store_true", help="print the JSON report")
    ap.add_argument("--no-public", action="store_true", help="skip tests that contact public resolvers")
    args = ap.parse_args(argv)
    config: dict = {}
    if Path(args.config).is_file():
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    if args.expected:
        config["expected_resolvers"] = args.expected
    if args.label:
        config["label"] = args.label
    if args.no_public:
        config["public"] = False
    report = run(config)
    path = save_report(report, Path(args.out))
    print(json.dumps(report, indent=2) if args.json else summary_text(report))
    print(f"\nReport saved: {path}")
    print("Copy the report back and open it on NetCheck's DNS Leakage page.")
    return 1 if report["result"] == FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
