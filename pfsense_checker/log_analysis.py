"""Log file analysis (Logs → Log Analysis): drop router log files in, get a summary.

Reads pfSense / OPNsense logs (filter, system, auth / sshguard, dhcpd, openvpn,
gateways), MikroTik logs (as downloaded by device_logs.py or copied from the
router) and plain syslog text, plain or .gz / .bz2. Each line is parsed into
time, host, service and message; a set of analyses then picks out what an
operator wants to know first — failed and blocked logins, what the firewall
blocks most, link flaps, Wi-Fi clients that will not stay connected, DHCP and
VPN trouble, reboots, and errors by service — each with the lines behind it.

Everything stays on this PC. Qt-free. (added 2026-11-15)
"""

from __future__ import annotations

import bz2
import gzip
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

MAX_FILE_BYTES = 80 * 1024 * 1024
MAX_LINES = 600_000  # kept for drill-down; more than this is counted but not kept
MAX_FINDING_LINES = 400  # lines kept behind one finding
LOG_SUFFIXES = {".log", ".txt", ".gz", ".bz2", ""}

ERROR, WARN, INFO = "error", "warn", "info"

_MONTHS = {m: i + 1 for i, m in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"))}

# "Nov 15 19:08:48 guardian sshd[123]: message"
_RFC3164 = re.compile(r"^(?:<\d+>)?([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\s:\[]+)(?:\[(\d+)\])?:\s?(.*)$")
# "2026-11-15T19:08:48.386741+00:00 guardian filterlog 12345 - - message"
_RFC5424 = re.compile(r"^(?:<\d+>\d?\s*)?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S*\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+(?:\[.*?\]|-)\s?(.*)$")
# MikroTik: "2026-11-09 14:03:07 caps,debug message" / "nov/09 14:03:07 topics message" / "14:03:07 topics message"
_ROS = re.compile(r"^\s*(?:\d+\s+)?(?:(\d{4}-\d{2}-\d{2})\s+|([a-z]{3})/(\d{2})(?:/(\d{4}))?\s+)?(\d{2}:\d{2}:\d{2})\s+([a-z][a-z0-9,!-]*)\s+(.*)$")
_IP = r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+)"
_MAC = r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"


@dataclass
class LogLine:
    file: str
    lineno: int
    when: datetime | None
    host: str
    service: str  # sshd, filterlog, dhcpd… or the MikroTik topic group (caps, system, interface…)
    message: str
    raw: str
    vendor: str = ""  # "pfsense" (syslog form) / "mikrotik" / ""
    topics: str = ""  # MikroTik: the full topic list


@dataclass
class Finding:
    area: str  # Logins, Firewall, Links, Wireless, DHCP, VPN, Gateways, System, Errors
    title: str
    severity: str = INFO
    count: int = 0
    detail: str = ""
    table: list[tuple[str, int]] = field(default_factory=list)  # (what, how many), most first
    lines: list[int] = field(default_factory=list)  # indexes into Analysis.lines
    notes: list[str] = field(default_factory=list)  # text shown before the lines (config findings have no lines)


@dataclass
class Analysis:
    files: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # files left out, with why
    total_lines: int = 0
    parsed_lines: int = 0
    kept_lines: int = 0
    first: datetime | None = None
    last: datetime | None = None
    services: Counter = field(default_factory=Counter)
    hosts: Counter = field(default_factory=Counter)
    lines: list[LogLine] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def by_area(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.area, []).append(f)
        return out

    def summary(self) -> str:
        if not self.total_lines:
            return "No log lines found."
        span = ""
        if self.first and self.last:
            span = f" from {self.first:%Y-%m-%d %H:%M} to {self.last:%Y-%m-%d %H:%M}"
        worst = sum(1 for f in self.findings if f.severity == ERROR)
        warn = sum(1 for f in self.findings if f.severity == WARN)
        return (f"{len(self.files)} file(s), {self.total_lines:,} lines{span}. "
                f"{worst} problem(s), {warn} warning(s), {len(self.findings) - worst - warn} note(s).")


# --------------------------------------------------------------------------- #
# Reading


def parse_line(raw: str, *, file: str = "", lineno: int = 0, year: int | None = None,
               day: datetime | None = None) -> LogLine:
    """One log line → LogLine. *year* fills in syslog dates (they have none);
    *day* fills in MikroTik lines that only carry a time."""
    text = raw.rstrip("\r\n")
    m = _RFC5424.match(text)
    if m:
        try:
            when = datetime.fromisoformat(m.group(1))
        except ValueError:
            when = None
        return LogLine(file, lineno, when, m.group(2), m.group(3).lower(), m.group(5), text, "pfsense")
    m = _RFC3164.match(text)
    if m:
        mon, dom, clock, host, proc, _pid, msg = m.groups()
        when = None
        try:
            h, mi, s = (int(x) for x in clock.split(":"))
            when = datetime(year or datetime.now().year, _MONTHS[mon.lower()], int(dom), h, mi, s)
        except (KeyError, ValueError):
            when = None
        return LogLine(file, lineno, when, host, proc.lower(), msg, text, "pfsense")
    m = _ROS.match(text)
    if m:
        iso, mon, dom, yr, clock, topics, msg = m.groups()
        when = None
        try:
            h, mi, s = (int(x) for x in clock.split(":"))
            if iso:
                y, mo, d = (int(x) for x in iso.split("-"))
                when = datetime(y, mo, d, h, mi, s)
            elif mon:
                when = datetime(int(yr) if yr else (year or datetime.now().year), _MONTHS[mon], int(dom), h, mi, s)
            elif day is not None:
                when = datetime(day.year, day.month, day.day, h, mi, s)
        except (KeyError, ValueError):
            when = None
        return LogLine(file, lineno, when, "", topics.split(",")[0], msg, text, "mikrotik", topics)
    return LogLine(file, lineno, None, "", "", text, text)


def _open_text(path: Path):  # noqa: ANN202
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".bz2":
        return bz2.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def expand_paths(paths: list[Path]) -> list[Path]:
    """Files to read: the files given, and every log-looking file under the folders given."""
    out: list[Path] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            out += sorted(f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in LOG_SUFFIXES
                          and f.name not in ("state.json", "settings.json"))
        elif p.is_file():
            out.append(p)
    seen: set[Path] = set()
    return [f for f in out if not (f in seen or seen.add(f))]


_DAY_IN_PATH = re.compile(r"(\d{4})-(\d{2})-(\d{2})")


def read_files(paths: list[Path]) -> Analysis:
    """Parse every line of every file (no findings yet)."""
    a = Analysis()
    for path in expand_paths(paths):
        try:
            size = path.stat().st_size
        except OSError as exc:
            a.skipped.append(f"{path.name}: {exc}")
            continue
        if size > MAX_FILE_BYTES:
            a.skipped.append(f"{path.name}: larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
            continue
        year = datetime.fromtimestamp(path.stat().st_mtime).year
        m = _DAY_IN_PATH.search(str(path.parent))  # device_logs keeps a folder per day
        day = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None
        device = path.parent.parent.name if m else ""
        try:
            with _open_text(path) as fh:
                for n, raw in enumerate(fh, 1):
                    if not raw.strip():
                        continue
                    a.total_lines += 1
                    line = parse_line(raw, file=path.name, lineno=n, year=day.year if day else year, day=day)
                    if not line.host and device:
                        line.host = device  # MikroTik lines carry no host: the device's folder does
                    if line.service:
                        a.parsed_lines += 1
                        a.services[line.service] += 1
                    if line.host:
                        a.hosts[line.host] += 1
                    if line.when is not None:
                        a.first = line.when if a.first is None or line.when < a.first else a.first
                        a.last = line.when if a.last is None or line.when > a.last else a.last
                    if len(a.lines) < MAX_LINES:
                        a.lines.append(line)
        except (OSError, EOFError) as exc:
            a.skipped.append(f"{path.name}: {exc}")
            continue
        a.files.append(str(path))
    a.kept_lines = len(a.lines)
    return a


# --------------------------------------------------------------------------- #
# Analyses


class _Bucket:
    """Collects matching lines and a tally for one finding."""

    def __init__(self) -> None:
        self.count = 0
        self.lines: list[int] = []
        self.tally: Counter = Counter()

    def add(self, idx: int, key: str = "") -> None:
        self.count += 1
        if len(self.lines) < MAX_FINDING_LINES:
            self.lines.append(idx)
        if key:
            self.tally[key] += 1

    def finding(self, area: str, title: str, severity: str, detail: str = "", top: int = 12) -> Finding:
        return Finding(area, title, severity, self.count, detail, self.tally.most_common(top), list(self.lines))


_FAILED_LOGIN = re.compile(
    r"(?:Failed (?:password|publickey|keyboard-interactive\S*) for (?:invalid user )?(\S+) from " + _IP
    + r"|Invalid user (\S*) from " + _IP
    + r"|authentication error for (?:user )?'?([^' ]+)'? from:? " + _IP
    + r"|login failure for user (\S+) from (\S+)"
    + r"|maximum authentication attempts exceeded for (?:invalid user )?(\S+) from " + _IP
    + r"|Connection closed by authenticating user (\S+) " + _IP + r")", re.IGNORECASE)
_GOOD_LOGIN = re.compile(
    r"(?:Accepted (\S+) for (\S+) from " + _IP
    + r"|Successful login for user '([^']+)' from:? " + _IP
    + r"|user (\S+) logged in from (\S+) via (\S+))", re.IGNORECASE)
_SSHGUARD_ATTACK = re.compile(r'Attack from "?' + _IP + r'"? on service (\S+)', re.IGNORECASE)
_SSHGUARD_BLOCK = re.compile(r'Blocking "?' + _IP + r'(?:/\d+)?"? for (\d+) secs', re.IGNORECASE)
_DENIED_CONNECT = re.compile(r"denied (\S+) connect from (\S+)", re.IGNORECASE)
_LINK = re.compile(r"^(.+?) link (down|up)\b", re.IGNORECASE)
_PF_LINK = re.compile(r"(\S+): link state changed to (DOWN|UP)", re.IGNORECASE)
_WIFI = re.compile(_MAC + r"@(\S+?):? (connected|disconnected|reassociating)", re.IGNORECASE)
_DPINGER = re.compile(r"(\S+) " + _IP + r": (Alarm|Clear) latency (\S+) stddev (\S+) loss (\S+)", re.IGNORECASE)
_ERROR_WORD = re.compile(r"\b(error|fail(?:ed|ure)?|critical|fatal|panic|denied|refused|timed? ?out|unreachable)\b",
                         re.IGNORECASE)
_NUMBERS = re.compile(_MAC + r"|" + _IP + r"|\b\d+\b")


def parse_filterlog(message: str) -> dict[str, str] | None:
    """pfSense filterlog CSV → action, direction, interface, protocol, src, dst, ports."""
    parts = message.split(",")
    if len(parts) < 9:
        return None
    out = {"interface": parts[4], "reason": parts[5], "action": parts[6], "direction": parts[7], "ipver": parts[8]}
    try:
        if parts[8] == "4":
            out.update(proto=parts[16].lower(), src=parts[18], dst=parts[19])
            rest = parts[20:]
        elif parts[8] == "6":
            out.update(proto=parts[12].lower(), src=parts[15], dst=parts[16])
            rest = parts[17:]
        else:
            return out
        if out["proto"] in ("tcp", "udp") and len(rest) >= 2:
            out.update(sport=rest[0], dport=rest[1])
    except IndexError:
        return out
    return out


def analyse(a: Analysis) -> Analysis:  # noqa: C901, PLR0912, PLR0915
    """Fill in a.findings from a.lines."""
    failed, good, attacks, blocks, denied = _Bucket(), _Bucket(), _Bucket(), _Bucket(), _Bucket()
    fw_block_src, fw_block_port, fw_block_if, fw_pass = _Bucket(), _Bucket(), _Bucket(), _Bucket()
    link_down, wifi_churn, capsman_lost, capsman_none = _Bucket(), _Bucket(), _Bucket(), _Bucket()
    dhcp_bad, dhcp_clients = _Bucket(), _Bucket()
    vpn_up, vpn_trouble, gw_alarm = _Bucket(), _Bucket(), _Bucket()
    reboots, changes, errors = _Bucket(), _Bucket(), _Bucket()
    error_msgs: Counter = Counter()
    wifi_connects: Counter = Counter()
    wifi_drops: Counter = Counter()

    for idx, ln in enumerate(a.lines):
        msg, svc = ln.message, ln.service
        where = f"{ln.host}: " if ln.host and len(a.hosts) > 1 else ""

        if svc == "filterlog":
            f = parse_filterlog(msg)
            if f:
                if f.get("action") == "block":
                    fw_block_src.add(idx, f.get("src", "?"))
                    if f.get("dport"):
                        fw_block_port.add(idx, f"{f['dport']}/{f.get('proto', '')}")
                    fw_block_if.add(idx, f"{f.get('interface', '?')} {f.get('direction', '')}")
                elif f.get("action") == "pass":
                    fw_pass.add(idx)
            continue

        m = _FAILED_LOGIN.search(msg)
        if m:
            g = [x for x in m.groups() if x]
            user, src = (g + ["?", "?"])[:2]
            failed.add(idx, f"{where}{user} from {src}")
        else:
            m = _GOOD_LOGIN.search(msg)
            if m:
                g = [x for x in m.groups() if x]
                if "logged in from" in msg:  # MikroTik: user, source, via
                    good.add(idx, f"{where}{g[0]} from {g[1]} via {g[2]}")
                elif msg.lower().startswith("accepted") or "Accepted " in msg:
                    good.add(idx, f"{where}{g[1]} from {g[2]} ({g[0]})")
                else:
                    good.add(idx, f"{where}{g[0]} from {g[1]} (web)")
        m = _SSHGUARD_ATTACK.search(msg)
        if m:
            attacks.add(idx, f"{m.group(1)} ({m.group(2)})")
        m = _SSHGUARD_BLOCK.search(msg)
        if m:
            blocks.add(idx, f"{m.group(1)} for {m.group(2)} s")
        m = _DENIED_CONNECT.search(msg)
        if m:
            denied.add(idx, f"{where}{m.group(1)} from {m.group(2)}")

        if ln.vendor == "mikrotik" and svc == "interface":
            m = _LINK.match(msg)
            if m and m.group(2).lower() == "down":
                link_down.add(idx, f"{where}{m.group(1)}")
        else:
            m = _PF_LINK.search(msg)
            if m and m.group(2).upper() == "DOWN":
                link_down.add(idx, f"{where}{m.group(1)}")

        if svc in ("caps", "wireless", "wifi"):
            m = _WIFI.search(msg)
            if m:
                client = f"{m.group(1).upper()} on {m.group(2)}"
                if m.group(3).lower() == "connected":
                    wifi_connects[client] += 1
                else:
                    wifi_drops[client] += 1
                    wifi_churn.add(idx)
            elif "no suitable CAPsMAN" in msg:
                capsman_none.add(idx, ln.host or "this device")
            elif "disconnected from" in msg and "CAP" in msg:
                capsman_lost.add(idx, f"{where}{msg.split(' (')[0]}")

        if svc == "dhcpd" or (ln.vendor == "mikrotik" and svc == "dhcp"):
            low = msg.lower()
            if "dhcpnak" in low or "no free leases" in low or "dhcpdecline" in low or "failed" in low:
                dhcp_bad.add(idx, "no free leases" if "no free leases" in low else low.split()[0].upper())
            m = re.search(r"DHCPACK on " + _IP + r" to " + _MAC, msg)
            if m:
                dhcp_clients.add(idx, f"{m.group(2).lower()} → {m.group(1)}")
            m = re.search(r"assigned " + _IP + r" (?:to|for) " + _MAC, msg)
            if m:
                dhcp_clients.add(idx, f"{m.group(2).lower()} → {m.group(1)}")

        if svc.startswith("openvpn") or svc in ("charon", "ipsec", "wireguard"):
            low = msg.lower()
            if "initialization sequence completed" in low or "peer connection initiated" in low:
                vpn_up.add(idx, ln.host or svc)
            elif any(w in low for w in ("tls error", "auth_failed", "inactivity timeout", "ping-restart",
                                        "connection reset", "tls handshake failed", "cannot resolve")):
                key = next(w for w in ("tls handshake failed", "tls error", "auth_failed", "inactivity timeout",
                                       "ping-restart", "connection reset", "cannot resolve") if w in low)
                vpn_trouble.add(idx, key)

        if svc == "dpinger":
            m = _DPINGER.search(msg)
            if m and m.group(3).lower() == "alarm":
                gw_alarm.add(idx, f"{m.group(1)} ({m.group(2)}) loss {m.group(6)}")

        low = msg.lower()
        if "rebooted without proper shutdown" in low or "kernel: copyright" in low or "syslogd: kernel boot file" in low \
                or "router rebooted" in low:
            reboots.add(idx, f"{where}{'unclean shutdown' if 'without proper shutdown' in low else 'boot'}")
        if " changed by " in msg:
            changes.add(idx, f"{where}{msg.split(' (')[0][:90]}")

        is_error = ("error" in ln.topics or "critical" in ln.topics or ln.topics == "warning") if ln.vendor == "mikrotik" \
            else bool(_ERROR_WORD.search(msg))
        if is_error and svc != "filterlog":
            errors.add(idx, svc or "(unrecognised)")
            error_msgs[f"{svc or '?'}: {_NUMBERS.sub('#', msg)[:110]}"] += 1

    out: list[Finding] = []

    def add(bucket: _Bucket, area: str, title: str, severity: str, detail: str = "", need: int = 1) -> None:
        if bucket.count >= need:
            out.append(bucket.finding(area, title, severity, detail))

    add(blocks, "Logins", "Addresses blocked by login protection (sshguard)", ERROR,
        "The firewall shut these addresses out after repeated failed logins. If one is your own PC, "
        "something on it keeps trying a login that fails.")
    add(attacks, "Logins", "Login attacks counted by sshguard", WARN,
        "Each failed attempt adds to a score; past the threshold the address is blocked.")
    add(failed, "Logins", "Failed logins", ERROR if failed.count >= 5 else WARN,
        "Who tried and from where. Repeats from one address are a wrong saved password / key, or an attack.")
    add(denied, "Logins", "Refused management connections", WARN,
        "Connections to WinBox / the API from addresses that are not allowed to manage the device.")
    add(good, "Logins", "Successful logins", INFO, "Who logged in, from where and how.")

    add(fw_block_src, "Firewall", "Most-blocked source addresses", INFO if fw_block_src.count < 1000 else WARN,
        "Where blocked traffic comes from. An inside address here is a device trying something the rules forbid.")
    add(fw_block_port, "Firewall", "Most-blocked destination ports", INFO,
        "What the blocked traffic was trying to reach.")
    add(fw_block_if, "Firewall", "Blocks by interface and direction", INFO)
    add(fw_pass, "Firewall", "Passed connections that were logged", INFO)

    add(link_down, "Links", "Links that went down", WARN if any(n >= 5 for _k, n in link_down.tally.items()) else INFO,
        "A port that drops again and again points at a cable, a connector, or the device on the other end "
        "going to sleep.")
    add(capsman_lost, "Wireless", "Access points that lost their controller", WARN,
        "A CAP that disconnects from CAPsMAN drops every Wi-Fi client on it.")
    add(capsman_none, "Wireless", "\"No suitable CAPsMAN\"", WARN if capsman_none.count >= 50 else INFO,
        "The access point is looking for a controller and not finding one it may use. Check the CAP's "
        "caps-man-addresses / discovery interface and the controller's provisioning rules.", need=5)
    # One row per client: how often it dropped / reassociated and how often it (re)connected.
    for client in set(wifi_drops) | {c for c, n in wifi_connects.items() if n >= 20}:
        drops, joins = wifi_drops.get(client, 0), wifi_connects.get(client, 0)
        wifi_churn.tally[f"{client} — {drops} drops / reassociations, {joins} connects"] = drops + joins
    wifi_churn.count = sum(wifi_churn.tally.values())
    add(wifi_churn, "Wireless", "Wi-Fi clients that will not stay connected",
        WARN if any(n >= 20 for _k, n in wifi_churn.tally.items()) else INFO,
        "Disconnects, reassociations and repeated reconnects per client. A client high on this list has a weak "
        "signal, is flapping between two access points, or is asleep most of the time.")

    add(dhcp_bad, "DHCP", "DHCP refusals and exhausted pools", ERROR if "no free leases" in dhcp_bad.tally else WARN,
        "NAK: the client asked for an address the server will not give. No free leases: the pool is full.")
    add(dhcp_clients, "DHCP", "Addresses handed out", INFO, "Client → address, most active first.")

    add(vpn_trouble, "VPN", "VPN errors and restarts", WARN, "Tunnels that timed out, failed TLS or were refused.")
    add(vpn_up, "VPN", "VPN tunnels that came up", INFO)
    add(gw_alarm, "Gateways", "Gateway alarms (packet loss / latency)", WARN,
        "The gateway monitor saw loss or delay on an Internet line.")

    add(reboots, "System", "Reboots", ERROR if any("unclean" in k for k in reboots.tally) else INFO,
        "An unclean shutdown means the device lost power or crashed.")
    add(changes, "System", "Configuration changes", INFO, "Who changed what, as the device logged it.")

    if errors.count:
        f = errors.finding("Errors", "Errors and warnings by service", WARN,
                           "Lines the device itself marked as an error, or that say failed / denied / timed out.")
        out.append(f)
        out.append(Finding("Errors", "Most frequent error messages", INFO, sum(error_msgs.values()),
                           "Addresses and numbers are replaced by # so that repeats group together.",
                           error_msgs.most_common(15), list(errors.lines)))

    services = Finding("Overview", "Lines per service", INFO, a.total_lines,
                       "What the files contain.", a.services.most_common(20), [])
    if a.total_lines - a.parsed_lines:
        services.table.append(("(not recognised as a log line)", a.total_lines - a.parsed_lines))
    out.append(services)
    if len(a.hosts) > 1:
        out.append(Finding("Overview", "Lines per device", INFO, a.total_lines, "", a.hosts.most_common(20), []))

    order = {ERROR: 0, WARN: 1, INFO: 2}
    a.findings = sorted(out, key=lambda f: (f.area == "Overview", order[f.severity], -f.count))
    return a


def analyse_paths(paths: list[Path]) -> Analysis:
    """Read the files / folders and analyse them."""
    return analyse(read_files(paths))


def lines_text(a: Analysis, finding: Finding, limit: int = MAX_FINDING_LINES) -> str:
    """The log lines behind a finding, as text (file:line before each)."""
    out = list(finding.notes)
    if finding.notes and finding.lines:
        out.append("")
    for idx in finding.lines[:limit]:
        ln = a.lines[idx]
        host = f"{ln.host} " if ln.host and ln.vendor == "mikrotik" else ""
        out.append(f"{ln.file}:{ln.lineno}  {host}{ln.raw}")
    if finding.lines and finding.count > len(finding.lines):
        out.append(f"… and {finding.count - len(finding.lines):,} more")
    return "\n".join(out)
