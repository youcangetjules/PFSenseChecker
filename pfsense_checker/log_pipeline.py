"""Incoming log pipeline: helpers for the live receiver on Logs → Syslog.

Log Pipeline used to be its own page with its own listener on port 59000.
Since 1.8.2 it is part of the Syslog page (one receiver, one port). What is
left here:

- the pipeline's saved port, and the one-time move of that port into the
  Syslog settings (:func:`merge_into_syslog`),
- reading a pfSense filter log line into plain words (:func:`filter_text`),
- the RouterOS commands that make a MikroTik send its log to this PC.

UDP carries syslog. TCP on the same port carries a newline-delimited stream,
which is how a log file is tailed into NetCheck. Lines are parsed and shown.
They are never executed.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pfsense_checker.paths import PROJECT_ROOT, ensure_data_dir
from pfsense_checker.syslog_recv import SyslogMessage, SyslogSettings

DEFAULT_PORT = 59000
SETTINGS_PATH = PROJECT_ROOT / "data" / "log_pipeline.json"

_FILTER_ACTION = {"pass", "block", "reject"}


@dataclass
class LogPipelineSettings:
    port: int = DEFAULT_PORT
    bind_host: str = "0.0.0.0"

    def to_dict(self) -> dict[str, Any]:
        return {"port": self.port, "bind_host": self.bind_host}


def clamp_port(value: object, *, default: int = DEFAULT_PORT) -> int:
    """Return a TCP/UDP port. Invalid values become *default* (59000)."""
    try:
        port = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    if port < 1 or port > 65535:
        return default
    return port


def load_settings(path: Path | None = None) -> LogPipelineSettings:
    target = path or SETTINGS_PATH
    if not target.is_file():
        return LogPipelineSettings()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return LogPipelineSettings()
    if not isinstance(data, dict):
        return LogPipelineSettings()
    host = str(data.get("bind_host") or "0.0.0.0").strip() or "0.0.0.0"
    return LogPipelineSettings(port=clamp_port(data.get("port")), bind_host=host)


def save_settings(settings: LogPipelineSettings, path: Path | None = None) -> Path:
    target = path or SETTINGS_PATH
    ensure_data_dir()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = LogPipelineSettings(
        port=clamp_port(settings.port),
        bind_host=(settings.bind_host or "0.0.0.0").strip() or "0.0.0.0",
    )
    target.write_text(json.dumps(payload.to_dict(), indent=2) + "\n", encoding="utf-8")
    return target


def receiver_settings(settings: LogPipelineSettings) -> SyslogSettings:
    """Syslog listener settings for this pipeline.

    UDP and TCP share the selected port. Sources are accepted: the operator
    chose to open the port. Nothing is written into the Syslog section's file.
    """
    port = clamp_port(settings.port)
    host = (settings.bind_host or "0.0.0.0").strip() or "0.0.0.0"
    return SyslogSettings(
        bind_host=host,
        udp_port=port,
        tcp_port=port,
        attached_only=False,
        file_enabled=False,
        auto_start=False,
    )


def format_message(message: SyslogMessage) -> str:
    """One screen line. Filter logs are expanded; other lines stay readable."""
    raw = (message.message or message.raw or "").replace("\x00", "")
    raw = re.sub(r"\s+", " ", raw).strip()
    if len(raw) > 500:
        raw = raw[:500] + "…"
    decoded = filter_text(message.raw or message.message)
    stamp = message.timestamp or message.received_at
    host = message.hostname or message.source_ip or "?"
    if decoded:
        return f"{stamp}  {host}  {decoded}"
    app = message.app_name or "log"
    return f"{stamp}  {host}  {app}  {raw}"


def filter_text(text: str) -> str:
    """A pfSense filter log line in plain words ("block in igb3  tcp  a:1 -> b:2"), else ""."""
    parsed = _filter_fields(text or "")
    if not parsed:
        return ""
    action, direction, iface, proto, src, dst = parsed
    return f"{action} {direction} {iface}  {proto}  {src} -> {dst}"


MERGED_SUFFIX = ".merged"


def merge_into_syslog(pipeline_path: Path | None = None, syslog_path: Path | None = None) -> str:
    """One time: carry the Log Pipeline's port over to the Syslog receiver.

    The pipeline listened on its port for UDP and TCP, so both Syslog ports
    take it. The pipeline's settings file is then renamed (``.merged``) so this
    runs once. Returns a line for the status label, or "" when there was
    nothing to do.
    """
    from pfsense_checker import syslog_recv

    source = pipeline_path or SETTINGS_PATH
    if not source.is_file():
        return ""
    port = load_settings(source).port
    try:
        settings = syslog_recv.load_settings(syslog_path)
        old = settings.udp_port
        settings.udp_port = port
        settings.tcp_port = port
        syslog_recv.save_settings(settings, syslog_path)
        source.replace(source.with_name(source.name + MERGED_SUFFIX))
    except OSError:
        return ""
    was = f" (UDP was {old})" if old != port else ""
    return f"Log Pipeline is now part of this page. Listening port set to {port}, UDP and TCP{was}."


def _filter_fields(text: str) -> tuple[str, str, str, str, str, str] | None:
    """pfSense filterlog CSV: action, direction, iface, proto, src, dst."""
    lower = (text or "").lower()
    idx = lower.find("filterlog")
    if idx < 0:
        return None
    rest = text[idx + len("filterlog") :]
    if rest.startswith("["):
        end = rest.find("]")
        if end >= 0:
            rest = rest[end + 1 :]
    rest = rest.split(":", 1)[-1].strip()
    fields = [part.strip() for part in rest.split(",")]
    if len(fields) < 9 or fields[6].lower() not in _FILTER_ACTION:
        return None
    action = fields[6].lower()
    iface = fields[4] or "?"
    direction = fields[7] or "?"
    proto = fields[16] if len(fields) > 16 else "?"
    src = fields[18] if len(fields) > 18 else "?"
    dst = fields[19] if len(fields) > 19 else "?"
    if proto.lower() in {"tcp", "udp"} and len(fields) > 21:
        src = f"{src}:{fields[20]}" if fields[20] else src
        dst = f"{dst}:{fields[21]}" if fields[21] else dst
    return action, direction, iface, proto or "?", src or "?", dst or "?"


# --------------------------------------------------------------------------- #
# MikroTik: the commands that make a RouterOS device send its log here.
# NetCheck only shows them. The operator pastes them into the router.
# --------------------------------------------------------------------------- #

MIKROTIK_ACTION = "netcheck"
# Debug topics are left out on purpose: caps,debug alone can log every few seconds.
MIKROTIK_TOPICS = ("info", "warning", "error", "critical")


def ipv4(text: object) -> str:
    """*text* as a plain IPv4 address, or "" when it is not one."""
    try:
        addr = ipaddress.ip_address(str(text or "").strip())
    except ValueError:
        return ""
    if addr.version != 4 or addr.is_unspecified or addr.is_loopback:
        return ""
    return str(addr)


def mikrotik_commands(
    address: object,
    port: object,
    *,
    topics: tuple[str, ...] = MIKROTIK_TOPICS,
    action: str = MIKROTIK_ACTION,
) -> list[str]:
    """RouterOS 7 commands that send a device's log to *address*:*port* over UDP.

    Empty when *address* is not an IPv4 address, so nothing half-formed is copied.
    """
    target = ipv4(address)
    if not target:
        return []
    lines = [
        f"/system logging action add name={action} target=remote remote={target} "
        f"remote-port={clamp_port(port)} remote-protocol=udp remote-log-format=syslog"
    ]
    lines.extend(f"/system logging add action={action} topics={t}" for t in topics)
    return lines


def mikrotik_undo_commands(action: str = MIKROTIK_ACTION) -> list[str]:
    """Remove exactly what :func:`mikrotik_commands` added (rules first, then the action)."""
    return [
        f"/system logging remove [find action={action}]",
        f"/system logging action remove [find name={action}]",
    ]


def mikrotik_hosts(site: Any) -> list[str]:
    """IPv4 addresses of the MikroTiks on Login to Routers."""
    from pfsense_checker import device_logs

    out: list[str] = []
    for dev in getattr(site, "devices", None) or []:
        if getattr(dev, "ignored", False) or device_logs.kind_of(dev) != "mikrotik":
            continue
        ssh = getattr(dev, "ssh", None)
        for raw in (getattr(ssh, "host", ""), getattr(dev, "mgmt_ip", "")):
            ip = ipv4(raw)
            if ip and ip not in out:
                out.append(ip)
    return out


def pick_address(nics: list[Any], router_hosts: list[str] | None = None) -> str:
    """This PC's address the routers should send to.

    The adapter that shares a subnet with the most routers wins. Otherwise the
    first ordinary LAN adapter (not Hyper-V, not link-local), then any address.
    """
    hosts = [ipaddress.ip_address(h) for h in (ipv4(x) for x in router_hosts or []) if h]
    best, best_hits = "", 0
    for nic in nics:
        ip = ipv4(getattr(nic, "ip", ""))
        if not ip:
            continue
        try:
            net = ipaddress.ip_network(str(getattr(nic, "cidr", "") or ""), strict=False)
        except ValueError:
            continue
        hits = sum(1 for h in hosts if h in net)
        if hits > best_hits:
            best, best_hits = ip, hits
    if best:
        return best
    usable = [n for n in nics if ipv4(getattr(n, "ip", ""))]
    for kind in ("lan", "vpn", "virtual"):
        for nic in usable:
            if getattr(nic, "kind", "lan") == kind:
                return ipv4(nic.ip)
    return ipv4(usable[0].ip) if usable else ""
