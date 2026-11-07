"""Incoming log pipeline.

pfSense (and anything else that speaks syslog) streams logs to a port on this
workstation. The operator picks that port. The default is 59000, which does
not need administrator rights the way port 514 does.

UDP carries syslog. TCP on the same port carries a newline-delimited stream,
which is how a log file is tailed into NetCheck. Lines are parsed and shown.
They are never executed.
"""

from __future__ import annotations

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
    parsed = _filter_fields(message.raw or message.message)
    stamp = message.timestamp or message.received_at
    host = message.hostname or message.source_ip or "?"
    if parsed:
        action, direction, iface, proto, src, dst = parsed
        return (
            f"{stamp}  {host}  {action} {direction} {iface}  {proto}  {src} -> {dst}"
        )
    app = message.app_name or "log"
    return f"{stamp}  {host}  {app}  {raw}"


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
