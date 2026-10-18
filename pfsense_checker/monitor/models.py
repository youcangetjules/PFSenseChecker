"""Continuous monitoring models (beacons, probes, heartbeats)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class ProbeKind(str, Enum):
    PING = "ping"
    DHCP = "dhcp"
    SPEED = "speed"
    HEARTBEAT = "heartbeat"


class ProbeStatus(str, Enum):
    OK = "ok"
    FAIL = "fail"
    WARN = "warn"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class ProbeResult:
    kind: str
    status: str
    target: str = ""
    subnet: str = ""
    interface: str = ""
    message: str = ""
    latency_ms: float | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    ts: str = ""  # ISO-8601 UTC
    beacon_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProbeResult:
        return cls(
            kind=str(data.get("kind", "")),
            status=str(data.get("status", ProbeStatus.ERROR.value)),
            target=str(data.get("target", "")),
            subnet=str(data.get("subnet", "")),
            interface=str(data.get("interface", "")),
            message=str(data.get("message", "")),
            latency_ms=data.get("latency_ms"),
            detail=dict(data.get("detail") or {}),
            ts=str(data.get("ts", "")),
            beacon_id=str(data.get("beacon_id", "")),
        )


@dataclass
class BeaconReport:
    """Payload a beacon POSTs to the collector each cycle."""

    beacon_id: str
    hostname: str = ""
    site: str = ""
    version: str = "1.0.0"
    results: list[ProbeResult] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "beacon_id": self.beacon_id,
            "hostname": self.hostname,
            "site": self.site,
            "version": self.version,
            "results": [r.to_dict() for r in self.results],
            "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BeaconReport:
        return cls(
            beacon_id=str(data.get("beacon_id", "")),
            hostname=str(data.get("hostname", "")),
            site=str(data.get("site", "")),
            version=str(data.get("version", "")),
            results=[ProbeResult.from_dict(r) for r in (data.get("results") or [])],
            meta=dict(data.get("meta") or {}),
        )


@dataclass
class BeaconStatus:
    beacon_id: str
    hostname: str = ""
    site: str = ""
    last_seen: str = ""
    online: bool = False
    ping_ok: int = 0
    ping_fail: int = 0
    dhcp_ok: int = 0
    dhcp_fail: int = 0
    last_message: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
