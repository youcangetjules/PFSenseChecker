"""Speed / reachability checks from a chosen network point.

Probes run on this workstation. The "source point" names where you are standing
in the topology (this PC, or a device's management host) so results are labelled
for corridor comparison — true remote iperf would require an agent on that node.
"""

from __future__ import annotations

import logging
import platform
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

from PySide6.QtCore import QThread, Signal

from pfsense_checker import winproc
from pfsense_checker.monitor.probes import ping_host

_LOG = logging.getLogger("netcheck.speed")


@dataclass
class SpeedSample:
    kind: str  # ping | traceroute | download
    status: str  # ok | fail | error
    target: str
    message: str
    latency_ms: float | None = None
    mbps: float | None = None
    bytes_read: int = 0
    elapsed_sec: float = 0.0


def measure_download(
    url: str,
    *,
    timeout_sec: float = 30.0,
    max_bytes: int = 8 * 1024 * 1024,
) -> SpeedSample:
    """Timed HTTP GET; reports approximate download throughput in Mbps."""
    url = (url or "").strip()
    if not url:
        return SpeedSample("download", "error", "", "no URL given")
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    started = time.perf_counter()
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "PFSenseChecker-SpeedCheck/1.0"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            total = 0
            while total < max_bytes:
                chunk = resp.read(min(64 * 1024, max_bytes - total))
                if not chunk:
                    break
                total += len(chunk)
        elapsed = max(time.perf_counter() - started, 1e-6)
        mbps = (total * 8) / elapsed / 1_000_000
        return SpeedSample(
            kind="download",
            status="ok" if total > 0 else "fail",
            target=url,
            message=f"read {total} bytes in {elapsed:.2f}s",
            mbps=round(mbps, 2),
            bytes_read=total,
            elapsed_sec=round(elapsed, 3),
            latency_ms=round(elapsed * 1000, 1),
        )
    except urllib.error.HTTPError as exc:
        elapsed = time.perf_counter() - started
        return SpeedSample(
            "download",
            "fail",
            url,
            f"HTTP {exc.code}: {exc.reason}",
            elapsed_sec=round(elapsed, 3),
        )
    except Exception as exc:  # noqa: BLE001
        elapsed = time.perf_counter() - started
        return SpeedSample(
            "download",
            "error",
            url,
            str(exc),
            elapsed_sec=round(elapsed, 3),
        )


def measure_ping(host: str, *, count: int = 4, timeout_sec: float = 2.0) -> SpeedSample:
    res = ping_host(host, count=count, timeout_sec=timeout_sec)
    return SpeedSample(
        kind="ping",
        status=res.status,
        target=host,
        message=res.message,
        latency_ms=res.latency_ms,
    )


def _traceroute_cmd(host: str, *, max_hops: int) -> list[str]:
    system = platform.system().lower()
    hops = str(max(1, max_hops))
    if system == "windows":
        return ["tracert", "-d", "-h", hops, host]
    return ["traceroute", "-n", "-m", hops, host]


def _traceroute_hop_count(output: str) -> int:
    hops = 0
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if re.match(r"^\s*\d+\s", line):
            hops += 1
        elif re.match(r"^\d+\s", line):
            hops += 1
    return hops


def _traceroute_last_rtt_ms(output: str) -> float | None:
    hop_lines = [
        line
        for line in output.splitlines()
        if re.match(r"^\s*\d+\s", line) or re.match(r"^\d+\s", line.strip())
    ]
    if not hop_lines:
        return None
    times = [float(x) for x in re.findall(r"([\d.]+)\s*ms", hop_lines[-1], re.I)]
    return times[-1] if times else None


def measure_traceroute(
    host: str,
    *,
    max_hops: int = 30,
    timeout_sec: float = 2.0,
) -> SpeedSample:
    """Trace the route to *host* using the OS traceroute utility."""
    host = (host or "").strip()
    if not host:
        return SpeedSample("traceroute", "error", "", "no target given")
    cmd = _traceroute_cmd(host, max_hops=max_hops)
    timeout = max_hops * timeout_sec + 15
    started = time.perf_counter()
    try:
        completed = winproc.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        out = ((completed.stdout or "") + (completed.stderr or "")).strip()
        elapsed = time.perf_counter() - started
        hop_count = _traceroute_hop_count(out)
        last_rtt = _traceroute_last_rtt_ms(out)
        ok = hop_count > 0 or completed.returncode == 0
        if not out:
            return SpeedSample(
                kind="traceroute",
                status="error",
                target=host,
                message="traceroute produced no output",
                elapsed_sec=round(elapsed, 3),
            )
        summary = f"{hop_count} hop(s)" if hop_count else "trace completed"
        detail = out if len(out) <= 1200 else out[:1200] + "\n…"
        return SpeedSample(
            kind="traceroute",
            status="ok" if ok else "fail",
            target=host,
            message=f"{summary} — {detail}",
            latency_ms=last_rtt,
            elapsed_sec=round(elapsed, 3),
        )
    except FileNotFoundError:
        return SpeedSample(
            "traceroute",
            "error",
            host,
            "traceroute command not found on this system",
        )
    except Exception as exc:  # noqa: BLE001
        elapsed = time.perf_counter() - started
        return SpeedSample(
            "traceroute",
            "error",
            host,
            str(exc),
            elapsed_sec=round(elapsed, 3),
        )


class SpeedCheckWorker(QThread):
    """Run ping, traceroute, or download off the UI thread."""

    sample = Signal(object)  # SpeedSample
    finished_ok = Signal()

    def __init__(
        self,
        *,
        test_type: str = "ping",
        ping_host_name: str = "",
        download_url: str = "",
        ping_count: int = 4,
        on_progress: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__()
        self._test_type = (test_type or "ping").strip().lower()
        self._ping_host = ping_host_name.strip()
        self._download_url = download_url.strip()
        self._ping_count = ping_count
        self._on_progress = on_progress

    def run(self) -> None:  # noqa: D102
        tt = self._test_type
        _LOG.debug(
            "Speed check start: type=%s host=%s url=%s",
            tt,
            self._ping_host or "—",
            self._download_url or "—",
        )
        started = time.perf_counter()
        result: SpeedSample | None = None
        if tt == "ping" and self._ping_host:
            if self._on_progress:
                self._on_progress(f"Pinging {self._ping_host}…")
            result = measure_ping(self._ping_host, count=self._ping_count)
        elif tt == "traceroute" and self._ping_host:
            if self._on_progress:
                self._on_progress(f"Traceroute to {self._ping_host}…")
            result = measure_traceroute(self._ping_host)
        elif tt == "download" and self._download_url:
            if self._on_progress:
                self._on_progress(f"Downloading from {self._download_url}…")
            result = measure_download(self._download_url)
        if result is not None:
            _LOG.debug(
                "Speed check done in %.2fs: %s %s → %s (%.120s)",
                time.perf_counter() - started,
                result.kind,
                result.target,
                result.status,
                result.message,
            )
            self.sample.emit(result)
        else:
            _LOG.debug("Speed check skipped — no target for type=%s", tt)
        self.finished_ok.emit()
