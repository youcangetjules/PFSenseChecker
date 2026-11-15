"""Is the nmap program installed, and does it actually work?

nmap is a separate program (``nmap.exe``), not a Python package. Subnet
Health's device scan uses it as its main source and falls back to a ping sweep
plus ARP without it. On Windows it needs Npcap for raw scans (OS detection,
SYN scans); Npcap is often already there from Wireshark.

"Working" means ``nmap --version`` answers and a quick host-discovery run
against this PC (127.0.0.1) completes. (added 2026-11-15)
"""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass, field

from pfsense_checker import device_scan, winproc

DOWNLOAD_URL = "https://nmap.org/download.html"


@dataclass
class NmapStatus:
    installed: bool = False
    path: str = ""
    version: str = ""
    on_path: bool = False
    works: bool = False
    test_ms: float | None = None
    npcap: str = ""  # running / stopped / not installed / unknown
    error: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if not self.installed:
            return "Not installed"
        if not self.works:
            return "Installed, but a test run failed"
        if self.npcap not in ("running", "unknown"):
            return "Installed and working (no Npcap)"
        return "Installed and working"


def npcap_state() -> str:
    """running / stopped / not installed (Windows service "npcap"); unknown elsewhere."""
    try:
        out = winproc.run(["sc", "query", "npcap"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    text = (out.stdout or "") + (out.stderr or "")
    if "RUNNING" in text:
        return "running"
    if "STOPPED" in text:
        return "stopped"
    if "1060" in text or "does not exist" in text.lower():
        return "not installed"
    return "unknown"


def check(*, timeout: float = 20.0) -> NmapStatus:
    st = NmapStatus()
    st.path = device_scan.nmap_path()
    st.installed = bool(st.path)
    import shutil

    st.on_path = bool(shutil.which("nmap"))
    st.npcap = npcap_state()
    if not st.installed:
        st.error = "nmap was not found on PATH or in the usual install folders"
        st.notes.append(f"Install nmap from {DOWNLOAD_URL} (the Windows installer also offers Npcap). "
                        "Subnet Health scans fall back to a ping sweep and ARP without it.")
        return st
    try:
        out = winproc.run([st.path, "--version"], capture_output=True, text=True, timeout=timeout, check=False)
        m = re.search(r"Nmap version (\S+)", out.stdout or "")
        first = ((out.stdout or "").strip().splitlines() or [""])[0]
        st.version = f"Nmap {m.group(1)}" if m else first
        start = time.monotonic()
        res = winproc.run([st.path, "-sn", "-n", "127.0.0.1"], capture_output=True, text=True,
                          timeout=timeout, check=False)
        st.test_ms = round((time.monotonic() - start) * 1000, 1)
        st.works = res.returncode == 0 and "Host is up" in (res.stdout or "")
        if not st.works:
            err = (res.stderr or res.stdout or "").strip()
            st.error = err.splitlines()[-1] if err else f"nmap exited with {res.returncode}"
    except (OSError, subprocess.TimeoutExpired) as exc:
        st.error = f"{type(exc).__name__}: {exc}"
    if st.npcap == "not installed":
        st.notes.append("Npcap is not installed: OS detection and SYN scans need it (install from npcap.com).")
    elif st.npcap == "stopped":
        st.notes.append("The Npcap driver is installed but stopped.")
    if not st.on_path:
        st.notes.append("nmap is not on PATH; NetCheck finds it in its install folder anyway.")
    return st
