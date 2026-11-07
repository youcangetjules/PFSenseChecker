"""Is the Graphviz program installed, and does it actually work?

Graphviz is a separate program (``dot.exe``), not a Python package. The
Python ``graphviz`` package only writes DOT text and runs ``dot`` from PATH,
so the useful questions are: where is ``dot``, which version, is it on PATH
(so the Python package can find it), and does a real render succeed.

Graphviz is not a service, so "running" means a test render completes.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from pfsense_checker import winproc

_CANDIDATES = (
    r"C:\Program Files\Graphviz\bin\dot.exe",
    r"C:\Program Files (x86)\Graphviz\bin\dot.exe",
    "/usr/bin/dot",
    "/usr/local/bin/dot",
    "/opt/homebrew/bin/dot",
)
_TEST_GRAPH = 'digraph netcheck { rankdir=LR; router -> switch -> "access point"; }'


@dataclass
class GraphvizStatus:
    installed: bool = False
    path: str = ""
    version: str = ""
    on_path: bool = False
    works: bool = False
    render_ms: float | None = None
    python_package: str = ""  # version of the Python graphviz package, "" if missing
    python_finds_dot: bool = False
    error: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if not self.installed:
            return "Not installed"
        if not self.works:
            return "Installed, but a test render failed"
        if not self.on_path:
            return "Installed and working (not on PATH)"
        return "Installed and working"


def find_dot() -> tuple[str, bool]:
    """(path to dot, whether it is on PATH)."""
    on_path = shutil.which("dot")
    if on_path:
        return on_path, True
    for cand in _CANDIDATES:
        if Path(cand).is_file():
            return cand, False
    return "", False


def check(*, timeout: float = 15.0) -> GraphvizStatus:
    st = GraphvizStatus()
    st.path, st.on_path = find_dot()
    st.installed = bool(st.path)
    try:
        import graphviz  # noqa: PLC0415

        st.python_package = getattr(graphviz, "__version__", "") or "installed"
    except Exception:  # noqa: BLE001
        st.python_package = ""
    if not st.installed:
        st.error = "dot was not found on PATH or in the usual install folders"
        st.notes.append("Install Graphviz from graphviz.org (tick 'add to PATH' in the installer).")
        return st
    try:
        out = winproc.run([st.path, "-V"], capture_output=True, text=True, timeout=timeout, check=False)
        st.version = ((out.stderr or "") + (out.stdout or "")).strip().splitlines()[0] if (
            (out.stderr or out.stdout or "").strip()) else ""
        start = time.monotonic()
        res = winproc.run([st.path, "-Tsvg"], input=_TEST_GRAPH, capture_output=True, text=True,
                          timeout=timeout, check=False)
        st.render_ms = round((time.monotonic() - start) * 1000, 1)
        st.works = res.returncode == 0 and "<svg" in (res.stdout or "")
        if not st.works:
            st.error = (res.stderr or "").strip().splitlines()[-1] if (res.stderr or "").strip() else (
                f"dot exited with {res.returncode}")
    except (OSError, subprocess.TimeoutExpired) as exc:
        st.error = f"{type(exc).__name__}: {exc}"
    st.python_finds_dot = st.on_path or str(Path(st.path).parent) in os.environ.get("PATH", "").split(os.pathsep)
    if not st.on_path:
        st.notes.append(f"Add {Path(st.path).parent} to PATH so the Python graphviz package can run dot.")
    return st
