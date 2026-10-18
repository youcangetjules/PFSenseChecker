"""Windows-safe subprocess helpers.

On Windows, launching ``ping`` / ``arp`` / ``powershell`` without
``CREATE_NO_WINDOW`` flashes a console for every process — a /24 scan can
spawn hundreds of black cmd windows. These helpers keep child processes silent.
"""

from __future__ import annotations

import logging
import subprocess
import sys
import time
from typing import Any

_LOG = logging.getLogger("netcheck.proc")


def silent_run_kwargs(*, allow_gui: bool = False, **extra: Any) -> dict[str, Any]:
    """kwargs for ``subprocess.run`` / ``Popen`` that hide consoles on Windows.

    ``allow_gui=True`` still suppresses a console (``CREATE_NO_WINDOW``) but
    does not set ``SW_HIDE``. 1Password's CLI approval window is a GUI owned
    by ``op.exe``; hiding the process keeps that prompt off screen.
    """
    kwargs: dict[str, Any] = dict(extra)
    if sys.platform == "win32":
        # CREATE_NO_WINDOW (0x08000000) — no console window for the child.
        no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        flags = int(kwargs.get("creationflags", 0) or 0) | no_window
        kwargs["creationflags"] = flags
        if not allow_gui:
            # Belt-and-suspenders for tools that still flash a window.
            startupinfo = kwargs.get("startupinfo")
            if startupinfo is None:
                startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0  # SW_HIDE
            kwargs["startupinfo"] = startupinfo
    return kwargs


def run(cmd: list[str] | tuple[str, ...] | str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """``subprocess.run`` with console windows suppressed on Windows.

    Pass ``allow_gui=True`` when the child must show its own window
    (1Password CLI approval). That flag is not forwarded to ``subprocess``.
    """
    allow_gui = bool(kwargs.pop("allow_gui", False))
    merged = silent_run_kwargs(allow_gui=allow_gui, **kwargs)
    if _LOG.isEnabledFor(logging.DEBUG):
        shown = cmd if isinstance(cmd, str) else " ".join(str(c) for c in cmd)
        started = time.perf_counter()
        result = subprocess.run(cmd, **merged)
        _LOG.debug(
            "exec %.200s → exit %s in %.0f ms",
            shown,
            result.returncode,
            (time.perf_counter() - started) * 1000.0,
        )
        return result
    return subprocess.run(cmd, **merged)
