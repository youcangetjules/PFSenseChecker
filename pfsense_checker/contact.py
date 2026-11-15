"""Get in Touch: start an email to Aliniant, in Outlook when it is installed.

Order of attempts:
  1. Outlook itself (``outlook.exe /c ipm.note /m "address?subject=…"``), so the
     message opens in Outlook even when another app owns mailto: links.
  2. The default mail app, through a ``mailto:`` link.
The caller shows the address when neither works. (added 2026-11-08)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from urllib.parse import quote

CONTACT_ADDRESS = "administrator@aliniant.com"
CONTACT_SUBJECT = "Tell me about netcheck"
_APP_PATHS = r"Software\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE"


def mailto_url(address: str = CONTACT_ADDRESS, subject: str = CONTACT_SUBJECT) -> str:
    return f"mailto:{address}?subject={quote(subject)}"


def outlook_recipient(address: str = CONTACT_ADDRESS, subject: str = CONTACT_SUBJECT) -> str:
    """Outlook's /m argument: the address, with the subject in mailto form."""
    return f"{address}?subject={quote(subject)}"


def outlook_path() -> str:
    """Where OUTLOOK.EXE is (Windows App Paths registration, then PATH), or ""."""
    if sys.platform == "win32":
        import winreg

        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                with winreg.OpenKey(hive, _APP_PATHS) as key:
                    path = str(winreg.QueryValue(key, None) or "").strip().strip('"')
            except OSError:
                continue
            if path and os.path.isfile(path):
                return path
    return shutil.which("outlook") or shutil.which("OUTLOOK.EXE") or ""


def open_email(
    *,
    find_outlook: Callable[[], str] = outlook_path,
    launch: Callable[[list[str]], object] = subprocess.Popen,
    open_url: Callable[[str], bool] | None = None,
) -> str:
    """Start the email. Returns "outlook", "mailto", or "" when nothing opened."""
    exe = find_outlook()
    if exe:
        try:
            launch([exe, "/c", "ipm.note", "/m", outlook_recipient()])
            return "outlook"
        except OSError:
            pass
    if open_url is None:
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices

        def open_url(url: str) -> bool:
            return bool(QDesktopServices.openUrl(QUrl(url)))

    try:
        if open_url(mailto_url()):
            return "mailto"
    except Exception:  # noqa: BLE001 - no mail handler must not crash the launcher
        pass
    return ""
