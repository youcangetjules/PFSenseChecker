"""Shared SSH / sudo password dialogs for config pull and similar flows."""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtWidgets import QInputDialog, QLineEdit, QWidget

from pfsense_checker.ssh_session import SshExportResult
from pfsense_checker.topology_site import Device


@dataclass(frozen=True)
class ConfigPullRetry:
    """Credentials to use for a follow-up config pull attempt."""

    ssh_password: str | None = None
    sudo_password: str | None = None


def prompt_ssh_password(
    parent: QWidget | None,
    device: Device,
    *,
    reason: str = "",
) -> str | None:
    """Ask for an SSH password. Returns the password or ``None`` if cancelled."""
    ssh = device.ensure_ssh()
    host = (ssh.host or device.mgmt_ip or "").strip() or "device"
    user = (ssh.username or "").strip() or "user"
    intro = reason.strip() or f"SSH login failed for {user}@{host}."
    text, ok = QInputDialog.getText(
        parent,
        "SSH password required",
        f"{intro}\n\nEnter the SSH password for this device:",
        QLineEdit.EchoMode.Password,
    )
    if not ok or not (text or "").strip():
        return None
    return text.strip()


def prompt_sudo_password(
    parent: QWidget | None,
    device: Device,
    *,
    reason: str = "",
) -> str | None:
    """Ask for a sudo password to read root-only files. ``None`` if cancelled."""
    ssh = device.ensure_ssh()
    host = (ssh.host or device.mgmt_ip or "").strip() or "device"
    user = (ssh.username or "").strip() or "user"
    intro = (
        reason.strip()
        or "Reading live config.xml requires root access on pfSense/OPNsense."
    )
    text, ok = QInputDialog.getText(
        parent,
        "Elevate privileges (sudo)",
        f"{intro}\n\n"
        f"sudo password for {user}@{host}\n\n"
        "Same password you type for `sudo id` in an SSH shell on the firewall.",
        QLineEdit.EchoMode.Password,
    )
    if not ok or not (text or "").strip():
        return None
    return text.strip()


def prompt_config_pull_retry(
    parent: QWidget | None,
    device: Device,
    result: SshExportResult,
) -> ConfigPullRetry | None:
    """Prompt when automatic SSH login or sudo elevation failed."""
    if result.needs_ssh_password:
        pw = prompt_ssh_password(parent, device, reason=result.error)
        if pw is None:
            return None
        return ConfigPullRetry(ssh_password=pw)

    if result.needs_sudo_password:
        pw = prompt_sudo_password(parent, device, reason=result.error)
        if pw is None:
            return None
        return ConfigPullRetry(sudo_password=pw)

    return None
