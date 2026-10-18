"""Chassis right-click actions: Pull Config and live Show more queries."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QMessageBox,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from pfsense_checker import app_log
from pfsense_checker.busy import busy_cursor, show_busy_while
from pfsense_checker.ssh_session import (
    export_mikrotik_verbose_ssh,
    export_pfsense_config_ssh,
    run_ssh_commands,
)
from pfsense_checker.topology_site import Device

# (action_id, menu label)
CHASSIS_MENU_ITEMS: tuple[tuple[str, str], ...] = (
    ("pull_config", "Pull Config"),
    ("os", "Show more: OS"),
    ("hardware", "Show more: hardware"),
    ("uptime", "Show more: uptime"),
    ("alerts", "Show more: alerts (SNMP)"),
)


def chassis_detail_commands(kind: str, topic: str) -> list[str]:
    """Remote commands for Show more topics (SSH)."""
    mikrotik = (kind or "").lower() == "mikrotik"
    if topic == "os":
        if mikrotik:
            return ["/system resource print", "/system identity print"]
        return [
            "cat /etc/version 2>/dev/null; "
            "uname -a; "
            "freebsd-version 2>/dev/null; "
            "cat /etc/os-release 2>/dev/null | head -n 12"
        ]
    if topic == "hardware":
        if mikrotik:
            return ["/system resource print", "/system routerboard print"]
        return [
            "sysctl -n hw.model hw.machine hw.ncpu 2>/dev/null; "
            "dmidecode -s system-product-name 2>/dev/null; "
            "pciconf -lv 2>/dev/null | head -n 80"
        ]
    if topic == "uptime":
        if mikrotik:
            return ["/system resource print"]
        return ["uptime; sysctl -n kern.boottime 2>/dev/null"]
    return []


def _show_text(parent: QWidget | None, title: str, body: str) -> None:
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.resize(640, 420)
    lay = QVBoxLayout(dlg)
    view = QPlainTextEdit()
    view.setReadOnly(True)
    view.setPlainText(body)
    lay.addWidget(view)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
    buttons.accepted.connect(dlg.accept)
    lay.addWidget(buttons)
    dlg.exec()


class _ChassisPullWorker(QThread):
    """Pull device config off the UI thread (chassis menu)."""

    finished_result = Signal(object)  # SshExportResult

    def __init__(
        self,
        device: Device,
        *,
        kind: str,
        password: str | None = None,
        sudo_password: str | None = None,
    ) -> None:
        super().__init__()
        self._device = device
        self._kind = kind
        self._password = password
        self._sudo_password = sudo_password

    def run(self) -> None:
        if self._kind in {"pfsense", "opnsense"}:
            result = export_pfsense_config_ssh(
                self._device,
                password=self._password,
                sudo_password=self._sudo_password,
            )
        else:
            result = export_mikrotik_verbose_ssh(
                self._device,
                password=self._password,
            )
        self.finished_result.emit(result)


def pull_config(
    parent: QWidget | None,
    device: Device,
    *,
    password: str | None = None,
    on_success: Callable[[], None] | None = None,
) -> None:
    """Pull live config over SSH (async). *on_success* runs when a file was attached."""
    from pfsense_checker.module_required import ensure_feature

    kind = (device.kind or "").lower()
    if kind in {"pfsense", "opnsense"}:
        if parent is not None and not ensure_feature(
            parent,
            "ssh",
            purpose="Pull pfSense/OPNsense config.xml over SSH",
        ):
            return
        host = (device.ensure_ssh().host or device.mgmt_ip or device.name or "device").strip()
        worker = _ChassisPullWorker(device, kind=kind, password=password)
        worker.finished_result.connect(
            lambda result: _on_chassis_pull_finished(
                parent,
                device,
                result,
                password=password,
                on_success=on_success,
                host=host,
            )
        )
        show_busy_while(worker, message=f"Pulling config.xml from {host}…")
        worker.start()
        return

    host = (device.ensure_ssh().host or device.mgmt_ip or device.name or "device").strip()
    worker = _ChassisPullWorker(device, kind=kind, password=password)
    worker.finished_result.connect(
        lambda result: _on_chassis_mikrotik_pull_finished(
            parent, device, result, on_success=on_success
        )
    )
    show_busy_while(worker, message=f"Exporting /export verbose from {host}…")
    worker.start()


def _on_chassis_mikrotik_pull_finished(
    parent: QWidget | None,
    device: Device,
    result: object,
    *,
    on_success: Callable[[], None] | None,
) -> None:
    from pfsense_checker.ssh_session import SshExportResult

    if not isinstance(result, SshExportResult):
        return
    if not result.ok:
        QMessageBox.warning(
            parent,
            "Pull Config",
            f"Could not export from {device.name}:\n{result.error}",
        )
        return
    QMessageBox.information(
        parent,
        "Pull Config",
        f"Pulled /export verbose from {device.name}:\n{Path(result.path).name}",
    )
    if on_success:
        on_success()


def _on_chassis_pull_finished(
    parent: QWidget | None,
    device: Device,
    result: object,
    *,
    password: str | None,
    on_success: Callable[[], None] | None,
    host: str,
) -> None:
    from pfsense_checker.ssh_prompts import prompt_config_pull_retry
    from pfsense_checker.ssh_session import SshExportResult, save_ssh_credentials

    if not isinstance(result, SshExportResult):
        return

    if (not result.ok) and (
        result.needs_ssh_password or result.needs_sudo_password
    ):
        retry = prompt_config_pull_retry(parent, device, result)
        if retry is None:
            QMessageBox.warning(
                parent,
                "Pull Config",
                f"Could not pull config.xml from {device.name}:\n{result.error}",
            )
            return
        ssh_pw = retry.ssh_password if retry.ssh_password is not None else password
        if retry.ssh_password:
            try:
                save_ssh_credentials(device, retry.ssh_password)
            except Exception:  # noqa: BLE001
                pass
        worker = _ChassisPullWorker(
            device,
            kind=(device.kind or "pfsense").lower(),
            password=ssh_pw,
            sudo_password=retry.sudo_password,
        )
        worker.finished_result.connect(
            lambda retry_result: _on_chassis_pull_finished(
                parent,
                device,
                retry_result,
                password=ssh_pw,
                on_success=on_success,
                host=host,
            )
        )
        msg = f"Pulling config.xml from {host}…"
        if retry.sudo_password:
            msg = f"Pulling config.xml from {host} (sudo)…"
        elif retry.ssh_password:
            msg = f"Pulling config.xml from {host} (SSH login)…"
        show_busy_while(worker, message=msg)
        worker.start()
        return

    if not result.ok:
        QMessageBox.warning(
            parent,
            "Pull Config",
            f"Could not pull config.xml from {device.name}:\n{result.error}",
        )
        return
    QMessageBox.information(
        parent,
        "Pull Config",
        f"Pulled config.xml from {device.name}:\n{Path(result.path).name}",
    )
    app_log.get_logger("ssh").info(
        "Chassis Pull Config device=%s path=%s", device.name, result.path
    )
    if on_success:
        on_success()


def show_ssh_topic(
    parent: QWidget | None,
    device: Device,
    topic: str,
    *,
    password: str | None = None,
) -> None:
    commands = chassis_detail_commands(device.kind, topic)
    if not commands:
        QMessageBox.warning(parent, "Show more", f"Unknown topic: {topic}")
        return
    with busy_cursor():
        result = run_ssh_commands(device, commands, password=password)
    title = f"{device.name} — {topic}"
    if not result.ok:
        QMessageBox.warning(parent, title, result.error or "Query failed")
        return
    _show_text(parent, title, result.output)


def show_snmp_alerts(parent: QWidget | None, device: Device) -> None:
    from pfsense_checker import snmp

    host = ""
    ssh = device.ssh
    if ssh is not None:
        host = (ssh.host or "").strip()
    host = host or (device.mgmt_ip or "").strip()
    if not host:
        QMessageBox.warning(
            parent,
            "Show more: alerts",
            "This chassis has no management IP / SSH host for SNMP.",
        )
        return
    if not snmp.pysnmp_available():
        QMessageBox.warning(
            parent,
            "Show more: alerts",
            "pysnmp is not installed. Use Python Modules to install pysnmp, "
            "then configure Setup → SNMP (v3).",
        )
        return
    if not snmp.snmp_configured():
        QMessageBox.warning(
            parent,
            "Show more: alerts",
            "SNMPv3 is not configured. Enable it under Setup → SNMP (v3).",
        )
        return
    with busy_cursor():
        text, err = snmp.fetch_snmp_alerts(host)
    if err:
        QMessageBox.warning(parent, f"{device.name} — SNMP alerts", err)
        return
    _show_text(parent, f"{device.name} — SNMP alerts", text)


def perform_chassis_action(
    parent: QWidget | None,
    device: Device,
    action: str,
    *,
    password: str | None = None,
) -> bool:
    """Run a chassis menu action. Pull Config is async — returns False immediately."""
    if action == "pull_config":

        def _on_pulled() -> None:
            if parent is not None and hasattr(parent, "device_changed"):
                parent.device_changed.emit(device.name)

        pull_config(parent, device, password=password, on_success=_on_pulled)
        return False
    if action in {"os", "hardware", "uptime"}:
        show_ssh_topic(parent, device, action, password=password)
        return False
    if action == "alerts":
        show_snmp_alerts(parent, device)
        return False
    return False
