"""Home section: stream logs in from pfSense on a chosen port."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QTextCursor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from pfsense_checker import log_pipeline
from pfsense_checker.lan_scan import local_ipv4_nics
from pfsense_checker.syslog_recv import SyslogMessage, SyslogReceiver

_MAX_LINES = 2000


class LogPipelinePage(QWidget):
    """Listen for a live log stream. The port is selectable; default 59000."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._receiver: SyslogReceiver | None = None
        self._settings = log_pipeline.load_settings()
        self._build()

    def _build(self) -> None:
        v = QVBoxLayout(self)
        intro = QLabel(
            "Stream logs in from pfSense. On the firewall, set Remote Logging "
            "to this workstation and the port below. UDP is syslog. TCP on the "
            "same port accepts a newline-delimited log file as it is written. "
            "Lines are shown here; they are not executed. Any host that can "
            "reach this port can insert lines into the stream."
        )
        intro.setWordWrap(True)
        v.addWidget(intro)

        row = QHBoxLayout()
        row.addWidget(QLabel("Incoming port:"))
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(self._settings.port)
        self.port.setToolTip(
            "Port pfSense sends logs to. 59000 is the default and does not "
            "need administrator rights."
        )
        self.port.valueChanged.connect(self._refresh_hint)
        self.port.valueChanged.connect(self._persist_port)
        row.addWidget(self.port)
        self.btn_start = QPushButton("Start stream")
        self.btn_start.clicked.connect(self.start_stream)
        row.addWidget(self.btn_start)
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_stream)
        row.addWidget(self.btn_stop)
        btn_clear = QPushButton("Clear")
        btn_clear.clicked.connect(self._clear)
        row.addWidget(btn_clear)
        row.addStretch(1)
        v.addLayout(row)

        self.hint = QLabel("")
        self.hint.setWordWrap(True)
        self.hint.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        v.addWidget(self.hint)

        self.status = QLabel("Stream stopped.")
        self.status.setWordWrap(True)
        self.status.setStyleSheet("color: #555;")
        v.addWidget(self.status)

        self.view = QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.view.setFont(QFont("Consolas", 10))
        self.view.setPlaceholderText("Waiting for log lines…")
        v.addWidget(self.view, stretch=1)
        self._refresh_hint()

    def _persist_port(self) -> None:
        if not self.port.isEnabled():
            return
        try:
            log_pipeline.save_settings(
                log_pipeline.LogPipelineSettings(port=int(self.port.value()))
            )
        except OSError:
            return

    def _clear(self) -> None:
        self.view.clear()

    def _refresh_hint(self) -> None:
        port = int(self.port.value())
        targets = _listen_targets(port)
        self.hint.setText(
            f"pfSense → Status → System Logs → Settings → Remote Logging: "
            f"{targets}  (UDP {port}). A TCP client can stream a log file to the same port."
        )

    def start_stream(self) -> None:
        self.stop_stream()
        port = log_pipeline.clamp_port(self.port.value())
        self.port.setValue(port)
        settings = log_pipeline.LogPipelineSettings(port=port, bind_host="0.0.0.0")
        try:
            log_pipeline.save_settings(settings)
        except OSError as exc:
            self.status.setText(f"Could not save the port: {exc}")
            return
        receiver = SyslogReceiver(log_pipeline.receiver_settings(settings), parent=self)
        receiver.received.connect(self._on_line)
        receiver.status.connect(self._on_status)
        receiver.failed.connect(self._on_failed)
        self._receiver = receiver
        receiver.start()
        self.port.setEnabled(False)
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.status.setText(f"Opening {port}/udp and {port}/tcp…")
        self.status.setStyleSheet("color: #1565c0;")

    def stop_stream(self) -> None:
        receiver = self._receiver
        self._receiver = None
        if receiver is not None:
            receiver.stop()
            receiver.wait(2000)
        self.port.setEnabled(True)
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        if receiver is not None:
            self.status.setText("Stream stopped.")
            self.status.setStyleSheet("color: #555;")

    def _on_status(self, text: str) -> None:
        if text and text != "Stopped":
            self.status.setText(text)
            self.status.setStyleSheet("color: #2e7d32;")

    def _on_failed(self, text: str) -> None:
        self.stop_stream()
        self.status.setText(f"Listener failed: {text}")
        self.status.setStyleSheet("color: #c62828;")

    def _on_line(self, message: object) -> None:
        if not isinstance(message, SyslogMessage):
            return
        if not message.accepted:
            return
        self.view.appendPlainText(log_pipeline.format_message(message))
        doc = self.view.document()
        extra = doc.blockCount() - _MAX_LINES
        if extra > 0:
            cursor = QTextCursor(doc)
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            for _ in range(extra):
                cursor.select(QTextCursor.SelectionType.BlockUnderCursor)
                cursor.removeSelectedText()
                cursor.deleteChar()
        self.view.moveCursor(QTextCursor.MoveOperation.End)


def _listen_targets(port: int) -> str:
    ips: list[str] = []
    try:
        for nic in local_ipv4_nics():
            ip = str(getattr(nic, "ip", "") or "")
            if ip and not ip.startswith("127."):
                ips.append(ip)
    except OSError:
        ips = []
    if not ips:
        return f"this workstation, port {port}"
    shown = ", ".join(f"{ip}:{port}" for ip in ips[:4])
    return shown
