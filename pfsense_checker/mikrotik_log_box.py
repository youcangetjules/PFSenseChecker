"""The MikroTik block on Logs → Syslog: commands that send a switch's log to this PC.

NetCheck only shows the commands. The operator copies them into each MikroTik.
The address and port follow the Syslog page: the UDP port it listens on, and
the adapter it is bound to (or, when it listens on every adapter, the one that
shares a network with the MikroTiks on Login to Routers).
"""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from pfsense_checker import log_pipeline
from pfsense_checker.lan_scan import local_ipv4_nics

NO_ADDRESS = "# Choose or type the IPv4 address of this PC above."


def local_nics() -> list:
    try:
        return list(local_ipv4_nics())
    except OSError:
        return []


class MikrotikLogBox(QGroupBox):
    """Send to (address) + the commands + Copy / Copy undo."""

    copied = Signal(str)  # a line for the page's status label

    def __init__(self, parent: QWidget | None = None, *, site=None, bind=None,  # noqa: ANN001
                 port: int = log_pipeline.DEFAULT_PORT) -> None:
        """*site*: callable → the Login to Routers site. *bind*: callable → the listener's bind address."""
        super().__init__("MikroTik: send logs to this PC", parent)
        self._site = site
        self._bind = bind
        self._port = log_pipeline.clamp_port(port)
        self._nics: list = []
        self._auto_address = ""  # what NetCheck picked; a different value is the operator's choice

        v = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(QLabel("Send to:"))
        self.address = QComboBox()
        self.address.setEditable(True)
        self.address.setMinimumWidth(320)
        self.address.setToolTip(
            "The address of this PC as the MikroTiks reach it. NetCheck picks the adapter the "
            "listener is bound to, else the one on the routers' network; choose another or type one."
        )
        self.address.currentTextChanged.connect(self._show_commands)
        row.addWidget(self.address)
        self.btn_copy = QPushButton("Copy commands")
        self.btn_copy.clicked.connect(self.copy_commands)
        row.addWidget(self.btn_copy)
        self.btn_copy_undo = QPushButton("Copy undo commands")
        self.btn_copy_undo.clicked.connect(self.copy_undo)
        row.addWidget(self.btn_copy_undo)
        row.addStretch(1)
        v.addLayout(row)

        self.wifi_clients = QCheckBox(
            "Also send Wi-Fi clients connecting and disconnecting (for the CAPsMAN controller)"
        )
        self.wifi_clients.setToolTip(
            "Adds a rule for topics caps,debug. A CAPsMAN controller logs every client that "
            "connects or disconnects there, and nowhere else. Leave it off for a switch that is "
            "only a CAP: there the same topics repeat “no suitable CAPsMAN” while it has no controller."
        )
        self.wifi_clients.toggled.connect(self._show_commands)
        v.addWidget(self.wifi_clients)

        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.text.setFont(QFont("Consolas", 10))
        self.text.setFixedHeight(self.text.fontMetrics().lineSpacing() * 11 + 16)
        v.addWidget(self.text)

        note = QLabel(
            "Paste into a terminal on each MikroTik (RouterOS 7). NetCheck does not change the "
            "router. Start the listener first, or the lines go nowhere. With “Only accept packets "
            "from attached routers” on, the switch has to be on Login to Routers or inside Also "
            "accept from. Debug topics are left out unless you tick the box above: on a CAP, "
            "caps,debug alone can send a line every few seconds."
        )
        note.setWordWrap(True)
        note.setStyleSheet("color: #555;")
        v.addWidget(note)
        self.refresh(reload=True)

    # -- inputs ------------------------------------------------------------- #

    def set_port(self, port: int) -> None:
        self._port = log_pipeline.clamp_port(port)
        self._show_commands()

    def refresh(self, *, reload: bool = False) -> None:
        """Pick the address again (unless the operator chose one). *reload* re-reads the adapters."""
        if reload or not self._nics:
            self._nics = local_nics()
        self._fill_addresses()
        self._show_commands()

    def showEvent(self, event) -> None:  # noqa: ANN001, N802
        """The devices on Login to Routers may have loaded since the box was built."""
        super().showEvent(event)
        self.refresh()

    # -- address ------------------------------------------------------------ #

    def chosen_address(self) -> str:
        """The chosen address: a listed adapter, or whatever IPv4 was typed."""
        text = self.address.currentText().strip()
        idx = self.address.findText(text)
        if idx >= 0:
            return log_pipeline.ipv4(self.address.itemData(idx))
        return log_pipeline.ipv4(text)

    def _pick(self) -> str:
        bound = log_pipeline.ipv4(self._bind() if callable(self._bind) else "")
        if bound:
            return bound  # the listener only hears on that adapter
        site = self._site() if callable(self._site) else None
        return log_pipeline.pick_address(self._nics, log_pipeline.mikrotik_hosts(site))

    def _fill_addresses(self) -> None:
        current = self.chosen_address() if self.address.count() else ""
        keep = current if current != self._auto_address else ""
        self._auto_address = self._pick()
        pick = keep or self._auto_address
        self.address.blockSignals(True)
        self.address.clear()
        for nic in self._nics:
            ip = log_pipeline.ipv4(getattr(nic, "ip", ""))
            if ip:
                self.address.addItem(nic.label(), ip)
        idx = self.address.findData(pick)
        if idx >= 0:
            self.address.setCurrentIndex(idx)
        else:
            self.address.setEditText(pick)
        self.address.blockSignals(False)

    # -- commands ----------------------------------------------------------- #

    def commands(self) -> list[str]:
        return log_pipeline.mikrotik_commands(self.chosen_address(), self._port,
                                              wifi_clients=self.wifi_clients.isChecked())

    def _show_commands(self, *_args) -> None:  # noqa: ANN002
        lines = self.commands()
        self.btn_copy.setEnabled(bool(lines))
        if not lines:
            self.text.setPlainText(NO_ADDRESS)
            return
        undo = log_pipeline.mikrotik_undo_commands()
        self.text.setPlainText(
            "\n".join([*lines, "", "# To stop sending (removes only the lines above):", *undo])
        )

    def copy_commands(self) -> None:
        lines = self.commands()
        if not lines:
            return
        QGuiApplication.clipboard().setText("\n".join(lines) + "\n")
        self.copied.emit(f"Copied {len(lines)} MikroTik commands for {self.chosen_address()}:{self._port}.")

    def copy_undo(self) -> None:
        lines = log_pipeline.mikrotik_undo_commands()
        QGuiApplication.clipboard().setText("\n".join(lines) + "\n")
        self.copied.emit("Copied the 2 commands that stop a MikroTik sending here.")
