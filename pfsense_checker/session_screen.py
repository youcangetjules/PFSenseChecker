"""Session / login screen: SSH connections into site devices + link map.

Shown in the Login to Routers home section. Lists routers/firewalls/switches,
lets you add targets by IP or MAC, search the LAN, test SSH, and shows how
selected devices link using Topology Builder data.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

from PySide6.QtCore import QSettings, Qt, QThread, Signal
from PySide6.QtGui import QAction, QColor, QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from pfsense_checker.lan_scan import (
    LanHost,
    classify_address,
    local_ipv4_cidrs,
    parse_arp_table,
    scan_subnet,
)
from pfsense_checker.busy import busy_cursor, show_busy_while
from pfsense_checker import app_log, net_discovery, oui
from pfsense_checker.site_canvas import SiteTopologyView
from pfsense_checker.ssh_session import (
    export_mikrotik_verbose_ssh,
    export_pfsense_config_ssh,
    identify_kind_from_banner,
    paramiko_available,
    probe_device,
    save_ssh_credentials,
    status_label,
)
from pfsense_checker.topology_site import (
    Device,
    PortComponent,
    SiteTopology,
    refresh_device_topology_from_config,
)

# Device kinds that belong on the session connection list
CONNECTABLE_KINDS = {
    "pfsense",
    "opnsense",
    "mikrotik",
    "juniper",
    "ubiquiti",
    "netgear-managed",
    "switch",
    "router",
    "egress",
    "access-point",
}

# Dropdown order for Kind (best-guess default stays whatever is on the device).
KIND_CHOICES: tuple[str, ...] = (
    "pfsense",
    "opnsense",
    "mikrotik",
    "juniper",
    "ubiquiti",
    "netgear-managed",
    "switch",
    "router",
    "egress",
    "access-point",
)

COL_INCLUDE, COL_DEVICE, COL_KIND, COL_HOST, COL_PORT, COL_USER, COL_STATUS, COL_CONFIG = (
    range(8)
)

# Persisted splitter / column sizes for the Login panel (survive app restarts).
_SETTINGS_ORG = "NetCheck"
_SETTINGS_APP = "PFSenseChecker"
_SETTINGS_LEFT_SPLIT = "session/leftSplitterV3"  # 3 panes: subnets / devices / login
_SETTINGS_MAIN_SPLIT = "session/mainSplitter"
_SETTINGS_RIGHT_SPLIT = "session/rightSplitter"  # map / device details
_SETTINGS_DEVICE_COLS = "session/deviceTableHeader"
_SETTINGS_FOUND_COLS = "session/foundTableHeaderV3"

# Clear blue highlight for the selected device row.
_TABLE_SELECTION_STYLE = """
QTableWidget::item:selected {
    background-color: #1565c0;
    color: #ffffff;
}
QTableWidget::item:selected:active {
    background-color: #1565c0;
    color: #ffffff;
}
QTableWidget::item:selected:!active {
    background-color: #1976d2;
    color: #ffffff;
}
"""

_CONNECT_BTN_GREEN = (
    "QPushButton {"
    " padding: 8px 28px; font-size: 14px; font-weight: bold;"
    " background-color: rgba(46, 125, 50, 200);"
    " border: 2px solid rgb(27, 94, 32); border-radius: 6px;"
    " color: white; }"
    "QPushButton:hover { background-color: rgba(56, 142, 60, 230); }"
    "QPushButton:pressed { background-color: rgb(27, 94, 32); }"
    "QPushButton:disabled {"
    " background-color: rgba(158, 158, 158, 120);"
    " border-color: #9e9e9e; color: #eee; }"
)

_CONNECT_BTN_BLUE = (
    "QPushButton {"
    " padding: 8px 28px; font-size: 14px; font-weight: bold;"
    " background-color: rgba(21, 101, 192, 220);"
    " border: 2px solid rgb(13, 71, 161); border-radius: 6px;"
    " color: white; }"
    "QPushButton:hover { background-color: rgba(25, 118, 210, 240); }"
    "QPushButton:pressed { background-color: rgb(13, 71, 161); }"
    "QPushButton:disabled {"
    " background-color: rgba(21, 101, 192, 200);"
    " border-color: rgb(13, 71, 161); color: white; }"
)

_CONNECT_BTN_GREY = (
    "QPushButton {"
    " padding: 8px 28px; font-size: 14px; font-weight: bold;"
    " background-color: rgba(158, 158, 158, 120);"
    " border: 2px solid #9e9e9e; border-radius: 6px;"
    " color: #eee; }"
)

_CONFIG_BTN_NORMAL = (
    "QPushButton { padding: 2px 10px; }"
)

_CONFIG_BTN_LOADED = (
    "QPushButton {"
    " padding: 2px 10px; font-weight: bold;"
    " background-color: rgba(21, 101, 192, 220);"
    " border: 1px solid rgb(13, 71, 161); border-radius: 3px;"
    " color: white; }"
    "QPushButton:hover { background-color: rgba(25, 118, 210, 240); }"
)

_DEVICE_SUBNET_TAB_STYLE_BASE = """
QTabWidget::pane {
    border: 1px solid #b0bec5;
    background: #fafafa;
    top: -1px;
}
QTabBar::tab {
    min-height: 22px;
    padding: 4px 10px;
    margin-right: 2px;
    border: 1px solid #b0bec5;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}
"""


class _ConnectedDevicePickerDialog(QDialog):
    """List SSH-connected devices and let the user pick one for config pull."""

    def __init__(
        self,
        devices: list[Device],
        *,
        preferred: Device | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Pull config from connected device")
        self.setModal(True)
        self.setMinimumSize(680, 340)
        self._devices = list(devices)
        self.selected_device: Device | None = None

        root = QVBoxLayout(self)
        blurb = QLabel(
            "These devices have an active SSH session on Login to Routers. "
            "Select one to pull its live configuration for Config Check."
        )
        blurb.setWordWrap(True)
        root.addWidget(blurb)

        self.table = QTableWidget(len(self._devices), 5)
        self.table.setHorizontalHeaderLabels(
            ["Device", "Kind", "Host", "Pull", "Cached config"]
        )
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.doubleClicked.connect(self._accept_selection)

        for row, dev in enumerate(self._devices):
            ssh = dev.ensure_ssh()
            host = (ssh.host or dev.mgmt_ip or "—").strip() or "—"
            kind = (dev.kind or "—").strip() or "—"
            kind_l = kind.lower()
            if kind_l in {"pfsense", "opnsense"}:
                pull = "config.xml"
            elif kind_l == "mikrotik" or "mikrotik" in kind_l:
                pull = "/export verbose"
            else:
                pull = "—"
            cached = (
                "yes"
                if SessionScreen._device_has_loaded_config(dev)
                else "—"
            )
            name_item = QTableWidgetItem(dev.name)
            name_item.setData(Qt.ItemDataRole.UserRole, dev.name)
            name_item.setToolTip("SSH connected")
            self.table.setItem(row, 0, name_item)
            self.table.setItem(row, 1, QTableWidgetItem(kind))
            self.table.setItem(row, 2, QTableWidgetItem(host))
            self.table.setItem(row, 3, QTableWidgetItem(pull))
            self.table.setItem(row, 4, QTableWidgetItem(cached))

        root.addWidget(self.table, stretch=1)

        select_row = 0
        if preferred is not None:
            for row, dev in enumerate(self._devices):
                if dev.name == preferred.name:
                    select_row = row
                    break
        if self._devices:
            self.table.selectRow(select_row)

        row_btns = QHBoxLayout()
        row_btns.addStretch(1)
        pull_btn = QPushButton("Pull config")
        pull_btn.setDefault(True)
        pull_btn.clicked.connect(self._accept_selection)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        for b in (pull_btn, cancel):
            b.setFixedSize(120, 32)
            row_btns.addWidget(b)
        root.addLayout(row_btns)

    def _accept_selection(self) -> None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self._devices):
            QMessageBox.information(
                self, "Pull config", "Select a connected device from the list."
            )
            return
        self.selected_device = self._devices[row]
        self.accept()


class _LoadConfigChooserDialog(QDialog):
    """Pick a local config file, or pull config from the device over SSH."""

    def __init__(self, device: Device, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Load config — {device.name}")
        self.setModal(True)
        self.setMinimumWidth(520)
        self.file_path = ""
        self.from_device = False
        kind = (device.kind or "").lower()
        self._mikrotik = kind == "mikrotik" or "mikrotik" in kind
        self._firewall = kind in {"pfsense", "opnsense"}
        self._device_pull = self._mikrotik or self._firewall

        root = QVBoxLayout(self)
        blurb = QLabel(
            f"Attach a configuration to <b>{device.name}</b> "
            f"({device.kind or 'unknown'})."
        )
        blurb.setWordWrap(True)
        root.addWidget(blurb)

        self.radio_file = QRadioButton("Browse for a local file…")
        self.radio_file.setChecked(True)
        root.addWidget(self.radio_file)

        file_row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("pfSense .xml or MikroTik .rsc")
        self.path_edit.setReadOnly(True)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        file_row.addWidget(self.path_edit, stretch=1)
        file_row.addWidget(browse)
        root.addLayout(file_row)
        self._browse_btn = browse

        if self._mikrotik:
            device_label = "Load directly from device  (/export verbose)"
            device_tip = (
                "SSH to the device and run /export verbose, then cache the .rsc locally."
            )
            tip_text = (
                "Requires an SSH login (username + password) already stored "
                "for this device."
            )
        elif self._firewall:
            product = "OPNsense" if kind == "opnsense" else "pfSense"
            device_label = (
                f"Load directly from device  ({product} /cf/conf/config.xml)"
            )
            device_tip = (
                f"SSH to the device and pull config.xml "
                f"(tries /cf/conf/config.xml then /conf/config.xml)."
            )
            tip_text = (
                "Requires Connect with a user that has shell access "
                "(not the webConfigurator-only account)."
            )
        else:
            device_label = "Load directly from device"
            device_tip = (
                "Set Kind to pfsense, opnsense, or mikrotik (or Connect so "
                "the banner can tag the device)."
            )
            tip_text = (
                "Set Kind to pfsense / opnsense / mikrotik to enable device pull."
            )

        self.radio_device = QRadioButton(device_label)
        self.radio_device.setEnabled(self._device_pull)
        self.radio_device.setToolTip(device_tip)
        root.addWidget(self.radio_device)

        tip = QLabel(tip_text)
        tip.setWordWrap(True)
        tip.setStyleSheet("color: #666;")
        root.addWidget(tip)

        self.radio_file.toggled.connect(self._sync_enabled)
        self.radio_device.toggled.connect(self._sync_enabled)
        self._sync_enabled()

        row = QHBoxLayout()
        row.addStretch(1)
        load_btn = QPushButton("Load")
        load_btn.setDefault(True)
        load_btn.clicked.connect(self._on_load)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        for b in (load_btn, cancel):
            b.setFixedSize(120, 32)
            row.addWidget(b)
        root.addLayout(row)

    def _sync_enabled(self) -> None:
        local = self.radio_file.isChecked()
        self.path_edit.setEnabled(local)
        self._browse_btn.setEnabled(local)

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Choose config file",
            self.path_edit.text() or "",
            "Config files (*.xml *.rsc);;pfSense XML (*.xml);;"
            "MikroTik script (*.rsc);;All files (*)",
        )
        if path:
            self.path_edit.setText(path)
            self.radio_file.setChecked(True)

    def _on_load(self) -> None:
        if self.radio_device.isChecked():
            if not self._device_pull:
                QMessageBox.warning(
                    self,
                    "Load Config",
                    "Load from device is supported for pfSense, OPNsense, "
                    "and MikroTik.",
                )
                return
            self.from_device = True
            self.file_path = ""
            self.accept()
            return
        path = self.path_edit.text().strip()
        if not path:
            QMessageBox.information(
                self, "Load Config", "Choose a local file, or select Load from device."
            )
            return
        self.from_device = False
        self.file_path = path
        self.accept()


def subnet_from_parts(address: str, prefix: int) -> str:
    """Normalise *address*/*prefix* to the network CIDR (raises ValueError)."""
    net = ipaddress.ip_network(f"{(address or '').strip()}/{int(prefix)}", strict=False)
    if net.version != 4:
        raise ValueError("IPv4 only")
    return str(net)


def subnet_usable_hosts(cidr: str) -> int:
    net = ipaddress.ip_network(cidr, strict=False)
    return net.num_addresses if net.prefixlen >= 31 else net.num_addresses - 2


class _AlterSubnetDialog(QDialog):
    """Change a subnet's network address and prefix length (pool size)."""

    def __init__(self, cidr: str, taken: list[str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Alter subnet")
        self.setModal(True)
        self._taken = {c for c in taken if c != cidr}
        net = ipaddress.ip_network(cidr, strict=False)
        form = QFormLayout(self)
        self.address = QLineEdit(str(net.network_address))
        self.address.setPlaceholderText("e.g. 192.168.1.0")
        form.addRow("Network address:", self.address)
        self.prefix = QSpinBox()
        self.prefix.setRange(8, 32)
        self.prefix.setPrefix("/")
        self.prefix.setValue(net.prefixlen)
        form.addRow("Prefix (pool size):", self.prefix)
        self.result_label = QLabel("")
        self.result_label.setWordWrap(True)
        form.addRow("", self.result_label)
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        form.addRow(self.buttons)
        self.address.textChanged.connect(self._update)
        self.prefix.valueChanged.connect(self._update)
        self.new_cidr = ""
        self._update()

    def _update(self) -> None:
        ok_btn = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        try:
            cidr = subnet_from_parts(self.address.text(), self.prefix.value())
        except ValueError:
            self.new_cidr = ""
            self.result_label.setText("Not a valid IPv4 network.")
            self.result_label.setStyleSheet("color: #c62828;")
            ok_btn.setEnabled(False)
            return
        self.new_cidr = cidr
        if cidr in self._taken:
            self.result_label.setText(f"{cidr} is already in the list.")
            self.result_label.setStyleSheet("color: #c62828;")
            ok_btn.setEnabled(False)
            return
        hosts = subnet_usable_hosts(cidr)
        note = ""
        if hosts > net_discovery.MAX_SWEEP_HOSTS:
            note = " — larger than /22, so it will not be swept for devices"
        self.result_label.setText(f"→ {cidr} · {hosts} usable addresses{note}")
        self.result_label.setStyleSheet("color: #555;")
        ok_btn.setEnabled(True)


class _ConfigPullWorker(QThread):
    """Pull pfSense/OPNsense config.xml off the UI thread."""

    finished_result = Signal(object)  # SshExportResult

    def __init__(
        self,
        device: Device,
        *,
        password: str | None = None,
        sudo_password: str | None = None,
    ) -> None:
        super().__init__()
        self._device = device
        self._password = password
        self._sudo_password = sudo_password

    def run(self) -> None:
        result = export_pfsense_config_ssh(
            self._device,
            password=self._password,
            sudo_password=self._sudo_password,
        )
        self.finished_result.emit(result)


class _ProbeWorker(QThread):
    """Probe SSH endpoints off the UI thread."""

    result = Signal(str, str, str, str)  # device_name, status, detail, banner
    done = Signal()

    def __init__(self, devices: list[Device], timeout: float = 6.0) -> None:
        super().__init__()
        self._devices = devices
        self._timeout = timeout

    def run(self) -> None:  # noqa: D102
        for dev in self._devices:
            try:
                res = probe_device(dev, timeout=self._timeout)
                self.result.emit(
                    dev.name, res.status, res.detail, res.banner
                )
            except Exception as exc:  # noqa: BLE001
                self.result.emit(dev.name, "unreachable", str(exc), "")
        self.done.emit()


class _ScanWorker(QThread):
    """Subnet discovery off the UI thread."""

    finished_ok = Signal(list)  # list[LanHost]
    failed = Signal(str)

    def __init__(self, cidr: str) -> None:
        super().__init__()
        self._cidr = cidr

    def run(self) -> None:  # noqa: D102
        try:
            hosts = scan_subnet(self._cidr, ping=True, check_ssh=True)
            self.finished_ok.emit(hosts)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class _DiscoveryWorker(QThread):
    """Sweep the listed subnets one at a time for network devices."""

    subnet_started = Signal(str)
    subnet_done = Signal(str, list)  # cidr, list[SeenDevice]
    subnet_failed = Signal(str, str, bool)  # cidr, message, too_large

    def __init__(self, cidrs: list[str], refresh: set[str] | None = None) -> None:
        super().__init__()
        self._cidrs = list(cidrs)
        self._refresh = set(refresh or ())

    def run(self) -> None:  # noqa: D102
        gateways = net_discovery.default_gateways()
        for cidr in self._cidrs:
            if self.isInterruptionRequested():
                return
            self.subnet_started.emit(cidr)
            try:
                seen = net_discovery.discover(
                    cidr,
                    gateways=gateways,
                    should_stop=self.isInterruptionRequested,
                    refresh=cidr in self._refresh,
                )
            except net_discovery.SweepTooLarge as exc:
                self.subnet_failed.emit(cidr, str(exc), True)
                continue
            except Exception as exc:  # noqa: BLE001
                self.subnet_failed.emit(cidr, str(exc), False)
                continue
            self.subnet_done.emit(cidr, seen)


class _InventoryWorker(QThread):
    """After Connect: collect remote ports / IPs for the topology map."""

    finished_ok = Signal(str, object)  # device_name, InventoryResult
    failed = Signal(str, str)  # device_name, error

    def __init__(self, device: Device, password: str | None = None) -> None:
        super().__init__()
        self._device = device
        self._password = password

    def run(self) -> None:  # noqa: D102
        from pfsense_checker import ssh_inventory

        try:
            result = ssh_inventory.collect_interfaces(
                self._device, password=self._password
            )
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(self._device.name, str(exc))
            return
        if result.ok:
            self.finished_ok.emit(self._device.name, result)
        else:
            self.failed.emit(self._device.name, result.error or "inventory failed")


class _AdapterLabelWorker(QThread):
    """Resolve the local NIC summary off the UI thread (PowerShell on Windows)."""

    finished_ok = Signal(str)

    def __init__(self, cidr: str = "") -> None:
        super().__init__()
        self._cidr = cidr

    def run(self) -> None:
        from pfsense_checker import subnet_health

        try:
            text = subnet_health.describe_local_adapter(self._cidr)
        except Exception:  # noqa: BLE001
            text = "Local adapter: unavailable"
        self.finished_ok.emit(text)


class SessionScreen(QWidget):
    """Login screen: SSH targets on the left, device link map on the right."""

    enter_workspace = Signal()
    load_site_requested = Signal()
    save_topology_requested = Signal()
    open_folder_requested = Signal()
    ssh_summary_changed = Signal(str)
    site_changed = Signal()  # devices added/updated — parent may refresh
    config_pulled_for_check = Signal(str)  # path to pulled config.xml / .rsc

    def __init__(self) -> None:
        super().__init__()
        self._site: SiteTopology | None = None
        self._worker: _ProbeWorker | None = None
        self._scan_worker: _ScanWorker | None = None
        self._inventory_worker: _InventoryWorker | None = None
        self._config_pull_worker: _ConfigPullWorker | None = None
        self._updating = False
        self._syncing_selection = False
        self._found_hosts: list[LanHost] = []
        # Subnets panel "Seen": network devices found per listed subnet.
        self._seen: dict[str, list] = {}
        self._seen_state: dict[str, str] = {}
        self._seen_error: dict[str, str] = {}
        self._discovery_worker: _DiscoveryWorker | None = None
        self._discovery_queue: list[str] = []
        self._discovery_refresh: set[str] = set()  # explicit scans: look again
        self._device_tab_user_chosen = False
        self._connected_name: str | None = None
        self._config_pull_for_check = False
        self._splitters_restored = False
        self._adapter_label_worker: _AdapterLabelWorker | None = None
        self._build()

    # ------------------------------------------------------------------ UI

    def _build(self) -> None:
        outer = QVBoxLayout(self)

        title = QLabel("Login to Routers")
        tf = QFont()
        tf.setPointSize(14)
        tf.setBold(True)
        title.setFont(tf)
        outer.addWidget(title)

        sub = QLabel(
            "Search the LAN, add found devices to the list, then select one "
            "device and log in with username + password (port 22) and/or a "
            "certificate. Passwords are stored in the OS keyring, never in "
            "site files."
            + (
                ""
                if paramiko_available()
                else "  Note: 'paramiko' is not installed — tests check SSH "
                "reachability only (pip install paramiko for full login checks)."
            )
        )
        sub.setWordWrap(True)
        sub.setStyleSheet("color: #555;")
        outer.addWidget(sub)

        split = QSplitter()
        outer.addWidget(split, stretch=1)

        # --- left: Subnets → Devices → Login (vertical splitters) ---
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)

        # ---------- A) Subnets ----------
        subnet_box = QGroupBox("Subnets")
        sn = QVBoxLayout(subnet_box)
        self.subnet_table = QTableWidget(0, 4)
        self.subnet_table.setHorizontalHeaderLabels(["Subnet", "Seen", "Connected", ""])
        self.subnet_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        for col in (1, 2, 3):
            self.subnet_table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents
            )
        self.subnet_table.horizontalHeader().setVisible(False)
        self.subnet_table.verticalHeader().setVisible(False)
        self.subnet_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.subnet_table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        self.subnet_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.subnet_table.setMinimumHeight(40)
        self.subnet_table.setToolTip(
            "Site subnets — select one to use it as the default for "
            "Search for devices. Click Devices to list hosts on that subnet "
            "in the Devices panel below."
        )
        self.subnet_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.subnet_table.customContextMenuRequested.connect(self._subnet_context_menu)
        self.subnet_table.itemSelectionChanged.connect(self._on_subnet_row_selected)
        sn.addWidget(self.subnet_table)
        subnet_row = QHBoxLayout()
        self.subnet_edit = QLineEdit()
        self.subnet_edit.setPlaceholderText("e.g. 192.168.1.0/24")
        self.subnet_edit.returnPressed.connect(self._add_subnet)
        subnet_row.addWidget(self.subnet_edit, stretch=1)
        btn_subnet_add = QPushButton("Add subnet")
        btn_subnet_add.clicked.connect(self._add_subnet)
        subnet_row.addWidget(btn_subnet_add)
        btn_subnet_del = QPushButton("Remove")
        btn_subnet_del.clicked.connect(lambda: self._remove_subnet())
        subnet_row.addWidget(btn_subnet_del)
        btn_subnet_import = QPushButton("From pfSense config…")
        btn_subnet_import.setToolTip(
            "Read the main router's pfSense config and import its "
            "interface subnets"
        )
        btn_subnet_import.clicked.connect(self._import_subnets_from_pfsense)
        subnet_row.addWidget(btn_subnet_import)
        btn_live_subnets = QPushButton("Show live subnets")
        btn_live_subnets.setToolTip(
            "List IPv4 subnets on this PC's network adapters and add any "
            "new ones to the site list"
        )
        btn_live_subnets.clicked.connect(self._show_live_subnets)
        subnet_row.addWidget(btn_live_subnets)
        self.btn_rescan = QPushButton("Rescan subnets")
        self.btn_rescan.setToolTip(
            "Look for routers, switches, gateways and firewalls (pfSense, "
            "OPNsense) on every listed subnet: ping + ARP, then TCP connects "
            "to 22, 23, 80, 443, 830, 8291 and 8728 only, the SSH banner and "
            "the web GUI title. No logins. Subnets larger than /22 are skipped."
        )
        self.btn_rescan.clicked.connect(lambda: self._start_discovery(rescan=True))
        subnet_row.addWidget(self.btn_rescan)
        sn.addLayout(subnet_row)

        # ---------- B) Devices (find + session list) ----------
        list_box = QGroupBox("Devices")
        list_lay = QVBoxLayout(list_box)

        addr_row = QHBoxLayout()
        addr_row.addWidget(QLabel("IP / MAC:"))
        self.address_edit = QLineEdit()
        self.address_edit.setPlaceholderText(
            "Subnet seed or address — use Search, then select a found device"
        )
        addr_row.addWidget(self.address_edit, stretch=1)
        self.btn_search = QPushButton("Search for devices")
        self.btn_search.setToolTip(
            "Ping-sweep a subnet, merge ARP, and list found hosts below"
        )
        self.btn_search.clicked.connect(self._search_for_devices)
        addr_row.addWidget(self.btn_search)
        self.btn_add = QPushButton("Add")
        self.btn_add.setToolTip("Add the selected found device to the login list")
        self.btn_add.setEnabled(False)
        self.btn_add.clicked.connect(self._add_selected_found)
        addr_row.addWidget(self.btn_add)
        self.btn_add_all = QPushButton("Add all")
        self.btn_add_all.setToolTip("Add every found device to the login list")
        self.btn_add_all.setEnabled(False)
        self.btn_add_all.clicked.connect(self._add_all_found)
        addr_row.addWidget(self.btn_add_all)
        list_lay.addLayout(addr_row)

        self.found_label = QLabel("Found devices — select one to enable Add")
        self.found_label.setStyleSheet("color: #555;")
        self.found_label.setVisible(False)
        list_lay.addWidget(self.found_label)
        self.found_table = QTableWidget(0, 6)
        self.found_table.setHorizontalHeaderLabels(
            ["IP", "MAC", "Vendor", "SSH :22", "HTTP :80", "HTTPS :443"]
        )
        found_hdr = self.found_table.horizontalHeader()
        found_hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        found_hdr.setStretchLastSection(False)
        self.found_table.setColumnWidth(0, 120)
        self.found_table.setColumnWidth(1, 130)
        self.found_table.setColumnWidth(2, 140)
        self.found_table.setColumnWidth(3, 70)
        self.found_table.setColumnWidth(4, 70)
        self.found_table.setColumnWidth(5, 80)
        self.found_table.verticalHeader().setVisible(False)
        self.found_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.found_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.found_table.setStyleSheet(_TABLE_SELECTION_STYLE)
        self.found_table.setMinimumHeight(60)
        self.found_table.setMaximumHeight(160)
        self.found_table.setVisible(False)
        self.found_table.itemSelectionChanged.connect(self._on_found_selection_changed)
        list_lay.addWidget(self.found_table)
        self.local_adapter_label = QLabel("")
        self.local_adapter_label.setWordWrap(True)
        self.local_adapter_label.setStyleSheet("color: #1565c0; font-weight: 600;")
        self.local_adapter_label.setVisible(False)
        list_lay.addWidget(self.local_adapter_label)

        self.device_subnet_tabs = QTabWidget()
        self.device_subnet_tabs.setDocumentMode(False)
        self.device_subnet_tabs.setToolTip(
            "One tab per subnet — session devices are grouped by SSH host / IP"
        )
        self.device_subnet_tabs.currentChanged.connect(self._on_device_subnet_tab_changed)
        list_lay.addWidget(self.device_subnet_tabs)
        self._device_subnet_keys: list[str] = []

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(
            [
                "Use",
                "Device",
                "Kind",
                "SSH Host",
                "Port",
                "User",
                "Status",
                "Config",
            ]
        )
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hdr.setStretchLastSection(False)
        self.table.setColumnWidth(COL_INCLUDE, 44)
        self.table.setColumnWidth(COL_DEVICE, 160)
        self.table.setColumnWidth(COL_KIND, 120)
        self.table.setColumnWidth(COL_HOST, 120)
        self.table.setColumnWidth(COL_PORT, 50)
        self.table.setColumnWidth(COL_USER, 90)
        self.table.setColumnWidth(COL_STATUS, 110)
        self.table.setColumnWidth(COL_CONFIG, 120)
        self.table.verticalHeader().setVisible(False)
        # Persist widths only after both tables exist (setColumnWidth emits resize).
        found_hdr.sectionResized.connect(self._save_column_widths)
        hdr.sectionResized.connect(self._save_column_widths)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setStyleSheet(_TABLE_SELECTION_STYLE)
        self.table.setEditTriggers(
            QTableWidget.EditTrigger.DoubleClicked
            | QTableWidget.EditTrigger.EditKeyPressed
            | QTableWidget.EditTrigger.AnyKeyPressed
        )
        self.table.cellChanged.connect(self._cell_changed)
        self.table.itemSelectionChanged.connect(self._on_device_selection_changed)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._table_context_menu)
        list_lay.addWidget(self.table, stretch=1)

        # ---------- C) Login ----------
        login_box = QGroupBox("Login (SSH, port 22)")
        lg = QVBoxLayout(login_box)

        user_row = QHBoxLayout()
        user_row.addWidget(QLabel("Username:"))
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText(
            "SSH username (e.g. admin / root) — select a device to apply it"
        )
        self.username_edit.setClearButtonEnabled(True)
        self.username_edit.textEdited.connect(self._username_edited)
        self.username_edit.textEdited.connect(self._refresh_connect_button)
        user_row.addWidget(self.username_edit, stretch=1)
        lg.addLayout(user_row)

        pw_row = QHBoxLayout()
        pw_row.addWidget(QLabel("Password:"))
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText(
            "password for the selected device — stored in OS keyring"
        )
        self.password.textChanged.connect(self._refresh_connect_button)
        pw_row.addWidget(self.password, stretch=1)
        btn_save = QPushButton("Save credentials")
        btn_save.setToolTip(
            "Store password in Windows Credential Manager; save a salted "
            "hash + username/IP in the netcheck DB (never the plaintext password)"
        )
        btn_save.clicked.connect(self._save_credentials)
        pw_row.addWidget(btn_save)
        lg.addLayout(pw_row)

        cert_row = QHBoxLayout()
        cert_row.addWidget(QLabel("Certificate:"))
        self.key_edit = QLineEdit()
        self.key_edit.setPlaceholderText(
            "optional private key / certificate file (OpenSSH format)"
        )
        self.key_edit.setClearButtonEnabled(True)
        self.key_edit.textEdited.connect(self._key_path_edited)
        self.key_edit.textEdited.connect(self._refresh_connect_button)
        cert_row.addWidget(self.key_edit, stretch=1)
        self.btn_browse_key = QPushButton("Browse…")
        self.btn_browse_key.clicked.connect(self._browse_key)
        cert_row.addWidget(self.btn_browse_key)
        lg.addLayout(cert_row)

        connect_row = QHBoxLayout()
        self.btn_test_sel = QPushButton("Test selected")
        self.btn_test_sel.setEnabled(False)
        self.btn_test_sel.setToolTip(
            "Test SSH to the selected found host or device in the list"
        )
        self.btn_test_sel.clicked.connect(lambda: self._test(selected_only=True))
        connect_row.addWidget(self.btn_test_sel)
        btn_test_all = QPushButton("Test all ticked")
        btn_test_all.clicked.connect(lambda: self._test(selected_only=False))
        connect_row.addWidget(btn_test_all)
        connect_row.addStretch(1)
        self.btn_connect = QPushButton("Connect")
        self.btn_connect.setMinimumHeight(36)
        self.btn_connect.setMinimumWidth(max(btn_save.sizeHint().width(), 120))
        self.btn_connect.setToolTip(
            "SSH into the selected device — needs username + password, "
            "or username + certificate"
        )
        self.btn_connect.setEnabled(False)
        self.btn_connect.setStyleSheet(_CONNECT_BTN_GREY)
        self.btn_connect.clicked.connect(self._connect_selected)
        connect_row.addWidget(self.btn_connect)
        lg.addLayout(connect_row)

        self.left_split = QSplitter(Qt.Orientation.Vertical)
        self.left_split.setChildrenCollapsible(False)
        self.left_split.addWidget(subnet_box)
        self.left_split.addWidget(list_box)
        self.left_split.addWidget(login_box)
        self.left_split.setStretchFactor(0, 1)
        self.left_split.setStretchFactor(1, 3)
        self.left_split.setStretchFactor(2, 1)
        self.left_split.setSizes([160, 420, 200])
        self.left_split.splitterMoved.connect(self._save_splitter_state)
        lv.addWidget(self.left_split, stretch=1)

        split.addWidget(left)

        # --- right: link map + device details ---
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.addWidget(QLabel("How the session devices link together:"))
        self.right_split = QSplitter(Qt.Orientation.Vertical)
        self.right_split.setChildrenCollapsible(False)
        self.map_view = SiteTopologyView()
        # Editable: drag chassis; drag port→port to link (Save Topology persists).
        self.map_view.set_locked(False)
        self.map_view.set_ssh_password_provider(lambda: self.password.text())
        self.map_view.positions_changed.connect(self.site_changed.emit)
        self.map_view.links_changed.connect(self.site_changed.emit)
        self.map_view.device_changed.connect(self._on_map_device_changed)
        self.right_split.addWidget(self.map_view)

        detail_box = QGroupBox("Device details")
        detail_lay = QVBoxLayout(detail_box)
        self.detail_split = QSplitter(Qt.Orientation.Horizontal)
        self.detail_split.setChildrenCollapsible(False)

        summary_col = QWidget()
        summary_lay = QVBoxLayout(summary_col)
        summary_lay.setContentsMargins(0, 0, 0, 0)
        summary_lay.setSpacing(4)
        summary_lay.addWidget(QLabel("Device"))
        self.device_detail = QPlainTextEdit()
        self.device_detail.setReadOnly(True)
        self.device_detail.setPlaceholderText(
            "Select a device — model, software version, SSH, links."
        )
        self.device_detail.setMinimumHeight(96)
        summary_lay.addWidget(self.device_detail, stretch=1)

        ports_col = QWidget()
        ports_lay = QVBoxLayout(ports_col)
        ports_lay.setContentsMargins(0, 0, 0, 0)
        ports_lay.setSpacing(4)
        ports_lay.addWidget(QLabel("Ports / interfaces"))
        self.device_detail_ports = QPlainTextEdit()
        self.device_detail_ports.setReadOnly(True)
        self.device_detail_ports.setFont(QFont("Consolas", 9))
        self.device_detail_ports.setPlaceholderText(
            "Port list appears here after Connect (SSH inventory)."
        )
        self.device_detail_ports.setMinimumHeight(96)
        ports_lay.addWidget(self.device_detail_ports, stretch=1)

        self.detail_split.addWidget(summary_col)
        self.detail_split.addWidget(ports_col)
        self.detail_split.setStretchFactor(0, 2)
        self.detail_split.setStretchFactor(1, 3)
        self.detail_split.setSizes([280, 360])
        detail_lay.addWidget(self.detail_split)
        self.right_split.addWidget(detail_box)
        self.right_split.setStretchFactor(0, 4)
        self.right_split.setStretchFactor(1, 1)
        self.right_split.setSizes([480, 140])
        self.right_split.splitterMoved.connect(self._save_splitter_state)
        rv.addWidget(self.right_split, stretch=1)
        split.addWidget(right)
        split.setSizes([540, 640])
        self.main_split = split
        self.main_split.splitterMoved.connect(self._save_splitter_state)

        # --- bottom bar ---
        bottom = QHBoxLayout()
        btn_load = QPushButton("Load Topology")
        btn_load.setToolTip("Load the single saved topology for this app")
        btn_load.clicked.connect(self.load_site_requested.emit)
        bottom.addWidget(btn_load)
        btn_save_topo = QPushButton("Save Topology")
        btn_save_topo.setToolTip(
            "Save the current site as the one topology kept for Login / Topology "
            "(overwrites the previous save)"
        )
        btn_save_topo.clicked.connect(self.save_topology_requested.emit)
        bottom.addWidget(btn_save_topo)
        btn_save_db = QPushButton("Save Connectivity to DB")
        btn_save_db.setToolTip(
            "Write subnets, devices (SSH status), and links into the netcheck "
            "PostgreSQL database as a timestamped snapshot (passwords never stored)"
        )
        btn_save_db.clicked.connect(self._save_connectivity_to_db)
        bottom.addWidget(btn_save_db)
        btn_folder = QPushButton("Import config folder…")
        btn_folder.clicked.connect(self.open_folder_requested.emit)
        bottom.addWidget(btn_folder)
        bottom.addStretch(1)
        self.btn_offline = QPushButton("Work offline")
        self.btn_offline.setToolTip("Skip SSH — analyze from files only")
        self.btn_offline.clicked.connect(self.enter_workspace.emit)
        bottom.addWidget(self.btn_offline)
        self.btn_enter = QPushButton("Open full workspace")
        self.btn_enter.setStyleSheet(
            "QPushButton { padding: 4px 24px;"
            " background-color: rgba(21, 101, 192, 128);"
            " border: 1px solid rgb(21, 101, 192); border-radius: 3px;"
            " color: white; font-weight: bold; }"
            "QPushButton:hover { background-color: rgba(21, 101, 192, 178); }"
        )
        self.btn_enter.clicked.connect(self.enter_workspace.emit)
        bottom.addWidget(self.btn_enter)
        outer.addLayout(bottom)

    # -------------------------------------------------- splitter / column persistence

    def showEvent(self, event) -> None:  # noqa: N802, ANN001
        super().showEvent(event)
        # Restore after the widget has a real size so splitter ratios stick.
        if not self._splitters_restored:
            self._splitters_restored = True
            self._restore_splitter_state()
            self._restore_column_widths()
        self._update_local_adapter_label()

    def hideEvent(self, event) -> None:  # noqa: N802, ANN001
        self._save_splitter_state()
        self._save_column_widths()
        super().hideEvent(event)

    def _ui_settings(self) -> QSettings:
        return QSettings(_SETTINGS_ORG, _SETTINGS_APP)

    def _save_splitter_state(self, *_args) -> None:  # noqa: ANN002
        settings = self._ui_settings()
        settings.setValue(_SETTINGS_LEFT_SPLIT, self.left_split.saveState())
        settings.setValue(_SETTINGS_MAIN_SPLIT, self.main_split.saveState())
        if hasattr(self, "right_split"):
            settings.setValue(_SETTINGS_RIGHT_SPLIT, self.right_split.saveState())

    def _restore_splitter_state(self) -> None:
        settings = self._ui_settings()
        # Drop obsolete splitter keys from earlier panel layouts.
        for obsolete in (
            "session/leftSplitter",
            "session/leftSplitterV2",
        ):
            if settings.contains(obsolete):
                settings.remove(obsolete)
        left = settings.value(_SETTINGS_LEFT_SPLIT)
        if left is not None:
            self.left_split.restoreState(left)
            # Reject a restore that doesn't match the current 3-pane layout.
            if len(self.left_split.sizes()) != 3:
                self.left_split.setSizes([160, 420, 200])
        main = settings.value(_SETTINGS_MAIN_SPLIT)
        if main is not None:
            self.main_split.restoreState(main)
        right = settings.value(_SETTINGS_RIGHT_SPLIT)
        if right is not None and hasattr(self, "right_split"):
            self.right_split.restoreState(right)
            if len(self.right_split.sizes()) != 2:
                self.right_split.setSizes([480, 140])

    def _infer_device_subnet(self, dev: Device) -> str:
        """Best subnet tab key for *dev* (site CIDR or inferred /24)."""
        host = ((dev.ssh.host if dev.ssh else "") or dev.mgmt_ip or "").strip()
        if not host:
            return "Unassigned"
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return "Unassigned"
        best = ""
        best_len = -1
        subnets = list(self._site.subnets) if self._site else []
        for cidr in subnets:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if ip in net and net.prefixlen > best_len:
                best = str(net)
                best_len = net.prefixlen
        if best:
            return best
        if isinstance(ip, ipaddress.IPv4Address):
            parts = str(ip).split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return "Other"

    def _device_subnet_groups(self) -> dict[str, list[Device]]:
        """Devices grouped by subnet tab, including empty site subnets."""
        groups: dict[str, list[Device]] = {}
        if self._site:
            for cidr in self._site.subnets:
                groups.setdefault(cidr, [])
        for dev in self._connectable_devices():
            key = self._infer_device_subnet(dev)
            groups.setdefault(key, []).append(dev)
        return groups

    def _rebuild_device_subnet_tabs(self) -> None:
        """Rebuild subnet tabs above the session device table."""
        if not hasattr(self, "device_subnet_tabs"):
            return
        groups = self._device_subnet_groups()
        ordered: list[str] = []
        seen: set[str] = set()
        if self._site:
            for cidr in self._site.subnets:
                if cidr not in seen:
                    ordered.append(cidr)
                    seen.add(cidr)
        for key in sorted(groups.keys()):
            if key not in seen:
                ordered.append(key)
                seen.add(key)
        prev = ""
        if self._device_subnet_keys and self.device_subnet_tabs.count():
            idx = self.device_subnet_tabs.currentIndex()
            if 0 <= idx < len(self._device_subnet_keys):
                prev = self._device_subnet_keys[idx]
        self.device_subnet_tabs.blockSignals(True)
        self.device_subnet_tabs.clear()
        self._device_subnet_keys = ordered
        for key in ordered:
            count = len(groups.get(key, []))
            self.device_subnet_tabs.addTab(QWidget(), f"{key} ({count})")
        target = 0
        if prev in ordered and (self._device_tab_user_chosen or groups.get(prev)):
            target = ordered.index(prev)
        else:
            populated = [i for i, k in enumerate(ordered) if groups.get(k)]
            if populated:
                target = populated[0]
        if ordered:
            self.device_subnet_tabs.setCurrentIndex(target)
        self.device_subnet_tabs.blockSignals(False)
        self._apply_device_subnet_tab_styles(ordered, groups)
        self._apply_device_subnet_tab_filter()

    def _apply_device_subnet_tab_styles(
        self,
        ordered: list[str],
        groups: dict[str, list[Device]],
    ) -> None:
        """Green tabs when a subnet has devices; grey when empty."""
        if not hasattr(self, "device_subnet_tabs"):
            return
        rules = [_DEVICE_SUBNET_TAB_STYLE_BASE.strip()]
        for i, key in enumerate(ordered):
            populated = len(groups.get(key, [])) > 0
            n = i + 1
            if populated:
                rules.append(
                    f"QTabBar::tab:nth-child({n}) {{"
                    f" background-color: #c8e6c9; color: #1b5e20;"
                    f"}}"
                    f"QTabBar::tab:nth-child({n}):selected {{"
                    f" background-color: #81c784; color: #1b5e20; font-weight: bold;"
                    f"}}"
                )
            else:
                rules.append(
                    f"QTabBar::tab:nth-child({n}) {{"
                    f" background-color: #cfd8dc; color: #546e7a;"
                    f"}}"
                    f"QTabBar::tab:nth-child({n}):selected {{"
                    f" background-color: #b0bec5; color: #37474f; font-weight: bold;"
                    f"}}"
                )
        self.device_subnet_tabs.setStyleSheet("\n".join(rules))

    def _apply_device_subnet_tab_filter(self) -> None:
        """Show only devices belonging to the active subnet tab."""
        if not self._device_subnet_keys or not hasattr(self, "table"):
            return
        idx = self.device_subnet_tabs.currentIndex()
        if idx < 0 or idx >= len(self._device_subnet_keys):
            return
        want = self._device_subnet_keys[idx]
        for row in range(self.table.rowCount()):
            dev = self._device_for_row(row)
            if dev is None:
                self.table.setRowHidden(row, True)
                continue
            self.table.setRowHidden(row, self._infer_device_subnet(dev) != want)
        row = self._exactly_one_selected_row()
        if row is not None and self.table.isRowHidden(row):
            self.table.clearSelection()
            self._refresh_device_details(None)

    def _on_device_subnet_tab_changed(self, _index: int) -> None:
        self._device_tab_user_chosen = True
        self._apply_device_subnet_tab_filter()
        self._refresh_connect_button()

    def _select_device_tab(self, cidr: str) -> None:
        """Show the Devices panel tab for *cidr*."""
        if cidr in self._device_subnet_keys:
            idx = self._device_subnet_keys.index(cidr)
            if self.device_subnet_tabs.currentIndex() != idx:
                self.device_subnet_tabs.setCurrentIndex(idx)
            else:
                self._apply_device_subnet_tab_filter()

    def _on_subnet_row_selected(self) -> None:
        cidr = self._selected_subnet()
        if cidr:
            self._select_device_tab(cidr)

    def _focus_subnet_tab_for_device(self, dev: Device | None) -> None:
        if dev is None or not self._device_subnet_keys:
            return
        key = self._infer_device_subnet(dev)
        if key in self._device_subnet_keys:
            self.device_subnet_tabs.setCurrentIndex(self._device_subnet_keys.index(key))

    def _format_device_summary(self, dev: Device | None) -> str:
        if dev is None:
            return ""
        model = (dev.model or dev.hardware or "").strip()
        if not model:
            title = dev.chassis_title()
            if title and title != dev.name:
                model = title
        lines: list[str] = [
            f"Name: {dev.name}",
            f"Model: {model or '—'}",
            f"Software: {(dev.software_version or '—').strip() or '—'}",
            f"Kind: {dev.kind or '—'}",
        ]
        if dev.role:
            lines.append(f"Role: {dev.role}")
        if dev.secpol:
            lines.append(f"SECPOL: {dev.secpol}")
        subnet = self._infer_device_subnet(dev)
        if subnet not in ("Unassigned", "Other"):
            lines.append(f"Subnet: {subnet}")
        ssh = dev.ssh
        if ssh:
            host = ssh.host or dev.mgmt_ip or "—"
            lines.append(
                f"SSH: {host}:{ssh.port or 22}  user={ssh.username or '—'}"
            )
            status = ssh.last_status or "never"
            line = f"Status: {status}"
            if ssh.last_error:
                line += f" — {ssh.last_error}"
            lines.append(line)
            if ssh.last_ok_at:
                lines.append(f"Last OK: {ssh.last_ok_at}")
        if self._site:
            links = [
                lk
                for lk in self._site.links
                if lk.a_device == dev.name or lk.b_device == dev.name
            ]
            if links:
                lines.append(f"Links: {len(links)}")
                for lk in links[:10]:
                    lines.append(
                        f"  • {lk.a_device}:{lk.a_port or '—'} ↔ "
                        f"{lk.b_device}:{lk.b_port or '—'}"
                    )
                if len(links) > 10:
                    lines.append(f"  … +{len(links) - 10} more")
        if dev.notes:
            lines.append(f"Notes: {dev.notes}")
        return "\n".join(lines)

    def _format_device_ports(self, dev: Device | None) -> str:
        if dev is None:
            return ""
        n_comp = len(dev.components)
        n_ports = len(dev.ports)
        if not n_comp and not n_ports:
            return "No ports — Connect to collect interface inventory."
        lines: list[str] = [f"{n_comp or n_ports} port(s) / interface(s)", ""]
        items = dev.components if dev.components else [
            PortComponent(name=p) for p in dev.ports
        ]
        for comp in items:
            extra = comp.address or comp.media or comp.slot or ""
            lines.append(
                f"{comp.name}" + (f"  {extra}" if extra else "")
            )
        return "\n".join(lines)

    def _refresh_device_details(self, dev: Device | None = None) -> None:
        summary = getattr(self, "device_detail", None)
        ports = getattr(self, "device_detail_ports", None)
        if summary is None and ports is None:
            return
        if dev is None:
            row = self._exactly_one_selected_row()
            dev = self._device_for_row(row) if row is not None else None
        if summary is not None:
            summary.setPlainText(self._format_device_summary(dev))
        if ports is not None:
            ports.setPlainText(self._format_device_ports(dev))

    def _save_column_widths(self, *_args) -> None:  # noqa: ANN002
        if not hasattr(self, "table") or not hasattr(self, "found_table"):
            return
        settings = self._ui_settings()
        settings.setValue(
            _SETTINGS_DEVICE_COLS, self.table.horizontalHeader().saveState()
        )
        settings.setValue(
            _SETTINGS_FOUND_COLS, self.found_table.horizontalHeader().saveState()
        )

    def _restore_column_widths(self) -> None:
        settings = self._ui_settings()
        device_hdr = self.table.horizontalHeader()
        found_hdr = self.found_table.horizontalHeader()
        device_state = settings.value(_SETTINGS_DEVICE_COLS)
        if device_state is not None:
            device_hdr.blockSignals(True)
            device_hdr.restoreState(device_state)
            device_hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            device_hdr.blockSignals(False)
        found_state = settings.value(_SETTINGS_FOUND_COLS)
        if found_state is not None:
            found_hdr.blockSignals(True)
            found_hdr.restoreState(found_state)
            found_hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            found_hdr.blockSignals(False)

    # ------------------------------------------------------------- populate

    def set_site(self, site: SiteTopology) -> None:
        """Refresh the connection table and link map from the topology."""
        self._site = site
        self._updating = True
        devices = self._connectable_devices()

        hosts_without_user: list[str] = []
        for dev in devices:
            ssh = dev.ensure_ssh()
            if not (ssh.username or "").strip():
                host = (ssh.host or dev.mgmt_ip or "").strip()
                if host:
                    hosts_without_user.append(host)

        creds_map: dict[str, dict] = {}
        if hosts_without_user:
            from pfsense_checker import ssh_credentials_db

            try:
                creds_map = ssh_credentials_db.get_credentials_map(
                    hosts_without_user
                )
            except Exception:  # noqa: BLE001
                creds_map = {}

        self.table.setRowCount(len(devices))
        for row, dev in enumerate(devices):
            ssh = dev.ensure_ssh()

            include = QCheckBox()
            include.setChecked(True)
            holder = QWidget()
            hl = QHBoxLayout(holder)
            hl.setContentsMargins(0, 0, 0, 0)
            hl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            hl.addWidget(include)
            self.table.setCellWidget(row, COL_INCLUDE, holder)

            name_item = QTableWidgetItem(dev.name)
            name_item.setFlags(name_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, COL_DEVICE, name_item)

            self._set_kind_combo(row, dev.kind or "router")

            self.table.setItem(row, COL_HOST, QTableWidgetItem(ssh.host))
            self.table.setItem(row, COL_PORT, QTableWidgetItem(str(ssh.port)))
            # Prefer saved DB credentials for this IP when the site row is bare.
            if not (ssh.username or "").strip() and (ssh.host or dev.mgmt_ip):
                host = (ssh.host or dev.mgmt_ip or "").strip()
                row_data = creds_map.get(host)
                if row_data and self._apply_saved_credential_row(dev, host, row_data):
                    ssh = dev.ensure_ssh()
            user_item = QTableWidgetItem(ssh.username)
            user_item.setFlags(
                user_item.flags()
                | Qt.ItemFlag.ItemIsEditable
                | Qt.ItemFlag.ItemIsEnabled
                | Qt.ItemFlag.ItemIsSelectable
            )
            if not ssh.username:
                user_item.setToolTip(
                    "No saved username for this IP — enter one below and "
                    "Save credentials"
                )
            self.table.setItem(row, COL_USER, user_item)

            self._set_status_cell(row, ssh.last_status or "never", ssh.last_error)
            self._set_config_button(row, self._device_has_loaded_config(dev))
            if dev.ignored:
                self._apply_ignored_row(row)
        for dev in devices:
            if not dev.components:
                refresh_device_topology_from_config(dev)
        self._updating = False

        self.map_view.render_site(site)
        self._refresh_subnet_list()
        self._rebuild_device_subnet_tabs()
        self._emit_summary()
        self._on_device_selection_changed()
        self._start_discovery()

    def _set_kind_combo(self, row: int, kind: str) -> None:
        """Kind column: dropdown of known kinds; current value is NetCheck's guess."""
        combo = QComboBox()
        combo.setEditable(False)
        current = (kind or "router").strip() or "router"
        choices = list(KIND_CHOICES)
        if current not in choices:
            choices = [current, *choices]
        combo.addItems(choices)
        idx = combo.findText(current)
        combo.setCurrentIndex(idx if idx >= 0 else 0)
        combo.setToolTip(
            "NetCheck's best guess — change if needed (pfSense, MikroTik, …)"
        )
        combo.currentTextChanged.connect(
            lambda text, r=row: self._kind_combo_changed(r, text)
        )
        self.table.setCellWidget(row, COL_KIND, combo)

    def _kind_combo_changed(self, row: int, text: str) -> None:
        if self._updating:
            return
        dev = self._device_for_row(row)
        if dev is None:
            return
        kind = (text or "").strip()
        if not kind or kind == (dev.kind or ""):
            return
        # Keep session list membership: only allow connectable kinds.
        if kind not in CONNECTABLE_KINDS:
            return
        dev.kind = kind
        self.site_changed.emit()
        # Load Config options depend on kind (MikroTik device export).
        self._set_config_button(row, self._device_has_loaded_config(dev))

    def _set_kind_value(self, row: int, kind: str) -> None:
        """Update Kind dropdown/text without emitting a user edit."""
        kind = (kind or "").strip()
        if not kind:
            return
        combo = self.table.cellWidget(row, COL_KIND)
        if isinstance(combo, QComboBox):
            if combo.findText(kind) < 0:
                combo.addItem(kind)
            combo.blockSignals(True)
            combo.setCurrentText(kind)
            combo.blockSignals(False)
            return
        item = self.table.item(row, COL_KIND)
        if item is not None:
            item.setText(kind)

    @staticmethod
    def _device_has_loaded_config(dev: Device) -> bool:
        src = dev.ensure_config_source()
        if src is None:
            return False
        path = src.analyzable_path()
        if path and Path(path).is_file() and (src.last_status or "") == "ok":
            return True
        if path and Path(path).is_file():
            return True
        return bool(dev.config_file and Path(dev.config_file).is_file())

    def _set_config_button(self, row: int, loaded: bool) -> None:
        btn = QPushButton("Config Loaded" if loaded else "Load Config")
        if loaded:
            btn.setStyleSheet(_CONFIG_BTN_LOADED)
            btn.setToolTip("Config attached — click to replace (file or from device)")
        else:
            btn.setStyleSheet(_CONFIG_BTN_NORMAL)
            btn.setToolTip(
                "Load a local config file, or pull from the device "
                "(pfSense/OPNsense config.xml or MikroTik /export verbose)"
            )
        btn.clicked.connect(lambda _checked=False, r=row: self._load_config_for_row(r))
        self.table.setCellWidget(row, COL_CONFIG, btn)

    def _sync_topology_from_config(self, dev: Device) -> None:
        """Rebuild chassis ports / details from an attached config.xml."""
        if refresh_device_topology_from_config(dev) and self._site is not None:
            self.map_view.render_site(self._site)
        self._refresh_device_details(dev)

    def _load_config_for_row(self, row: int) -> None:
        """Chooser: browse for a local file, or pull config from the device."""
        dev = self._device_for_row(row)
        if dev is None:
            return
        dlg = _LoadConfigChooserDialog(dev, parent=self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        if dlg.from_device:
            kind = (dev.kind or "").lower()
            if kind in {"pfsense", "opnsense"}:
                self._load_config_from_pfsense(row, dev)
            else:
                self._load_config_from_mikrotik(row, dev)
            return

        path = dlg.file_path
        if not path:
            return
        p = Path(path)
        if not p.is_file():
            QMessageBox.warning(self, "Load Config", f"File not found:\n{path}")
            return
        if p.suffix.lower() == ".xml":
            check_result = None
            try:
                from pfsense_checker.checker import check_file

                check_result = check_file(p)
                if not check_result.valid_xml:
                    QMessageBox.warning(
                        self,
                        "Load Config",
                        f"Could not parse as pfSense XML:\n{path}",
                    )
                    return
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(
                    self, "Load Config", f"Could not parse config:\n{exc}"
                )
                return

        from datetime import datetime, timezone

        src = dev.attach_local_config(p)
        src.last_status = "ok"
        src.last_error = ""
        src.last_collected_at = (
            datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        )
        self._set_config_button(row, True)
        if p.suffix.lower() == ".xml" and check_result is not None:
            from pfsense_checker.topology_site import apply_config_to_device

            apply_config_to_device(dev, check_result)
            if self._site is not None:
                self.map_view.render_site(self._site)
            self._refresh_device_details(dev)
        self.site_changed.emit()
        QMessageBox.information(
            self,
            "Load Config",
            f"Loaded config for {dev.name}:\n{p.name}",
        )

    def _load_config_from_pfsense(self, row: int, dev: Device) -> None:
        """Pull ``config.xml`` over SSH and attach the cached file."""
        from pfsense_checker.module_required import ensure_feature

        if not ensure_feature(
            self,
            "ssh",
            purpose="Pull pfSense/OPNsense config.xml over SSH",
        ):
            return
        if self._config_pull_worker and self._config_pull_worker.isRunning():
            return
        typed_pw = ""
        if hasattr(self, "password"):
            typed_pw = (self.password.text() or "").strip()
        host = (dev.ensure_ssh().host or dev.mgmt_ip or dev.name or "device").strip()
        self._config_pull_row = row
        self._config_pull_device = dev
        self._config_pull_password = typed_pw or None
        self._config_pull_worker = _ConfigPullWorker(
            dev,
            password=self._config_pull_password,
        )
        self._config_pull_worker.finished_result.connect(
            self._on_config_pull_finished
        )
        show_busy_while(
            self._config_pull_worker,
            message=f"Pulling config.xml from {host}…",
        )
        self._config_pull_worker.start()

    def _on_config_pull_finished(self, result: object) -> None:
        from pfsense_checker.ssh_prompts import prompt_config_pull_retry
        from pfsense_checker.ssh_session import SshExportResult

        row = getattr(self, "_config_pull_row", -1)
        dev = getattr(self, "_config_pull_device", None)
        typed_pw = getattr(self, "_config_pull_password", None)
        if dev is None or not isinstance(result, SshExportResult):
            return

        if (not result.ok) and (
            result.needs_ssh_password or result.needs_sudo_password
        ):
            retry = prompt_config_pull_retry(self, dev, result)
            if retry is None:
                if getattr(self, "_config_pull_for_check", False):
                    self._config_pull_for_check = False
                QMessageBox.warning(
                    self,
                    "Load Config",
                    f"Could not pull config.xml from device:\n{result.error}",
                )
                return
            ssh_pw = retry.ssh_password if retry.ssh_password is not None else typed_pw
            if retry.ssh_password:
                self._config_pull_password = retry.ssh_password
                try:
                    save_ssh_credentials(dev, retry.ssh_password)
                except Exception:  # noqa: BLE001
                    pass
            if self._config_pull_worker and self._config_pull_worker.isRunning():
                return
            ssh = dev.ensure_ssh()
            host = (ssh.host or dev.mgmt_ip or "").strip() or "device"
            self._config_pull_worker = _ConfigPullWorker(
                dev,
                password=ssh_pw,
                sudo_password=retry.sudo_password,
            )
            self._config_pull_worker.finished_result.connect(
                self._on_config_pull_finished
            )
            msg = f"Pulling config.xml from {host}…"
            if retry.sudo_password:
                msg = f"Pulling config.xml from {host} (sudo)…"
            elif retry.ssh_password:
                msg = f"Pulling config.xml from {host} (SSH login)…"
            show_busy_while(self._config_pull_worker, message=msg)
            self._config_pull_worker.start()
            return

        if not result.ok:
            QMessageBox.warning(
                self,
                "Load Config",
                f"Could not pull config.xml from device:\n{result.error}",
            )
            app_log.get_logger("ssh").warning(
                "pfSense config.xml pull failed device=%s error=%s",
                dev.name,
                result.error,
            )
            if getattr(self, "_config_pull_for_check", False):
                self._config_pull_for_check = False
            return

        self._set_config_button(row, True)
        self._set_kind_value(row, dev.kind or "")
        self._sync_topology_from_config(dev)
        self.site_changed.emit()
        app_log.get_logger("ssh").info(
            "pfSense config.xml saved device=%s path=%s bytes=%s",
            dev.name,
            result.path,
            result.bytes_written,
        )
        if getattr(self, "_config_pull_for_check", False):
            self._finish_config_pull_for_check(result.path, dev)
            return
        QMessageBox.information(
            self,
            "Load Config",
            f"Pulled config.xml from {dev.name}:\n{Path(result.path).name}",
        )

    def _load_config_from_mikrotik(self, row: int, dev: Device) -> None:
        """Pull ``/export verbose`` over SSH and attach the cached .rsc."""
        with busy_cursor():
            # Prefer password typed on the login form if present.
            typed_pw = ""
            if hasattr(self, "password"):
                typed_pw = (self.password.text() or "").strip()
            result = export_mikrotik_verbose_ssh(
                dev,
                password=typed_pw or None,
            )

        if not result.ok:
            QMessageBox.warning(
                self,
                "Load Config",
                f"Could not export from device:\n{result.error}",
            )
            app_log.get_logger("ssh").warning(
                "MikroTik /export verbose failed device=%s error=%s",
                dev.name,
                result.error,
            )
            if getattr(self, "_config_pull_for_check", False):
                self._config_pull_for_check = False
            return

        self._set_config_button(row, True)
        # Refresh kind cell if we tagged mikrotik
        self._set_kind_value(row, dev.kind or "")
        self._sync_topology_from_config(dev)
        self.site_changed.emit()
        app_log.get_logger("ssh").info(
            "MikroTik /export verbose saved device=%s path=%s bytes=%s",
            dev.name,
            result.path,
            result.bytes_written,
        )
        if getattr(self, "_config_pull_for_check", False):
            self._finish_config_pull_for_check(result.path, dev)
            return
        QMessageBox.information(
            self,
            "Load Config",
            f"Loaded /export verbose from {dev.name}:\n{Path(result.path).name}",
        )

    def _ensure_site(self) -> SiteTopology:
        """Return the live site. Never replace an existing shared object."""
        if self._site is None:
            # Parent should have called set_site; create only as last resort and
            # notify so MainWindow can re-bind _live_site to this same object.
            self._site = SiteTopology()
            self.site_changed.emit()
        return self._site

    def _row_for_device_name(self, name: str) -> int | None:
        for row in range(self.table.rowCount()):
            item = self.table.item(row, COL_DEVICE)
            if item is not None and item.text() == name:
                return row
        return None

    def _connected_pullable_devices(self) -> list[Device]:
        """SSH-connected devices that support live config export."""
        out: list[Device] = []
        for dev in self._connectable_devices():
            kind = (dev.kind or "").lower()
            if kind not in {"pfsense", "opnsense", "mikrotik"} and "mikrotik" not in kind:
                continue
            ssh = dev.ssh
            if ssh and (ssh.last_status or "") == "ok":
                out.append(dev)
        return out

    def pull_config_from_connected_device(self) -> None:
        """Pull config over SSH from a connected device (for Config Check)."""
        connected = self._connected_pullable_devices()
        if not connected:
            QMessageBox.information(
                self,
                "Pull Config",
                "No SSH-connected pfSense, OPNsense, or MikroTik devices.\n\n"
                "On Login to Routers, select a device, enter credentials, and "
                "Connect — then try again.",
            )
            return

        preferred: Device | None = None
        row = self._exactly_one_selected_row()
        if row is not None:
            selected = self._device_for_row(row)
            if selected in connected:
                preferred = selected

        dlg = _ConnectedDevicePickerDialog(
            connected,
            preferred=preferred,
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted or dlg.selected_device is None:
            return
        dev = dlg.selected_device

        row = self._row_for_device_name(dev.name)
        if row is None:
            QMessageBox.warning(
                self,
                "Pull Config",
                f"Device {dev.name} is not listed in the session table.",
            )
            return

        self._config_pull_for_check = True
        kind = (dev.kind or "").lower()
        if kind in {"pfsense", "opnsense"}:
            self._load_config_from_pfsense(row, dev)
        elif kind == "mikrotik" or "mikrotik" in kind:
            self._load_config_from_mikrotik(row, dev)
        else:
            self._config_pull_for_check = False
            QMessageBox.warning(
                self,
                "Pull Config",
                f"Live config pull is not supported for kind “{dev.kind or '?'}”.",
            )

    def _finish_config_pull_for_check(self, path: str, dev: Device) -> None:
        self._config_pull_for_check = False
        if not path or not Path(path).is_file():
            QMessageBox.warning(
                self,
                "Pull Config",
                f"Pulled config for {dev.name} but the file was not found on disk.",
            )
            return
        self.config_pulled_for_check.emit(path)

    def _connectable_devices(self) -> list[Device]:
        if self._site is None:
            return []
        return [d for d in self._site.devices if d.kind in CONNECTABLE_KINDS]

    def _device_for_row(self, row: int) -> Device | None:
        item = self.table.item(row, COL_DEVICE)
        if item is None or self._site is None:
            return None
        return self._site.device(item.text())

    def _on_map_device_changed(self, name: str) -> None:
        """Refresh the Load Config button after chassis Pull Config."""
        for row in range(self.table.rowCount()):
            item = self.table.item(row, COL_DEVICE)
            if item is None or item.text() != name:
                continue
            dev = self._device_for_row(row)
            if dev is not None:
                self._set_config_button(row, self._device_has_loaded_config(dev))
                self._sync_topology_from_config(dev)
            break
        self._refresh_device_details()
        self.site_changed.emit()

    def _row_included(self, row: int) -> bool:
        holder = self.table.cellWidget(row, COL_INCLUDE)
        if holder is None:
            return False
        box = holder.findChild(QCheckBox)
        return bool(box and box.isChecked())

    def _set_status_cell(self, row: int, status: str, detail: str = "") -> None:
        text, color = status_label(status)
        item = QTableWidgetItem(f"● {text}")
        item.setForeground(QColor(color))
        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        if detail:
            item.setToolTip(detail)
        was = self._updating
        self._updating = True
        self.table.setItem(row, COL_STATUS, item)
        self._updating = was

    def _find_device_by_host_or_mac(self, ip: str = "", mac: str = "") -> Device | None:
        site = self._site
        if site is None:
            return None
        ip = (ip or "").strip()
        mac_n = (mac or "").strip().lower()
        for dev in site.devices:
            ssh = dev.ssh
            if ip and (
                (ssh and ssh.host == ip)
                or (dev.mgmt_ip == ip)
            ):
                return dev
            if mac_n and mac_n in (dev.notes or "").lower():
                return dev
            if mac_n and mac_n.replace(":", "") in (dev.notes or "").lower().replace(
                ":", ""
            ).replace("-", ""):
                return dev
        return None

    # ------------------------------------------------ add IP / MAC / search

    _IGNORED_NOTE = 'Ignored — right-click → Stop ignoring device. Not tested, connected or counted (for example the same box reached through another VLAN).'

    def _apply_ignored_row(self, row: int) -> None:
        """Grey out an ignored device's row and lock its Use box."""
        was = self._updating
        self._updating = True
        holder = self.table.cellWidget(row, COL_INCLUDE)
        box = holder.findChild(QCheckBox) if holder is not None else None
        if box is not None:
            box.setChecked(False)
            box.setEnabled(False)
            box.setToolTip(self._IGNORED_NOTE)
        grey = QColor("#9e9e9e")
        for col in (COL_DEVICE, COL_HOST, COL_PORT, COL_USER):
            item = self.table.item(row, col)
            if item is None:
                continue
            item.setForeground(grey)
            font = item.font()
            font.setItalic(True)
            item.setFont(font)
            item.setToolTip(self._IGNORED_NOTE)
        status = QTableWidgetItem("● ignored")
        status.setForeground(grey)
        status.setFlags(status.flags() & ~Qt.ItemFlag.ItemIsEditable)
        status.setToolTip(self._IGNORED_NOTE)
        self.table.setItem(row, COL_STATUS, status)
        for col in (COL_KIND, COL_CONFIG):
            widget = self.table.cellWidget(row, col)
            if widget is not None:
                widget.setEnabled(False)
        self._updating = was

    def _set_device_ignored(self, dev: Device, ignored: bool) -> None:
        if bool(dev.ignored) == ignored:
            return
        dev.ignored = ignored
        app_log.get_logger("session").info(
            "Device %s %s", dev.name, "ignored" if ignored else "no longer ignored"
        )
        keep = dev.name
        self.set_site(self._ensure_site())
        for row in range(self.table.rowCount()):
            item = self.table.item(row, COL_DEVICE)
            if item is not None and item.text() == keep:
                self.table.selectRow(row)
                break
        self.site_changed.emit()

    def _table_context_menu(self, pos) -> None:  # noqa: ANN001
        menu = QMenu(self)
        row = self.table.indexAt(pos).row()
        dev = self._device_for_row(row) if row >= 0 else None
        if dev is not None:
            self.table.selectRow(row)
            if dev.ignored:
                act = menu.addAction("Stop ignoring device")
                act.triggered.connect(lambda _c=False, d=dev: self._set_device_ignored(d, False))
            else:
                act = menu.addAction("Ignore device")
                act.setToolTip(
                    "Grey this device out: not tested, connected or counted. "
                    "Use it for a box that is also listed through another VLAN."
                )
                act.triggered.connect(lambda _c=False, d=dev: self._set_device_ignored(d, True))
            menu.addSeparator()
        act_search = QAction("Search for devices…", self)
        act_search.triggered.connect(self._search_for_devices)
        menu.addAction(act_search)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _update_add_enabled(self) -> None:
        has_sel = bool(self.found_table.selectedIndexes()) and bool(self._found_hosts)
        self.btn_add.setEnabled(has_sel)
        self.btn_add_all.setEnabled(bool(self._found_hosts))

    def _has_connect_target(self) -> bool:
        return (
            self._exactly_one_selected_row() is not None
            or self._selected_found_host() is not None
        )

    def _has_login_credentials(self) -> bool:
        """Username + password, username + certificate, or stored keyring/key."""
        user = (self.username_edit.text() or "").strip()
        if user and (self.password.text() or "").strip():
            return True
        if user and (self.key_edit.text() or "").strip():
            return True
        row = self._exactly_one_selected_row()
        if row is None:
            return False
        dev = self._device_for_row(row)
        if dev is None or not dev.ssh:
            return False
        ssh = dev.ssh
        uname = (ssh.username or user or "").strip()
        if not uname:
            return False
        if (ssh.key_path or "").strip():
            return True
        if (ssh.credential_ref or "").strip():
            return True
        return False

    def _selected_device_is_connected(self) -> bool:
        row = self._exactly_one_selected_row()
        if row is None:
            return False
        dev = self._device_for_row(row)
        return bool(dev and dev.ssh and dev.ssh.last_status == "ok")

    def _refresh_connect_button(self, *_args) -> None:  # noqa: ANN002
        """Blue = Connect (action); green = Connected (success)."""
        has_target = self._has_connect_target()
        self.btn_test_sel.setEnabled(has_target)

        if self._selected_device_is_connected():
            self.btn_connect.setText("Connected")
            self.btn_connect.setStyleSheet(_CONNECT_BTN_GREEN)
            self.btn_connect.setEnabled(False)
            self.btn_connect.setToolTip("SSH session authenticated for this device")
            return

        self.btn_connect.setText("Connect")
        if not has_target:
            self.btn_connect.setStyleSheet(_CONNECT_BTN_GREY)
            self.btn_connect.setEnabled(False)
            self.btn_connect.setToolTip(
                "Select a found device (blue row) or a device in the list below"
            )
            return

        ready = self._has_login_credentials()
        self.btn_connect.setStyleSheet(_CONNECT_BTN_BLUE)
        self.btn_connect.setEnabled(True)
        if ready:
            self.btn_connect.setToolTip(
                "SSH into the selected device (username + password, "
                "or username + certificate / stored credentials)"
            )
        else:
            self.btn_connect.setToolTip(
                "Connect — enter username + password (or certificate) first; "
                "stored keyring credentials are used when available"
            )

    def _update_connect_enabled(self) -> None:
        self._refresh_connect_button()

    def _sync_login_fields_from_device(self, dev: Device | None) -> None:
        """Copy username / key / password into Login fields (DB + keyring)."""
        self._apply_saved_credentials_to_login(dev)

    def _apply_saved_credentials_to_login(self, dev: Device | None) -> None:
        """Populate Login panel from device, DB row for IP, and OS keyring."""
        user = key_path = ""
        password = ""
        if dev is not None:
            ssh = dev.ensure_ssh()
            host = (ssh.host or dev.mgmt_ip or "").strip()
            if host:
                self._hydrate_device_from_saved_credentials(dev, host)
                ssh = dev.ensure_ssh()
            user = (ssh.username or "").strip()
            key_path = (ssh.key_path or "").strip()
            if ssh.credential_ref and user:
                try:
                    from pfsense_checker.credentials import get_password, ssh_ref_from_id

                    password = (
                        get_password(ssh_ref_from_id(ssh.credential_ref, user)) or ""
                    )
                except Exception:  # noqa: BLE001
                    password = ""
            # Keep the User column in sync with what we loaded.
            row = self._find_row_for_ip(host) if host else None
            if row is not None:
                user_item = self.table.item(row, COL_USER)
                if user_item is not None and user_item.text() != user:
                    was = self._updating
                    self._updating = True
                    user_item.setText(user)
                    self._updating = was
        for widget, text in ((self.username_edit, user), (self.key_edit, key_path)):
            widget.blockSignals(True)
            widget.setText(text)
            widget.blockSignals(False)
        self.password.blockSignals(True)
        self.password.setText(password)
        self.password.blockSignals(False)

    def _hydrate_device_from_saved_credentials(self, dev: Device, host: str) -> bool:
        """Apply netcheck.ssh_host_credentials for *host* onto *dev*. Returns True if found."""
        from pfsense_checker import ssh_credentials_db

        try:
            row = ssh_credentials_db.get_host_credentials(host)
        except Exception:  # noqa: BLE001
            return False
        if not row:
            return False
        return self._apply_saved_credential_row(dev, host, row)

    def _apply_saved_credential_row(
        self, dev: Device, host: str, row: dict
    ) -> bool:
        ssh = dev.ensure_ssh()
        if not ssh.host:
            ssh.host = host
        if not dev.mgmt_ip:
            dev.mgmt_ip = host
        saved_user = str(row.get("ssh_user") or "").strip()
        if saved_user:
            ssh.username = saved_user
        saved_key = str(row.get("ssh_key_path") or "").strip()
        if saved_key:
            ssh.key_path = saved_key
        saved_ref = str(row.get("ssh_credential_ref") or "").strip()
        if saved_ref:
            ssh.credential_ref = saved_ref
        try:
            port = int(row.get("ssh_port") or 22)
            if port > 0:
                ssh.port = port
        except (TypeError, ValueError):
            pass
        return True

    def _find_row_for_ip(self, ip: str) -> int | None:
        want = (ip or "").strip()
        if not want:
            return None
        for row in range(self.table.rowCount()):
            dev = self._device_for_row(row)
            if dev is None:
                continue
            ssh = dev.ssh
            if (ssh and ssh.host == want) or (dev.mgmt_ip or "") == want:
                return row
        return None

    def _select_session_row_for_ip(self, ip: str) -> int | None:
        """Highlight the session-table row for *ip* without clearing Found."""
        row = self._find_row_for_ip(ip)
        if row is None:
            return None
        self.table.blockSignals(True)
        self.table.selectRow(row)
        self.table.blockSignals(False)
        dev = self._device_for_row(row)
        self._focus_subnet_tab_for_device(dev)
        self._apply_saved_credentials_to_login(dev)
        self._refresh_device_details(dev)
        return row

    def _on_found_selection_changed(self) -> None:
        """Blue found-row is a link: add/select that device in the table below."""
        self._update_add_enabled()
        if self._syncing_selection:
            self._refresh_connect_button()
            return
        host = self._selected_found_host()
        if host is None:
            self._refresh_connect_button()
            return
        self._syncing_selection = True
        try:
            self._add_host_to_site(host)
            site = self._ensure_site()
            self.set_site(site)
            self.site_changed.emit()
            # set_site may clear table selection; re-select matching device.
            self._select_session_row_for_ip(host.ip)
            self.address_edit.setText(host.ip)
            # Keep the found row highlighted (device handler must not clear).
            for r, h in enumerate(self._found_hosts):
                if h.ip == host.ip:
                    self.found_table.blockSignals(True)
                    self.found_table.selectRow(r)
                    self.found_table.blockSignals(False)
                    break
        finally:
            self._syncing_selection = False
        self._refresh_connect_button()

    def _on_device_selection_changed(self) -> None:
        if self._syncing_selection:
            self._refresh_connect_button()
            return
        if self._exactly_one_selected_row() is not None:
            self.found_table.blockSignals(True)
            self.found_table.clearSelection()
            self.found_table.blockSignals(False)
            self._update_add_enabled()
        row = self._exactly_one_selected_row()
        if row is not None:
            dev = self._device_for_row(row)
            self._focus_subnet_tab_for_device(dev)
            self._apply_saved_credentials_to_login(dev)
        else:
            self._apply_saved_credentials_to_login(None)
        self._refresh_device_details(dev if row is not None else None)
        self._refresh_connect_button()

    def _ensure_target_device(self) -> Device | None:
        """Device for Connect / Test / Save — from list or selected found host."""
        row = self._exactly_one_selected_row()
        if row is not None:
            return self._device_for_row(row)
        host = self._selected_found_host()
        if host is None:
            return None
        # Keep typed credentials across the table refresh that follows Add.
        typed_user = self.username_edit.text()
        typed_key = self.key_edit.text()
        self._add_host_to_site(host)
        site = self._ensure_site()
        self.set_site(site)
        self.site_changed.emit()
        # Keep found hosts visible and re-select the new/updated device.
        self._populate_found_table(self._found_hosts)
        for r in range(self.table.rowCount()):
            dev = self._device_for_row(r)
            if dev is None:
                continue
            ssh = dev.ssh
            if (ssh and ssh.host == host.ip) or dev.mgmt_ip == host.ip:
                self.table.selectRow(r)
                if typed_user.strip():
                    self.username_edit.blockSignals(True)
                    self.username_edit.setText(typed_user)
                    self.username_edit.blockSignals(False)
                    self._username_edited(typed_user)
                if typed_key.strip():
                    self.key_edit.blockSignals(True)
                    self.key_edit.setText(typed_key)
                    self.key_edit.blockSignals(False)
                    self._key_path_edited(typed_key)
                return dev
        return self._find_device_by_host_or_mac(ip=host.ip, mac=host.mac)

    def _username_edited(self, text: str) -> None:
        """Apply the Username field to the selected device + table cell."""
        row = self._exactly_one_selected_row()
        if row is None:
            return
        dev = self._device_for_row(row)
        if dev is None:
            return
        user = (text or "").strip()
        ssh = dev.ensure_ssh()
        ssh.username = user
        was = self._updating
        self._updating = True
        item = self.table.item(row, COL_USER)
        if item is None:
            item = QTableWidgetItem(user)
            item.setFlags(
                item.flags()
                | Qt.ItemFlag.ItemIsEditable
                | Qt.ItemFlag.ItemIsEnabled
                | Qt.ItemFlag.ItemIsSelectable
            )
            self.table.setItem(row, COL_USER, item)
        else:
            item.setText(user)
        self._updating = was

    def _apply_username_from_field(self) -> None:
        """Push Username / Certificate onto the selected device before connect/save."""
        self._username_edited(self.username_edit.text())
        self._key_path_edited(self.key_edit.text())

    # ------------------------------------------------- certificate / key auth

    def _key_path_edited(self, text: str) -> None:
        """Apply the Certificate field to the selected device."""
        row = self._exactly_one_selected_row()
        if row is None:
            return
        dev = self._device_for_row(row)
        if dev is None:
            return
        ssh = dev.ensure_ssh()
        ssh.key_path = (text or "").strip()
        ssh.auth = "key" if ssh.key_path else "password"

    def _browse_key(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Choose SSH private key / certificate",
            "",
            "Key files (*.pem *.key *.ppk id_*);;All files (*)",
        )
        if not path:
            return
        self.key_edit.setText(path)
        self._key_path_edited(path)
        self._refresh_connect_button()

    # ----------------------------------------------------------- subnets

    def _refresh_subnet_list(self) -> None:
        self.subnet_table.setRowCount(0)
        if self._site is None:
            return
        for cidr in self._site.subnets:
            row = self.subnet_table.rowCount()
            self.subnet_table.insertRow(row)
            item = QTableWidgetItem(cidr)
            item.setFlags(
                Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled
            )
            self.subnet_table.setItem(row, 0, item)
            self.subnet_table.setCellWidget(row, 1, QLabel())
            self.subnet_table.setCellWidget(row, 2, QLabel())

            btn = QPushButton("Devices")
            btn.setToolTip(
                f"Show hosts seen on {cidr} in the Devices panel"
            )
            btn.clicked.connect(
                lambda _checked=False, c=cidr: self._show_devices_on_subnet(c)
            )
            holder = QWidget()
            hl = QHBoxLayout(holder)
            hl.setContentsMargins(4, 0, 4, 0)
            hl.addWidget(btn)
            self.subnet_table.setCellWidget(row, 3, holder)
        self._refresh_subnet_connected_labels()

    def _connected_devices_in_subnet(self, cidr: str) -> list[Device]:
        """Session devices with SSH status ok whose host/IP falls in *cidr*."""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return []
        out: list[Device] = []
        for dev in self._connectable_devices():
            if dev.ignored:
                continue
            ssh = dev.ssh
            if not ssh or (ssh.last_status or "") != "ok":
                continue
            host = (ssh.host or dev.mgmt_ip or "").strip()
            if not host:
                continue
            try:
                if ipaddress.ip_address(host) in net:
                    out.append(dev)
            except ValueError:
                continue
        return out

    def _selected_subnet(self) -> str:
        rows = sorted({i.row() for i in self.subnet_table.selectedIndexes()})
        if len(rows) != 1:
            return ""
        item = self.subnet_table.item(rows[0], 0)
        return item.text() if item else ""

    def _show_devices_on_subnet(self, cidr: str) -> None:
        """Scan *cidr* and list found hosts in the Devices panel."""
        cidr = (cidr or "").strip()
        if not cidr:
            return
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            QMessageBox.warning(self, "Devices", f"Not a valid subnet: {cidr}")
            return
        self.address_edit.setText(cidr)
        self._select_device_tab(cidr)
        self._start_subnet_scan(cidr)

    def _add_subnet(self) -> None:
        text = (self.subnet_edit.text() or "").strip()
        if not text:
            return
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            QMessageBox.warning(
                self, "Subnets", f"Not a valid subnet: {text}\n\nUse CIDR "
                "notation, e.g. 192.168.1.0/24."
            )
            return
        self._store_subnets([str(net)])
        self.subnet_edit.clear()

    def _subnet_context_menu(self, pos) -> None:  # noqa: ANN001
        row = self.subnet_table.indexAt(pos).row()
        item = self.subnet_table.item(row, 0) if row >= 0 else None
        if item is None:
            return
        cidr = item.text()
        self.subnet_table.selectRow(row)
        menu = QMenu(self)
        act_scan = menu.addAction("Scan this subnet")
        act_scan.setToolTip("Look for routers, switches, gateways and firewalls")
        act_alter = menu.addAction("Alter this subnet…")
        act_remove = menu.addAction("Remove this subnet")
        busy = self._discovery_worker is not None and self._discovery_worker.isRunning()
        if busy:
            act_scan.setText("Scan this subnet (queued after the current sweep)")
        chosen = menu.exec(self.subnet_table.viewport().mapToGlobal(pos))
        if chosen is act_scan:
            self._start_discovery([cidr], rescan=True)
        elif chosen is act_alter:
            self._alter_subnet(cidr)
        elif chosen is act_remove:
            self._remove_subnet(cidr)

    def _alter_subnet(self, cidr: str) -> None:
        if self._site is None or cidr not in self._site.subnets:
            return
        dlg = _AlterSubnetDialog(cidr, list(self._site.subnets), self)
        if dlg.exec() != QDialog.DialogCode.Accepted or not dlg.new_cidr:
            return
        self._replace_subnet(cidr, dlg.new_cidr)

    def _replace_subnet(self, old: str, new: str) -> None:
        """Swap *old* for *new* in place, then sweep the new one."""
        if self._site is None or old not in self._site.subnets or old == new:
            return
        if new in self._site.subnets:
            return
        idx = self._site.subnets.index(old)
        self._site.subnets[idx] = new
        for cache in (self._seen, self._seen_state, self._seen_error):
            cache.pop(old, None)
        app_log.get_logger("subnets").info("Subnet altered: %s → %s", old, new)
        self._refresh_subnet_list()
        self._rebuild_device_subnet_tabs()
        self.site_changed.emit()
        self._start_discovery([new])

    def _remove_subnet(self, subnet: str = "") -> None:
        subnet = subnet or self._selected_subnet()
        if not subnet or self._site is None:
            return
        self._site.subnets = [s for s in self._site.subnets if s != subnet]
        for cache in (self._seen, self._seen_state, self._seen_error):
            cache.pop(subnet, None)
        self._refresh_subnet_list()
        self.site_changed.emit()

    def _store_subnets(self, subnets: list[str]) -> int:
        """Add subnets to the site (deduplicated). Returns how many were new."""
        site = self._ensure_site()
        added = 0
        for s in subnets:
            if s not in site.subnets:
                site.subnets.append(s)
                added += 1
        if added:
            self._refresh_subnet_list()
            self.site_changed.emit()
            self._start_discovery()
        return added

    def _pfsense_config_path(self) -> str:
        """An analyzable config path from a pfSense device in the site, if any."""
        if self._site is None:
            return ""
        for dev in self._site.devices:
            if dev.kind not in ("pfsense", "opnsense"):
                continue
            if dev.config_source is not None:
                path = dev.config_source.analyzable_path()
                if path and Path(path).is_file():
                    return path
            if dev.config_file and Path(dev.config_file).is_file():
                return dev.config_file
        return ""

    def _show_live_subnets(self) -> None:
        """Discover this PC's interface subnets and add them to the site list."""
        from pfsense_checker import subnet_health

        try:
            rows = subnet_health.discover_local_subnets(force_refresh=True)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(
                self, "Live subnets", f"Could not read local adapters:\n{exc}"
            )
            return
        subnets: list[str] = []
        for row in rows:
            cidr = (row.cidr or "").strip()
            if not cidr or cidr in subnets:
                continue
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            subnets.append(cidr)
        if not subnets:
            QMessageBox.information(
                self,
                "Live subnets",
                "No live IPv4 subnets found on this PC's adapters.",
            )
            return
        added = self._store_subnets(subnets)
        # Select the first live subnet in the table for Search / Devices.
        for row in range(self.subnet_table.rowCount()):
            item = self.subnet_table.item(row, 0)
            if item is not None and item.text() in subnets:
                self.subnet_table.selectRow(row)
                break
        detail = "\n".join(f"  • {c}" for c in subnets)
        QMessageBox.information(
            self,
            "Live subnets",
            f"Found {len(subnets)} subnet(s) on this PC "
            f"({added} new):\n\n{detail}",
        )

    def _import_subnets_from_pfsense(self) -> None:
        path = self._pfsense_config_path()
        if not path:
            path, _ = QFileDialog.getOpenFileName(
                self,
                "Choose the main router's pfSense config",
                "",
                "pfSense config (*.xml);;All files (*)",
            )
            if not path:
                return
        from pfsense_checker.checker import check_file

        try:
            result = check_file(path)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(
                self, "Subnets", f"Could not parse config:\n{exc}"
            )
            return
        subnets: list[str] = []
        for iface in result.interfaces:
            if not iface.enabled or not iface.ipaddr or not iface.subnet:
                continue
            if iface.ipaddr in ("dhcp", "pppoe"):
                continue
            try:
                net = ipaddress.ip_network(
                    f"{iface.ipaddr}/{iface.subnet}", strict=False
                )
            except ValueError:
                continue
            if str(net) not in subnets:
                subnets.append(str(net))
        if not subnets:
            QMessageBox.information(
                self,
                "Subnets",
                f"No static interface subnets found in {Path(path).name}.",
            )
            return
        added = self._store_subnets(subnets)
        QMessageBox.information(
            self,
            "Subnets",
            f"Imported {len(subnets)} subnet(s) from {Path(path).name} "
            f"({added} new).",
        )

    @staticmethod
    def _port_cell(state: bool | None, port: int, label: str) -> QTableWidgetItem:
        if state is True:
            text, tip = "open", f"TCP port {port} ({label}) accepted a connection"
        elif state is False:
            text, tip = (
                "closed",
                f"Connection refused — nothing listening on TCP/{port}",
            )
        elif state is None:
            text, tip = (
                "no reply",
                f"No TCP response on port {port} within the probe timeout "
                f"(firewall, slow device, or service on another port)",
            )
        else:
            text, tip = "—", ""
        item = QTableWidgetItem(text)
        item.setToolTip(tip)
        return item

    def _populate_found_table(self, hosts: list[LanHost]) -> None:
        self._found_hosts = list(hosts)
        self.found_table.setRowCount(len(hosts))
        link_font = QFont()
        link_font.setUnderline(True)
        for row, host in enumerate(hosts):
            ip_item = QTableWidgetItem(host.ip)
            ip_item.setForeground(QColor("#1565c0"))
            ip_item.setFont(link_font)
            ip_item.setToolTip(
                "Click to show this device in the session list below and enable Connect"
            )
            self.found_table.setItem(row, 0, ip_item)
            self.found_table.setItem(row, 1, QTableWidgetItem(host.mac or ""))
            seen = self._seen_device(host.ip)
            vendor_item = QTableWidgetItem(
                f"{seen.vendor} {seen.role}".strip() if seen else ""
            )
            if seen and seen.evidence:
                vendor_item.setToolTip("\n".join(seen.evidence))
            self.found_table.setItem(row, 2, vendor_item)
            self.found_table.setItem(
                row, 3, self._port_cell(host.ssh_open, 22, "SSH")
            )
            self.found_table.setItem(
                row, 4, self._port_cell(host.http_open, 80, "HTTP")
            )
            self.found_table.setItem(
                row, 5, self._port_cell(host.https_open, 443, "HTTPS")
            )
        show = bool(hosts)
        self.found_label.setVisible(show)
        self.found_table.setVisible(show)
        if show:
            self.found_label.setText(
                f"Found devices ({len(hosts)}) — click an IP (blue link) to "
                "show it in the list below, then Connect / Test selected "
                "(or Add). SSH :22 / HTTP :80 / HTTPS :443 = open / closed / "
                "no reply (TCP probe only)."
            )
        self._update_local_adapter_label()
        self._update_add_enabled()
        self._update_connect_enabled()
        self._enrich_found_vendors()

    def _update_local_adapter_label(self, cidr: str = "") -> None:
        """Show this PC's NIC (type, speed, duplex, MTU) under Found devices."""
        label = getattr(self, "local_adapter_label", None)
        if label is None:
            return
        seed = (cidr or self.address_edit.text() or "").strip()
        worker = getattr(self, "_adapter_label_worker", None)
        if worker is not None and worker.isRunning():
            worker.requestInterruption()
            worker.wait(50)
        label.setText("Local adapter: detecting…")
        label.setVisible(True)
        self._adapter_label_worker = _AdapterLabelWorker(seed)
        self._adapter_label_worker.finished_ok.connect(label.setText)
        self._adapter_label_worker.finished.connect(
            self._adapter_label_worker.deleteLater
        )
        self._adapter_label_worker.start()

    def _enrich_found_vendors(self) -> None:
        """Fill Vendor column from OUI API when a key is configured."""
        if not oui.has_oui_api_key():
            return
        for row, host in enumerate(self._found_hosts):
            if not host.mac:
                continue
            try:
                vendor = oui.lookup_vendor(host.mac, timeout=5)
            except (RuntimeError, ValueError):
                vendor = ""
            if not vendor:
                continue
            item = self.found_table.item(row, 2)
            if item is not None:
                item.setText(vendor)
            else:
                self.found_table.setItem(row, 2, QTableWidgetItem(vendor))

    def _selected_found_host(self) -> LanHost | None:
        rows = sorted({i.row() for i in self.found_table.selectedIndexes()})
        if len(rows) != 1:
            return None
        idx = rows[0]
        if idx < 0 or idx >= len(self._found_hosts):
            return None
        return self._found_hosts[idx]

    def _add_host_to_site(self, host: LanHost) -> bool:
        """Add or update one found host. Returns True if something changed."""
        site = self._ensure_site()
        existing = self._find_device_by_host_or_mac(ip=host.ip, mac=host.mac)
        if existing is not None:
            ssh = existing.ensure_ssh()
            ssh.host = host.ip
            existing.mgmt_ip = host.ip
            if host.mac and host.mac not in (existing.notes or ""):
                note = f"MAC {host.mac}"
                existing.notes = (
                    f"{existing.notes}; {note}" if existing.notes else note
                )
            self._hydrate_device_from_saved_credentials(existing, host.ip)
            return True
        name = self._unique_device_name(host.ip)
        notes = f"MAC {host.mac}" if host.mac else ""
        if host.ssh_open:
            notes = (notes + "; SSH open").strip("; ")
        dev = Device(name=name, kind="router", mgmt_ip=host.ip, notes=notes)
        ssh = dev.ensure_ssh()
        ssh.host = host.ip
        self._hydrate_device_from_saved_credentials(dev, host.ip)
        site.add_or_update_device(dev)
        return True

    def _add_selected_found(self) -> None:
        host = self._selected_found_host()
        if host is None:
            QMessageBox.information(
                self,
                "Add",
                "Select a found device first.\n\n"
                "Run Search for devices, click a row in Found devices, then Add.",
            )
            return
        self._add_host_to_site(host)
        site = self._ensure_site()
        self.set_site(site)
        self.site_changed.emit()
        # Keep the IP field in sync with what was just added
        self.address_edit.setText(host.ip)

    def _add_all_found(self) -> None:
        if not self._found_hosts:
            QMessageBox.information(
                self, "Add all", "No found devices — run Search for devices first."
            )
            return
        for host in self._found_hosts:
            self._add_host_to_site(host)
        site = self._ensure_site()
        self.set_site(site)
        self.site_changed.emit()
        QMessageBox.information(
            self,
            "Add all",
            f"Added / updated {len(self._found_hosts)} device(s).",
        )

    def _unique_device_name(self, seed: str) -> str:
        site = self._ensure_site()
        base = "host-" + seed.replace(":", "").replace(".", "-")
        if site.device(base) is None:
            return base
        n = 2
        while site.device(f"{base}-{n}") is not None:
            n += 1
        return f"{base}-{n}"

    def _search_for_devices(self) -> None:
        if self._scan_worker and self._scan_worker.isRunning():
            return
        suggestions = local_ipv4_cidrs()
        box = (self.address_edit.text() or "").strip()
        default = suggestions[0] if suggestions else "192.168.1.0/24"
        # Prefer whatever is already in the IP/MAC box (CIDR, IP → /24, or MAC skip).
        if box:
            try:
                default = str(ipaddress.ip_network(box, strict=False))
            except ValueError:
                seed = classify_address(box)
                if seed.kind == "ip":
                    parts = seed.value.split(".")
                    default = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        # A subnet selected in the Subnets section wins only when the box is empty.
        if not box and self._selected_subnet():
            default = self._selected_subnet()
        cidr, ok = QInputDialog.getText(
            self,
            "Search for devices",
            "Subnet to scan (ping + ARP, then TCP 22/80/443):",
            text=default,
        )
        if not ok or not cidr.strip():
            return
        self.address_edit.setText(cidr.strip())
        self._start_subnet_scan(cidr.strip())

    def _start_subnet_scan(self, cidr: str) -> None:
        """Ping/ARP/SSH-probe *cidr* and show results in the Devices panel."""
        if self._scan_worker and self._scan_worker.isRunning():
            return
        self.address_edit.setEnabled(False)
        self.btn_search.setEnabled(False)
        self._set_subnet_device_buttons_enabled(False)
        self._scan_worker = _ScanWorker(cidr)
        self._scan_worker.finished_ok.connect(
            lambda hosts, c=cidr: self._on_scan_finished(c, hosts)
        )
        self._scan_worker.failed.connect(self._on_scan_failed)
        self._update_local_adapter_label(cidr)
        show_busy_while(self._scan_worker)
        self._scan_worker.start()

    def _set_subnet_device_buttons_enabled(self, enabled: bool) -> None:
        for row in range(self.subnet_table.rowCount()):
            holder = self.subnet_table.cellWidget(row, 3)
            btn = holder.findChild(QPushButton) if holder is not None else None
            if isinstance(btn, QPushButton):
                btn.setEnabled(enabled)

    @staticmethod
    def _hosts_in_cidr(hosts: list[LanHost], cidr: str) -> list[LanHost]:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return list(hosts)
        out: list[LanHost] = []
        for host in hosts:
            try:
                if ipaddress.ip_address(host.ip) in net:
                    out.append(host)
            except ValueError:
                continue
        return out

    def _on_scan_finished(self, cidr: str, hosts: list) -> None:
        self.address_edit.setEnabled(True)
        self.btn_search.setEnabled(True)
        self._set_subnet_device_buttons_enabled(True)
        hosts = [h for h in hosts if isinstance(h, LanHost)]
        hosts = self._hosts_in_cidr(hosts, cidr)
        if not hosts:
            arp = self._hosts_in_cidr(parse_arp_table(), cidr)
            if not arp:
                self._populate_found_table([])
                QMessageBox.information(
                    self,
                    "Search for devices",
                    f"No hosts found on {cidr}.",
                )
                return
            hosts = arp
            QMessageBox.information(
                self,
                "Search for devices",
                f"No ping replies on {cidr}; showing ARP entries for that "
                "subnet instead.",
            )
        self._populate_found_table(hosts)

    def _on_scan_failed(self, msg: str) -> None:
        self.address_edit.setEnabled(True)
        self.btn_search.setEnabled(True)
        self._set_subnet_device_buttons_enabled(True)
        QMessageBox.critical(self, "Search for devices", msg)

    def _exactly_one_selected_row(self) -> int | None:
        rows = sorted({i.row() for i in self.table.selectedIndexes()})
        return rows[0] if len(rows) == 1 else None

    def _connect_selected(self) -> None:
        """SSH-connect exactly one selected found host or list device."""
        if self._worker and self._worker.isRunning():
            return
        if self._connected_name is not None and self._worker and self._worker.isRunning():
            QMessageBox.information(
                self,
                "Connect",
                f"Already connecting to “{self._connected_name}”.\n\n"
                "Only one device can be connected at a time.",
            )
            return
        from pfsense_checker.module_required import ensure_feature

        if not ensure_feature(
            self,
            "ssh",
            purpose="Connect over SSH (login / inventory)",
        ):
            return
        dev = self._ensure_target_device()
        if dev is None:
            QMessageBox.information(
                self,
                "Connect",
                "Select a found device (or a device in the list), then Connect.",
            )
            return
        # Apply typed username/password/key now that a device row exists.
        user = (self.username_edit.text() or "").strip()
        if user:
            self.username_edit.blockSignals(True)
            self.username_edit.setText(user)
            self.username_edit.blockSignals(False)
            self._username_edited(user)
        self._key_path_edited(self.key_edit.text())
        ssh = dev.ensure_ssh()
        if not ssh.host:
            QMessageBox.warning(self, "Connect", "Set an SSH Host for this device first.")
            return
        if not ssh.username:
            ssh.username = user
        pw = self.password.text()
        if pw and ssh.username:
            try:
                save_ssh_credentials(dev, pw)
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, "Connect", f"Could not store password: {exc}")
                return
        elif not ssh.username:
            QMessageBox.information(
                self,
                "Connect",
                "Enter a Username for this device before connecting.",
            )
            self.username_edit.setFocus()
            return

        if dev.ignored:
            QMessageBox.information(
                self,
                "Connect",
                f"“{dev.name}” is ignored. Right-click it → Stop ignoring device "
                "to connect.",
            )
            return
        self._connected_name = dev.name
        row = self._exactly_one_selected_row()
        if row is not None:
            self._set_status_cell(row, "never", "connecting…")
        self.btn_connect.setEnabled(False)
        self.btn_test_sel.setEnabled(False)
        self._worker = _ProbeWorker([dev])
        self._worker.result.connect(self._probe_result)
        self._worker.done.connect(self._on_connect_done)
        show_busy_while(self._worker)
        self._worker.start()

    def _on_connect_done(self) -> None:
        self._emit_summary()
        name = self._connected_name
        self._connected_name = None
        if name and self._site is not None:
            dev = self._site.device(name)
            if dev and dev.ssh:
                status = dev.ssh.last_status or ""
                detail = (dev.ssh.last_error or "").strip()
                if status == "ok":
                    self.ssh_summary_changed.emit(f"SSH connected to {name}")
                    ssh = dev.ssh
                    app_log.get_logger("ssh").info(
                        "Login successful device=%s host=%s user=%s",
                        name,
                        ssh.host if ssh else "",
                        ssh.username if ssh else "",
                    )
                    QMessageBox.information(
                        self,
                        "Login Successful",
                        f"Login Successful\n\nDevice: {name}\n\n"
                        "Collecting ports and assigned IPs for the topology…",
                    )
                    self._start_interface_inventory(dev)
                    self._rebuild_device_subnet_tabs()
                    self._refresh_device_details(dev)
                else:
                    reason = self._login_failure_reason(status, detail)
                    self.ssh_summary_changed.emit(f"SSH login failed ({name})")
                    ssh = dev.ssh
                    app_log.get_logger("ssh").error(
                        "Login failed device=%s host=%s user=%s status=%s "
                        "reason=%s detail=%s has_key=%s has_cred_ref=%s",
                        name,
                        ssh.host if ssh else "",
                        ssh.username if ssh else "",
                        status,
                        reason,
                        detail or "(none)",
                        bool(ssh and ssh.key_path),
                        bool(ssh and ssh.credential_ref),
                    )
                    QMessageBox.warning(
                        self,
                        "Login Failed",
                        f"Login Failed; Reason: {reason}",
                    )
        self._refresh_connect_button()

    def _start_interface_inventory(self, dev: Device) -> None:
        """After a successful Connect, pull ports/IPs into the right-hand map."""
        if self._inventory_worker and self._inventory_worker.isRunning():
            return
        typed_pw = (self.password.text() or "").strip() or None
        self.ssh_summary_changed.emit(
            f"SSH connected — collecting ports on {dev.name}…"
        )
        self._inventory_worker = _InventoryWorker(dev, password=typed_pw)
        self._inventory_worker.finished_ok.connect(self._on_inventory_ok)
        self._inventory_worker.failed.connect(self._on_inventory_failed)
        show_busy_while(self._inventory_worker)
        self._inventory_worker.start()

    def _on_inventory_ok(self, name: str, result: object) -> None:
        from pfsense_checker import ssh_inventory

        if self._site is None:
            return
        dev = self._site.device(name)
        if dev is None:
            return
        n = ssh_inventory.apply_inventory_to_device(dev, result)  # type: ignore[arg-type]
        # Refresh Kind / map.
        for row in range(self.table.rowCount()):
            item = self.table.item(row, COL_DEVICE)
            if item and item.text() == name:
                self._set_kind_value(row, dev.kind or "")
                break
        self.map_view.render_site(self._site)
        self.map_view.highlight_devices([name])
        self._rebuild_device_subnet_tabs()
        self._refresh_device_details(dev)
        self.site_changed.emit()
        platform = getattr(result, "platform", "") or ""
        self.ssh_summary_changed.emit(
            f"SSH connected to {name} — {n} port(s) on topology"
            + (f" ({platform})" if platform else "")
        )
        app_log.get_logger("ssh").info(
            "Interface inventory device=%s ports=%s platform=%s",
            name,
            n,
            platform,
        )

    def _on_inventory_failed(self, name: str, error: str) -> None:
        app_log.get_logger("ssh").warning(
            "Interface inventory failed device=%s error=%s", name, error
        )
        self.ssh_summary_changed.emit(
            f"SSH connected to {name} — port inventory unavailable"
        )

    @staticmethod
    def _login_failure_reason(status: str, detail: str) -> str:
        """Human-readable reason for a failed Connect attempt."""
        labels = {
            "auth-fail": "authentication failed",
            "banner-only": "host reachable but authentication did not complete",
            "unreachable": "host unreachable",
            "no-host": "no SSH host set",
            "never": "connection not completed",
        }
        base = labels.get(status, status or "unknown error")
        if detail:
            return f"{base} ({detail})"
        return base

    # --------------------------------------------------------------- events

    def _cell_changed(self, row: int, col: int) -> None:
        if self._updating or col not in (COL_HOST, COL_PORT, COL_USER):
            return
        dev = self._device_for_row(row)
        if dev is None:
            return
        ssh = dev.ensure_ssh()
        text = (self.table.item(row, col).text() or "").strip()
        if col == COL_HOST:
            ssh.host = text
            if text:
                dev.mgmt_ip = text
        elif col == COL_PORT:
            try:
                ssh.port = int(text) if text else 22
            except ValueError:
                ssh.port = 22
        elif col == COL_USER:
            ssh.username = text
            # Keep the Username field in sync when editing the table cell
            if self._exactly_one_selected_row() == row:
                self.username_edit.blockSignals(True)
                self.username_edit.setText(text)
                self.username_edit.blockSignals(False)

    def _selected_rows(self) -> list[int]:
        return sorted({i.row() for i in self.table.selectedIndexes()})

    def _save_credentials(self) -> None:
        pw = self.password.text()
        if not pw:
            QMessageBox.information(self, "Credentials", "Enter a password first.")
            return
        user = (self.username_edit.text() or "").strip()
        if not user:
            QMessageBox.information(
                self, "Credentials", "Enter a username before saving."
            )
            self.username_edit.setFocus()
            return
        dev = self._ensure_target_device()
        if dev is None:
            QMessageBox.information(
                self,
                "Credentials",
                "Select a found device or a device in the list first.",
            )
            return
        self._username_edited(user)
        self._key_path_edited(self.key_edit.text())
        ssh = dev.ensure_ssh()
        host = (ssh.host or dev.mgmt_ip or "").strip()
        if not host:
            QMessageBox.warning(
                self, "Credentials", "Selected device has no SSH host / IP."
            )
            return
        try:
            save_ssh_credentials(dev, pw)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(
                self, "Credentials", f"Could not store password in keyring:\n{exc}"
            )
            return

        from pfsense_checker import ssh_credentials_db

        try:
            result = ssh_credentials_db.save_host_credentials(dev, pw)
        except Exception as exc:  # noqa: BLE001
            app_log.get_logger("ssh").error(
                "Save credentials DB failed host=%s: %s", host, exc
            )
            QMessageBox.warning(
                self,
                "Credentials",
                f"Password saved in Windows Credential Manager for {host}, "
                f"but the database write failed:\n{exc}",
            )
            return

        self.password.clear()
        # Re-load into the Login panel so username/password stay available for Connect.
        self._apply_saved_credentials_to_login(dev)
        self.site_changed.emit()
        QMessageBox.information(
            self,
            "Credentials saved",
            f"Credentials saved and confirmed for IP {result.ssh_host}\n\n"
            f"Username: {result.ssh_user}\n"
            f"Port: {result.ssh_port}\n"
            f"Device: {result.device_name or '(unnamed)'}\n\n"
            "Database: salted password hash only "
            f"(ssh_host_credentials row {result.row_id}) — "
            "plaintext password is never stored in the DB.\n"
            "Live SSH secret: Windows Credential Manager.\n\n"
            "Selecting this IP again will reload these login fields.",
        )
        self._refresh_connect_button()

    def _test(self, *, selected_only: bool) -> None:
        if self._worker and self._worker.isRunning():
            return
        devices: list[Device] = []
        if selected_only:
            typed_user = self.username_edit.text()
            typed_key = self.key_edit.text()
            typed_pw = self.password.text()
            dev = self._ensure_target_device()
            if dev is None:
                QMessageBox.information(
                    self,
                    "Test",
                    "Select a found device (or a device in the list) to test.",
                )
                return
            if typed_user.strip():
                self._username_edited(typed_user)
            if typed_key.strip():
                self._key_path_edited(typed_key)
            ssh = dev.ensure_ssh()
            if typed_pw and ssh.username:
                try:
                    save_ssh_credentials(dev, typed_pw)
                except Exception:  # noqa: BLE001
                    pass
            devices = [dev]
            row = self._exactly_one_selected_row()
            if row is not None:
                self._set_status_cell(row, "never", "testing…")
        else:
            rows = list(range(self.table.rowCount()))
            for row in rows:
                if not self._row_included(row):
                    continue
                dev = self._device_for_row(row)
                if dev is not None:
                    devices.append(dev)
                    self._set_status_cell(row, "never", "testing…")
        devices = [d for d in devices if not d.ignored]
        if not devices:
            return
        self.btn_connect.setEnabled(False)
        self.btn_test_sel.setEnabled(False)
        self._worker = _ProbeWorker(devices)
        self._worker.result.connect(self._probe_result)
        self._worker.done.connect(self._on_test_done)
        show_busy_while(self._worker)
        self._worker.start()

    def _on_test_done(self) -> None:
        self._emit_summary()
        self._refresh_connect_button()

    # Device kinds generic enough to overwrite with a banner-based guess
    _GENERIC_KINDS = {"router", "switch", "host", "other", ""}

    def _probe_result(self, name: str, status: str, detail: str, banner: str) -> None:
        log = app_log.get_logger("ssh")
        if status == "ok":
            log.info(
                "SSH probe ok device=%s banner=%s",
                name,
                (banner or "")[:120],
            )
        elif status == "banner-only":
            log.warning(
                "SSH probe banner-only device=%s detail=%s banner=%s "
                "(authentication did not complete — check username/password/key)",
                name,
                detail or "(none)",
                (banner or "")[:120],
            )
        else:
            log.error(
                "SSH probe failed device=%s status=%s detail=%s banner=%s",
                name,
                status,
                detail or "(none)",
                (banner or "")[:120],
            )
        for row in range(self.table.rowCount()):
            item = self.table.item(row, COL_DEVICE)
            if item and item.text() == name:
                self._set_status_cell(row, status, detail)
                self._identify_device(row, name, banner)
                break
        self._highlight_map()
        self._refresh_connect_button()
        self._refresh_subnet_list()

    def _identify_device(self, row: int, name: str, banner: str) -> None:
        """Update the device kind from its SSH banner when we can do better."""
        guess = identify_kind_from_banner(banner)
        if not guess or self._site is None:
            return
        dev = self._site.device(name)
        if dev is None or dev.kind == guess:
            return
        if dev.kind not in self._GENERIC_KINDS:
            return  # respect an explicit user-chosen kind (e.g. mikrotik)
        if guess not in CONNECTABLE_KINDS:
            # e.g. a Linux server — note it, but keep the device on this list
            note = f"identified as {guess}"
            if note not in (dev.notes or ""):
                dev.notes = f"{dev.notes}; {note}" if dev.notes else note
            return
        dev.kind = guess
        was = self._updating
        self._updating = True
        self._set_kind_value(row, guess)
        combo = self.table.cellWidget(row, COL_KIND)
        if isinstance(combo, QComboBox):
            combo.setToolTip(f"Identified from SSH banner: {banner}")
        else:
            kind_item = self.table.item(row, COL_KIND)
            if kind_item is not None:
                kind_item.setToolTip(f"Identified from SSH banner: {banner}")
        self._updating = was
        self.site_changed.emit()

    def _highlight_map(self) -> None:
        if self._site is None:
            return
        ok = [
            d.name
            for d in self._connectable_devices()
            if d.ssh and d.ssh.last_status == "ok"
        ]
        if ok:
            self.map_view.highlight_devices(ok)

    def _included_device_names(self) -> list[str]:
        names: list[str] = []
        for row in range(self.table.rowCount()):
            if not self._row_included(row):
                continue
            item = self.table.item(row, COL_DEVICE)
            if item is not None and item.text().strip():
                names.append(item.text().strip())
        return names

    def _save_connectivity_to_db(self) -> None:
        site = self._ensure_site()
        from pfsense_checker import connectivity_db
        from pfsense_checker.module_required import ensure_feature

        if not ensure_feature(
            self,
            "postgres",
            purpose="Save Connectivity to DB",
        ):
            return
        try:
            result = connectivity_db.save_connectivity(
                site,
                included_names=self._included_device_names(),
            )
        except Exception as exc:  # noqa: BLE001
            app_log.get_logger("database").error(
                "Save connectivity failed: %s", exc
            )
            QMessageBox.critical(
                self,
                "Save Connectivity to DB",
                f"Could not save to PostgreSQL:\n\n{exc}",
            )
            return
        app_log.get_logger("database").info(
            "Connectivity snapshot #%s saved devices=%s links=%s "
            "subnets=%s connected=%s",
            result.snapshot_id,
            result.device_count,
            result.link_count,
            result.subnet_count,
            result.connected_count,
        )
        QMessageBox.information(
            self,
            "Save Connectivity to DB",
            f"Saved snapshot #{result.snapshot_id} to netcheck.\n\n"
            f"Devices: {result.device_count}  ·  "
            f"SSH ok: {result.connected_count}\n"
            f"Links: {result.link_count}  ·  "
            f"Subnets: {result.subnet_count}\n"
            f"At: {result.saved_at}",
        )

    def _emit_summary(self) -> None:
        devs = [d for d in self._connectable_devices() if not d.ignored]
        up = sum(1 for d in devs if d.ssh and d.ssh.last_status == "ok")
        self.ssh_summary_changed.emit(f"SSH {up}/{len(devs)} connected")
        # Keep subnet "N connected" labels in sync without requiring a full
        # site reload (selection may change during Connect).
        if self.subnet_table.rowCount() == len(getattr(self._site, "subnets", []) or []):
            self._refresh_subnet_connected_labels()
        else:
            self._refresh_subnet_list()

    def _refresh_subnet_connected_labels(self) -> None:
        """Update the Seen and Connected labels in place (keeps selection)."""
        if self._site is None:
            return
        for row, cidr in enumerate(self._site.subnets):
            if row >= self.subnet_table.rowCount():
                break
            seen_label = self.subnet_table.cellWidget(row, 1)
            if isinstance(seen_label, QLabel):
                text, color, tip = net_discovery.seen_summary(
                    self._seen_state.get(cidr, "pending"),
                    self._seen.get(cidr, []),
                    self._seen_error.get(cidr, ""),
                )
                weight = "600" if color == net_discovery.SEEN_COLOR else "normal"
                seen_label.setText(text)
                seen_label.setStyleSheet(
                    f"color: {color}; font-weight: {weight}; padding: 0 8px;"
                )
                seen_label.setToolTip(tip)
            conn_label = self.subnet_table.cellWidget(row, 2)
            if isinstance(conn_label, QLabel):
                names = [d.name for d in self._connected_devices_in_subnet(cidr)]
                text, color = net_discovery.connected_summary(names)
                weight = "600" if names else "normal"
                conn_label.setText(text)
                conn_label.setStyleSheet(
                    f"color: {color}; font-weight: {weight}; padding: 0 8px;"
                )
                conn_label.setToolTip(
                    f"SSH-connected session devices on {cidr}"
                    + (":\n" + "\n".join(names) if names else " — none yet")
                )

    # ------------------------------------------------- network discovery

    def _start_discovery(
        self, cidrs: list[str] | None = None, *, rescan: bool = False
    ) -> None:
        """Sweep listed subnets for routers, switches, gateways, firewalls."""
        if self._site is None:
            return
        wanted = list(cidrs) if cidrs is not None else list(self._site.subnets)
        if not rescan:
            wanted = [c for c in wanted if c not in self._seen_state]
        for cidr in wanted:
            if rescan:
                self._discovery_refresh.add(cidr)
            if cidr not in self._discovery_queue:
                self._discovery_queue.append(cidr)
                self._seen_state[cidr] = "pending"
        self._refresh_subnet_connected_labels()
        self._run_discovery_queue()

    def _run_discovery_queue(self) -> None:
        worker = self._discovery_worker
        if worker is not None and worker.isRunning():
            return  # the finished handler starts the rest
        if not self._discovery_queue:
            self.btn_rescan.setEnabled(True)
            return
        batch, self._discovery_queue = self._discovery_queue, []
        refresh = {c for c in batch if c in self._discovery_refresh}
        self._discovery_refresh -= refresh
        self.btn_rescan.setEnabled(False)
        worker = _DiscoveryWorker(batch, refresh)
        worker.subnet_started.connect(self._on_discovery_started)
        worker.subnet_done.connect(self._on_discovery_done)
        worker.subnet_failed.connect(self._on_discovery_failed)
        worker.finished.connect(self._on_discovery_finished)
        self._discovery_worker = worker
        worker.start()

    def _on_discovery_started(self, cidr: str) -> None:
        self._seen_state[cidr] = "scanning"
        self._refresh_subnet_connected_labels()

    def _on_discovery_done(self, cidr: str, seen: list) -> None:
        self._seen[cidr] = list(seen)
        self._seen_state[cidr] = "done"
        self._seen_error.pop(cidr, None)
        if self._add_seen_to_site(seen):
            keep = self._selected_subnet()
            self.set_site(self._ensure_site())
            if keep and self._site and keep in self._site.subnets:
                self.subnet_table.selectRow(self._site.subnets.index(keep))
            self.site_changed.emit()
        self._refresh_subnet_connected_labels()

    _GENERIC_SEEN_KINDS = {"", "router", "switch", "host", "other"}

    def _add_seen_to_site(self, seen: list) -> bool:
        """Put each seen network device on the login list (no duplicates).

        A device already listed by IP or MAC keeps its name and any kind the
        operator chose; only a generic kind is upgraded. Returns True if the
        site changed.
        """
        site = self._ensure_site()
        changed = False
        for found in seen:
            kind = net_discovery.kind_for(found)
            evidence = "; ".join(found.evidence)
            existing = self._find_device_by_host_or_mac(ip=found.ip, mac=found.mac)
            if existing is not None:
                if existing.ignored:
                    continue
                if (existing.kind or "") in self._GENERIC_SEEN_KINDS and kind != existing.kind:
                    existing.kind = kind
                    changed = True
                ssh = existing.ensure_ssh()
                if not ssh.host:
                    ssh.host = found.ip
                    changed = True
                continue
            notes = "; ".join(
                part
                for part in (f"MAC {found.mac}" if found.mac else "", f"seen: {evidence}")
                if part
            )
            dev = Device(
                name=self._unique_device_name(found.ip),
                kind=kind,
                mgmt_ip=found.ip,
                notes=notes,
            )
            dev.ensure_ssh().host = found.ip
            self._hydrate_device_from_saved_credentials(dev, found.ip)
            site.add_or_update_device(dev)
            app_log.get_logger("discovery").info(
                "Seen device added: %s %s (%s)", found.ip, kind, found.vendor or found.role
            )
            changed = True
        return changed

    def _on_discovery_failed(self, cidr: str, message: str, too_large: bool) -> None:
        self._seen_state[cidr] = "too_large" if too_large else "error"
        self._seen_error[cidr] = message
        self._seen.pop(cidr, None)
        app_log.get_logger("discovery").warning("Discovery %s: %s", cidr, message)
        self._refresh_subnet_connected_labels()

    def _on_discovery_finished(self) -> None:
        worker = self._discovery_worker
        self._discovery_worker = None
        if worker is not None:
            worker.deleteLater()
        self._run_discovery_queue()

    def _seen_device(self, ip: str):  # noqa: ANN202
        for devices in self._seen.values():
            for dev in devices:
                if dev.ip == ip:
                    return dev
        return None
