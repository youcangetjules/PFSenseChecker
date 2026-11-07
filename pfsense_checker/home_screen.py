"""Home hub — opening GUI with feature sections.

Sections:
  • Login to Routers — SSH session targets
  • File / Folder Ops — open configs, re-check, export, workspace
  • Beaconing — live monitor + beacon creator entry
  • Subnet Health — local + beacon subnet access, Wired/WLAN, ping/speed
  • Config Check — open / import configs
  • Speed Checker — ping & download from a chosen point
  • Topology — site map / builder entry
  • Database — PostgreSQL login, browse, SQL, schema
  • Users — manage sign-in accounts
  • Python Modules — requirements.txt vs installed / loaded
  • Tests — run the project pytest suite
  • Ollama — enable and configure local LLM advisor
  • Problems/Troubleshooting — findings, resiliency, live monitor
  • Console — live debug / failure log viewer
  • Syslog — receive remote syslog from attached routers
  • Log Pipeline — stream incoming pfSense logs on a chosen port (default 59000)
  • Wireshark — Lua API bridge (capture / dissection hooks)
  • Setup — API keys, OpenObserve, and tool preferences (subcategories)
  • About — app info (placeholder)
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QTextCursor
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from pfsense_checker import ai, app_log, auth, oui, python_modules, snmp, subnet_health, syslog_recv
from pfsense_checker.branding import NAV_TREE_STYLE, render_logo_pixmap
from pfsense_checker.db_admin_screen import DatabaseScreen
from pfsense_checker.session_screen import SessionScreen
from pfsense_checker.site_canvas import SiteTopologyView
from pfsense_checker.speed_check import SpeedCheckWorker, SpeedSample
from pfsense_checker.topology_site import SiteTopology
from pfsense_checker.tests_screen import TestsScreen
from pfsense_checker.users_screen import UsersScreen

# Top-level nav order (Setup has nested subcategories)
SECTIONS = (
    ("login", "Login to Routers"),
    ("files", "File / Folder Ops"),
    ("beaconing", "Beaconing"),
    ("subnet_health", "Subnet Health"),
    ("config", "Config Check"),
    ("speed", "Speed Checker"),
    ("topology", "Topology"),
    ("database", "Database"),
    ("users", "Users"),
    ("modules", "Python Modules"),
    ("tests", "Tests"),
    ("ollama", "Ollama"),
    ("problems", "Problems/Troubleshooting"),
    ("console", "Console"),
    ("syslog", "Syslog"),
    ("log_pipeline", "Log Pipeline"),
    ("wireshark", "Wireshark"),
    ("setup", "Setup"),
    ("about", "About"),
)

SETUP_SUBSECTIONS = (
    ("setup.oui", "OUI / MAC Lookup"),
    ("setup.logging", "Logging"),
    ("setup.openobserve", "OpenObserve"),
    ("setup.snmp", "SNMP (v3)"),
    ("setup.mibs", "MIB Libraries"),
    ("setup.version", "Version"),
)

# Short capability blurbs for the status-bar (user | module — capabilities).
SECTION_CAPABILITIES: dict[str, str] = {
    "login": "SSH login · LAN search · topology map · save connectivity",
    "files": "Open config/folder · re-check · export report · workspace",
    "beaconing": "Live monitor · beacon creator · collector health",
    "subnet_health": "Local + beacon subnets · ping/speed · Wired/WLAN",
    "config": "Open pfSense/MikroTik configs · findings workspace",
    "speed": "Ping & download checks from chosen source",
    "topology": "Live/experimental site map · load/save · builder",
    "database": "PostgreSQL browse · SQL · schema · NetCheck tables",
    "users": "Accounts · roles · password reset · enable/disable",
    "modules": "requirements.txt · install/load · Save/Commit",
    "tests": "Discover & run pytest suite",
    "ollama": "Enable local LLM · models · API key · test",
    "problems": "Findings · resiliency · live monitor · AI advisor",
    "console": "Live app logs · failures · debug output",
    "syslog": "UDP/TCP receiver · attached-router allowlist · live messages",
    "log_pipeline": "Stream incoming pfSense logs · listen port default 59000",
    "wireshark": "Lua API bridge · Listener / Field / Proto hooks",
    "setup": "API keys and tool preferences",
    "setup.oui": "RapidAPI MAC/OUI vendor lookup key",
    "setup.logging": "Log directory · level · ring file",
    "setup.openobserve": "Ingest and search logs · syslog forward · SQL query",
    "setup.snmp": "SNMPv3 credentials · test probe",
    "setup.mibs": "MIB search paths · vendor MIB files for SNMP",
    "setup.version": "App version · full changelog of each release",
    "about": "Product info · licensing · credits (placeholder)",
}


def section_title(key: str) -> str:
    for k, label in SECTIONS:
        if k == key:
            return label
    for k, label in SETUP_SUBSECTIONS:
        if k == key:
            return label
    return key.replace(".", " / ").title()


def section_capabilities(key: str) -> str:
    return SECTION_CAPABILITIES.get(key, "")


def _section_card(title: str, body: str) -> QWidget:
    box = QGroupBox(title)
    lay = QVBoxLayout(box)
    label = QLabel(body)
    label.setWordWrap(True)
    label.setStyleSheet("color: #444;")
    lay.addWidget(label)
    return box


_CONSOLE_VIEW_STYLE = (
    "QPlainTextEdit {"
    " background: #111111; color: #e0e0e0;"
    " border: 1px solid #333; border-radius: 4px;"
    " padding: 6px;"
    "}"
)


class HomeScreen(QWidget):
    """Opening page: section nav + content for each major feature."""

    # Navigate into the analysis workspace at a named tab (or "" for default)
    open_workspace = Signal(str)
    load_site_requested = Signal()
    save_topology_requested = Signal()
    load_live_topology_requested = Signal()
    save_live_topology_requested = Signal()
    open_folder_requested = Signal()
    open_config_requested = Signal()
    config_pulled_for_check = Signal(str)  # path after SSH pull for Config Check
    recheck_requested = Signal()
    export_report_requested = Signal()
    ssh_summary_changed = Signal(str)
    ollama_status_changed = Signal()  # settings saved / connection probed
    db_status_changed = Signal(bool, str, str)  # connected, text, tooltip
    section_changed = Signal(str, str, str)  # key, title, capabilities
    site_changed = Signal()  # login panel mutated the live site
    topology_mode_requested = Signal(str)  # "live" | "experimental"

    def __init__(self) -> None:
        super().__init__()
        self._live_site: SiteTopology | None = None
        self._topology_site: SiteTopology | None = None
        self._topology_mode = "live"
        self._speed_worker: SpeedCheckWorker | None = None
        self._subnet_health_worker: QThread | None = None
        self._subnet_health_timer = QTimer(self)
        self._subnet_health_timer.timeout.connect(self._subnet_health_run)
        self._recheck_enabled = False
        self._current_user: auth.AuthUser | None = None
        self._site_changed_timer = QTimer(self)
        self._site_changed_timer.setSingleShot(True)
        self._site_changed_timer.setInterval(150)
        self._site_changed_timer.timeout.connect(self._flush_session_site_changed)
        self._build()

    # ------------------------------------------------------------------ UI

    def _build(self) -> None:
        root = QHBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(10)

        # --- left nav ---
        nav_col = QVBoxLayout()
        logo_pix = render_logo_pixmap(width=160)
        if logo_pix is not None:
            brand = QLabel()
            brand.setPixmap(logo_pix)
            brand.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            brand.setToolTip("NetCheck")
        else:
            brand = QLabel("NetCheck")
            bf = QFont()
            bf.setPointSize(16)
            bf.setBold(True)
            brand.setFont(bf)
        nav_col.addWidget(brand)
        hint = QLabel("Choose a section")
        hint.setStyleSheet("color: #666; margin-bottom: 6px;")
        nav_col.addWidget(hint)

        self.nav = QTreeWidget()
        self.nav.setHeaderHidden(True)
        self.nav.setFixedWidth(200)
        self.nav.setIndentation(12)
        self.nav.setRootIsDecorated(True)
        self.nav.setStyleSheet(NAV_TREE_STYLE)
        for key, label in SECTIONS:
            item = QTreeWidgetItem([label])
            item.setData(0, Qt.ItemDataRole.UserRole, key)
            self.nav.addTopLevelItem(item)
            if key == "setup":
                for sub_key, sub_label in SETUP_SUBSECTIONS:
                    child = QTreeWidgetItem([sub_label])
                    child.setData(0, Qt.ItemDataRole.UserRole, sub_key)
                    item.addChild(child)
                item.setExpanded(True)
        self.nav.currentItemChanged.connect(self._on_nav_item)
        self.nav.itemClicked.connect(self._on_nav_clicked)
        nav_col.addWidget(self.nav, stretch=1)

        btn_workspace = QPushButton("Full workspace…")
        btn_workspace.setToolTip("Open the full analysis tab set")
        btn_workspace.clicked.connect(lambda: self.open_workspace.emit(""))
        nav_col.addWidget(btn_workspace)
        root.addLayout(nav_col)

        # --- content stack (pages built lazily on first visit) ---
        self.stack = QStackedWidget()
        self._page_index: dict[str, int] = {}
        self._page_builders = {
            "login": self._build_login,
            "beaconing": self._build_beaconing,
            "subnet_health": self._build_subnet_health,
            "config": self._build_config,
            "speed": self._build_speed,
            "topology": self._build_topology,
            "database": self._build_database,
            "users": self._build_users,
            "files": self._build_files,
            "modules": self._build_modules,
            "tests": self._build_tests,
            "ollama": self._build_ollama,
            "problems": self._build_problems,
            "console": self._build_console,
            "syslog": self._build_syslog,
            "log_pipeline": self._build_log_pipeline,
            "wireshark": self._build_wireshark,
            "setup.oui": self._build_setup_oui,
            "setup.logging": self._build_setup_logging,
            "setup.openobserve": self._build_setup_openobserve,
            "setup.snmp": self._build_setup_snmp,
            "setup.mibs": self._build_setup_mibs,
            "setup.version": self._build_setup_version,
            "about": self._build_about,
        }
        # Default landing page — defer Login build so the hub paints first.
        placeholder = QLabel("Loading Login to Routers…")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder.setStyleSheet("color: #666;")
        self.stack.addWidget(placeholder)
        self._login_placeholder = placeholder
        QTimer.singleShot(0, self._deferred_ensure_login_page)

        root.addWidget(self.stack, stretch=1)

        if self.nav.topLevelItemCount():
            self.nav.setCurrentItem(self.nav.topLevelItem(0))

    def _deferred_ensure_login_page(self) -> None:
        """Build the Login page after the first event-loop turn (faster hub paint)."""
        if "login" in self._page_index:
            return
        idx = self._ensure_page("login")
        placeholder = getattr(self, "_login_placeholder", None)
        if placeholder is not None:
            ph_idx = self.stack.indexOf(placeholder)
            if ph_idx >= 0:
                self.stack.removeWidget(placeholder)
                placeholder.deleteLater()
            self._login_placeholder = None
        if idx is not None:
            self.stack.setCurrentIndex(idx)

    def _ensure_page(self, key: str) -> int | None:
        """Build and cache a section page on first use; return stack index."""
        if key in self._page_index:
            return self._page_index[key]
        builder = self._page_builders.get(key)
        if builder is None:
            return None
        widget = builder()
        idx = self.stack.addWidget(widget)
        self._page_index[key] = idx
        # Apply any site already loaded before this page existed.
        if key == "login" and self._live_site is not None:
            self.session.set_site(self._live_site)
            self._refresh_speed_sources()
        elif key == "topology" and self._topology_site is not None:
            self.topo_preview.render_site(self._topology_site)
            if hasattr(self, "btn_use_live"):
                self._update_mode_buttons()
        elif key == "speed":
            self._refresh_speed_sources()
        elif key == "users" and hasattr(self, "users_page"):
            self.users_page.set_current_user(self._current_user)
        elif key == "log_pipeline" and hasattr(self, "log_pipeline"):
            self.log_pipeline._refresh_hint()
        elif key == "syslog":
            self._syslog_refresh_sources()
            if hasattr(self, "syslog_bind") and isinstance(self.syslog_bind, QComboBox):
                self._syslog_fill_iface_combo()
                self._syslog_refresh_listen_hint()
            if hasattr(self, "_syslog_buffer"):
                self._syslog_rebuild_filter_options_from_buffer()
        elif key == "console":
            self._refresh_console_status()
        return idx

    def _find_nav_item(self, key: str) -> QTreeWidgetItem | None:
        def walk(item: QTreeWidgetItem) -> QTreeWidgetItem | None:
            if item.data(0, Qt.ItemDataRole.UserRole) == key:
                return item
            for i in range(item.childCount()):
                found = walk(item.child(i))
                if found is not None:
                    return found
            return None

        for i in range(self.nav.topLevelItemCount()):
            found = walk(self.nav.topLevelItem(i))
            if found is not None:
                return found
        return None

    def _default_page_key(self, key: str, item: QTreeWidgetItem | None) -> str:
        """First page shown for a nav node (Setup → first subsection, etc.)."""
        if key == "setup":
            return SETUP_SUBSECTIONS[0][0]
        if (
            item is not None
            and item.childCount() > 0
            and key not in self._page_builders
        ):
            child_key = item.child(0).data(0, Qt.ItemDataRole.UserRole)
            return str(child_key) if child_key else key
        return key

    def _resolve_nav_target(
        self, item: QTreeWidgetItem
    ) -> tuple[QTreeWidgetItem, str]:
        """Map a clicked nav row to the leaf item + page key to display."""
        key = str(item.data(0, Qt.ItemDataRole.UserRole) or "")
        if key == "setup" and item.childCount() > 0:
            item.setExpanded(True)
            item = item.child(0)
            key = str(item.data(0, Qt.ItemDataRole.UserRole) or "")
        else:
            page_key = self._default_page_key(key, item)
            if page_key != key:
                found = self._find_nav_item(page_key)
                if found is not None:
                    parent = found.parent()
                    if parent is not None:
                        parent.setExpanded(True)
                    item = found
                    key = page_key
            elif item.parent() is not None:
                item.parent().setExpanded(True)
        return item, key

    def _show_page(self, key: str, nav_item: QTreeWidgetItem | None) -> None:
        app_log.get_logger("nav").debug("Home page: %s", key)
        idx = self._ensure_page(key)
        if idx is not None:
            self.stack.setCurrentIndex(idx)
        if key == "syslog":
            self._syslog_refresh_sources()
            if hasattr(self, "syslog_bind") and isinstance(self.syslog_bind, QComboBox):
                self._syslog_fill_iface_combo()
                self._syslog_refresh_listen_hint()
            self._syslog_rebuild_filter_options_from_buffer()
            self._syslog_apply_filter()
        elif key == "console":
            self._refresh_console_status()
        if key:
            title = (
                nav_item.text(0) if nav_item is not None else section_title(str(key))
            ) or section_title(str(key))
            self.section_changed.emit(
                str(key), title, section_capabilities(str(key))
            )

    def _activate_nav_item(self, item: QTreeWidgetItem | None) -> None:
        if item is None:
            return
        target_item, page_key = self._resolve_nav_target(item)
        if self.nav.currentItem() is not target_item:
            self.nav.blockSignals(True)
            self.nav.setCurrentItem(target_item)
            self.nav.blockSignals(False)
        self._show_page(page_key, target_item)

    def _on_nav_item(
        self, current: QTreeWidgetItem | None, _previous: QTreeWidgetItem | None
    ) -> None:
        self._activate_nav_item(current)

    def _on_nav_clicked(self, item: QTreeWidgetItem, _column: int) -> None:
        """Always navigate — even re-clicking a section or its parent header."""
        self._activate_nav_item(item)

    def show_section(self, key: str) -> None:
        """Select a section by key (e.g. 'login', 'topology', 'setup.oui')."""
        page_key = self._default_page_key(key, self._find_nav_item(key))
        found = self._find_nav_item(page_key)
        if found is not None:
            parent = found.parent()
            if parent is not None:
                parent.setExpanded(True)
            self.nav.blockSignals(True)
            self.nav.setCurrentItem(found)
            self.nav.blockSignals(False)
            self._show_page(page_key, found)
            return
        self._show_page(page_key, None)

    # ----------------------------------------------------------- sections

    def _build_beaconing(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("Beaconing")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        v.addWidget(
            _section_card(
                "Continuous subnet monitoring",
                "Deploy corridor beacons (one per subnet, or one trunked host with "
                "multiple VLAN/DHCP configs). Beacons POST ping + DHCP results to the "
                "collector. Start the collector with  python run_collector.py  then run "
                "beacons with  python run_beacon.py --config samples/beacon_lan.json",
            )
        )

        actions = QHBoxLayout()
        btn_monitor = QPushButton("Open Live Monitor")
        btn_monitor.setStyleSheet(_primary_btn())
        btn_monitor.clicked.connect(lambda: self.open_workspace.emit("Live Monitor"))
        actions.addWidget(btn_monitor)
        btn_creator = QPushButton("Open Beacon Creator")
        btn_creator.clicked.connect(lambda: self.open_workspace.emit("Beacon Creator"))
        actions.addWidget(btn_creator)
        actions.addStretch(1)
        v.addLayout(actions)

        tip = QLabel(
            "Live Monitor polls the collector for beacon health, ping latency charts, "
            "and DHCP probe status. Beacon Creator builds stdlib-only deploy bundles "
            "for Windows, macOS, Linux, and BSD."
        )
        tip.setWordWrap(True)
        tip.setStyleSheet("color: #555;")
        v.addWidget(tip)
        v.addStretch(1)
        return page

    def _build_subnet_health(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("Subnet Health")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        v.addWidget(
            _section_card(
                "Access, link type, connectivity & speed",
                "This PC and each beacon report which subnets they can reach, "
                "whether the path is Wired or WLAN, and periodic ping / download "
                "samples. Beacon interval is set in the beacon config "
                "(interval_sec); local interval is below.",
            )
        )

        settings = subnet_health.load_settings()
        box = QGroupBox("This PC — check schedule")
        form = QFormLayout(box)
        self.sh_interval = QSpinBox()
        self.sh_interval.setRange(10, 3600)
        self.sh_interval.setSuffix(" sec")
        self.sh_interval.setValue(settings.interval_sec)
        form.addRow("Interval:", self.sh_interval)

        self.sh_auto = QCheckBox("Auto-refresh")
        self.sh_auto.setChecked(settings.auto_refresh)
        form.addRow(self.sh_auto)

        self.sh_run_speed = QCheckBox("Include download speed sample")
        self.sh_run_speed.setChecked(settings.run_speed)
        form.addRow(self.sh_run_speed)

        self.sh_speed_url = QLineEdit(settings.speed_url)
        self.sh_speed_url.setPlaceholderText(subnet_health.DEFAULT_SPEED_URL)
        form.addRow("Speed URL:", self.sh_speed_url)

        self.sh_collector = QLineEdit(settings.collector_url)
        form.addRow("Collector URL:", self.sh_collector)

        self.sh_token = QLineEdit(settings.collector_token)
        self.sh_token.setEchoMode(QLineEdit.EchoMode.Password)
        self.sh_token.setPlaceholderText("optional Bearer token")
        form.addRow("Collector token:", self.sh_token)
        v.addWidget(box)

        actions = QHBoxLayout()
        self.btn_sh_run = QPushButton("Run check now")
        self.btn_sh_run.setStyleSheet(_primary_btn())
        self.btn_sh_run.clicked.connect(self._subnet_health_run)
        actions.addWidget(self.btn_sh_run)
        btn_save = QPushButton("Save settings")
        btn_save.clicked.connect(self._subnet_health_save)
        actions.addWidget(btn_save)
        btn_monitor = QPushButton("Open Live Monitor")
        btn_monitor.clicked.connect(lambda: self.open_workspace.emit("Live Monitor"))
        actions.addWidget(btn_monitor)
        actions.addStretch(1)
        self.sh_status = QLabel("")
        self.sh_status.setStyleSheet("color: #555;")
        actions.addWidget(self.sh_status)
        v.addLayout(actions)

        self.sh_table = QTableWidget(0, 9)
        self.sh_table.setHorizontalHeaderLabels(
            [
                "Source",
                "Subnet",
                "Link",
                "Interface",
                "Gateway",
                "Ping",
                "Speed",
                "Last check",
                "Notes",
            ]
        )
        hdr = self.sh_table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hdr.setStretchLastSection(True)
        self.sh_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.sh_table.verticalHeader().setVisible(False)
        v.addWidget(self.sh_table, stretch=1)

        tip = QLabel(
            "Beacons: set interval_sec, optional speed_url / speed_every_n_cycles, "
            "and link_type (wired|wlan) or subnets[].link_type in the beacon JSON. "
            "Accessible subnets are published in report meta for this view."
        )
        tip.setWordWrap(True)
        tip.setStyleSheet("color: #555;")
        v.addWidget(tip)

        self.sh_auto.toggled.connect(self._subnet_health_apply_timer)
        self.sh_interval.valueChanged.connect(self._subnet_health_apply_timer)
        self._subnet_health_apply_timer()
        QTimer.singleShot(200, self._subnet_health_run)
        return page

    def _subnet_health_settings_from_ui(self) -> subnet_health.SubnetHealthSettings:
        return subnet_health.SubnetHealthSettings(
            interval_sec=int(self.sh_interval.value()),
            speed_url=self.sh_speed_url.text().strip()
            or subnet_health.DEFAULT_SPEED_URL,
            run_speed=self.sh_run_speed.isChecked(),
            collector_url=self.sh_collector.text().strip(),
            collector_token=self.sh_token.text().strip(),
            auto_refresh=self.sh_auto.isChecked(),
        )

    def _subnet_health_save(self) -> None:
        settings = self._subnet_health_settings_from_ui()
        try:
            subnet_health.save_settings(settings)
        except OSError as exc:
            QMessageBox.critical(self, "Subnet Health", str(exc))
            return
        self._subnet_health_apply_timer()
        self.sh_status.setText("Settings saved.")
        self.sh_status.setStyleSheet("color: #1565c0;")
        app_log.get_logger("subnet_health").info(
            "Subnet health settings saved interval=%ss speed=%s",
            settings.interval_sec,
            settings.run_speed,
        )

    def _subnet_health_apply_timer(self) -> None:
        if not hasattr(self, "sh_auto"):
            return
        self._subnet_health_timer.stop()
        if self.sh_auto.isChecked():
            self._subnet_health_timer.start(max(10, int(self.sh_interval.value())) * 1000)

    def _subnet_health_run(self) -> None:
        if not hasattr(self, "sh_table"):
            return
        if self._subnet_health_worker and self._subnet_health_worker.isRunning():
            return
        settings = self._subnet_health_settings_from_ui()
        self.btn_sh_run.setEnabled(False)
        self.sh_status.setText("Checking…")
        self.sh_status.setStyleSheet("color: #555;")

        class _Worker(QThread):
            finished_ok = Signal(list)
            failed = Signal(str)

            def __init__(self, cfg: subnet_health.SubnetHealthSettings) -> None:
                super().__init__()
                self._cfg = cfg

            def run(self) -> None:  # noqa: D102
                try:
                    rows = subnet_health.check_all_local(
                        ping_count=self._cfg.ping_count,
                        speed_url=self._cfg.speed_url,
                        run_speed=self._cfg.run_speed,
                    )
                    for b in subnet_health.fetch_collector_beacons(
                        self._cfg.collector_url, token=self._cfg.collector_token
                    ):
                        rows.extend(subnet_health.subnet_rows_from_beacon(b))
                    self.finished_ok.emit(rows)
                except Exception as exc:  # noqa: BLE001
                    self.failed.emit(str(exc))

        worker = _Worker(settings)
        self._subnet_health_worker = worker
        worker.finished_ok.connect(self._subnet_health_done)
        worker.failed.connect(self._subnet_health_failed)
        worker.finished.connect(lambda: self.btn_sh_run.setEnabled(True))
        worker.start()

    def _subnet_health_failed(self, msg: str) -> None:
        self.sh_status.setText(msg)
        self.sh_status.setStyleSheet("color: #c62828;")
        app_log.get_logger("subnet_health").error("Subnet health check failed: %s", msg)

    def _subnet_health_done(self, rows: object) -> None:
        if not isinstance(rows, list):
            return
        self.sh_table.setRowCount(len(rows))
        local_n = 0
        beacon_n = 0
        for r, row in enumerate(rows):
            if not isinstance(row, subnet_health.SubnetAccess):
                continue
            if row.source == "local":
                local_n += 1
                source = "This PC"
            else:
                beacon_n += 1
                source = row.source.replace("beacon:", "Beacon ")
                if row.hostname:
                    source += f" ({row.hostname})"
            ping = (
                f"{row.ping_ms:.0f} ms"
                if row.ping_ms is not None
                else (row.ping_status or "—")
            )
            if row.ping_status and row.ping_status != "ok" and row.ping_ms is not None:
                ping = f"{row.ping_status} ({ping})"
            elif row.ping_status and row.ping_ms is None:
                ping = row.ping_status
            speed = (
                f"{row.speed_mbps:.1f} Mbps"
                if row.speed_mbps is not None
                else (row.speed_status or "—")
            )
            values = [
                source,
                row.cidr,
                subnet_health.link_type_label(row.link_type),
                row.interface or "—",
                row.gateway or "—",
                ping,
                speed,
                row.last_check or "—",
                row.message or "",
            ]
            for c, text in enumerate(values):
                item = QTableWidgetItem(str(text))
                if c == 2:
                    lt = subnet_health.normalize_link_type(row.link_type)
                    if lt == "wired":
                        item.setForeground(Qt.GlobalColor.darkBlue)
                    elif lt == "wlan":
                        item.setForeground(Qt.GlobalColor.darkGreen)
                if c == 5 and row.ping_status == "ok":
                    item.setForeground(Qt.GlobalColor.darkGreen)
                elif c == 5 and row.ping_status in {"fail", "error"}:
                    item.setForeground(Qt.GlobalColor.red)
                self.sh_table.setItem(r, c, item)
        self.sh_status.setText(
            f"Updated — {local_n} local subnet(s), {beacon_n} from beacons."
        )
        self.sh_status.setStyleSheet("color: #2e7d32;")
        app_log.get_logger("subnet_health").info(
            "Subnet health refreshed local=%s beacon_rows=%s", local_n, beacon_n
        )

    def _build_config(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("Config Check")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        v.addWidget(
            _section_card(
                "Validate firewall & router exports",
                "Open a pfSense/OPNsense config.xml or MikroTik RouterOS .rsc export, "
                "or pull live config from an SSH-connected device on Login to Routers. "
                "The checker reports structure, interfaces, bridges/VLANs/LAGG, "
                "firewall/NAT, VPN, DNS, users, and more — with a dashboard and "
                "findings you can export.",
            )
        )

        actions = QHBoxLayout()
        btn_open = QPushButton("Open config…")
        btn_open.setStyleSheet(_primary_btn())
        btn_open.clicked.connect(self.open_config_requested.emit)
        actions.addWidget(btn_open)
        btn_folder = QPushButton("Import config folder…")
        btn_folder.clicked.connect(self.open_folder_requested.emit)
        actions.addWidget(btn_folder)
        btn_pull = QPushButton("Pull config from connected device")
        btn_pull.setToolTip(
            "SSH-pull config.xml or /export verbose from a device already "
            "connected on Login to Routers, then run Config Check"
        )
        btn_pull.clicked.connect(self._pull_config_from_connected_device)
        actions.addWidget(btn_pull)
        btn_dash = QPushButton("Open Dashboard")
        btn_dash.clicked.connect(lambda: self.open_workspace.emit("Dashboard"))
        actions.addWidget(btn_dash)
        actions.addStretch(1)
        v.addLayout(actions)

        drop = QFrame()
        drop.setObjectName("configDrop")
        drop.setAcceptDrops(True)
        drop.setMinimumHeight(220)
        drop.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        drop.setFrameShape(QFrame.Shape.StyledPanel)
        drop.setStyleSheet(
            "QFrame#configDrop { border: 2px dashed #90a4ae; border-radius: 6px; "
            "background: #f5f7f8; }"
        )
        dl = QVBoxLayout(drop)
        hint = QLabel("Drop a config.xml or RouterOS .rsc here")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setStyleSheet("color: #455a64; font-size: 14px;")
        dl.addStretch(1)
        dl.addWidget(hint)
        detail = QLabel("pfSense / OPNsense XML, or a MikroTik export. One file.")
        detail.setAlignment(Qt.AlignmentFlag.AlignCenter)
        detail.setStyleSheet("color: #78909c;")
        dl.addWidget(detail)
        dl.addStretch(1)
        v.addWidget(drop, stretch=1)
        return page

    def _build_speed(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("Speed Checker")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        v.addWidget(
            _section_card(
                "Measure from a certain point",
                "Pick where you are testing from (this PC, or a device management host "
                "as the labelled source point), then choose Ping, Traceroute, or Download. "
                "Probes run on this workstation — use the label to record which corridor / "
                "device you stood at.",
            )
        )

        form_box = QGroupBox("Test setup")
        form = QFormLayout(form_box)
        self.speed_source = QComboBox()
        self.speed_source.setMinimumWidth(280)
        form.addRow("Source point", self.speed_source)

        self.speed_test_type = QComboBox()
        self.speed_test_type.setMinimumWidth(280)
        for label, key in (
            ("Ping", "ping"),
            ("Traceroute", "traceroute"),
            ("Download", "download"),
        ):
            self.speed_test_type.addItem(label, key)
        form.addRow("Test type", self.speed_test_type)

        self.speed_target_label = QLabel("Target")
        self.speed_ping = QLineEdit()
        self.speed_ping.setPlaceholderText("e.g. 8.8.8.8 or gateway IP")
        form.addRow(self.speed_target_label, self.speed_ping)

        self.speed_url_label = QLabel("Download URL")
        self.speed_url = QLineEdit()
        self.speed_url.setPlaceholderText(
            "e.g. https://speed.cloudflare.com/__down?bytes=5000000"
        )
        form.addRow(self.speed_url_label, self.speed_url)

        self.speed_count_label = QLabel("Ping count")
        self.speed_count = QSpinBox()
        self.speed_count.setRange(1, 20)
        self.speed_count.setValue(4)
        form.addRow(self.speed_count_label, self.speed_count)
        self.speed_test_type.currentIndexChanged.connect(self._sync_speed_form)
        v.addWidget(form_box)

        row = QHBoxLayout()
        self.btn_speed_run = QPushButton("Run check")
        self.btn_speed_run.setStyleSheet(_primary_btn())
        self.btn_speed_run.clicked.connect(self._run_speed)
        row.addWidget(self.btn_speed_run)
        self.speed_status = QLabel("Idle")
        self.speed_status.setStyleSheet("color: #555;")
        row.addWidget(self.speed_status, stretch=1)
        v.addLayout(row)

        self.speed_table = QTableWidget(0, 5)
        self.speed_table.setHorizontalHeaderLabels(
            ["Kind", "Status", "Target", "Latency / Mbps", "Detail"]
        )
        self.speed_table.horizontalHeader().setStretchLastSection(True)
        v.addWidget(self.speed_table, stretch=1)

        self.speed_log = QTextEdit()
        self.speed_log.setReadOnly(True)
        self.speed_log.setMaximumHeight(90)
        self.speed_log.setPlaceholderText("Run log…")
        v.addWidget(self.speed_log)

        self._refresh_speed_sources()
        self._sync_speed_form()
        return page

    def _pull_config_from_connected_device(self) -> None:
        """Ensure Login is loaded, then pull from an SSH-connected device."""
        self._ensure_page("login")
        self.session.pull_config_from_connected_device()

    def _sync_speed_form(self) -> None:
        """Show fields relevant to the selected test type."""
        if not hasattr(self, "speed_test_type"):
            return
        test_type = self.speed_test_type.currentData() or "ping"
        is_ping = test_type == "ping"
        is_trace = test_type == "traceroute"
        is_download = test_type == "download"
        self.speed_target_label.setVisible(is_ping or is_trace)
        self.speed_ping.setVisible(is_ping or is_trace)
        self.speed_count_label.setVisible(is_ping)
        self.speed_count.setVisible(is_ping)
        self.speed_url_label.setVisible(is_download)
        self.speed_url.setVisible(is_download)

    def _build_login(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        v.setContentsMargins(0, 0, 0, 0)
        self.session = SessionScreen()
        # SessionScreen already has Enter Workspace — route through home signal
        self.session.enter_workspace.connect(lambda: self.open_workspace.emit(""))
        self.session.load_site_requested.connect(self.load_live_topology_requested.emit)
        self.session.save_topology_requested.connect(self.save_live_topology_requested.emit)
        self.session.open_folder_requested.connect(self.open_folder_requested.emit)
        self.session.ssh_summary_changed.connect(self.ssh_summary_changed.emit)
        self.session.site_changed.connect(self._on_session_site_changed)
        self.session.config_pulled_for_check.connect(self.config_pulled_for_check.emit)
        v.addWidget(self.session)
        return page

    def _on_session_site_changed(self) -> None:
        """Debounce map drags so topology preview is not rebuilt every pixel."""
        self._site_changed_timer.start()

    def _flush_session_site_changed(self) -> None:
        """Keep topology preview / speed sources in sync when login mutates the site."""
        if self._live_site is None:
            return
        if self._topology_mode == "live" and hasattr(self, "topo_preview"):
            self.topo_preview.render_site(self._live_site)
        self._refresh_speed_sources()
        self.site_changed.emit()

    def _build_topology(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("Topology")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        v.addWidget(
            _section_card(
                "Physical & logical site map",
                "Live Topology is the same object as Login to Routers — edit devices "
                "on either page and both update. Experimental Topology is a separate "
                "sandbox that does not change login targets. Save / Load apply to the "
                "active mode.",
            )
        )

        mode_row = QHBoxLayout()
        self.btn_use_live = QPushButton("Use Live Topology")
        self.btn_use_live.setToolTip(
            "Same topology as Login to Routers — shared live site"
        )
        self.btn_use_live.clicked.connect(
            lambda: self.topology_mode_requested.emit("live")
        )
        mode_row.addWidget(self.btn_use_live)
        self.btn_use_experimental = QPushButton("Use Experimental Topology")
        self.btn_use_experimental.setToolTip(
            "Separate sandbox — edits do not change Login to Routers"
        )
        self.btn_use_experimental.clicked.connect(
            lambda: self.topology_mode_requested.emit("experimental")
        )
        mode_row.addWidget(self.btn_use_experimental)
        mode_row.addStretch(1)
        self.topology_mode_label = QLabel("Mode: Live (= Login to Routers)")
        self.topology_mode_label.setStyleSheet("color: #1565c0; font-weight: bold;")
        mode_row.addWidget(self.topology_mode_label)
        v.addLayout(mode_row)

        actions = QHBoxLayout()
        btn_load = QPushButton("Load Topology")
        btn_load.setToolTip("Load the saved topology for the active mode")
        btn_load.clicked.connect(self.load_site_requested.emit)
        actions.addWidget(btn_load)
        btn_save = QPushButton("Save Topology")
        btn_save.setToolTip(
            "Save the active topology (one slot per mode — live or experimental)"
        )
        btn_save.clicked.connect(self.save_topology_requested.emit)
        actions.addWidget(btn_save)
        btn_builder = QPushButton("Open Topology Builder")
        btn_builder.setStyleSheet(_primary_btn())
        btn_builder.clicked.connect(lambda: self.open_workspace.emit("Topology Builder"))
        actions.addWidget(btn_builder)
        btn_logic = QPushButton("Open Logical Topology")
        btn_logic.clicked.connect(lambda: self.open_workspace.emit("Topology"))
        actions.addWidget(btn_logic)
        actions.addStretch(1)
        v.addLayout(actions)

        self.topo_preview = SiteTopologyView()
        self.topo_preview.set_locked(True)
        self.topo_preview.set_ssh_password_provider(
            lambda: self.session.password.text()
        )
        self.topo_preview.device_changed.connect(
            lambda _n: self.session.site_changed.emit()
        )
        v.addWidget(self.topo_preview, stretch=1)
        self._update_mode_buttons()
        return page

    def set_current_user(self, user: auth.AuthUser | None) -> None:
        """Propagate the signed-in user to sections that need it (Users)."""
        self._current_user = user
        if hasattr(self, "users_page"):
            self.users_page.set_current_user(user)

    def _build_database(self) -> QWidget:
        page = DatabaseScreen()
        page.status_changed.connect(
            lambda text: app_log.get_logger("database").info("%s", text)
        )
        page.db_status_changed.connect(self.db_status_changed.emit)
        return page

    def _build_users(self) -> QWidget:
        self.users_page = UsersScreen()
        self.users_page.set_current_user(self._current_user)
        return self.users_page

    def _build_files(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("File / Folder Ops")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        v.addWidget(
            _section_card(
                "Configs, reports & workspace",
                "Open a single config or an entire folder, re-run the last check, "
                "export the report, or jump into the full analysis workspace. "
                "These replace the old top-toolbar file actions.",
            )
        )

        box = QGroupBox("Actions")
        lay = QVBoxLayout(box)

        row1 = QHBoxLayout()
        btn_open = QPushButton("Open Config…")
        btn_open.setStyleSheet(_primary_btn())
        btn_open.setToolTip("Ctrl+O — open a pfSense XML or MikroTik .rsc")
        btn_open.clicked.connect(self.open_config_requested.emit)
        row1.addWidget(btn_open)
        btn_folder = QPushButton("Open Folder…")
        btn_folder.setToolTip("Ctrl+Shift+O — import all configs in a folder")
        btn_folder.clicked.connect(self.open_folder_requested.emit)
        row1.addWidget(btn_folder)
        row1.addStretch(1)
        lay.addLayout(row1)

        row2 = QHBoxLayout()
        self.btn_files_recheck = QPushButton("Re-check")
        self.btn_files_recheck.setToolTip("F5 — re-run the last opened config")
        self.btn_files_recheck.setEnabled(self._recheck_enabled)
        self.btn_files_recheck.clicked.connect(self.recheck_requested.emit)
        row2.addWidget(self.btn_files_recheck)
        btn_export = QPushButton("Export Report…")
        btn_export.setToolTip("Ctrl+S — save the current report text")
        btn_export.clicked.connect(self.export_report_requested.emit)
        row2.addWidget(btn_export)
        row2.addStretch(1)
        lay.addLayout(row2)

        row3 = QHBoxLayout()
        btn_workspace = QPushButton("Open Full Workspace…")
        btn_workspace.clicked.connect(lambda: self.open_workspace.emit(""))
        row3.addWidget(btn_workspace)
        btn_dash = QPushButton("Open Dashboard")
        btn_dash.clicked.connect(lambda: self.open_workspace.emit("Dashboard"))
        row3.addWidget(btn_dash)
        row3.addStretch(1)
        lay.addLayout(row3)

        v.addWidget(box)
        tip = QLabel(
            "Keyboard shortcuts still work from anywhere: Ctrl+O, Ctrl+Shift+O, "
            "F5 (re-check), Ctrl+S (export)."
        )
        tip.setWordWrap(True)
        tip.setStyleSheet("color: #555;")
        v.addWidget(tip)
        v.addStretch(1)
        return page

    def set_recheck_enabled(self, enabled: bool) -> None:
        self._recheck_enabled = bool(enabled)
        if hasattr(self, "btn_files_recheck"):
            self.btn_files_recheck.setEnabled(self._recheck_enabled)

    def _build_tests(self) -> QWidget:
        page = TestsScreen()
        page.status_changed.connect(
            lambda text: app_log.get_logger("tests").info("%s", text)
        )
        return page

    def _build_modules(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("Python Modules")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        v.addWidget(
            _section_card(
                "Requirements vs this process",
                "Lists packages from requirements.txt, whether they are installed "
                "in the active interpreter, whether their import module can be "
                "found, and whether that module is already loaded in this process. "
                "Toggle Installed / Loaded, then Save/Commit to apply "
                "(install missing packages or import modules into this process). "
                "If you use a feature that needs a package that is missing or "
                "not loaded, NetCheck will remind you to come here and install "
                "or load it.",
            )
        )

        summary = python_modules.runtime_summary()
        self.modules_runtime = QLabel(
            f"Python {summary['python']}  ·  {summary['executable']}\n"
            f"requirements.txt: {summary['requirements']}"
        )
        self.modules_runtime.setWordWrap(True)
        self.modules_runtime.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self.modules_runtime.setStyleSheet("color: #444; padding: 2px 0;")
        v.addWidget(self.modules_runtime)

        actions = QHBoxLayout()
        btn_refresh = QPushButton("Refresh")
        btn_refresh.setStyleSheet(_modules_action_btn_style("refresh"))
        btn_refresh.clicked.connect(self._modules_refresh)
        actions.addWidget(btn_refresh)
        btn_open = QPushButton("Open requirements.txt")
        btn_open.setStyleSheet(_modules_action_btn_style("open"))
        btn_open.clicked.connect(self._modules_open_requirements)
        actions.addWidget(btn_open)
        self.btn_modules_save = QPushButton("Save/Commit")
        self.btn_modules_save.setEnabled(False)
        self.btn_modules_save.setStyleSheet(_modules_action_btn_style("save_idle"))
        self.btn_modules_save.setToolTip(
            "Apply checkbox changes: install packages marked Installed, "
            "import modules marked Loaded"
        )
        self.btn_modules_save.clicked.connect(self._modules_save_commit)
        actions.addWidget(self.btn_modules_save)
        # Match height to Refresh, width to Open requirements.txt; same font size.
        for b in (btn_refresh, btn_open, self.btn_modules_save):
            b.ensurePolished()
        width = max(btn_open.sizeHint().width(), 168)
        height = max(btn_refresh.sizeHint().height(), 28)
        for b in (btn_refresh, btn_open, self.btn_modules_save):
            b.setFixedSize(width, height)
        actions.addStretch(1)
        self.modules_summary = QLabel("")
        self.modules_summary.setStyleSheet("color: #555;")
        actions.addWidget(self.modules_summary)
        v.addLayout(actions)

        self.modules_table = QTableWidget(0, 7)
        self.modules_table.setHorizontalHeaderLabels(
            [
                "Package",
                "Required",
                "Installed",
                "Importable",
                "Loaded",
                "Import name",
                "Notes",
            ]
        )
        self.modules_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.modules_table.horizontalHeader().setSectionResizeMode(
            6, QHeaderView.ResizeMode.Stretch
        )
        self.modules_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.modules_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.modules_table.setAlternatingRowColors(True)
        self.modules_table.setColumnWidth(2, 72)
        self.modules_table.setColumnWidth(4, 72)
        v.addWidget(self.modules_table, stretch=1)

        tip = QLabel(
            "Optional packages (AI, Excel, SSH, Postgres) may show as missing "
            "if you skipped them on install — that is expected. "
            "Check Installed / Loaded, then Save/Commit (turns green when changed)."
        )
        tip.setWordWrap(True)
        tip.setStyleSheet("color: #555;")
        v.addWidget(tip)

        self._modules_baseline: list[tuple[bool, bool]] = []
        self._modules_status_rows: list = []
        self._modules_refresh()
        return page

    def _modules_checkbox(self, checked: bool, tooltip: str = "") -> QWidget:
        box = QCheckBox()
        box.setChecked(checked)
        box.setStyleSheet(_modules_checkbox_style())
        box.setToolTip(tooltip)
        box.stateChanged.connect(self._modules_update_save_btn)
        holder = QWidget()
        lay = QHBoxLayout(holder)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(box)
        holder.setProperty("checkbox", box)
        return holder

    def _modules_cell_checkbox(self, holder: QWidget | None) -> QCheckBox | None:
        if holder is None:
            return None
        box = holder.property("checkbox")
        if isinstance(box, QCheckBox):
            return box
        return holder.findChild(QCheckBox)

    def _modules_refresh(self) -> None:
        if not hasattr(self, "modules_table"):
            return
        rows = python_modules.inspect_requirements()
        self._modules_status_rows = list(rows)
        self.modules_table.setRowCount(len(rows))
        baseline: list[tuple[bool, bool]] = []
        installed_n = 0
        loaded_n = 0
        missing_n = 0
        for r, st in enumerate(rows):
            is_installed = bool(st.installed_version)
            if is_installed:
                installed_n += 1
            else:
                missing_n += 1
            if st.loaded:
                loaded_n += 1
            baseline.append((is_installed, bool(st.loaded)))
            pkg = st.name + (f"[{st.extras}]" if st.extras else "")
            self.modules_table.setItem(r, 0, QTableWidgetItem(pkg))
            self.modules_table.setItem(
                r, 1, QTableWidgetItem(st.specifier or "(any)")
            )
            inst_tip = (
                f"Installed: {st.installed_version}"
                if st.installed_version
                else "Not installed"
            )
            self.modules_table.setCellWidget(
                r, 2, self._modules_checkbox(is_installed, inst_tip)
            )
            imp = QTableWidgetItem("yes" if st.importable else "no")
            if not st.importable:
                imp.setForeground(Qt.GlobalColor.red)
            self.modules_table.setItem(r, 3, imp)
            self.modules_table.setCellWidget(
                r,
                4,
                self._modules_checkbox(
                    bool(st.loaded),
                    "Loaded in this process" if st.loaded else "Not loaded",
                ),
            )
            self.modules_table.setItem(r, 5, QTableWidgetItem(st.import_name))
            self.modules_table.setItem(r, 6, QTableWidgetItem(st.optional_note))
        self._modules_baseline = baseline
        summary = python_modules.runtime_summary()
        self.modules_runtime.setText(
            f"Python {summary['python']}  ·  {summary['executable']}\n"
            f"requirements.txt: {summary['requirements']}"
        )
        self.modules_summary.setText(
            f"{installed_n} installed · {missing_n} missing · {loaded_n} loaded now"
        )
        self._modules_update_save_btn()

    def _modules_current_checks(self) -> list[tuple[bool, bool]]:
        out: list[tuple[bool, bool]] = []
        for r in range(self.modules_table.rowCount()):
            inst = self._modules_cell_checkbox(self.modules_table.cellWidget(r, 2))
            load = self._modules_cell_checkbox(self.modules_table.cellWidget(r, 4))
            out.append(
                (
                    bool(inst and inst.isChecked()),
                    bool(load and load.isChecked()),
                )
            )
        return out

    def _modules_is_dirty(self) -> bool:
        current = self._modules_current_checks()
        baseline = getattr(self, "_modules_baseline", [])
        if len(current) != len(baseline):
            return False
        return current != list(baseline)

    def _modules_update_save_btn(self, *_args) -> None:  # noqa: ANN002
        if not hasattr(self, "btn_modules_save"):
            return
        dirty = self._modules_is_dirty()
        self.btn_modules_save.setEnabled(dirty)
        self.btn_modules_save.setStyleSheet(
            _modules_action_btn_style("save_active" if dirty else "save_idle")
        )

    def _modules_save_commit(self) -> None:
        if not self._modules_is_dirty():
            return
        rows = getattr(self, "_modules_status_rows", [])
        current = self._modules_current_checks()
        baseline = list(getattr(self, "_modules_baseline", []))
        to_install: list[str] = []
        to_import: list[str] = []
        notes: list[str] = []
        for i, st in enumerate(rows):
            want_inst, want_load = current[i]
            was_inst, was_load = baseline[i]
            raw = st.raw or st.name
            if want_inst and not was_inst:
                to_install.append(raw)
            elif (not want_inst) and was_inst:
                notes.append(
                    f"Skipped uninstall for {st.name} (uncheck is display-only; "
                    "remove from the venv with pip if needed)."
                )
            if want_load and not was_load:
                to_import.append(st.import_name)
            elif (not want_load) and was_load:
                notes.append(
                    f"Cannot unload {st.import_name} from a running process."
                )

        if not to_install and not to_import and not notes:
            QMessageBox.information(self, "Save/Commit", "Nothing to apply.")
            return

        confirm = QMessageBox.question(
            self,
            "Save/Commit",
            "Apply module changes?\n\n"
            + (
                f"Install: {', '.join(to_install)}\n" if to_install else ""
            )
            + (f"Import: {', '.join(to_import)}\n" if to_import else "")
            + ("\n".join(notes[:5]) if notes else ""),
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        results: list[str] = []
        for spec in to_install:
            try:
                python_modules.pip_install(spec)
                results.append(f"Installed {spec}")
                app_log.get_logger("modules").info("pip install %s", spec)
            except Exception as exc:  # noqa: BLE001
                results.append(f"Install failed {spec}: {exc}")
                app_log.get_logger("modules").error(
                    "pip install failed %s: %s", spec, exc
                )
        for mod in to_import:
            try:
                python_modules.import_now(mod)
                results.append(f"Loaded {mod}")
            except Exception as exc:  # noqa: BLE001
                results.append(f"Load failed {mod}: {exc}")

        results.extend(notes)
        self._modules_refresh()
        QMessageBox.information(
            self,
            "Save/Commit",
            "Done.\n\n" + ("\n".join(results) if results else "No changes applied."),
        )

    def _modules_open_requirements(self) -> None:
        path = python_modules.requirements_path()
        if not path.is_file():
            QMessageBox.warning(
                self, "Requirements", f"File not found:\n{path}"
            )
            return
        from PySide6.QtGui import QDesktopServices
        from PySide6.QtCore import QUrl

        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _build_problems(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("Problems / Troubleshooting")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        v.addWidget(
            _section_card(
                "Diagnose site issues",
                "Start from config findings and resiliency gaps, watch live beacon "
                "health, then use the AI Advisor (Ollama or Poe) on redacted "
                "evidence. Measure reachability with Speed Checker when you need "
                "a quick corridor check.",
            )
        )

        actions = QHBoxLayout()
        btn_findings = QPushButton("Open Findings")
        btn_findings.setStyleSheet(_primary_btn())
        btn_findings.clicked.connect(lambda: self.open_workspace.emit("Findings"))
        actions.addWidget(btn_findings)
        btn_res = QPushButton("Open Resiliency")
        btn_res.clicked.connect(lambda: self.open_workspace.emit("Resiliency"))
        actions.addWidget(btn_res)
        btn_monitor = QPushButton("Open Live Monitor")
        btn_monitor.clicked.connect(lambda: self.open_workspace.emit("Live Monitor"))
        actions.addWidget(btn_monitor)
        actions.addStretch(1)
        v.addLayout(actions)

        more = QHBoxLayout()
        btn_ai = QPushButton("Open AI Advisor")
        btn_ai.clicked.connect(lambda: self.open_workspace.emit("AI Advisor"))
        more.addWidget(btn_ai)
        btn_speed = QPushButton("Speed Checker…")
        btn_speed.clicked.connect(lambda: self.show_section("speed"))
        more.addWidget(btn_speed)
        btn_config = QPushButton("Open config…")
        btn_config.clicked.connect(self.open_config_requested.emit)
        more.addWidget(btn_config)
        more.addStretch(1)
        v.addLayout(more)

        tip = QLabel(
            "Typical path: open a config → review Findings → Analyze resiliency → "
            "ask AI Advisor. Use Live Monitor when beacons are deployed."
        )
        tip.setWordWrap(True)
        tip.setStyleSheet("color: #555;")
        v.addWidget(tip)
        v.addStretch(1)
        return page

    def _build_wireshark(self) -> QWidget:
        from pfsense_checker.wireshark_bridge import (
            WIRESHARK_LUA_API_DOCS,
            WiresharkBridge,
        )

        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("Wireshark")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        v.addWidget(
            _section_card(
                "Lua API bridge (framework)",
                "NetCheck will connect to Wireshark through its embedded Lua API "
                "(Listener, Field, Proto, Pinfo, Tvb, …). "
                "This page is a scaffold — no live capture process is launched yet.",
            )
        )

        bridge = WiresharkBridge()
        status = bridge.probe()
        status_lbl = QLabel(status.message)
        status_lbl.setWordWrap(True)
        status_lbl.setStyleSheet(
            "color: #2e7d32;" if status.available else "color: #555;"
        )
        v.addWidget(status_lbl)

        docs = QLabel(
            f'<a href="{WIRESHARK_LUA_API_DOCS}">Wireshark Lua API reference '
            "(WSDG Ch. 13)</a>"
        )
        docs.setOpenExternalLinks(True)
        docs.setTextFormat(Qt.TextFormat.RichText)
        v.addWidget(docs)

        table = QTableWidget(0, 3)
        table.setHorizontalHeaderLabels(["Module", "WSDG", "Summary"])
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        for note in bridge.list_lua_modules():
            row = table.rowCount()
            table.insertRow(row)
            table.setItem(row, 0, QTableWidgetItem(note.title))
            table.setItem(row, 1, QTableWidgetItem(note.wsdg_anchor))
            table.setItem(row, 2, QTableWidgetItem(note.summary))
        table.setMinimumHeight(220)
        v.addWidget(table, stretch=1)

        stub = QPlainTextEdit()
        stub.setReadOnly(True)
        stub.setFont(QFont("Consolas", 9))
        stub.setPlainText(bridge.render_stub_lua())
        stub.setMaximumHeight(160)
        v.addWidget(QLabel("Stub Lua plugin (not loaded):"))
        v.addWidget(stub)
        return page

    def _build_about(self) -> QWidget:
        from pfsense_checker import version as ver

        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("About")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        v.addWidget(
            _section_card(
                f"{ver.APP_NAME} {ver.full_version()}",
                "Placeholder — product overview, licensing, and credits will go here.",
            )
        )
        body = QLabel(
            "aliniant labs · NetCheck\n\n"
            "This section is reserved for About content."
        )
        body.setWordWrap(True)
        body.setStyleSheet("color: #555;")
        v.addWidget(body)
        v.addStretch(1)
        return page

    def _build_setup_oui(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("Setup — OUI / MAC Lookup")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        v.addWidget(
            _section_card(
                "Manufacturer from MAC address",
                "Store a RapidAPI key for mac-address-lookup1 so Found devices "
                "can show the vendor for each MAC. The key is saved in gitignored "
                "secrets.local.json — never committed.",
            )
        )

        box = QGroupBox("OUI API key (RapidAPI)")
        form = QFormLayout(box)
        self.oui_api_key = QLineEdit(oui.load_oui_api_key())
        self.oui_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.oui_api_key.setPlaceholderText("Paste your RapidAPI x-rapidapi-key")
        form.addRow("API key:", self.oui_api_key)

        self.oui_test_mac = QLineEdit("00:15:5d:86:eb:5f")
        self.oui_test_mac.setPlaceholderText("MAC or OUI to test")
        form.addRow("Test MAC:", self.oui_test_mac)
        v.addWidget(box)

        actions = QHBoxLayout()
        btn_save = QPushButton("Save")
        btn_save.setStyleSheet(_primary_btn())
        btn_save.clicked.connect(self._setup_oui_save)
        actions.addWidget(btn_save)
        btn_test = QPushButton("Test lookup")
        btn_test.clicked.connect(self._setup_oui_test)
        actions.addWidget(btn_test)
        btn_clear = QPushButton("Clear key")
        btn_clear.clicked.connect(self._setup_oui_clear)
        actions.addWidget(btn_clear)
        actions.addStretch(1)
        v.addLayout(actions)

        self.oui_setup_status = QLabel(
            "Key configured." if oui.has_oui_api_key() else "No OUI API key saved yet."
        )
        self.oui_setup_status.setWordWrap(True)
        self.oui_setup_status.setStyleSheet("color: #555;")
        v.addWidget(self.oui_setup_status)
        tip = QLabel(
            'Uses RapidAPI <a href="https://rapidapi.com">'
            "mac-address-lookup1</a> — re-run Search for devices on Login to "
            "Routers to fill the Vendor column."
        )
        tip.setWordWrap(True)
        tip.setOpenExternalLinks(True)
        tip.setTextFormat(Qt.TextFormat.RichText)
        tip.setStyleSheet("color: #555;")
        v.addWidget(tip)
        v.addStretch(1)
        return page

    def _setup_oui_save(self) -> None:
        key = self.oui_api_key.text().strip()
        try:
            oui.save_oui_api_key(key)
            oui.clear_vendor_cache()
        except OSError as exc:
            QMessageBox.critical(self, "Setup", str(exc))
            return
        if key:
            self.oui_setup_status.setText("OUI API key saved.")
            self.oui_setup_status.setStyleSheet("color: #1565c0;")
        else:
            self.oui_setup_status.setText("OUI API key cleared.")
            self.oui_setup_status.setStyleSheet("color: #555;")

    def _setup_oui_clear(self) -> None:
        self.oui_api_key.clear()
        self._setup_oui_save()

    def _setup_oui_test(self) -> None:
        key = self.oui_api_key.text().strip() or oui.load_oui_api_key()
        if not key:
            QMessageBox.information(
                self, "OUI lookup", "Enter and save an API key first."
            )
            return
        mac = self.oui_test_mac.text().strip()
        try:
            vendor = oui.lookup_vendor(mac, api_key=key, use_cache=False)
        except (RuntimeError, ValueError) as exc:
            self.oui_setup_status.setText(str(exc))
            self.oui_setup_status.setStyleSheet("color: #c62828;")
            QMessageBox.warning(self, "OUI lookup", str(exc))
            return
        if not vendor:
            self.oui_setup_status.setText(f"No vendor found for {mac}.")
            self.oui_setup_status.setStyleSheet("color: #ef6c00;")
            return
        self.oui_setup_status.setText(f"{mac} → {vendor}")
        self.oui_setup_status.setStyleSheet("color: #2e7d32;")
        QMessageBox.information(self, "OUI lookup", f"{mac}\n{vendor}")

    def _build_setup_snmp(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("Setup — SNMP (v3)")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        v.addWidget(
            _section_card(
                "SNMPv3 only",
                "Configure default SNMPv3 credentials for device polling. "
                "Community-based v1/v2c is not supported. Passwords are stored in "
                "gitignored secrets.local.json; other options in data/snmp.json.",
            )
        )

        cfg = snmp.load_snmp_settings()
        box = QGroupBox("SNMPv3 defaults")
        form = QFormLayout(box)

        self.snmp_enabled = QCheckBox("Enable SNMP in this tool")
        self.snmp_enabled.setChecked(cfg.enabled)
        form.addRow(self.snmp_enabled)

        self.snmp_username = QLineEdit(cfg.username)
        self.snmp_username.setPlaceholderText("securityName / user")
        form.addRow("Username:", self.snmp_username)

        self.snmp_level = QComboBox()
        self.snmp_level.addItems(list(snmp.SECURITY_LEVELS))
        idx = self.snmp_level.findText(cfg.security_level)
        self.snmp_level.setCurrentIndex(idx if idx >= 0 else 0)
        form.addRow("Security level:", self.snmp_level)

        self.snmp_auth_proto = QComboBox()
        self.snmp_auth_proto.addItems(list(snmp.AUTH_PROTOCOLS))
        idx = self.snmp_auth_proto.findText(cfg.auth_protocol)
        self.snmp_auth_proto.setCurrentIndex(idx if idx >= 0 else 0)
        form.addRow("Auth protocol:", self.snmp_auth_proto)

        self.snmp_auth_password = QLineEdit(cfg.auth_password)
        self.snmp_auth_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.snmp_auth_password.setPlaceholderText("authKey / passphrase")
        form.addRow("Auth password:", self.snmp_auth_password)

        self.snmp_priv_proto = QComboBox()
        self.snmp_priv_proto.addItems(list(snmp.PRIV_PROTOCOLS))
        idx = self.snmp_priv_proto.findText(cfg.priv_protocol)
        self.snmp_priv_proto.setCurrentIndex(idx if idx >= 0 else 0)
        form.addRow("Priv protocol:", self.snmp_priv_proto)

        self.snmp_priv_password = QLineEdit(cfg.priv_password)
        self.snmp_priv_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.snmp_priv_password.setPlaceholderText("privKey / passphrase")
        form.addRow("Priv password:", self.snmp_priv_password)

        self.snmp_context = QLineEdit(cfg.context_name)
        self.snmp_context.setPlaceholderText("optional contextName")
        form.addRow("Context:", self.snmp_context)

        self.snmp_port = QSpinBox()
        self.snmp_port.setRange(1, 65535)
        self.snmp_port.setValue(cfg.port)
        form.addRow("Port:", self.snmp_port)

        self.snmp_timeout = QDoubleSpinBox()
        self.snmp_timeout.setRange(0.5, 60.0)
        self.snmp_timeout.setSingleStep(0.5)
        self.snmp_timeout.setSuffix(" s")
        self.snmp_timeout.setValue(cfg.timeout_sec)
        form.addRow("Timeout:", self.snmp_timeout)

        self.snmp_retries = QSpinBox()
        self.snmp_retries.setRange(0, 5)
        self.snmp_retries.setValue(cfg.retries)
        form.addRow("Retries:", self.snmp_retries)

        self.snmp_test_host = QLineEdit(cfg.test_host)
        self.snmp_test_host.setPlaceholderText("e.g. 192.168.1.1 — for Test only")
        form.addRow("Test host:", self.snmp_test_host)

        v.addWidget(box)

        actions = QHBoxLayout()
        btn_save = QPushButton("Save")
        btn_save.setStyleSheet(_primary_btn())
        btn_save.clicked.connect(self._setup_snmp_save)
        actions.addWidget(btn_save)
        btn_clear = QPushButton("Clear secrets")
        btn_clear.setToolTip("Clear username and passwords from secrets.local.json")
        btn_clear.clicked.connect(self._setup_snmp_clear_secrets)
        actions.addWidget(btn_clear)
        actions.addStretch(1)
        v.addLayout(actions)

        self.snmp_setup_status = QLabel(self._snmp_status_text(cfg))
        self.snmp_setup_status.setWordWrap(True)
        self.snmp_setup_status.setStyleSheet("color: #555;")
        v.addWidget(self.snmp_setup_status)
        tip = QLabel(
            "SNMPv3 only (no community strings). Preferred level is "
            "<b>authPriv</b> with SHA + AES. Device polling will use these "
            "defaults; per-device overrides can come later."
        )
        tip.setWordWrap(True)
        tip.setTextFormat(Qt.TextFormat.RichText)
        tip.setStyleSheet("color: #555;")
        v.addWidget(tip)
        v.addStretch(1)
        self.snmp_level.currentTextChanged.connect(self._setup_snmp_level_changed)
        self._setup_snmp_level_changed(self.snmp_level.currentText())
        return page

    def _build_setup_mibs(self) -> QWidget:
        from pfsense_checker import mib_libraries as mibs

        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("Setup — MIB Libraries")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        v.addWidget(
            _section_card(
                "SNMP MIB search paths",
                "Drop vendor MIB files (.mib / .txt) into data/mibs or add extra "
                "folders. Used with pysnmp/pysmi for TP-Link, Netgear, Dell iDRAC, "
                "and standard IF-MIB / BRIDGE-MIB / LLDP-MIB lookups. "
                "Install pysnmp + pysmi under Python Modules if missing.",
            )
        )

        self.mib_stack_status = QLabel(mibs.stack_status_text())
        self.mib_stack_status.setWordWrap(True)
        self.mib_stack_status.setStyleSheet("color: #1565c0; font-weight: 600;")
        v.addWidget(self.mib_stack_status)
        mib_mod_row = QHBoxLayout()
        btn_mib_mods = QPushButton("Install / Load SNMP modules…")
        btn_mib_mods.setToolTip(
            "Reminders if pysnmp/pysmi are missing — opens Python Modules "
            "or loads them into this process."
        )
        btn_mib_mods.clicked.connect(self._setup_mibs_ensure_modules)
        mib_mod_row.addWidget(btn_mib_mods)
        mib_mod_row.addStretch(1)
        v.addLayout(mib_mod_row)

        paths_box = QGroupBox("Search paths")
        paths_lay = QVBoxLayout(paths_box)
        self.mib_paths_list = QListWidget()
        self.mib_paths_list.setMinimumHeight(90)
        paths_lay.addWidget(self.mib_paths_list)
        path_btns = QHBoxLayout()
        btn_add = QPushButton("Add folder…")
        btn_add.clicked.connect(self._setup_mibs_add_path)
        path_btns.addWidget(btn_add)
        btn_remove = QPushButton("Remove selected")
        btn_remove.clicked.connect(self._setup_mibs_remove_path)
        path_btns.addWidget(btn_remove)
        btn_open = QPushButton("Open data/mibs")
        btn_open.clicked.connect(self._setup_mibs_open_default)
        path_btns.addWidget(btn_open)
        btn_refresh = QPushButton("Refresh")
        btn_refresh.setStyleSheet(_primary_btn())
        btn_refresh.clicked.connect(self._setup_mibs_refresh)
        path_btns.addWidget(btn_refresh)
        path_btns.addStretch(1)
        paths_lay.addLayout(path_btns)
        v.addWidget(paths_box)

        files_box = QGroupBox("MIB files found")
        files_lay = QVBoxLayout(files_box)
        self.mib_files_table = QTableWidget(0, 3)
        self.mib_files_table.setHorizontalHeaderLabels(["MIB file", "Folder", "Size"])
        self.mib_files_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.mib_files_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.mib_files_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        self.mib_files_table.verticalHeader().setVisible(False)
        self.mib_files_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.mib_files_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        files_lay.addWidget(self.mib_files_table)
        v.addWidget(files_box, stretch=1)

        tip = QLabel(
            "Suggested baselines: SNMPv2-MIB, IF-MIB, BRIDGE-MIB, Q-BRIDGE-MIB, "
            "LLDP-MIB, ENTITY-MIB — plus vendor packs for your switches / iDRAC."
        )
        tip.setWordWrap(True)
        tip.setStyleSheet("color: #555;")
        v.addWidget(tip)

        self._setup_mibs_refresh()
        return page

    def _setup_mibs_refresh(self) -> None:
        from pfsense_checker import mib_libraries as mibs

        if not hasattr(self, "mib_paths_list"):
            return
        cfg = mibs.load_settings()
        self.mib_paths_list.clear()
        for path in cfg.search_paths:
            self.mib_paths_list.addItem(path)
        files = mibs.list_mib_files(cfg)
        self.mib_files_table.setRowCount(len(files))
        for row, info in enumerate(files):
            self.mib_files_table.setItem(row, 0, QTableWidgetItem(info.name))
            self.mib_files_table.setItem(row, 1, QTableWidgetItem(info.folder))
            size_kb = info.size_bytes / 1024.0
            size_txt = f"{size_kb:.1f} KB" if size_kb >= 1 else f"{info.size_bytes} B"
            self.mib_files_table.setItem(row, 2, QTableWidgetItem(size_txt))
        if hasattr(self, "mib_stack_status"):
            self.mib_stack_status.setText(mibs.stack_status_text())

    def _setup_mibs_ensure_modules(self) -> None:
        from pfsense_checker.module_required import ensure_feature

        ok = ensure_feature(
            self,
            "mibs",
            purpose="use SNMP MIB libraries (pysnmp + pysmi)",
            quiet_load=False,
        )
        self._setup_mibs_refresh()
        if ok:
            QMessageBox.information(
                self,
                "MIB Libraries",
                "pysnmp and pysmi are installed and loaded for this process.",
            )

    def _setup_mibs_add_path(self) -> None:
        from pfsense_checker import mib_libraries as mibs

        start = str(mibs.DEFAULT_MIB_DIR)
        chosen = QFileDialog.getExistingDirectory(self, "Add MIB folder", start)
        if not chosen:
            return
        try:
            mibs.add_search_path(chosen)
        except ValueError as exc:
            QMessageBox.warning(self, "MIB Libraries", str(exc))
            return
        self._setup_mibs_refresh()
        app_log.get_logger("snmp").info("MIB search path added: %s", chosen)

    def _setup_mibs_remove_path(self) -> None:
        from pfsense_checker import mib_libraries as mibs

        item = self.mib_paths_list.currentItem()
        if item is None:
            QMessageBox.information(
                self, "MIB Libraries", "Select a search path to remove."
            )
            return
        path = item.text()
        mibs.remove_search_path(path)
        self._setup_mibs_refresh()
        app_log.get_logger("snmp").info("MIB search path removed: %s", path)

    def _setup_mibs_open_default(self) -> None:
        import os
        import subprocess

        from pfsense_checker import mib_libraries as mibs

        folder = mibs.ensure_default_mib_dir()
        try:
            if os.name == "nt":
                os.startfile(str(folder))  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", str(folder)])
        except OSError as exc:
            QMessageBox.warning(self, "MIB Libraries", str(exc))

    def _build_setup_version(self) -> QWidget:
        from pfsense_checker import version as ver

        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("Setup — Version")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        v.addWidget(
            _section_card(
                f"{ver.APP_NAME} {ver.full_version()}",
                "Each release is listed below with its changes. "
                "Source of truth: pfsense_checker/version.py.",
            )
        )

        row = QHBoxLayout()
        ver_lbl = QLabel(ver.format_version_line())
        ver_lbl.setWordWrap(True)
        ver_lbl.setStyleSheet("font-weight: bold; color: #1565c0;")
        row.addWidget(ver_lbl, stretch=1)
        btn_copy = QPushButton("Copy changelog")
        btn_copy.clicked.connect(self._setup_version_copy)
        row.addWidget(btn_copy)
        v.addLayout(row)

        self.version_log = QPlainTextEdit()
        self.version_log.setReadOnly(True)
        self.version_log.setFont(QFont("Consolas", 10))
        self.version_log.setPlainText(ver.format_changelog())
        v.addWidget(self.version_log, stretch=1)
        return page

    def _setup_version_copy(self) -> None:
        from PySide6.QtWidgets import QApplication

        from pfsense_checker import version as ver

        text = ver.format_changelog()
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, "Version", "Changelog copied to the clipboard.")

    @staticmethod
    def _snmp_status_text(cfg: snmp.SnmpV3Settings) -> str:
        if not cfg.enabled:
            return "SNMP disabled."
        if snmp.snmp_configured():
            return (
                f"SNMPv3 enabled — user “{cfg.username}”, "
                f"{cfg.security_level}, port {cfg.port}."
            )
        return "SNMP enabled but credentials incomplete."

    def _setup_snmp_level_changed(self, level: str) -> None:
        if not hasattr(self, "snmp_auth_password"):
            return
        need_auth = level in {"authNoPriv", "authPriv"}
        need_priv = level == "authPriv"
        self.snmp_auth_proto.setEnabled(need_auth)
        self.snmp_auth_password.setEnabled(need_auth)
        self.snmp_priv_proto.setEnabled(need_priv)
        self.snmp_priv_password.setEnabled(need_priv)

    def _setup_snmp_from_ui(self) -> snmp.SnmpV3Settings:
        return snmp.SnmpV3Settings(
            enabled=self.snmp_enabled.isChecked(),
            username=self.snmp_username.text().strip(),
            security_level=self.snmp_level.currentText(),
            auth_protocol=self.snmp_auth_proto.currentText(),
            auth_password=self.snmp_auth_password.text(),
            priv_protocol=self.snmp_priv_proto.currentText(),
            priv_password=self.snmp_priv_password.text(),
            context_name=self.snmp_context.text().strip(),
            port=int(self.snmp_port.value()),
            timeout_sec=float(self.snmp_timeout.value()),
            retries=int(self.snmp_retries.value()),
            test_host=self.snmp_test_host.text().strip(),
        )

    def _setup_snmp_save(self) -> None:
        settings = self._setup_snmp_from_ui()
        err = snmp.validate_snmp_settings(settings)
        if err:
            QMessageBox.warning(self, "SNMP", err)
            return
        try:
            snmp.save_snmp_settings(settings)
        except OSError as exc:
            QMessageBox.critical(self, "SNMP", str(exc))
            return
        self.snmp_setup_status.setText(self._snmp_status_text(settings))
        self.snmp_setup_status.setStyleSheet("color: #1565c0;")
        app_log.get_logger("snmp").info(
            "SNMPv3 settings saved enabled=%s level=%s user=%s",
            settings.enabled,
            settings.security_level,
            settings.username or "(none)",
        )

    def _setup_snmp_clear_secrets(self) -> None:
        self.snmp_username.clear()
        self.snmp_auth_password.clear()
        self.snmp_priv_password.clear()
        settings = self._setup_snmp_from_ui()
        try:
            snmp.save_snmp_settings(settings)
        except OSError as exc:
            QMessageBox.critical(self, "SNMP", str(exc))
            return
        self.snmp_setup_status.setText("SNMP secrets cleared.")
        self.snmp_setup_status.setStyleSheet("color: #555;")

    def _build_console(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("Console")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        v.addWidget(
            _section_card(
                "Debug & failure log",
                "SSH login failures and other diagnostic messages appear here "
                "and in the companion console window that opens with NetCheck. "
                "At DEBUG level, paramiko transport trace is included. "
                "File logging and level are controlled under Setup → Logging. "
                "Pop out raises that companion window.",
            )
        )

        actions = QHBoxLayout()
        btn_clear = QPushButton("Clear console")
        btn_clear.clicked.connect(self._console_clear)
        actions.addWidget(btn_clear)
        btn_refresh = QPushButton("Reload")
        btn_refresh.clicked.connect(self._console_reload)
        actions.addWidget(btn_refresh)
        btn_open = QPushButton("Open log file…")
        btn_open.clicked.connect(self._console_open_file)
        actions.addWidget(btn_open)
        btn_logging = QPushButton("Logging settings…")
        btn_logging.clicked.connect(lambda: self.show_section("setup.logging"))
        actions.addWidget(btn_logging)
        btn_pop = QPushButton("Pop out")
        btn_pop.setToolTip("Raise the companion console window")
        btn_pop.clicked.connect(self._console_pop_out)
        actions.addWidget(btn_pop)
        actions.addStretch(1)
        v.addLayout(actions)

        self.console_status = QLabel()
        self.console_status.setWordWrap(True)
        self.console_status.setTextFormat(Qt.TextFormat.RichText)
        self.console_status.setStyleSheet(
            "QLabel { background: #eceff1; border: 1px solid #cfd8dc; "
            "border-radius: 4px; padding: 6px 10px; color: #37474f; }"
        )
        v.addWidget(self.console_status)

        self.console_view = QPlainTextEdit()
        self.console_view.setReadOnly(True)
        self.console_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.console_view.setFont(QFont("Consolas", 10))
        self.console_view.setStyleSheet(_CONSOLE_VIEW_STYLE)
        v.addWidget(self.console_view, stretch=1)

        self._console_listener = self._on_console_log_event
        app_log.get_hub().subscribe(self._console_listener)
        self._console_reload()
        self._refresh_console_status()
        return page

    def _refresh_console_status(self) -> None:
        text = app_log.logging_status_html()
        if hasattr(self, "console_status") and self.console_status is not None:
            self.console_status.setText(text)

    def _console_views(self) -> list[QPlainTextEdit]:
        views: list[QPlainTextEdit] = []
        if hasattr(self, "console_view") and self.console_view is not None:
            views.append(self.console_view)
        return views

    def _on_console_log_event(self, event: app_log.LogEvent) -> None:
        line = event.format_line()
        for view in self._console_views():
            view.appendPlainText(line)
            view.moveCursor(QTextCursor.MoveOperation.End)

    def _console_reload(self) -> None:
        text = "\n".join(e.format_line() for e in app_log.get_hub().recent())
        for view in self._console_views():
            view.setPlainText(text)
            view.moveCursor(QTextCursor.MoveOperation.End)
        self._refresh_console_status()

    def _console_clear(self) -> None:
        app_log.get_hub().clear_memory()
        for view in self._console_views():
            view.clear()

    def _console_pop_out(self) -> None:
        from pfsense_checker.console_window import open_companion

        open_companion(show=True, activate=True)

    def close_console_popout(self) -> None:
        """Close the companion console (called when the main GUI closes)."""
        from pfsense_checker.console_window import close_companion

        close_companion()

    def _console_open_file(self) -> None:
        path = app_log.get_hub().settings.log_path()
        if not path.is_file():
            QMessageBox.information(
                self,
                "Console",
                f"No log file yet at:\n{path}\n\n"
                "Enable file logging under Setup → Logging.",
            )
            return
        from PySide6.QtGui import QDesktopServices
        from PySide6.QtCore import QUrl

        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _build_log_pipeline(self) -> QWidget:
        from pfsense_checker.log_pipeline_screen import LogPipelinePage

        self.log_pipeline = LogPipelinePage()
        return self.log_pipeline

    def _build_syslog(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("Syslog")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        v.addWidget(
            _section_card(
                "Remote syslog from attached routers",
                "Listen for RFC 3164 / RFC 5424 syslog from devices on Login to "
                "Routers (mgmt IP / SSH host). Point pfSense "
                "(Status → System Logs → Settings → Remote Logging) or MikroTik "
                "(/system logging action target=remote) at this PC. UDP/514 "
                "usually needs Administrator on Windows — default port is 5514.",
            )
        )

        settings = syslog_recv.load_settings()
        box = QGroupBox("Syslog settings")
        form = QFormLayout(box)

        self.syslog_bind = QComboBox()
        self.syslog_bind.setMinimumWidth(360)
        self.syslog_bind.setToolTip(
            "NIC the UDP listener binds. Pick the fiber LAN (222.10.50.x), "
            "not Hyper-V Default Switch or Wi-Fi link-local. "
            "All interfaces (0.0.0.0) listens on every NIC."
        )
        form.addRow("Listen on:", self.syslog_bind)

        self.syslog_udp_port = QSpinBox()
        self.syslog_udp_port.setRange(1, 65535)
        self.syslog_udp_port.setValue(settings.udp_port)
        self.syslog_udp_port.valueChanged.connect(self._syslog_refresh_listen_hint)
        form.addRow("UDP port:", self.syslog_udp_port)

        self.syslog_tcp_port = QSpinBox()
        self.syslog_tcp_port.setRange(0, 65535)
        self.syslog_tcp_port.setSpecialValueText("off")
        self.syslog_tcp_port.setValue(settings.tcp_port)
        form.addRow("TCP port:", self.syslog_tcp_port)

        self.syslog_attached_only = QCheckBox(
            "Only accept packets from attached routers"
        )
        self.syslog_attached_only.setChecked(settings.attached_only)
        self.syslog_attached_only.toggled.connect(self._syslog_refresh_sources)
        form.addRow(self.syslog_attached_only)

        self.syslog_file_enabled = QCheckBox("Write received messages to disk")
        self.syslog_file_enabled.setChecked(settings.file_enabled)
        form.addRow(self.syslog_file_enabled)

        self.syslog_auto_start = QCheckBox("Start listener when this section opens")
        self.syslog_auto_start.setChecked(settings.auto_start)
        form.addRow(self.syslog_auto_start)

        self.syslog_memory_lines = QSpinBox()
        self.syslog_memory_lines.setRange(10, syslog_recv.MAX_MEMORY_LINES)
        self.syslog_memory_lines.setValue(settings.memory_lines)
        form.addRow("On-screen buffer (lines):", self.syslog_memory_lines)

        self.syslog_extra_allow = QLineEdit(
            settings.extra_allow or "222.10.50.0/24"
        )
        self.syslog_extra_allow.setPlaceholderText("222.10.50.0/24")
        self.syslog_extra_allow.setToolTip(
            "Also accept syslog sourced from these IPs/CIDRs (fiber LAN). "
            "Needed when the firewall sends from 222.10.50.x but SSH is 100.48.62.1."
        )
        self.syslog_extra_allow.textChanged.connect(self._syslog_refresh_listen_hint)
        self.syslog_extra_allow.textChanged.connect(self._syslog_refresh_sources)
        form.addRow("Also accept from:", self.syslog_extra_allow)

        v.addWidget(box)

        dest = QGroupBox("Send from the firewall TO this PC")
        dest_l = QVBoxLayout(dest)
        self.syslog_listen_hint = QLabel("")
        self.syslog_listen_hint.setWordWrap(True)
        self.syslog_listen_hint.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        dest_l.addWidget(self.syslog_listen_hint)
        self.syslog_fw_hint = QLabel(
            "On pfSense: Remote Logging source = the main fiber / 222.10.50.0/24 "
            "interface (not backup igb1). Destination = Listen on IP:UDP port. "
            "syslogd “Host is down” / ARP Incomplete means that IP is not on that "
            "L2. Put 222.10.50.0/24 in Also accept from so packets sourced from "
            "the fiber IP are not dropped while SSH is still 100.48.62.1."
        )
        self.syslog_fw_hint.setWordWrap(True)
        self.syslog_fw_hint.setStyleSheet("color: #555;")
        dest_l.addWidget(self.syslog_fw_hint)
        v.addWidget(dest)

        src_row = QHBoxLayout()
        src_row.addWidget(QLabel("Attached sources:"))
        self.syslog_sources = QLabel("—")
        self.syslog_sources.setWordWrap(True)
        self.syslog_sources.setStyleSheet("color: #555;")
        src_row.addWidget(self.syslog_sources, stretch=1)
        v.addLayout(src_row)

        actions = QHBoxLayout()
        self.btn_syslog_start = QPushButton("Start listener")
        self.btn_syslog_start.clicked.connect(self._syslog_start)
        self._syslog_set_start_button(active=False)
        actions.addWidget(self.btn_syslog_start)
        self.btn_syslog_stop = QPushButton("Stop")
        self.btn_syslog_stop.setEnabled(False)
        self.btn_syslog_stop.clicked.connect(self._syslog_stop)
        actions.addWidget(self.btn_syslog_stop)
        btn_save = QPushButton("Save settings")
        btn_save.clicked.connect(self._syslog_save)
        actions.addWidget(btn_save)
        btn_clear = QPushButton("Clear")
        btn_clear.clicked.connect(self._syslog_clear)
        actions.addWidget(btn_clear)
        btn_export = QPushButton("Export…")
        btn_export.clicked.connect(self._syslog_export)
        actions.addWidget(btn_export)
        actions.addStretch(1)
        v.addLayout(actions)

        self.syslog_status = QLabel("Listener stopped.")
        self.syslog_status.setWordWrap(True)
        self.syslog_status.setStyleSheet("color: #555;")
        v.addWidget(self.syslog_status)

        filt = QHBoxLayout()
        filt.addWidget(QLabel("Filter:"))
        # Column dropdowns fill with values seen in received messages.
        self.syslog_f_source = QComboBox()
        self.syslog_f_device = QComboBox()
        self.syslog_f_severity = QComboBox()
        self.syslog_f_facility = QComboBox()
        self.syslog_f_apptype = QComboBox()
        self._syslog_filter_combos: dict[str, QComboBox] = {
            "source": self.syslog_f_source,
            "device": self.syslog_f_device,
            "severity": self.syslog_f_severity,
            "facility": self.syslog_f_facility,
            "app": self.syslog_f_apptype,
        }
        for key, label in (
            ("source", "All sources"),
            ("device", "All devices"),
            ("severity", "All severities"),
            ("facility", "All facilities"),
            ("app", "All message types"),
        ):
            combo = self._syslog_filter_combos[key]
            combo.addItem(label, "")
            combo.setMinimumWidth(120)
            combo.currentIndexChanged.connect(self._syslog_apply_filter)
            filt.addWidget(combo)
        self._syslog_filter_seen: dict[str, set[str]] = {
            key: set() for key in self._syslog_filter_combos
        }
        self.syslog_filter = QLineEdit()
        self.syslog_filter.setPlaceholderText("IP, device, severity, or text…")
        self.syslog_filter.textChanged.connect(self._syslog_apply_filter)
        filt.addWidget(self.syslog_filter, stretch=1)
        v.addLayout(filt)

        self.syslog_table = QTableWidget(0, 8)
        self.syslog_table.setHorizontalHeaderLabels(
            [
                "Received",
                "Source",
                "Device",
                "Severity",
                "Facility",
                "Host",
                "App",
                "Message",
            ]
        )
        self.syslog_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.syslog_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.syslog_table.setAlternatingRowColors(True)
        hdr = self.syslog_table.horizontalHeader()
        hdr.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        self.syslog_table.verticalHeader().setVisible(False)
        self.syslog_table.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu
        )
        self.syslog_table.customContextMenuRequested.connect(
            self._syslog_context_menu
        )
        v.addWidget(self.syslog_table, stretch=1)
        self._syslog_ai_workers: list[QThread] = []

        self._syslog_receiver: syslog_recv.SyslogReceiver | None = None
        self._syslog_buffer = syslog_recv.SyslogBuffer(settings.memory_lines)
        self._syslog_saved_bind = settings.bind_host
        self._syslog_fill_iface_combo()
        self.syslog_bind.currentIndexChanged.connect(self._syslog_refresh_listen_hint)
        self._syslog_refresh_sources()
        self._syslog_refresh_listen_hint()
        py_footer = QLabel(f"Running on Python {sys.version.split()[0]}")
        py_footer.setStyleSheet("color: #757575;")
        v.addWidget(py_footer)
        if settings.auto_start:
            QTimer.singleShot(0, self._syslog_start)
        return page

    def _syslog_current_bind_host(self) -> str:
        if not hasattr(self, "syslog_bind"):
            return syslog_recv.DEFAULT_BIND_HOST
        data = self.syslog_bind.currentData()
        text = str(data or "").strip()
        return text or syslog_recv.DEFAULT_BIND_HOST

    def _syslog_select_bind_host(self, host: str) -> None:
        if not hasattr(self, "syslog_bind"):
            return
        want = (host or "").strip() or syslog_recv.DEFAULT_BIND_HOST
        idx = self.syslog_bind.findData(want)
        if idx < 0:
            self.syslog_bind.addItem(want, want)
            idx = self.syslog_bind.findData(want)
        self.syslog_bind.blockSignals(True)
        self.syslog_bind.setCurrentIndex(max(0, idx))
        self.syslog_bind.blockSignals(False)

    def _syslog_fill_iface_combo(self) -> None:
        if not hasattr(self, "syslog_bind"):
            return
        from pfsense_checker.lan_scan import local_ipv4_nics

        extra = ""
        if hasattr(self, "syslog_extra_allow"):
            extra = self.syslog_extra_allow.text()
        previous = self.syslog_bind.currentData()
        saved = str(previous or getattr(self, "_syslog_saved_bind", "") or "")
        nics = syslog_recv.order_listen_nics(local_ipv4_nics(), extra)
        self.syslog_bind.blockSignals(True)
        self.syslog_bind.clear()
        self.syslog_bind.addItem("All interfaces (0.0.0.0)", syslog_recv.DEFAULT_BIND_HOST)
        seen = {syslog_recv.DEFAULT_BIND_HOST}
        for nic in nics:
            if nic.ip in seen:
                continue
            seen.add(nic.ip)
            self.syslog_bind.addItem(nic.label(), nic.ip)
        pick = syslog_recv.pick_listen_bind(nics, saved, extra)
        if pick not in seen:
            self.syslog_bind.addItem(pick, pick)
        idx = self.syslog_bind.findData(pick)
        self.syslog_bind.setCurrentIndex(max(0, idx))
        self.syslog_bind.blockSignals(False)

    def _syslog_collect_settings(self) -> syslog_recv.SyslogSettings:
        raw = syslog_recv.SyslogSettings(
            bind_host=self._syslog_current_bind_host(),
            udp_port=int(self.syslog_udp_port.value()),
            tcp_port=int(self.syslog_tcp_port.value()),
            attached_only=self.syslog_attached_only.isChecked(),
            file_enabled=self.syslog_file_enabled.isChecked(),
            memory_lines=int(self.syslog_memory_lines.value()),
            extra_allow=self.syslog_extra_allow.text().strip(),
            auto_start=self.syslog_auto_start.isChecked(),
        )
        settings, note = syslog_recv.normalize_bind_settings(raw)
        if note:
            self._syslog_select_bind_host(settings.bind_host)
            self.syslog_extra_allow.setText(settings.extra_allow)
            self._syslog_bind_note = note
        else:
            self._syslog_bind_note = ""
        return settings

    def _syslog_save(self) -> None:
        settings = self._syslog_collect_settings()
        try:
            path = syslog_recv.save_settings(settings)
        except OSError as exc:
            QMessageBox.critical(self, "Syslog", str(exc))
            return
        self._syslog_buffer.resize(settings.memory_lines)
        self._syslog_saved_bind = settings.bind_host
        note = getattr(self, "_syslog_bind_note", "")
        saved = f"Settings saved — bind {settings.bind_host}:{settings.udp_port} — {path}"
        self.syslog_status.setText(f"{note} {saved}".strip() if note else saved)
        self.syslog_status.setStyleSheet("color: #1565c0;")

    def _syslog_refresh_listen_hint(self) -> None:
        if not hasattr(self, "syslog_listen_hint"):
            return
        from pfsense_checker.lan_scan import local_ipv4_nics

        port = int(self.syslog_udp_port.value()) if hasattr(self, "syslog_udp_port") else 5514
        extra = ""
        if hasattr(self, "syslog_extra_allow"):
            extra = self.syslog_extra_allow.text()
        bind = self._syslog_current_bind_host() if hasattr(self, "syslog_bind") else ""
        nics = syslog_recv.order_listen_nics(local_ipv4_nics(), extra)
        if bind and bind != syslog_recv.DEFAULT_BIND_HOST:
            label = bind
            for nic in nics:
                if nic.ip == bind:
                    label = f"{nic.ip}:{port}"
                    name = (nic.name or "").strip()
                    if name and name != nic.ip:
                        label += f"  ({name})"
                    break
            else:
                label = f"{bind}:{port}"
            self.syslog_listen_hint.setText(
                f"<b>Remote syslog server (copy into pfSense):</b> {label}"
            )
            self.syslog_listen_hint.setTextFormat(Qt.TextFormat.RichText)
            return
        ips = [nic.ip for nic in nics if nic.kind == "lan"] or [nic.ip for nic in nics]
        if not ips:
            self.syslog_listen_hint.setText(
                f"Could not list this PC’s IPv4 addresses. On the firewall, "
                f"set remote syslog to this workstation’s LAN or VPN IP, UDP {port}."
            )
            return
        targets = "  ·  ".join(f"{ip}:{port}" for ip in ips[:8])
        more = " …" if len(ips) > 8 else ""
        self.syslog_listen_hint.setText(
            f"<b>Remote syslog server (copy into pfSense):</b> {targets}{more}"
        )
        self.syslog_listen_hint.setTextFormat(Qt.TextFormat.RichText)

    def _syslog_refresh_sources(self) -> None:
        if not hasattr(self, "syslog_sources"):
            return
        sources = syslog_recv.attached_sources(self._live_site)
        recv = getattr(self, "_syslog_receiver", None)
        if recv is not None:
            recv.set_allowlist(
                sources,
                site=self._live_site,
                settings=self._syslog_collect_settings(),
            )
        nets = syslog_recv.site_allow_networks(
            self._live_site,
            self._syslog_collect_settings() if hasattr(self, "syslog_extra_allow") else syslog_recv.load_settings(),
        )
        if not sources and not nets:
            self.syslog_sources.setText(
                "None — add devices on Login to Routers, or set Also accept from "
                "(e.g. 222.10.50.0/24 when pfSense sends from fiber LAN)."
            )
            self._syslog_refresh_listen_hint()
            return
        bits = [f"{name} ({ip})" for ip, name in sorted(sources.items(), key=lambda x: x[1])]
        if nets:
            cidr_bits = ", ".join(str(n) for n in nets[:6])
            if len(nets) > 6:
                cidr_bits += "…"
            bits.append(f"allow CIDRs: {cidr_bits}")
        self.syslog_sources.setText(", ".join(bits[:24]) + ("…" if len(bits) > 24 else ""))
        self._syslog_refresh_listen_hint()

    def _syslog_start(self) -> None:
        existing = getattr(self, "_syslog_receiver", None)
        if existing is not None and existing.isRunning():
            return
        settings = self._syslog_collect_settings()
        note = getattr(self, "_syslog_bind_note", "")
        if note:
            self.syslog_status.setText(note)
            self.syslog_status.setStyleSheet("color: #1565c0;")
        self._syslog_buffer.resize(settings.memory_lines)
        sources = syslog_recv.attached_sources(self._live_site)
        nets = syslog_recv.site_allow_networks(self._live_site, settings)
        recv = syslog_recv.SyslogReceiver(settings, self)
        recv.set_allowlist(sources, site=self._live_site, settings=settings)
        recv.received.connect(self._syslog_on_message)
        recv.status.connect(self._syslog_on_status)
        recv.failed.connect(self._syslog_on_failed)
        self._syslog_receiver = recv
        self._syslog_set_start_button(active=True)
        self.btn_syslog_stop.setEnabled(True)
        allow_bits = [
            f"{len(sources)} attached IP(s)" if sources else "no attached IPs yet",
            f"{len(nets)} allow CIDR(s)",
        ]
        self.syslog_status.setText(
            f"Starting listener…  ({', '.join(allow_bits)})"
        )
        self.syslog_status.setStyleSheet("color: #555;")
        recv.start()

    def _syslog_stop(self) -> None:
        recv = getattr(self, "_syslog_receiver", None)
        if recv is None:
            return
        recv.stop()
        recv.wait(1500)
        self._syslog_receiver = None
        self._syslog_set_start_button(active=False)
        if hasattr(self, "btn_syslog_stop"):
            self.btn_syslog_stop.setEnabled(False)

    def stop_syslog_receiver(self) -> None:
        """Stop the listener when the main window closes."""
        self._syslog_stop()

    def _syslog_set_start_button(self, *, active: bool) -> None:
        if not hasattr(self, "btn_syslog_start"):
            return
        if active:
            self.btn_syslog_start.setText("Listener Active")
            self.btn_syslog_start.setEnabled(False)
        else:
            self.btn_syslog_start.setText("Start listener")
            self.btn_syslog_start.setEnabled(True)
        self.btn_syslog_start.setStyleSheet(_syslog_listener_btn(active=active))

    def _syslog_on_status(self, text: str) -> None:
        if not hasattr(self, "syslog_status"):
            return
        recv = getattr(self, "_syslog_receiver", None)
        extra = ""
        if recv is not None:
            extra = f"  · accepted {recv.accepted_count}  · dropped {recv.dropped_count}"
        self.syslog_status.setText(text + extra)
        listening = text.startswith("Listening")
        self.syslog_status.setStyleSheet("color: #2e7d32;" if listening else "color: #555;")
        if listening:
            self._syslog_set_start_button(active=True)
        elif text.startswith("Stopped"):
            self._syslog_set_start_button(active=False)

    def _syslog_on_failed(self, message: str) -> None:
        hint = ""
        if "11001" in message or "getaddrinfo" in message.lower():
            hint = (
                " Bind address must be 0.0.0.0 or a single IP "
                "(e.g. 222.10.50.25). Put 222.10.50.0/24 in Also accept from."
            )
        elif "10013" in message or "permission" in message.lower() or "access" in message.lower():
            hint = (
                " Windows often blocks UDP/514 unless NetCheck runs as "
                "Administrator — try port 5514."
            )
        QMessageBox.critical(self, "Syslog", message + hint)
        self._syslog_stop()
        if hasattr(self, "syslog_status"):
            self.syslog_status.setText(f"Failed: {message}")
            self.syslog_status.setStyleSheet("color: #c62828;")

    def _syslog_on_message(self, msg: object) -> None:
        if not isinstance(msg, syslog_recv.SyslogMessage):
            return
        self._syslog_buffer.append(msg)
        self._syslog_register_filter_options(msg)
        self._syslog_append_row(msg)
        if not msg.accepted:
            recv = getattr(self, "_syslog_receiver", None)
            if recv is not None and hasattr(self, "syslog_status"):
                self.syslog_status.setText(
                    f"Listening  · accepted {recv.accepted_count}  · "
                    f"dropped {recv.dropped_count}  "
                    f"(last drop: {msg.source_ip} — {msg.drop_reason})"
                )
                self.syslog_status.setStyleSheet("color: #ef6c00;")

    def _syslog_filter_value(
        self, msg: syslog_recv.SyslogMessage, key: str
    ) -> str:
        if key == "source":
            return msg.source_ip
        if key == "device":
            return msg.device_name or ("—" if msg.accepted else "dropped")
        if key == "severity":
            return msg.severity_name
        if key == "facility":
            return msg.facility_name
        if key == "app":
            return _syslog_message_type(msg)
        return ""

    def _syslog_combo_filter_value(self, combo: QComboBox) -> str:
        """Selected filter value; index 0 means no filter."""
        if combo.currentIndex() <= 0:
            return ""
        data = combo.currentData(Qt.ItemDataRole.UserRole)
        if data is not None:
            text = str(data).strip()
            if text:
                return text
        return combo.currentText().strip()

    def _syslog_rebuild_filter_options_from_buffer(self) -> None:
        if not hasattr(self, "_syslog_buffer"):
            return
        for msg in self._syslog_buffer.lines:
            self._syslog_register_filter_options(msg)

    def _syslog_set_combo_filter(self, key: str, value: str) -> None:
        combo = getattr(self, "_syslog_filter_combos", {}).get(key)
        if combo is None:
            return
        want = (value or "").strip()
        if not want:
            combo.blockSignals(True)
            combo.setCurrentIndex(0)
            combo.blockSignals(False)
            return
        if want not in self._syslog_filter_seen[key]:
            self._syslog_register_filter_options_for_value(key, want)
        idx = combo.findData(want, Qt.ItemDataRole.UserRole)
        if idx < 0:
            idx = combo.findText(want)
        combo.blockSignals(True)
        combo.setCurrentIndex(max(0, idx) if idx >= 0 else 0)
        combo.blockSignals(False)

    def _syslog_register_filter_options_for_value(
        self, key: str, value: str
    ) -> None:
        combo = self._syslog_filter_combos.get(key)
        if combo is None or not value or value in self._syslog_filter_seen[key]:
            return
        self._syslog_filter_seen[key].add(value)
        pos = 1
        while pos < combo.count() and combo.itemText(pos) < value:
            pos += 1
        combo.blockSignals(True)
        combo.insertItem(pos, value, value)
        combo.blockSignals(False)

    def _syslog_register_filter_options(
        self, msg: syslog_recv.SyslogMessage
    ) -> None:
        """Add newly-seen column values to the filter dropdowns."""
        if not hasattr(self, "_syslog_filter_combos"):
            return
        for key in self._syslog_filter_combos:
            value = self._syslog_filter_value(msg, key)
            self._syslog_register_filter_options_for_value(key, value)

    def _syslog_msg_visible(self, msg: syslog_recv.SyslogMessage) -> bool:
        needle = (self.syslog_filter.text() or "").strip().lower()
        if needle and needle not in _syslog_haystack(msg):
            return False
        for key, combo in getattr(self, "_syslog_filter_combos", {}).items():
            want = self._syslog_combo_filter_value(combo)
            if want and self._syslog_filter_value(msg, key) != want:
                return False
        return True

    def _syslog_append_row(
        self, msg: syslog_recv.SyslogMessage, *, scroll: bool = True
    ) -> None:
        if not hasattr(self, "syslog_table"):
            return
        if not self._syslog_msg_visible(msg):
            return
        table = self.syslog_table
        row = table.rowCount()
        table.insertRow(row)
        values = [
            msg.received_at,
            msg.source_ip,
            self._syslog_filter_value(msg, "device"),
            msg.severity_name,
            msg.facility_name,
            msg.hostname or "—",
            msg.app_name or "—",
            (
                msg.message
                if msg.accepted
                else f"[dropped: {msg.drop_reason}] {msg.message}"
            ),
        ]
        color = _syslog_severity_color(msg.severity)
        if not msg.accepted:
            color = QColor("#ef6c00")
        for col, text in enumerate(values):
            item = QTableWidgetItem(text)
            if col == 0:
                item.setData(Qt.ItemDataRole.UserRole, msg)
            if color is not None:
                item.setForeground(color)
            if not msg.accepted:
                item.setToolTip(msg.drop_reason or "Source not on allow list")
            table.setItem(row, col, item)
        if scroll:
            table.scrollToBottom()
        max_rows = max(10, int(self.syslog_memory_lines.value()))
        while table.rowCount() > max_rows:
            table.removeRow(0)

    def _syslog_apply_filter(self) -> None:
        if not hasattr(self, "syslog_table"):
            return
        table = self.syslog_table
        table.setUpdatesEnabled(False)
        try:
            table.setRowCount(0)
            for msg in self._syslog_buffer.lines:
                self._syslog_append_row(msg, scroll=False)
            if table.rowCount():
                table.scrollToBottom()
        finally:
            table.setUpdatesEnabled(True)

    def _syslog_filter_by_message_type(
        self, msg: syslog_recv.SyslogMessage
    ) -> None:
        mtype = _syslog_message_type(msg)
        self._syslog_set_combo_filter("app", mtype)
        self._syslog_apply_filter()

    def _syslog_clear(self) -> None:
        if hasattr(self, "_syslog_buffer"):
            self._syslog_buffer.clear()
        if hasattr(self, "syslog_table"):
            self.syslog_table.setRowCount(0)
        # Filter options belong to the cleared messages — reset them too.
        for key, combo in getattr(self, "_syslog_filter_combos", {}).items():
            self._syslog_filter_seen[key].clear()
            combo.blockSignals(True)
            while combo.count() > 1:
                combo.removeItem(1)
            combo.setCurrentIndex(0)
            combo.blockSignals(False)

    def _syslog_msg_at_row(self, row: int) -> syslog_recv.SyslogMessage | None:
        item = self.syslog_table.item(row, 0)
        if item is None:
            return None
        msg = item.data(Qt.ItemDataRole.UserRole)
        return msg if isinstance(msg, syslog_recv.SyslogMessage) else None

    def _syslog_context_menu(self, pos) -> None:
        row = self.syslog_table.rowAt(pos.y())
        if row < 0:
            return
        msg = self._syslog_msg_at_row(row)
        if msg is None:
            return
        menu = QMenu(self.syslog_table)
        act_filter_type = menu.addAction("Filter by this message type")
        menu.addSeparator()
        act_debug = menu.addAction("Debug this error")
        act_case = menu.addAction("Create Background casefile")
        act_info = menu.addAction("Send to Ollama for information")
        act_fixes = menu.addAction("Suggest fixes")
        chosen = menu.exec(self.syslog_table.viewport().mapToGlobal(pos))
        if chosen is act_filter_type:
            self._syslog_filter_by_message_type(msg)
        elif chosen is act_debug:
            self._syslog_ai_action(msg, "debug")
        elif chosen is act_case:
            self._syslog_create_casefile(msg)
        elif chosen is act_info:
            self._syslog_ai_action(msg, "info")
        elif chosen is act_fixes:
            self._syslog_ai_action(msg, "fixes")

    def _syslog_msg_context(
        self, msg: syslog_recv.SyslogMessage, *, limit: int = 40
    ) -> str:
        """The selected line plus recent lines from the same source."""
        related = [
            m
            for m in self._syslog_buffer.lines
            if m.source_ip == msg.source_ip
        ][-limit:]
        lines = [
            f"{m.received_at} [{m.facility_name}/{m.severity_name}] "
            f"{m.hostname or m.source_ip} {m.app_name or '-'}: {m.message}"
            for m in related
        ]
        return (
            "Selected syslog message:\n"
            f"  received: {msg.received_at}\n"
            f"  source: {msg.source_ip} (device: {msg.device_name or 'unknown'})\n"
            f"  facility/severity: {msg.facility_name}/{msg.severity_name}\n"
            f"  host: {msg.hostname or '-'}  app: {msg.app_name or '-'}\n"
            f"  message: {msg.message}\n"
            f"  raw: {msg.raw}\n\n"
            f"Recent messages from the same source ({len(lines)}):\n"
            + "\n".join(lines)
        )

    def _syslog_ai_action(
        self, msg: syslog_recv.SyslogMessage, mode: str
    ) -> None:
        if not ai.is_ollama_enabled():
            QMessageBox.information(
                self,
                "Ollama",
                "Ollama is not enabled — turn it on in the Ollama section "
                "to use AI analysis.",
            )
            return
        url, model = ai.load_ollama_settings()
        title, question = _SYSLOG_AI_PROMPTS[mode]
        context = self._syslog_msg_context(msg)

        dlg = QDialog(self)
        dlg.setWindowTitle(f"{title} — {msg.source_ip}")
        dlg.resize(720, 480)
        lay = QVBoxLayout(dlg)
        head = QLabel(f"<b>{msg.message[:160]}</b>")
        head.setWordWrap(True)
        lay.addWidget(head)
        out = QTextEdit()
        out.setReadOnly(True)
        out.setPlainText(f"Asking {model} at {url}…")
        lay.addWidget(out, stretch=1)
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(dlg.close)
        lay.addWidget(btn_close, alignment=Qt.AlignmentFlag.AlignRight)

        worker = _SyslogAiWorker(context, question, url=url, model=model)
        worker.done.connect(out.setPlainText)
        worker.failed.connect(
            lambda err: out.setPlainText(f"Ollama request failed:\n{err}")
        )
        self._syslog_ai_workers.append(worker)
        worker.finished.connect(
            lambda w=worker: self._syslog_ai_workers.remove(w)
            if w in self._syslog_ai_workers
            else None
        )
        worker.finished.connect(worker.deleteLater)
        worker.start()
        dlg.show()

    def _syslog_create_casefile(self, msg: syslog_recv.SyslogMessage) -> None:
        """Write a casefile JSON now; append AI analysis in the background."""
        case_dir = syslog_recv.PROJECT_ROOT / "data" / "casefiles"
        case_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe_ip = msg.source_ip.replace(":", "_") or "unknown"
        path = case_dir / f"case-{stamp}-{safe_ip}.json"
        related = [
            m.to_dict()
            for m in self._syslog_buffer.lines
            if m.source_ip == msg.source_ip
        ][-40:]
        payload = {
            "created_at": msg.received_at,
            "status": "open",
            "message": msg.to_dict(),
            "context_messages": related,
            "ai_analysis": None,
        }
        try:
            path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            QMessageBox.critical(self, "Casefile", str(exc))
            return
        app_log.get_logger("syslog").info("Casefile created: %s", path)
        self.syslog_status.setText(f"Casefile created: {path}")
        self.syslog_status.setStyleSheet("color: #1565c0;")
        if not ai.is_ollama_enabled():
            return
        url, model = ai.load_ollama_settings()
        _, question = _SYSLOG_AI_PROMPTS["debug"]
        worker = _SyslogAiWorker(
            self._syslog_msg_context(msg), question, url=url, model=model
        )

        def _attach_analysis(reply: str, case_path: Path = path) -> None:
            try:
                data = json.loads(case_path.read_text(encoding="utf-8"))
                data["ai_analysis"] = reply
                case_path.write_text(
                    json.dumps(data, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
            except OSError:
                return
            app_log.get_logger("syslog").info(
                "Casefile AI analysis added: %s", case_path
            )
            if hasattr(self, "syslog_status"):
                self.syslog_status.setText(
                    f"Casefile ready (AI analysis attached): {case_path}"
                )
                self.syslog_status.setStyleSheet("color: #2e7d32;")

        worker.done.connect(_attach_analysis)
        worker.failed.connect(
            lambda err: app_log.get_logger("syslog").warning(
                "Casefile AI analysis failed: %s", err
            )
        )
        self._syslog_ai_workers.append(worker)
        worker.finished.connect(
            lambda w=worker: self._syslog_ai_workers.remove(w)
            if w in self._syslog_ai_workers
            else None
        )
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def _syslog_export(self) -> None:
        if not hasattr(self, "_syslog_buffer") or not self._syslog_buffer.lines:
            QMessageBox.information(self, "Syslog", "No messages to export.")
            return
        path, _ok = QFileDialog.getSaveFileName(
            self,
            "Export syslog",
            str(syslog_recv.PROJECT_ROOT / "data" / "syslog-export.jsonl"),
            "JSON lines (*.jsonl);;Text (*.txt)",
        )
        if not path:
            return
        try:
            lines = [json.dumps(m.to_dict(), ensure_ascii=False) for m in self._syslog_buffer.lines]
            Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError as exc:
            QMessageBox.critical(self, "Syslog", str(exc))

    def _build_setup_openobserve(self) -> QWidget:
        from pfsense_checker.openobserve_screen import OpenObserveScreen

        return OpenObserveScreen()

    def _build_setup_logging(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("Setup — Logging")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        v.addWidget(
            _section_card(
                "Log level & files",
                "Choose how much detail is kept in the Console memory ring and "
                "on disk. The log file is a FIFO ring: when it exceeds the max "
                "size, the oldest bytes are discarded.",
            )
        )

        settings = app_log.get_hub().settings
        box = QGroupBox("Logging control")
        form = QFormLayout(box)

        self.log_level = QComboBox()
        self.log_level.addItems(list(app_log.LEVELS))
        idx = self.log_level.findText(settings.level)
        self.log_level.setCurrentIndex(idx if idx >= 0 else 1)
        form.addRow("Log level:", self.log_level)

        self.log_file_enabled = QCheckBox("Write log file to disk")
        self.log_file_enabled.setChecked(settings.file_enabled)
        form.addRow(self.log_file_enabled)

        dir_row = QHBoxLayout()
        self.log_dir = QLineEdit(settings.log_dir or str(app_log.DEFAULT_LOG_DIR))
        dir_row.addWidget(self.log_dir, stretch=1)
        btn_browse = QPushButton("Browse…")
        btn_browse.clicked.connect(self._setup_log_browse_dir)
        dir_row.addWidget(btn_browse)
        form.addRow("Log directory:", dir_row)

        self.log_filename = QLineEdit(settings.log_filename)
        form.addRow("Log filename:", self.log_filename)

        self.log_max_kb = QSpinBox()
        self.log_max_kb.setRange(64, 1024 * 512)  # 64 KiB … 512 MiB
        self.log_max_kb.setSuffix(" KiB")
        self.log_max_kb.setValue(max(64, settings.max_bytes // 1024))
        form.addRow("Max logfile size:", self.log_max_kb)

        self.log_memory_lines = QSpinBox()
        self.log_memory_lines.setRange(10, 50_000)
        self.log_memory_lines.setValue(settings.memory_lines)
        form.addRow("Console buffer (lines):", self.log_memory_lines)

        v.addWidget(box)

        actions = QHBoxLayout()
        btn_save = QPushButton("Save")
        btn_save.setStyleSheet(_primary_btn())
        btn_save.clicked.connect(self._setup_log_save)
        actions.addWidget(btn_save)
        btn_open_dir = QPushButton("Open log folder")
        btn_open_dir.clicked.connect(self._setup_log_open_dir)
        actions.addWidget(btn_open_dir)
        btn_console = QPushButton("Open Console…")
        btn_console.clicked.connect(lambda: self.show_section("console"))
        actions.addWidget(btn_console)
        actions.addStretch(1)
        v.addLayout(actions)

        self.log_setup_status = QLabel(f"Active file: {settings.log_path()}")
        self.log_setup_status.setWordWrap(True)
        self.log_setup_status.setStyleSheet("color: #555;")
        v.addWidget(self.log_setup_status)
        v.addStretch(1)
        return page

    def _setup_log_browse_dir(self) -> None:
        start = self.log_dir.text().strip() or str(app_log.DEFAULT_LOG_DIR)
        chosen = QFileDialog.getExistingDirectory(self, "Log directory", start)
        if chosen:
            self.log_dir.setText(chosen)

    def _setup_log_open_dir(self) -> None:
        path = Path(self.log_dir.text().strip() or app_log.DEFAULT_LOG_DIR)
        path.mkdir(parents=True, exist_ok=True)
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices

        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _setup_log_save(self) -> None:
        settings = app_log.LogSettings(
            level=self.log_level.currentText(),
            file_enabled=self.log_file_enabled.isChecked(),
            log_dir=self.log_dir.text().strip(),
            log_filename=self.log_filename.text().strip() or app_log.DEFAULT_LOG_FILENAME,
            max_bytes=int(self.log_max_kb.value()) * 1024,
            memory_lines=int(self.log_memory_lines.value()),
        )
        try:
            app_log.get_hub().apply_settings(settings, persist=True)
        except OSError as exc:
            QMessageBox.critical(self, "Logging", str(exc))
            return
        self.log_setup_status.setText(f"Saved — active file: {settings.log_path()}")
        self.log_setup_status.setStyleSheet("color: #1565c0;")
        self._refresh_console_status()
        app_log.get_logger("logging").info(
            "Logging settings updated level=%s file=%s max=%s",
            settings.level,
            settings.log_path() if settings.file_enabled else "(disabled)",
            settings.max_bytes,
        )

    def _build_ollama(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("Ollama")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        v.addWidget(
            _section_card(
                "Local AI advisor",
                "Use a local Ollama instance for the AI Advisor (findings stay on "
                "this machine). Enable it here, pick a model, then open Full "
                "workspace → AI Advisor to ask questions.",
            )
        )

        url, model = ai.load_ollama_settings()
        box = QGroupBox("Connection")
        form = QFormLayout(box)

        self.ollama_enabled = QCheckBox("Enable Ollama in this tool")
        self.ollama_enabled.setChecked(ai.is_ollama_enabled())
        self.ollama_enabled.toggled.connect(self._ollama_fields_enabled)
        form.addRow(self.ollama_enabled)

        self.ollama_url = QLineEdit(url)
        self.ollama_url.setPlaceholderText(ai.DEFAULT_OLLAMA_URL)
        form.addRow("Server URL:", self.ollama_url)

        self.ollama_model = QComboBox()
        self.ollama_model.setEditable(True)
        self.ollama_model.addItem(model)
        form.addRow("Default model:", self.ollama_model)

        self.ollama_api_key = QLineEdit(ai.load_ollama_api_key())
        self.ollama_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.ollama_api_key.setPlaceholderText("Optional — local installs usually leave blank")
        form.addRow("API key:", self.ollama_api_key)

        v.addWidget(box)

        actions = QHBoxLayout()
        btn_test = QPushButton("Test connection")
        btn_test.clicked.connect(self._ollama_test)
        actions.addWidget(btn_test)
        btn_refresh = QPushButton("Refresh models")
        btn_refresh.clicked.connect(self._ollama_refresh_models)
        actions.addWidget(btn_refresh)
        btn_save = QPushButton("Save")
        btn_save.setStyleSheet(_primary_btn())
        btn_save.clicked.connect(self._ollama_save)
        actions.addWidget(btn_save)
        btn_ai = QPushButton("Open AI Advisor…")
        btn_ai.clicked.connect(lambda: self.open_workspace.emit("AI Advisor"))
        actions.addWidget(btn_ai)
        actions.addStretch(1)
        v.addLayout(actions)

        self.ollama_status = QLabel("")
        self.ollama_status.setWordWrap(True)
        self.ollama_status.setStyleSheet("color: #555;")
        v.addWidget(self.ollama_status)
        tip = QLabel(
            "Ensure the Ollama app is running (default "
            f"{ai.DEFAULT_OLLAMA_URL}). Pull a model with  ollama pull "
            f"{ai.DEFAULT_OLLAMA_MODEL}"
        )
        tip.setWordWrap(True)
        tip.setStyleSheet("color: #555;")
        v.addWidget(tip)
        v.addStretch(1)
        self._ollama_fields_enabled(self.ollama_enabled.isChecked())
        return page

    def _ollama_fields_enabled(self, on: bool) -> None:
        for w in (
            self.ollama_url,
            self.ollama_model,
            self.ollama_api_key,
        ):
            w.setEnabled(on)

    def _ollama_save(self) -> None:
        try:
            ai.save_ollama_settings(
                self.ollama_url.text().strip(),
                self.ollama_model.currentText().strip() or ai.DEFAULT_OLLAMA_MODEL,
                api_key=self.ollama_api_key.text().strip(),
                enabled=self.ollama_enabled.isChecked(),
            )
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, "Ollama", str(exc))
            return
        state = "enabled" if self.ollama_enabled.isChecked() else "disabled"
        self.ollama_status.setText(f"Settings saved — Ollama {state}.")
        self.ollama_status.setStyleSheet("color: #1565c0;")
        self.ollama_status_changed.emit()

    def _ollama_refresh_models(self) -> None:
        url = self.ollama_url.text().strip() or ai.DEFAULT_OLLAMA_URL
        try:
            models = ai.list_ollama_models(
                url, api_key=self.ollama_api_key.text().strip() or ai.load_ollama_api_key()
            )
        except (RuntimeError, ValueError) as exc:
            self.ollama_status.setText(str(exc))
            self.ollama_status.setStyleSheet("color: #c62828;")
            QMessageBox.warning(self, "Ollama", str(exc))
            return
        if not models:
            self.ollama_status.setText(
                "Reachable, but no models installed. Run: ollama pull llama3.2"
            )
            self.ollama_status.setStyleSheet("color: #ef6c00;")
            return
        current = self.ollama_model.currentText()
        self.ollama_model.clear()
        self.ollama_model.addItems(models)
        if current in models:
            self.ollama_model.setCurrentText(current)
        self.ollama_status.setText(f"Found {len(models)} model(s).")
        self.ollama_status.setStyleSheet("color: #2e7d32;")
        self.ollama_status_changed.emit()

    def _ollama_test(self) -> None:
        url = self.ollama_url.text().strip() or ai.DEFAULT_OLLAMA_URL
        try:
            models = ai.list_ollama_models(
                url, api_key=self.ollama_api_key.text().strip() or ai.load_ollama_api_key()
            )
        except (RuntimeError, ValueError) as exc:
            self.ollama_status.setText(f"Not reachable: {exc}")
            self.ollama_status.setStyleSheet("color: #c62828;")
            self.ollama_status_changed.emit()
            QMessageBox.warning(self, "Ollama", f"Connection failed:\n{exc}")
            return
        n = len(models)
        msg = f"Connected to {url} — {n} model(s) available."
        self.ollama_status.setText(msg)
        self.ollama_status.setStyleSheet("color: #2e7d32;")
        self.ollama_status_changed.emit()
        QMessageBox.information(self, "Ollama", msg)

    def _update_mode_buttons(self) -> None:
        live = self._topology_mode == "live"
        self.btn_use_live.setStyleSheet(_primary_btn() if live else "")
        self.btn_use_experimental.setStyleSheet("" if live else _primary_btn())
        if live:
            self.topology_mode_label.setText("Mode: Live (= Login to Routers)")
        else:
            self.topology_mode_label.setText("Mode: Experimental (sandbox)")

    # -------------------------------------------------------- site / speed

    def set_site(self, site: SiteTopology) -> None:
        """Back-compat: treat as live + preview (same object)."""
        self.set_sites(live=site, topology=site, mode=self._topology_mode)

    def set_sites(
        self,
        *,
        live: SiteTopology,
        topology: SiteTopology | None = None,
        mode: str = "live",
    ) -> None:
        """Login always uses *live*; Topology preview uses *topology* (or live).

        When mode is live, *topology* must be the same object as *live* so edits
        on Login and Topology stay in sync.
        """
        self._live_site = live
        self._topology_mode = mode if mode in ("live", "experimental") else "live"
        if self._topology_mode == "live":
            self._topology_site = live
        else:
            self._topology_site = topology if topology is not None else live
        if hasattr(self, "session"):
            self.session.set_site(live)
        if hasattr(self, "topo_preview"):
            self.topo_preview.render_site(self._topology_site)
        self._refresh_speed_sources()
        self._syslog_refresh_sources()
        if hasattr(self, "btn_use_live"):
            self._update_mode_buttons()

    def _refresh_speed_sources(self) -> None:
        if not hasattr(self, "speed_source"):
            return
        current = self.speed_source.currentData()
        self.speed_source.blockSignals(True)
        self.speed_source.clear()
        self.speed_source.addItem("This PC (local probes)", "local")
        if self._live_site is not None:
            for dev in self._live_site.devices:
                ssh = getattr(dev, "ssh", None)
                host = (ssh.host if ssh and ssh.host else "").strip()
                label = f"{dev.name} ({dev.kind})"
                if host:
                    label += f" — {host}"
                self.speed_source.addItem(label, host or dev.name)
        # restore selection if possible
        if current is not None:
            idx = self.speed_source.findData(current)
            if idx >= 0:
                self.speed_source.setCurrentIndex(idx)
        self.speed_source.blockSignals(False)

    def _run_speed(self) -> None:
        if self._speed_worker and self._speed_worker.isRunning():
            return
        test_type = self.speed_test_type.currentData() or "ping"
        ping_target = self.speed_ping.text().strip()
        url = self.speed_url.text().strip()
        if test_type == "download":
            if not url:
                QMessageBox.information(
                    self, "Speed Checker", "Enter a download URL."
                )
                return
            ping_target = ""
        elif test_type == "traceroute":
            if not ping_target:
                QMessageBox.information(
                    self, "Speed Checker", "Enter a target for traceroute."
                )
                return
            url = ""
        else:
            if not ping_target:
                QMessageBox.information(
                    self, "Speed Checker", "Enter a ping target."
                )
                return
            url = ""
        source = self.speed_source.currentText()
        self.speed_table.setRowCount(0)
        self.speed_log.clear()
        self.speed_log.append(f"Source point: {source}")
        self.speed_log.append(f"Test type: {self.speed_test_type.currentText()}")
        self.btn_speed_run.setEnabled(False)
        self.speed_status.setText("Running…")

        self._speed_worker = SpeedCheckWorker(
            test_type=test_type,
            ping_host_name=ping_target,
            download_url=url,
            ping_count=self.speed_count.value(),
        )
        self._speed_worker.sample.connect(self._speed_sample)
        self._speed_worker.finished_ok.connect(self._speed_done)
        self._speed_worker.finished.connect(lambda: self.btn_speed_run.setEnabled(True))
        self._speed_worker.start()

    def _speed_sample(self, sample: object) -> None:
        if not isinstance(sample, SpeedSample):
            return
        row = self.speed_table.rowCount()
        self.speed_table.insertRow(row)
        metric = ""
        if sample.kind == "ping" and sample.latency_ms is not None:
            metric = f"{sample.latency_ms} ms"
        elif sample.kind == "traceroute":
            if sample.latency_ms is not None:
                metric = f"{sample.latency_ms} ms (last hop)"
            elif sample.elapsed_sec:
                metric = f"{sample.elapsed_sec:.1f} s"
        elif sample.kind == "download" and sample.mbps is not None:
            metric = f"{sample.mbps} Mbps"
        elif sample.latency_ms is not None:
            metric = f"{sample.latency_ms} ms"
        for col, text in enumerate(
            [sample.kind, sample.status, sample.target, metric, sample.message]
        ):
            self.speed_table.setItem(row, col, QTableWidgetItem(text))
        self.speed_log.append(f"[{sample.kind}] {sample.status}: {sample.message}")

    def _speed_done(self) -> None:
        self.speed_status.setText("Done")


_SYSLOG_AI_PROMPTS: dict[str, tuple[str, str]] = {
    "debug": (
        "Debug this error",
        "Debug this syslog message. Explain what happened, the most likely "
        "root cause, and give step-by-step checks to confirm it. The context "
        "includes recent messages from the same device.",
    ),
    "info": (
        "Ollama — information",
        "Explain what this syslog message means in plain language: which "
        "process produced it, what each field says, and whether it is "
        "normal or needs attention.",
    ),
    "fixes": (
        "Suggest fixes",
        "Suggest concrete fixes for whatever this syslog message reports. "
        "Give specific pfSense/MikroTik configuration steps or commands "
        "where relevant, ordered from most to least likely to help.",
    ),
}


class _SyslogAiWorker(QThread):
    """Ask Ollama about a syslog message off the UI thread."""

    done = Signal(str)
    failed = Signal(str)

    def __init__(
        self, context: str, question: str, *, url: str, model: str
    ) -> None:
        super().__init__()
        self._context = context
        self._question = question
        self._url = url
        self._model = model

    def run(self) -> None:  # noqa: D102
        try:
            reply = ai.ask_ollama(
                self._context,
                self._question,
                model=self._model,
                base_url=self._url,
            )
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))
            return
        self.done.emit(reply)


def _syslog_message_type(msg: syslog_recv.SyslogMessage) -> str:
    """Normalized message type for filtering (app name without PID suffix)."""
    app = (msg.app_name or "").strip()
    if app:
        base = app.split("[", 1)[0].strip()
        return base or app
    return f"{msg.facility_name}/{msg.severity_name}"


def _syslog_haystack(msg: syslog_recv.SyslogMessage) -> str:
    return " ".join(
        [
            msg.received_at,
            msg.source_ip,
            msg.device_name,
            msg.severity_name,
            msg.facility_name,
            msg.hostname,
            msg.app_name,
            _syslog_message_type(msg),
            msg.message,
        ]
    ).lower()


def _syslog_severity_color(severity: int) -> QColor | None:
    if severity <= 3:
        return QColor("#c62828")
    if severity == 4:
        return QColor("#ef6c00")
    return None


def _primary_btn() -> str:
    return (
        "QPushButton { padding: 4px 18px;"
        " background-color: rgba(21, 101, 192, 128);"
        " border: 1px solid rgb(21, 101, 192); border-radius: 3px;"
        " color: white; font-weight: bold; }"
        "QPushButton:hover { background-color: rgba(21, 101, 192, 178); }"
    )


def _syslog_listener_btn(*, active: bool) -> str:
    """Blue Start listener; green Listener Active (stays vivid when disabled)."""
    if not active:
        return _primary_btn()
    return (
        "QPushButton { padding: 4px 18px;"
        " background-color: rgba(46, 125, 50, 220);"
        " border: 1px solid rgb(27, 94, 32); border-radius: 3px;"
        " color: white; font-weight: bold; }"
        "QPushButton:disabled {"
        " background-color: rgba(46, 125, 50, 220);"
        " border: 1px solid rgb(27, 94, 32);"
        " color: white; font-weight: bold; }"
    )


def _modules_checkbox_style() -> str:
    return (
        "QCheckBox { background: transparent; spacing: 0; }"
        "QCheckBox::indicator {"
        " width: 16px; height: 16px;"
        " border: 1px solid #000000;"
        " border-radius: 2px;"
        " background: #ffffff;"
        "}"
        "QCheckBox::indicator:checked {"
        " background-color: #1565c0;"
        " border: 1px solid #1565c0;"
        "}"
        "QCheckBox::indicator:hover {"
        " border: 1px solid #000000;"
        "}"
    )


def _modules_action_btn_style(kind: str) -> str:
    """Shared size metrics; colours: refresh blue, open amber, save grey→green."""
    base = (
        "QPushButton {"
        " padding: 4px 12px;"
        " font-size: 13px;"
        " font-weight: bold;"
        " border-radius: 3px;"
    )
    if kind == "refresh":
        return (
            base
            + " background-color: rgba(21, 101, 192, 200);"
            + " border: 1px solid rgb(13, 71, 161);"
            + " color: white; }"
            + "QPushButton:hover { background-color: rgba(25, 118, 210, 230); }"
        )
    if kind == "open":
        return (
            base
            + " background-color: rgba(255, 193, 7, 200);"
            + " border: 1px solid rgb(245, 158, 11);"
            + " color: #3e2723; }"
            + "QPushButton:hover { background-color: rgba(255, 213, 79, 230); }"
        )
    if kind == "save_active":
        return (
            base
            + " background-color: rgba(46, 125, 50, 220);"
            + " border: 1px solid rgb(27, 94, 32);"
            + " color: white; }"
            + "QPushButton:hover { background-color: rgba(56, 142, 60, 240); }"
        )
    # save_idle (grey)
    return (
        base
        + " background-color: #bdbdbd;"
        + " border: 1px solid #9e9e9e;"
        + " color: #f5f5f5; }"
        + "QPushButton:disabled {"
        + " background-color: #bdbdbd;"
        + " border: 1px solid #9e9e9e;"
        + " color: #eeeeee; }"
    )


def _modules_save_btn_style(active: bool) -> str:
    """Back-compat alias for save button colour state."""
    return _modules_action_btn_style("save_active" if active else "save_idle")
