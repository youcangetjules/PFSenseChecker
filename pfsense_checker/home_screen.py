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
from datetime import datetime, timezone
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
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QStackedWidget,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from pfsense_checker import (
    ai,
    app_log,
    auth,
    device_scan,
    oui,
    python_modules,
    snmp,
    subnet_health,
    syslog_recv,
    troubleshoot,
)
from pfsense_checker.branding import NAV_TREE_STYLE, render_logo_pixmap
from pfsense_checker.paths import PROJECT_ROOT
from pfsense_checker.db_admin_screen import DatabaseScreen
from pfsense_checker.section_menu import SlidingSectionMenu
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
    ("security_holes", "Security Holes"),
    ("pentesting", "Pentesting"),
    ("dns_leakage", "DNS Leakage"),
    ("speed", "Speed Checker"),
    ("topology", "Topology"),
    ("database", "Database"),
    ("users", "Users"),
    ("modules", "Python Modules"),
    ("tests", "Tests"),
    ("ollama", "Ollama"),
    ("problems", "Problems/Troubleshooting"),
    ("wireshark", "Wireshark"),
    ("logs", "Logs"),
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

# Everything about logs sits under the one Logs entry: router logs first (read,
# download, receive), then NetCheck's own. Console and Syslog keep the keys they
# had as top-level sections, so show_section("console") still works. Log Pipeline
# is part of the Syslog page (one receiver).
LOGS_SUBSECTIONS = (
    ("logs.analysis", "Log Analysis"),
    ("logs.devices", "Device Logs"),
    ("syslog", "Syslog"),
    ("console", "Console"),
    ("logs.logins", "Login History"),
)

# Config Check: the open/pull page, then one entry per workspace tab
# ("config.tab:<tab title>"), added once the workspace has been built.
CONFIG_OPEN_KEY = "config.open"
CONFIG_TAB_PREFIX = "config.tab:"
CONFIG_SUBSECTIONS = ((CONFIG_OPEN_KEY, "Open / Pull config"),)

# Short capability blurbs for the status-bar (user | module — capabilities).
SECTION_CAPABILITIES: dict[str, str] = {
    "login": "SSH login · LAN search · topology map · save connectivity",
    "files": "Open config/folder · re-check · export report · workspace",
    "beaconing": "Live monitor · beacon creator · collector health",
    "subnet_health": "Local + beacon subnets · ping/speed · Wired/WLAN",
    "config": "Open pfSense/MikroTik configs · findings workspace",
    "config.open": "Open a config file or folder · pull from a connected device",
    "logs": "Router logs: analyse · download · receive live · NetCheck's own log and logins",
    "logs.logins": "Who signed in · from which address · for how long · failed attempts",
    "logs.devices": "Router logs downloaded over SSH · on a schedule and after Connect",
    "logs.analysis": "Drop log files in · failed logins, blocks, link drops, Wi-Fi, DHCP, VPN, errors",
    "security_holes": "Open services · firewall gaps · known vulnerabilities · old software · weak logins",
    "pentesting": "Authorised testing of your own devices · scope before tests",
    "dns_leakage": "Where DNS queries really go · bypass and leak checks",
    "speed": "Ping & download checks from chosen source",
    "topology": "Live/experimental site map · load/save · builder",
    "database": "PostgreSQL browse · SQL · schema · NetCheck tables",
    "users": "Accounts · roles · password reset · enable/disable",
    "modules": "requirements.txt · install/load · Save/Commit",
    "tests": "Discover & run pytest suite",
    "ollama": "Enable local LLM · models · API key · test",
    "problems": "Findings · resiliency · live monitor · AI advisor",
    "console": "Live app logs · failures · debug output",
    "syslog": "Live logs from pfSense and MikroTik · UDP/TCP receiver · setup commands · allowlist",
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


def loaded_config_devices(site: SiteTopology | None) -> list[tuple[str, str, str, str, bool]]:
    """(name, kind, ip, config path, ignored) for devices with a config on disk.

    Same rule as the Config Loaded button on Login to Routers.
    """
    out: list[tuple[str, str, str, str, bool]] = []
    if site is None:
        return out
    for dev in site.devices:
        src = dev.ensure_config_source()
        path = (src.analyzable_path() if src is not None else "") or dev.config_file or ""
        if not path or not Path(path).is_file():
            continue
        ip = ((dev.ssh.host if dev.ssh else "") or dev.mgmt_ip or "").strip()
        out.append((dev.name, dev.kind or "", ip, path, bool(getattr(dev, "ignored", False))))
    out.sort(key=lambda r: (r[4], r[0].lower()))
    return out


class LoadedConfigList(QListWidget):
    """Loaded configs: click to open, or drag an entry onto Config Check."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setDragEnabled(True)
        self.setDragDropMode(QListWidget.DragDropMode.DragOnly)
        self.setDefaultDropAction(Qt.DropAction.CopyAction)

    def mimeData(self, items):  # noqa: ANN001, N802
        from PySide6.QtCore import QMimeData, QUrl

        paths = [str(i.data(Qt.ItemDataRole.UserRole)) for i in items if i.data(Qt.ItemDataRole.UserRole)]
        data = QMimeData()
        data.setUrls([QUrl.fromLocalFile(p) for p in paths])
        data.setText("\n".join(paths))
        return data


_SH_DEVICE_COLUMNS = (
    "IP", "MAC", "Type", "Hostname", "Vendor", "Beacon", "Age", "First seen", "Last seen",
    "Seen by", "OS / services",
)
_SH_TYPE_COLOURS = {
    device_scan.CONN_ROUTER: "#e3f2fd",
    device_scan.CONN_DHCP: "#e8f5e9",
    device_scan.CONN_DHCP_INFERRED: "#f1f8e9",
    device_scan.CONN_STATIC_DHCP: "#f3e5f5",
    device_scan.CONN_STATIC: "#fff8e1",
    device_scan.CONN_MACVLAN: "#e0f7fa",
}
_SH_SEVERITY = {
    device_scan.SEV_FAIL: ("Fault", "#ffebee", "#c62828"),
    device_scan.SEV_WARN: ("Warning", "#fff3e0", "#e65100"),
    device_scan.SEV_INFO: ("Info", "#f5f5f5", "#546e7a"),
}


class _IpItem(QTableWidgetItem):
    """Sorts IP addresses numerically."""

    def __lt__(self, other: QTableWidgetItem) -> bool:
        a = self.data(Qt.ItemDataRole.UserRole)
        b = other.data(Qt.ItemDataRole.UserRole)
        if isinstance(a, int) and isinstance(b, int):
            return a < b
        return super().__lt__(other)


def _when(t: datetime | None) -> str:
    return t.astimezone().strftime("%Y-%m-%d %H:%M") if t else "—"


def fill_device_table(table: QTableWidget, devices: list) -> None:
    import ipaddress

    table.setSortingEnabled(False)
    table.setRowCount(len(devices))
    for r, d in enumerate(devices):
        sources = ", ".join(s.replace("router-arp:", "ARP ").replace("lease:", "lease ") for s in d.sources)
        values = [
            d.ip, d.mac or "—", d.conn_type, d.hostname or d.known_name or "", d.vendor or "",
            d.beacon_id or "", device_scan.age_text(d.first_seen) or "—", _when(d.first_seen),
            _when(d.last_seen), sources, "; ".join(filter(None, [d.os_guess, *d.services])),
        ]
        for c, text in enumerate(values):
            item = _IpItem(str(text)) if c == 0 else QTableWidgetItem(str(text))
            if c == 0:
                item.setData(Qt.ItemDataRole.UserRole, int(ipaddress.IPv4Address(d.ip)))
            if c == 2:
                item.setBackground(QColor(_SH_TYPE_COLOURS.get(d.conn_type, "#ffffff")))
            if c == 5 and d.beacon_id:
                item.setForeground(QColor("#1565c0"))
            if not d.answered and c in (0, 1):
                item.setForeground(QColor("#90a4ae"))
                item.setToolTip("Only in a router table or the topology; did not answer this scan")
            table.setItem(r, c, item)
    table.setSortingEnabled(True)
    table.sortItems(0, Qt.SortOrder.AscendingOrder)
    table.resizeColumnsToContents()


def fill_problem_table(table: QTableWidget, problems: list) -> None:
    table.setSortingEnabled(False)
    table.setRowCount(len(problems))
    for r, p in enumerate(problems):
        label, bg, fg = _SH_SEVERITY.get(p.severity, (p.severity, "#ffffff", "#000000"))
        for c, text in enumerate([label, p.kind, p.subject, p.detail, p.fix]):
            item = QTableWidgetItem(text)
            item.setBackground(QColor(bg))
            if c == 0:
                item.setForeground(QColor(fg))
                f = item.font()
                f.setBold(True)
                item.setFont(f)
            table.setItem(r, c, item)
    table.setSortingEnabled(True)
    table.resizeColumnsToContents()


def section_title(key: str) -> str:

    for k, label in SECTIONS:
        if k == key:
            return label
    for k, label in (*SETUP_SUBSECTIONS, *CONFIG_SUBSECTIONS, *LOGS_SUBSECTIONS):
        if k == key:
            return label
    if key.startswith(CONFIG_TAB_PREFIX):
        return key[len(CONFIG_TAB_PREFIX):]
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
    config_menu_opened = Signal()  # Config Check submenu shown: build its tabs

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
        from pfsense_checker.device_log_manager import DeviceLogManager

        # Router logs over SSH, on a timer and after Connect / Load Config.
        self.device_logs = DeviceLogManager(lambda: self._live_site, self)
        self.device_logs.status.connect(self.ssh_summary_changed.emit)
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

        # Main sections; Config Check and Setup slide open a submenu.
        self.nav = SlidingSectionMenu()
        self.nav.set_sections(self._menu_sections())
        self.nav.section_selected.connect(self._on_menu_selected)
        self.nav.parent_opened.connect(self._on_menu_parent_opened)
        nav_col.addWidget(self.nav, stretch=1)

        # Devices whose config is already loaded (Login to Routers): one
        # click opens it in Config Check.
        loaded_title = QLabel("Loaded configs")
        loaded_title.setStyleSheet("font-weight: bold; color: #1a237e; padding: 6px 2px 2px 2px;")
        nav_col.addWidget(loaded_title)
        self.loaded_configs = LoadedConfigList()
        self.loaded_configs.setFixedWidth(300)
        self.loaded_configs.setMaximumHeight(170)
        self.loaded_configs.setStyleSheet(
            "QListWidget { border: 1px solid #cfd8dc; border-radius: 4px; background: #f7f9fa; }"
            "QListWidget::item { padding: 4px 8px; }"
            "QListWidget::item:hover { background: #e3eef8; }"
        )
        self.loaded_configs.setToolTip(
            "Click a device to open its config in Config Check, or drag it onto Config Check"
        )
        self.loaded_configs.itemClicked.connect(self._open_loaded_config)
        nav_col.addWidget(self.loaded_configs)
        self._refresh_loaded_configs()

        btn_workspace = QPushButton("Full workspace…")
        btn_workspace.setToolTip("Open the full analysis tab set")
        btn_workspace.clicked.connect(lambda: self.open_workspace.emit(""))
        nav_col.addWidget(btn_workspace)
        root.addLayout(nav_col)

        # --- content stack (pages built lazily on first visit) ---
        self.stack = QStackedWidget()
        # Pages by key. Kept as widgets: stack indexes shift when the
        # startup placeholder is removed.
        self._pages: dict[str, QWidget] = {}
        self._page_builders = {
            "login": self._build_login,
            "beaconing": self._build_beaconing,
            "subnet_health": self._build_subnet_health,
            "config.open": self._build_config,
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
            "wireshark": self._build_wireshark,
            "logs.logins": self._build_login_history,
            "logs.devices": self._build_device_logs,
            "logs.analysis": self._build_log_analysis,
            "security_holes": self._build_security_holes,
            "pentesting": self._build_pentesting,
            "dns_leakage": self._build_dns_leakage,
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

        self.nav.select("login", animate=False)

    def _deferred_ensure_login_page(self) -> None:
        """Build the Login page after the first event-loop turn (faster hub paint)."""
        if "login" in self._pages:
            return
        idx = self._ensure_page("login")
        placeholder = getattr(self, "_login_placeholder", None)
        if placeholder is not None:
            ph_idx = self.stack.indexOf(placeholder)
            if ph_idx >= 0:
                self.stack.removeWidget(placeholder)
                placeholder.deleteLater()
            self._login_placeholder = None
        # Removing the placeholder shifted the indexes: select by widget.
        if idx is not None and self.nav.current_key() == "login":
            self.stack.setCurrentWidget(self._pages["login"])

    def _ensure_page(self, key: str) -> int | None:
        """Build and cache a section page on first use; return stack index."""
        if key in self._pages:
            return self.stack.indexOf(self._pages[key])
        builder = self._page_builders.get(key)
        if builder is None:
            return None
        widget = builder()
        idx = self.stack.addWidget(widget)
        self._pages[key] = widget
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

    def _refresh_loaded_configs(self) -> None:
        lst = getattr(self, "loaded_configs", None)
        if lst is None:
            return
        lst.clear()
        rows = loaded_config_devices(self._live_site)
        if not rows:
            item = QListWidgetItem("None yet — Load Config on Login to Routers")
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            item.setForeground(QColor("#90a4ae"))
            lst.addItem(item)
            return
        for name, kind, ip, path, ignored in rows:
            detail = " · ".join(x for x in (kind, ip) if x)
            item = QListWidgetItem(f"{name}  —  {detail}" if detail else name)
            item.setData(Qt.ItemDataRole.UserRole, path)
            item.setToolTip(f"{path}\nClick, or drag onto Config Check, to check it")
            if ignored:
                item.setForeground(QColor("#9e9e9e"))
                item.setToolTip(f"{path}\nIgnored on Login to Routers")
            lst.addItem(item)

    def _open_loaded_config(self, item: QListWidgetItem) -> None:
        path = item.data(Qt.ItemDataRole.UserRole)
        if path:
            app_log.get_logger("nav").info("Open loaded config: %s", item.text())
            self.config_pulled_for_check.emit(str(path))

    def _menu_sections(self) -> list[tuple[str, str, list[tuple[str, str]] | None]]:
        out: list[tuple[str, str, list[tuple[str, str]] | None]] = []
        for key, label in SECTIONS:
            if key == "setup":
                out.append((key, label, list(SETUP_SUBSECTIONS)))
            elif key == "config":
                out.append((key, label, list(CONFIG_SUBSECTIONS)))
            elif key == "logs":
                out.append((key, label, list(LOGS_SUBSECTIONS)))
            else:
                out.append((key, label, None))
        return out

    def set_config_tabs(self, titles: list[str]) -> None:
        """Config Check submenu: Open / Pull config, then each workspace tab."""
        self.nav.set_children(
            "config",
            [*CONFIG_SUBSECTIONS, *((CONFIG_TAB_PREFIX + t, t) for t in titles)],
        )

    def attach_workspace(self, widget: QWidget) -> None:
        """Host the Config Check workspace (path bar + tabs) as a page."""
        if "config.workspace" in self._pages:
            return
        self.stack.addWidget(widget)
        self._pages["config.workspace"] = widget

    def show_workspace_page(self, tab_title: str = "") -> None:
        """Show the hosted workspace and mark its tab in the Config submenu."""
        page = self._pages.get("config.workspace")
        if page is None:
            return
        self.stack.setCurrentWidget(page)
        if tab_title:
            self.nav.select(CONFIG_TAB_PREFIX + tab_title)

    def current_section_key(self) -> str:
        return self.nav.current_key()

    def _on_menu_parent_opened(self, key: str) -> None:
        if key == "config":
            self.config_menu_opened.emit()

    def _on_menu_selected(self, key: str) -> None:
        if key.startswith(CONFIG_TAB_PREFIX):
            self.open_workspace.emit(key[len(CONFIG_TAB_PREFIX):])
            return
        self._show_page(key)

    def _show_page(self, key: str) -> None:
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
        elif key == "problems":
            self._ts_refresh_devices()
        if key:
            title = self.nav.label(key) or section_title(key)
            self.section_changed.emit(key, title, section_capabilities(key))

    def show_section(self, key: str) -> None:
        """Select a section by key (e.g. 'login', 'config', 'setup.oui')."""
        page_key = key
        if self.nav.has_children(key):
            page_key = self.nav.first_child(key)
            if key == "config":
                self.config_menu_opened.emit()
        self.nav.select(page_key)
        if page_key.startswith(CONFIG_TAB_PREFIX):
            self.open_workspace.emit(page_key[len(CONFIG_TAB_PREFIX):])
        else:
            self._show_page(page_key)

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
                "Devices, clashes and connection types",
                "nmap scans the subnet (aggressive -sV -O by default); router ARP / DHCP "
                "tables and loaded configs fill the gaps; beacons mark the devices they run "
                "on. Device age is kept in PostgreSQL.",
            )
        )

        scan_bar = QHBoxLayout()
        scan_bar.addWidget(QLabel("Subnet:"))
        self.sh_subnet = QComboBox()
        self.sh_subnet.setEditable(True)
        self.sh_subnet.setMinimumWidth(230)
        self.sh_subnet.setToolTip("Pick a subnet, or type one (CIDR)")
        scan_bar.addWidget(self.sh_subnet)
        self.sh_aggressive = QCheckBox("Aggressive (-sV -O)")
        self.sh_aggressive.setChecked(True)
        self.sh_aggressive.setToolTip("Service and OS detection. Untick for a quick host sweep (-sn).")
        scan_bar.addWidget(self.sh_aggressive)
        self.sh_firewalls = QCheckBox("Probe firewalls")
        self.sh_firewalls.setChecked(False)
        self.sh_firewalls.setToolTip(
            "pfSense / OPNsense are skipped by default: repeated probes make sshguard "
            "ban this PC. Tick to scan them and read their ARP / DHCP tables too."
        )
        scan_bar.addWidget(self.sh_firewalls)
        self.sh_router_tables = QCheckBox("Read router ARP / DHCP")
        self.sh_router_tables.setChecked(True)
        self.sh_router_tables.setToolTip("Uses saved logins only; read-only print commands.")
        scan_bar.addWidget(self.sh_router_tables)
        self.btn_sh_scan = QPushButton("Scan subnet")
        self.btn_sh_scan.setStyleSheet(_primary_btn())
        self.btn_sh_scan.clicked.connect(self._subnet_scan_run)
        scan_bar.addWidget(self.btn_sh_scan)
        scan_bar.addStretch(1)
        v.addLayout(scan_bar)
        self.sh_scan_status = QLabel("")
        self.sh_scan_status.setWordWrap(True)
        self.sh_scan_status.setStyleSheet("color: #555;")
        v.addWidget(self.sh_scan_status)
        self._subnet_scan_worker = None
        self._subnet_scan_result = None

        tabs = QTabWidget()
        self.sh_tabs = tabs
        self.sh_devices = QTableWidget(0, len(_SH_DEVICE_COLUMNS))
        self.sh_devices.setHorizontalHeaderLabels(list(_SH_DEVICE_COLUMNS))
        self.sh_problems = QTableWidget(0, 5)
        self.sh_problems.setHorizontalHeaderLabels(["Severity", "Problem", "Where", "Detail", "Fix"])
        for table in (self.sh_devices, self.sh_problems):
            table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            table.horizontalHeader().setStretchLastSection(True)
            table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            table.verticalHeader().setVisible(False)
            table.setSortingEnabled(True)
        tabs.addTab(self.sh_devices, "Devices")
        tabs.addTab(self.sh_problems, "Problems")
        access = QWidget()
        av = QVBoxLayout(access)
        av.setContentsMargins(0, 6, 0, 0)
        tabs.addTab(access, "Access && speed")
        v.addWidget(tabs, stretch=1)
        page_v = v
        v = av
        access_tip = QLabel(
            "This PC and each beacon report which subnets they can reach, whether the path is "
            "Wired or WLAN, and periodic ping / download samples."
        )
        access_tip.setWordWrap(True)
        v.addWidget(access_tip)

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
        v = page_v

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

    # --- device scan ------------------------------------------------------ #
    def _subnet_scan_choices(self) -> list[tuple[str, str, str]]:
        """(cidr, gateway, where) from this PC's adapters, the site and beacons."""
        import ipaddress

        out: dict[str, tuple[str, str]] = {}
        for row in getattr(self, "_sh_last_rows", []) or []:
            if isinstance(row, subnet_health.SubnetAccess) and row.cidr:
                where = "this PC" if row.source == "local" else row.source.replace("beacon:", "beacon ")
                out.setdefault(row.cidr, (row.gateway, where))
        site = getattr(self, "_live_site", None)
        for dev in getattr(site, "devices", []) or []:
            if getattr(dev, "ignored", False):
                continue
            for comp in getattr(dev, "components", []) or []:
                addr = (getattr(comp, "address", "") or "").strip()
                if "/" not in addr:
                    continue
                try:
                    iface = ipaddress.IPv4Interface(addr)
                except ValueError:
                    continue
                if iface.network.prefixlen < 16 or iface.network.prefixlen > 30:
                    continue
                gw = str(iface.ip) if (dev.kind or "").lower() in device_scan.ROUTER_KINDS else ""
                cidr = str(iface.network)
                prev = out.get(cidr)
                if prev is None:
                    out[cidr] = (gw, dev.name)
                elif not prev[0] and gw:
                    out[cidr] = (gw, prev[1])
        return [(c, gw, where) for c, (gw, where) in sorted(out.items())]

    def _subnet_scan_refresh_choices(self) -> None:
        if not hasattr(self, "sh_subnet"):
            return
        current = self.sh_subnet.currentText().strip()
        self.sh_subnet.blockSignals(True)
        self.sh_subnet.clear()
        for cidr, gw, where in self._subnet_scan_choices():
            self.sh_subnet.addItem(f"{cidr}  ({where})", (cidr, gw))
        if current:
            idx = self.sh_subnet.findText(current)
            if idx >= 0:
                self.sh_subnet.setCurrentIndex(idx)
            else:
                self.sh_subnet.setEditText(current)
        self.sh_subnet.blockSignals(False)
        if not self.sh_scan_status.text():
            self.sh_scan_status.setText(
                "nmap found." if device_scan.nmap_path() else
                "nmap is not installed: scans use a ping sweep + ARP. Install Nmap from nmap.org "
                "for service / OS detection."
            )

    def _subnet_scan_target(self) -> tuple[str, str]:
        import ipaddress

        text = self.sh_subnet.currentText().split("(")[0].strip()
        net = ipaddress.IPv4Network(text, strict=False)
        for cidr, gw, _where in self._subnet_scan_choices():
            if cidr == str(net):
                return cidr, gw
        return str(net), ""

    def _subnet_scan_run(self) -> None:
        if self._subnet_scan_worker is not None and self._subnet_scan_worker.isRunning():
            return
        try:
            cidr, gateway = self._subnet_scan_target()
        except ValueError:
            self.sh_scan_status.setText("Enter a subnet in CIDR form, e.g. 192.168.1.0/24.")
            self.sh_scan_status.setStyleSheet("color: #c62828;")
            return
        opts = device_scan.ScanOptions(
            aggressive=self.sh_aggressive.isChecked(),
            include_firewalls=self.sh_firewalls.isChecked(),
            router_tables=self.sh_router_tables.isChecked(),
        )
        cfg = self._subnet_health_settings_from_ui()
        site = getattr(self, "_live_site", None)

        class _ScanWorker(QThread):
            progress = Signal(str)
            done = Signal(object)
            failed = Signal(str)

            def run(self) -> None:  # noqa: D102
                try:
                    beacons: list[dict] = []
                    if cfg.collector_url:
                        try:
                            beacons = subnet_health.fetch_collector_beacons(
                                cfg.collector_url, token=cfg.collector_token
                            )
                        except Exception as exc:  # noqa: BLE001
                            self.progress.emit(f"collector not reached ({exc}); no beacons this time")
                    result = device_scan.scan(cidr, gateway=gateway, site=site, beacons=beacons,
                                              options=opts, progress=self.progress.emit)
                    self.done.emit(result)
                except Exception as exc:  # noqa: BLE001
                    self.failed.emit(f"{type(exc).__name__}: {exc}")

        worker = _ScanWorker()
        self._subnet_scan_worker = worker
        self.btn_sh_scan.setEnabled(False)
        self.sh_scan_status.setStyleSheet("color: #1565c0;")
        self.sh_scan_status.setText(f"Scanning {cidr}…")
        worker.progress.connect(lambda m: self.sh_scan_status.setText(f"Scanning {cidr}: {m}…"))
        worker.done.connect(self._subnet_scan_done)
        worker.failed.connect(self._subnet_scan_failed)
        worker.finished.connect(lambda: self.btn_sh_scan.setEnabled(True))
        worker.start()

    def _subnet_scan_failed(self, msg: str) -> None:
        self.sh_scan_status.setText(f"Scan failed: {msg}")
        self.sh_scan_status.setStyleSheet("color: #c62828;")
        app_log.get_logger("subnet_health").error("Subnet scan failed: %s", msg)

    def _subnet_scan_done(self, result: object) -> None:
        if not isinstance(result, device_scan.ScanResult):
            return
        self._subnet_scan_result = result
        fill_device_table(self.sh_devices, result.devices)
        fill_problem_table(self.sh_problems, result.problems)
        fails = sum(1 for p in result.problems if p.severity == device_scan.SEV_FAIL)
        warns = sum(1 for p in result.problems if p.severity == device_scan.SEV_WARN)
        self.sh_tabs.setTabText(0, f"Devices ({len(result.devices)})")
        self.sh_tabs.setTabText(1, f"Problems ({len(result.problems)})" if result.problems else "Problems")
        head = (f"{result.cidr} via {result.engine}: {len(result.devices)} device(s), "
                f"{fails} fault(s), {warns} warning(s).")
        self.sh_scan_status.setText("  ".join([head, *result.notes]))
        self.sh_scan_status.setStyleSheet(
            "color: #c62828;" if fails else ("color: #e65100;" if warns else "color: #2e7d32;")
        )
        app_log.get_logger("subnet_health").info(
            "Subnet scan %s engine=%s devices=%s problems=%s",
            result.cidr, result.engine, len(result.devices), len(result.problems),
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
        self._sh_last_rows = list(rows)
        self._subnet_scan_refresh_choices()
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
        self.session.device_logged_in.connect(self.device_logs.on_device_logged_in)
        v.addWidget(self.session)
        return page

    def _on_topology_edited(self) -> None:
        """Cables / positions changed on the Topology page: share with the app."""
        site = self._topology_site
        if site is None:
            return
        if self._topology_mode == "live" and hasattr(self, "session"):
            self.session.map_view.render_site(site)
        self.site_changed.emit()

    def _topology_add_device(self) -> None:
        """Add Device: Manufacturer / Model from the device library, placed in view."""
        from pfsense_checker.add_device_dialog import AddDeviceDialog

        site = self._topology_site
        if site is None:
            QMessageBox.information(self, "Add Device", "Load or start a topology first.")
            return
        dlg = AddDeviceDialog({d.name for d in site.devices}, self)
        if dlg.exec() != QDialog.DialogCode.Accepted or dlg.device() is None:
            return
        dev = dlg.device()
        view = self.topo_preview
        centre = view.mapToScene(view.viewport().rect().center())
        dev.x, dev.y = site.snap(centre.x() - 200), site.snap(centre.y() - 40)
        site.devices.append(dev)
        view.render_site(site)
        view.select_device(dev.name)
        self._on_topology_edited()
        app_log.get_logger("topology").info("Added device %s (%s)", dev.name, dev.hardware)

    def _topology_auto_arrange(self) -> None:
        """Auto-arrange the Topology canvas with ELK (elk_layout.py)."""
        from pfsense_checker import elk_layout
        from pfsense_checker.busy import busy_cursor

        try:
            with busy_cursor("Arranging the topology…"):
                msg = self.topo_preview.auto_arrange()
        except elk_layout.ElkUnavailable as exc:
            QMessageBox.warning(self, "Auto-arrange", f"ELK is not available: {exc}")
            return
        except Exception as exc:  # noqa: BLE001
            app_log.get_logger("topology").exception("Auto-arrange failed")
            QMessageBox.warning(self, "Auto-arrange", f"ELK could not lay out the site:\n{exc}")
            return
        self.btn_undo_arrange.setEnabled(self.topo_preview.can_undo_arrange())
        if self.topo_preview.can_undo_arrange():
            self._on_topology_edited()
        self.ssh_summary_changed.emit(msg)

    def _topology_undo_arrange(self) -> None:
        if self.topo_preview.undo_arrange():
            self._on_topology_edited()
            self.ssh_summary_changed.emit("Topology put back as it was before Auto-arrange.")
        self.btn_undo_arrange.setEnabled(False)

    def _set_topology_locked(self, locked: bool) -> None:
        self.topo_preview.set_locked(locked)

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
        self._refresh_loaded_configs()
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
        btn_add_dev = QPushButton("Add Device…")
        btn_add_dev.setToolTip("Pick a manufacturer and model from the device library")
        btn_add_dev.clicked.connect(self._topology_add_device)
        actions.addWidget(btn_add_dev)
        btn_arrange = QPushButton("Auto-arrange")
        btn_arrange.setToolTip(
            "Lay the site out with ELK: upstream devices at the top, switches below, then what hangs "
            "off them, with tidy square-cornered cables. Drag anything afterwards as usual."
        )
        btn_arrange.clicked.connect(self._topology_auto_arrange)
        actions.addWidget(btn_arrange)
        self.btn_undo_arrange = QPushButton("Undo arrange")
        self.btn_undo_arrange.setToolTip("Put every device back where it was before Auto-arrange")
        self.btn_undo_arrange.setEnabled(False)
        self.btn_undo_arrange.clicked.connect(self._topology_undo_arrange)
        actions.addWidget(self.btn_undo_arrange)
        self.topo_lock = QCheckBox("Lock layout")
        self.topo_lock.setToolTip("Freeze the map: no moving chassis or drawing / deleting cables")
        self.topo_lock.toggled.connect(self._set_topology_locked)
        actions.addWidget(self.topo_lock)
        actions.addStretch(1)
        v.addLayout(actions)

        self.topo_preview = SiteTopologyView()
        # Fully interactive: drag chassis, drag port → port to cable, right-click
        # a cable to delete it. Lock layout freezes it.
        self.topo_preview.set_locked(False)
        self.topo_preview.links_changed.connect(self._on_topology_edited)
        self.topo_preview.cable_message.connect(self.ssh_summary_changed.emit)
        self.topo_preview.positions_changed.connect(self._on_topology_edited)
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
        self.btn_modules_persist = QPushButton("Persist Changes")
        self.btn_modules_persist.setEnabled(False)
        self.btn_modules_persist.setStyleSheet(_modules_action_btn_style("save_idle"))
        self.btn_modules_persist.setToolTip(
            "Make the Loaded column survive log-out / log-in: ticked modules "
            "are loaded now (if not already) and again after each sign-in. "
            "Turns purple when the ticks differ from what is saved."
        )
        self.btn_modules_persist.clicked.connect(self._modules_persist)
        actions.addWidget(self.btn_modules_persist)
        # Match height to Refresh, width to Open requirements.txt; same font size.
        for b in (btn_refresh, btn_open, self.btn_modules_save, self.btn_modules_persist):
            b.ensurePolished()
        width = max(btn_open.sizeHint().width(), 168)
        height = max(btn_refresh.sizeHint().height(), 28)
        for b in (btn_refresh, btn_open, self.btn_modules_save, self.btn_modules_persist):
            b.setFixedSize(width, height)
        actions.addStretch(1)
        self.modules_summary = QLabel("")
        self.modules_summary.setStyleSheet("color: #555;")
        actions.addWidget(self.modules_summary)
        v.addLayout(actions)

        self.modules_table = QTableWidget(0, 8)
        self.modules_table.setHorizontalHeaderLabels(
            [
                "Package",
                "Required",
                "Installed",
                "Importable",
                "Loaded",
                "Available",
                "Import name",
                "Notes",
            ]
        )
        avail_hdr = self.modules_table.horizontalHeaderItem(5)
        if avail_hdr is not None:
            avail_hdr.setToolTip(
                "Set by NetCheck: green = installed, version meets Required, and "
                "loaded in this process without error. You change Installed and "
                "Loaded; this follows."
            )
        self.modules_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.modules_table.horizontalHeader().setSectionResizeMode(
            7, QHeaderView.ResizeMode.Stretch
        )
        self.modules_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.modules_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.modules_table.setAlternatingRowColors(True)
        self.modules_table.setColumnWidth(2, 72)
        self.modules_table.setColumnWidth(4, 72)
        self.modules_table.setColumnWidth(5, 84)
        v.addWidget(self.modules_table, stretch=1)

        tip = QLabel(
            "Optional packages (AI, Excel, SSH, Postgres) may show as missing "
            "if you skipped them on install — that is expected. "
            "Check Installed / Loaded, then Save/Commit (turns green when changed)."
        )
        tip.setWordWrap(True)
        tip.setStyleSheet("color: #555;")
        v.addWidget(tip)

        # Graphviz and nmap are programs, not Python modules: their own panel,
        # one row each (name, status, details, Check again).
        gv_box = QGroupBox("Programs (not Python modules)")
        gv_lay = QGridLayout(gv_box)
        gv_lay.setColumnStretch(2, 1)

        def program_row(row: int, name: str, refresh) -> tuple[QLabel, QLabel]:  # noqa: ANN001
            title = QLabel(name)
            title.setStyleSheet("font-weight: 600;")
            title.setMinimumWidth(80)
            gv_lay.addWidget(title, row, 0)
            badge = QLabel("Checking…")
            badge.setMinimumWidth(230)
            badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            gv_lay.addWidget(badge, row, 1)
            detail = QLabel("")
            detail.setWordWrap(True)
            detail.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            gv_lay.addWidget(detail, row, 2)
            again = QPushButton("Check again")
            again.clicked.connect(refresh)
            gv_lay.addWidget(again, row, 3)
            return badge, detail

        self.graphviz_badge, self.graphviz_detail = program_row(0, "Graphviz", self._graphviz_refresh)
        self.nmap_badge, self.nmap_detail = program_row(1, "nmap", self._nmap_refresh)
        v.addWidget(gv_box)
        QTimer.singleShot(0, self._graphviz_refresh)
        QTimer.singleShot(0, self._nmap_refresh)

        self._modules_baseline: list[tuple[bool, bool]] = []
        self._modules_status_rows: list = []
        self._modules_refresh()
        return page

    def _graphviz_refresh(self) -> None:
        from pfsense_checker import graphviz_status

        st = graphviz_status.check()
        if st.works and st.on_path:
            bg, fg = "#c8e6c9", "#1b5e20"
        elif st.works:
            bg, fg = "#fff3e0", "#e65100"
        else:
            bg, fg = "#ffcdd2", "#b71c1c"
        self.graphviz_badge.setText(st.summary)
        self.graphviz_badge.setStyleSheet(
            f"background: {bg}; color: {fg}; font-weight: 600; border: 1px solid {fg}; "
            "border-radius: 4px; padding: 6px 10px;"
        )
        lines = []
        if st.installed:
            lines.append(f"{st.version or 'dot'}  ·  {st.path}")
            lines.append(
                f"Test render: {'OK in ' + format(st.render_ms, 'g') + ' ms' if st.works else 'failed — ' + st.error}"
                f"  ·  On PATH: {'yes' if st.on_path else 'no'}"
            )
        else:
            lines.append(st.error)
        lines.append(
            f"Python graphviz package: {st.python_package or 'not installed'}"
            + (f" (finds dot: {'yes' if st.python_finds_dot else 'no'})" if st.python_package else "")
        )
        lines += st.notes
        self.graphviz_detail.setText("\n".join(lines))

    def _nmap_refresh(self) -> None:
        from pfsense_checker import nmap_status

        st = nmap_status.check()
        if st.works and st.npcap in ("running", "unknown"):
            bg, fg = "#c8e6c9", "#1b5e20"
        elif st.works:
            bg, fg = "#fff3e0", "#e65100"
        else:
            bg, fg = "#ffcdd2", "#b71c1c"
        self.nmap_badge.setText(st.summary)
        self.nmap_badge.setStyleSheet(
            f"background: {bg}; color: {fg}; font-weight: 600; border: 1px solid {fg}; "
            "border-radius: 4px; padding: 6px 10px;"
        )
        lines = []
        if st.installed:
            lines.append(f"{st.version or 'nmap'}  ·  {st.path}")
            lines.append(
                f"Test run (127.0.0.1): {'OK in ' + format(st.test_ms, 'g') + ' ms' if st.works else 'failed — ' + st.error}"
                f"  ·  On PATH: {'yes' if st.on_path else 'no'}"
            )
        else:
            lines.append(st.error)
        lines.append(f"Npcap driver: {st.npcap}  ·  used by Subnet Health device scans")
        lines += st.notes
        self.nmap_detail.setText("\n".join(lines))

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

    def _modules_shade_row(self, row: int, st) -> None:  # noqa: ANN001
        """Needed: green when loaded and available, red when not.
        Not needed but loaded anyway: light blue. Not needed, not loaded: plain.
        """
        if not python_modules.is_needed(st):
            if not st.loaded:
                return
            colour = QColor("#e3f2fd")
            why = "Loaded, but NetCheck does not use it (not required)."
        else:
            ok = bool(st.loaded and st.available)
            colour = QColor("#e8f5e9" if ok else "#ffebee")
            why = (
                "Needed by NetCheck — loaded and available."
                if ok
                else "Needed by NetCheck — not loaded or not available: " + (st.available_reason or "")
            )
        for col in range(self.modules_table.columnCount()):
            if col == 5:
                continue  # Available keeps its own green / red
            item = self.modules_table.item(row, col)
            if item is not None:
                item.setBackground(colour)
                if col == 0:
                    item.setToolTip(why)
            holder = self.modules_table.cellWidget(row, col)
            if holder is not None:
                holder.setAutoFillBackground(True)
                pal = holder.palette()
                pal.setColor(holder.backgroundRole(), colour)
                holder.setPalette(pal)

    @staticmethod
    def _modules_available_item(st) -> QTableWidgetItem:  # noqa: ANN001
        """Read-only green / red cell; the system sets it, not the user."""
        item = QTableWidgetItem("yes" if st.available else "no")
        item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
        if st.available:
            item.setBackground(QColor("#c8e6c9"))
            item.setForeground(QColor("#1b5e20"))
        else:
            item.setBackground(QColor("#ffcdd2"))
            item.setForeground(QColor("#b71c1c"))
        font = item.font()
        font.setBold(True)
        item.setFont(font)
        item.setToolTip(st.available_reason)
        return item

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
        available_n = 0
        saved_loads = set(python_modules.load_at_start_names())
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
                    ("Loaded in this process" if st.loaded else "Not loaded")
                    + (
                        " · loaded again after each login"
                        if st.import_name in saved_loads
                        else ""
                    ),
                ),
            )
            self.modules_table.setItem(r, 5, self._modules_available_item(st))
            if st.available:
                available_n += 1
            self.modules_table.setItem(r, 6, QTableWidgetItem(st.import_name))
            note_item = QTableWidgetItem(st.optional_note)
            note_item.setToolTip(st.optional_note)  # long notes are elided
            self.modules_table.setItem(r, 7, note_item)
            self._modules_shade_row(r, st)
        self._modules_baseline = baseline
        summary = python_modules.runtime_summary()
        self.modules_runtime.setText(
            f"Python {summary['python']}  ·  {summary['executable']}\n"
            f"requirements.txt: {summary['requirements']}"
        )
        self.modules_summary.setText(
            f"{installed_n} installed · {missing_n} missing · {loaded_n} loaded now"
            f" · {available_n} available"
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
        persist = getattr(self, "btn_modules_persist", None)
        if persist is not None:
            changed = self._modules_persist_dirty()
            persist.setEnabled(changed)
            persist.setStyleSheet(
                _modules_action_btn_style("persist_active" if changed else "save_idle")
            )

    def _modules_ticked_loaded(self) -> set[str]:
        """Import names whose Loaded box is ticked right now."""
        rows = getattr(self, "_modules_status_rows", [])
        current = self._modules_current_checks()
        return {
            st.import_name
            for st, (_inst, load) in zip(rows, current)
            if load and st.import_name
        }

    def _modules_persist_dirty(self) -> bool:
        rows = getattr(self, "_modules_status_rows", [])
        if not rows:
            return False
        known = {st.import_name for st in rows}
        saved = set(python_modules.load_at_start_names()) & known
        return self._modules_ticked_loaded() != saved

    def _modules_persist(self) -> None:
        """Save the Loaded column as the set imported after every sign-in.

        Ticked modules not loaded yet are imported first, so what the table
        shows, what is loaded now, and what is saved stay the same.
        """
        rows = getattr(self, "_modules_status_rows", [])
        loaded_now = {st.import_name for st in rows if st.loaded}
        failed: list[str] = []
        names: list[str] = []
        for name in sorted(self._modules_ticked_loaded()):
            if name not in loaded_now:
                try:
                    python_modules.import_now(name)
                except Exception as exc:  # noqa: BLE001
                    failed.append(f"{name}: {exc}")
                    continue
            names.append(name)
        if failed:
            QMessageBox.warning(
                self,
                "Persist Changes",
                "Not saved — these could not be loaded:\n" + "\n".join(failed),
            )
        try:
            python_modules.save_load_at_start(names)
        except OSError as exc:
            QMessageBox.critical(self, "Persist Changes", f"Could not save:\n{exc}")
            return
        app_log.get_logger("modules").info(
            "Loaded modules persisted for next sign-in: %s", ", ".join(names) or "(none)"
        )
        QMessageBox.information(
            self,
            "Persist Changes",
            (
                "These modules will be loaded again after each sign-in:\n"
                + "\n".join(names)
            )
            if names
            else "No modules will be loaded at sign-in (beyond what NetCheck needs).",
        )
        self._modules_refresh()

    def _modules_save_commit(self) -> None:
        if not self._modules_is_dirty():
            return
        rows = getattr(self, "_modules_status_rows", [])
        current = self._modules_current_checks()
        baseline = list(getattr(self, "_modules_baseline", []))
        to_install: list[str] = []
        to_import: list[str] = []
        to_unload: list[str] = []  # unticked Loaded: applied at the next login
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
            elif (not want_load) and was_load and st.import_name:
                to_unload.append(st.import_name)

        if not to_install and not to_import and not to_unload and not notes:
            QMessageBox.information(self, "Save/Commit", "Nothing to apply.")
            return

        next_login = (
            f"Stop loading: {', '.join(to_unload)}\n"
            "These changes will be updated at your next login "
            "(they stay loaded until then).\n"
            if to_unload
            else ""
        )
        confirm = QMessageBox.question(
            self,
            "Save/Commit",
            "Apply module changes?\n\n"
            + (
                f"Install: {', '.join(to_install)}\n" if to_install else ""
            )
            + (f"Import: {', '.join(to_import)}\n" if to_import else "")
            + next_login
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
        if to_import:
            results.append("Use Persist Changes to load these again after each sign-in.")
        if to_unload:
            try:
                for mod in to_unload:
                    python_modules.set_load_at_start(mod, False)
                results.append(
                    f"{', '.join(to_unload)}: will not be loaded at your next login. "
                    "These changes will be updated at your next login; they stay "
                    "loaded until then."
                )
                app_log.get_logger("modules").info(
                    "Stop loading at next login: %s", ", ".join(to_unload)
                )
            except OSError as exc:
                results.append(f"Could not save the next-login change: {exc}")

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
        blurb = QLabel(
            "Describe the problem: pick the device and interface, the kind of problem, and "
            "add anything else you know. NetCheck sends Ollama the parts of that device's "
            "loaded config that matter (interface, VLAN / bridge, DHCP, routes, gateways, "
            "firewall and NAT rules, DNS, VPN) plus its own checks — passwords, keys and "
            "other secrets are removed first."
        )
        blurb.setWordWrap(True)
        blurb.setStyleSheet("color: #555;")
        v.addWidget(blurb)

        box = QGroupBox("Describe the problem")
        form = QFormLayout(box)
        dev_row = QHBoxLayout()
        self.ts_device = QComboBox()
        self.ts_device.setMinimumWidth(420)
        self.ts_device.currentIndexChanged.connect(self._ts_device_changed)
        dev_row.addWidget(self.ts_device, stretch=1)
        btn_ts_refresh = QPushButton("Refresh")
        btn_ts_refresh.setToolTip("Re-read the loaded configs from Login to Routers")
        btn_ts_refresh.clicked.connect(self._ts_refresh_devices)
        dev_row.addWidget(btn_ts_refresh)
        form.addRow("Device:", dev_row)
        self.ts_iface = QComboBox()
        self.ts_iface.setMinimumWidth(420)
        self.ts_iface.setMaxVisibleItems(25)
        form.addRow("Interface:", self.ts_iface)
        self.ts_problem = QComboBox()
        for p in troubleshoot.PROBLEMS:
            self.ts_problem.addItem(p.label, p.key)
        form.addRow("Problem:", self.ts_problem)
        self.ts_notes = QPlainTextEdit()
        self.ts_notes.setPlaceholderText(
            "Anything else: what stopped working and when, which clients / addresses, what "
            "you have tried, error messages…"
        )
        self.ts_notes.setFixedHeight(90)
        form.addRow("Further info:", self.ts_notes)
        model_row = QHBoxLayout()
        self.ts_model = QComboBox()
        self.ts_model.setEditable(True)
        self.ts_model.setMinimumWidth(240)
        model_row.addWidget(self.ts_model)
        self.ts_think = QCheckBox("Think first")
        self.ts_think.setChecked(False)
        self.ts_think.setToolTip(
            "Let thinking models (gemma4, qwen3, …) reason before answering. On this PC "
            "gemma4:26b took about 9½ minutes with thinking and 1½ without, with the same "
            "main causes found."
        )
        model_row.addWidget(self.ts_think)
        self.ts_ollama_lbl = QLabel("")
        self.ts_ollama_lbl.setStyleSheet("color: #555;")
        model_row.addWidget(self.ts_ollama_lbl, stretch=1)
        form.addRow("Ollama model:", model_row)
        v.addWidget(box)

        run_row = QHBoxLayout()
        self.ts_ask_btn = QPushButton("Ask Ollama")
        self.ts_ask_btn.setStyleSheet(_primary_btn())
        self.ts_ask_btn.clicked.connect(self._ts_ask)
        run_row.addWidget(self.ts_ask_btn)
        self.ts_stop_btn = QPushButton("Stop")
        self.ts_stop_btn.setEnabled(False)
        self.ts_stop_btn.clicked.connect(self._ts_stop)
        run_row.addWidget(self.ts_stop_btn)
        btn_preview = QPushButton("Show what will be sent")
        btn_preview.clicked.connect(self._ts_preview)
        run_row.addWidget(btn_preview)
        btn_copy = QPushButton("Copy answer")
        btn_copy.clicked.connect(self._ts_copy)
        run_row.addWidget(btn_copy)
        self.ts_status = QLabel("")
        self.ts_status.setWordWrap(True)
        self.ts_status.setStyleSheet("color: #555;")
        run_row.addWidget(self.ts_status, stretch=1)
        v.addLayout(run_row)

        self.ts_answer = QTextEdit()
        self.ts_answer.setReadOnly(True)
        self.ts_answer.setPlaceholderText("Ollama's answer appears here.")
        v.addWidget(self.ts_answer, stretch=1)
        self._ts_worker: QThread | None = None
        self._ts_last_answer = ""
        self._ts_partial = ""
        self._ts_thinking = 0
        self._ts_timer = QTimer(self)
        self._ts_timer.setInterval(1000)
        self._ts_timer.timeout.connect(self._ts_tick)
        self._ts_fill_models()

        other = QLabel("Other tools:")
        other.setStyleSheet("color: #555;")
        v.addWidget(other)
        actions = QHBoxLayout()
        btn_findings = QPushButton("Open Findings")
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
        self._ts_refresh_devices()
        return page

    # ---- Problems / Troubleshooting: describe → Ollama -------------------

    def _ts_device_rows(self) -> list[tuple[str, str]]:
        """(label, config path) for every device with a loaded config."""
        rows = [
            (f"{name}  —  {' · '.join(x for x in (kind, ip) if x)}", path)
            for name, kind, ip, path, ignored in loaded_config_devices(self._live_site)
            if not ignored
        ]
        if rows:
            return rows
        # No Login to Routers site yet: offer the pulled configs on disk.
        export_dir = PROJECT_ROOT / "data" / "mikrotik_exports"
        newest: dict[str, Path] = {}
        if export_dir.is_dir():
            for f in sorted(export_dir.iterdir(), key=lambda p: p.stat().st_mtime):
                if f.suffix.lower() in (".xml", ".rsc"):
                    newest[f.name.split("_", 1)[0]] = f
        out: list[tuple[str, str]] = []
        for f in newest.values():
            from pfsense_checker import device_identity

            try:
                ident = device_identity.identity_from_config(f)
            except Exception:  # noqa: BLE001
                ident = device_identity.Identity()
            parts = f.stem.split("_")
            ip = parts[1] if len(parts) > 1 else ""
            what = " ".join(x for x in (ident.vendor_name, ident.model) if x)
            detail = " · ".join(x for x in (what, ip, "pulled config") if x)
            out.append((f"{ident.hostname or f.stem}  —  {detail}", str(f)))
        return sorted(out, key=lambda r: r[0].lower())

    def _ts_refresh_devices(self) -> None:
        combo = getattr(self, "ts_device", None)
        if combo is None:
            return
        current = combo.currentData()
        combo.blockSignals(True)
        combo.clear()
        rows = self._ts_device_rows()
        for label, path in rows:
            combo.addItem(label, path)
        if not rows:
            combo.addItem("No loaded configs — Load Config on Login to Routers", "")
        idx = combo.findData(current) if current else -1
        combo.setCurrentIndex(max(idx, 0))
        combo.blockSignals(False)
        self._ts_device_changed()

    def _ts_device_changed(self, *_args) -> None:  # noqa: ANN002
        path = self.ts_device.currentData()
        keep = self.ts_iface.currentData()
        self.ts_iface.clear()
        if not path:
            return
        try:
            result = troubleshoot.load_result(path)
            choices = troubleshoot.interface_choices(result)
        except Exception as exc:  # noqa: BLE001
            self.ts_status.setText(f"Could not read that config: {exc}")
            return
        for c in choices:
            self.ts_iface.addItem(c.label, c.key)
        idx = self.ts_iface.findData(keep) if keep else -1
        self.ts_iface.setCurrentIndex(idx if idx >= 0 else (1 if len(choices) > 1 else 0))

    def _ts_fill_models(self) -> None:
        url, model = ai.load_ollama_settings()
        self.ts_model.clear()
        self.ts_model.addItem(model)
        if not ai.is_ollama_enabled():
            self.ts_ollama_lbl.setText("Ollama is turned off in Setup → Ollama.")
            return
        try:
            names = ai.list_ollama_models(url, timeout=2)
        except Exception as exc:  # noqa: BLE001
            self.ts_ollama_lbl.setText(f"{url}: not reachable ({exc})")
            return
        for name in names:
            if self.ts_model.findText(name) < 0:
                self.ts_model.addItem(name)
        self.ts_ollama_lbl.setText(f"{url} · {len(names)} model(s)")

    def _ts_inputs(self):  # noqa: ANN202
        """(result, peers, iface, problem key, notes) or None with a status message."""
        path = self.ts_device.currentData()
        if not path:
            self.ts_status.setText("Pick a device with a loaded config first.")
            return None
        try:
            result = troubleshoot.load_result(path)
        except Exception as exc:  # noqa: BLE001
            self.ts_status.setText(f"Could not read that config: {exc}")
            return None
        peers = []
        for i in range(self.ts_device.count()):
            other = self.ts_device.itemData(i)
            if other and other != path:
                try:
                    peers.append(troubleshoot.load_result(other))
                except Exception:  # noqa: BLE001, S112
                    continue
        return (result, peers, self.ts_iface.currentData() or "",
                self.ts_problem.currentData(), self.ts_notes.toPlainText())

    def _ts_context(self) -> tuple[str, str, str] | None:
        got = self._ts_inputs()
        if got is None:
            return None
        result, peers, iface, problem, notes = got
        context = troubleshoot.build_context(result, iface, problem, notes, peers=peers)
        return context, iface, problem

    def _ts_preview(self) -> None:
        built = self._ts_context()
        if built is None:
            return
        context, iface, problem = built
        dlg = QDialog(self)
        dlg.setWindowTitle("What will be sent to Ollama")
        dlg.resize(1000, 750)
        lay = QVBoxLayout(dlg)
        note = QLabel(
            f"{len(context):,} characters · question: {troubleshoot.question_for(problem, iface)}"
        )
        note.setWordWrap(True)
        lay.addWidget(note)
        text = QPlainTextEdit(context)
        text.setReadOnly(True)
        text.setFont(QFont("Consolas", 9))
        lay.addWidget(text, stretch=1)
        close = QPushButton("Close")
        close.clicked.connect(dlg.accept)
        lay.addWidget(close, alignment=Qt.AlignmentFlag.AlignRight)
        dlg.exec()

    def _ts_ask(self) -> None:
        if self._ts_worker is not None and self._ts_worker.isRunning():
            return
        if not ai.is_ollama_enabled():
            self.ts_status.setText("Ollama is turned off in Setup → Ollama.")
            return
        model = self.ts_model.currentText().strip()
        if not model:
            self.ts_status.setText("Pick an Ollama model.")
            return
        built = self._ts_context()
        if built is None:
            return
        context, iface, problem = built
        url, _ = ai.load_ollama_settings()
        worker = _TroubleshootWorker(
            context, problem, iface, url=url, model=model, think=self.ts_think.isChecked()
        )
        worker.done.connect(self._ts_done)
        worker.failed.connect(self._ts_failed)
        worker.partial.connect(self._ts_on_partial)
        worker.thinking.connect(self._ts_on_thinking)
        self._ts_worker = worker
        self._ts_started = datetime.now()
        self._ts_partial = ""
        self._ts_thinking = 0
        self._ts_asking = (model, len(context))
        self.ts_ask_btn.setEnabled(False)
        self.ts_stop_btn.setEnabled(True)
        self.ts_answer.clear()
        self._ts_timer.start()
        self._ts_tick()
        app_log.get_logger("troubleshoot").info(
            "Ask Ollama: device=%s iface=%s problem=%s model=%s chars=%d",
            self.ts_device.currentText(), iface or "(device)", problem, model, len(context),
        )
        worker.start()

    def _ts_elapsed(self) -> str:
        secs = (datetime.now() - getattr(self, "_ts_started", datetime.now())).total_seconds()
        return f"{secs:.0f} s"

    def _ts_tick(self) -> None:
        model, chars = getattr(self, "_ts_asking", ("", 0))
        if self._ts_partial:
            what = "writing the answer"
        elif self._ts_thinking:
            what = f"thinking ({self._ts_thinking} steps)"
        else:
            what = f"loading the model and reading {chars:,} characters of config"
        self.ts_status.setText(f"{model}: {what}… {self._ts_elapsed()}")
        if self._ts_partial:
            bar = self.ts_answer.verticalScrollBar()
            at_end = bar.value() >= bar.maximum() - 4
            self.ts_answer.setMarkdown(self._ts_partial)
            if at_end:
                bar.setValue(bar.maximum())

    def _ts_on_partial(self, text: str) -> None:
        self._ts_partial = text

    def _ts_on_thinking(self, count: int) -> None:
        self._ts_thinking = count

    def _ts_stop(self) -> None:
        if self._ts_worker is not None and self._ts_worker.isRunning():
            self._ts_worker.stop()
            self.ts_stop_btn.setEnabled(False)
            self.ts_status.setText("Stopping…")

    def _ts_finish(self) -> None:
        self._ts_timer.stop()
        self.ts_ask_btn.setEnabled(True)
        self.ts_stop_btn.setEnabled(False)

    def _ts_done(self, reply: str) -> None:
        self._ts_finish()
        self._ts_last_answer = reply
        self.ts_answer.setMarkdown(reply)
        self.ts_status.setText(f"Answered by {self.ts_model.currentText()} in {self._ts_elapsed()}.")

    def _ts_failed(self, error: str) -> None:
        self._ts_finish()
        if self._ts_partial:
            self._ts_last_answer = self._ts_partial
            self.ts_answer.setMarkdown(self._ts_partial)
        self.ts_status.setText(f"Ollama stopped after {self._ts_elapsed()}: {error}")
        app_log.get_logger("troubleshoot").warning("Ollama failed: %s", error)

    def _ts_copy(self) -> None:
        from PySide6.QtGui import QGuiApplication

        if self._ts_last_answer:
            QGuiApplication.clipboard().setText(self._ts_last_answer)
            self.ts_status.setText("Answer copied.")

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

    # ----------------------------------------------------------- Logs

    current_login_session_id: int | None = None

    def _build_login_history(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("Login History")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        blurb = QLabel(
            "Every sign-in to NetCheck: who, from which computer and address, when, and for "
            "how long. Refused attempts are listed too — the name only when it is a real "
            "account. Kept in the netcheck database; no passwords are stored."
        )
        blurb.setWordWrap(True)
        blurb.setStyleSheet("color: #555;")
        v.addWidget(blurb)
        row = QHBoxLayout()
        btn = QPushButton("Refresh")
        btn.clicked.connect(self._refresh_login_history)
        row.addWidget(btn)
        self.login_hist_failed = QCheckBox("Show failed attempts")
        self.login_hist_failed.setChecked(True)
        self.login_hist_failed.toggled.connect(self._refresh_login_history)
        row.addWidget(self.login_hist_failed)
        self.login_hist_summary = QLabel("")
        self.login_hist_summary.setStyleSheet("color: #555;")
        row.addWidget(self.login_hist_summary, stretch=1)
        v.addLayout(row)
        self.login_hist_table = QTableWidget(0, 8)
        self.login_hist_table.setHorizontalHeaderLabels(
            ["User", "Result", "IP address", "Computer", "Signed in", "Signed out", "Duration", "How it ended"]
        )
        self.login_hist_table.verticalHeader().setVisible(False)
        self.login_hist_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.login_hist_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.login_hist_table.setAlternatingRowColors(True)
        self.login_hist_table.horizontalHeader().setStretchLastSection(True)
        for col, width in enumerate((120, 80, 120, 150, 150, 150, 90)):
            self.login_hist_table.setColumnWidth(col, width)
        v.addWidget(self.login_hist_table, stretch=1)
        self._refresh_login_history()
        return page

    def _refresh_login_history(self, *_args) -> None:  # noqa: ANN002
        from pfsense_checker import login_history as lh

        table = getattr(self, "login_hist_table", None)
        if table is None:
            return
        try:
            records = lh.list_sessions()
        except Exception as exc:  # noqa: BLE001
            table.setRowCount(0)
            self.login_hist_summary.setText(f"Login history unavailable: {exc}")
            return
        if not self.login_hist_failed.isChecked():
            records = [r for r in records if r.outcome == lh.OUTCOME_SUCCESS]
        now = datetime.now(timezone.utc)

        def local(ts) -> str:  # noqa: ANN001
            return ts.astimezone().strftime("%Y-%m-%d %H:%M:%S") if ts else ""

        table.setRowCount(len(records))
        for r, rec in enumerate(records):
            mine = rec.id == self.current_login_session_id
            cells = [
                rec.username,
                "OK" if rec.outcome == lh.OUTCOME_SUCCESS else "Refused",
                rec.client_ip,
                rec.client_host,
                local(rec.started_at),
                local(rec.ended_at) if rec.ended_at else ("—" if rec.active(now) else local(rec.last_seen_at)),
                lh.format_duration(rec.duration(now)),
                ("this session · " if mine else "") + rec.how_it_ended(now),
            ]
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if rec.outcome != lh.OUTCOME_SUCCESS:
                    item.setForeground(QColor("#c62828"))
                elif rec.active(now):
                    item.setForeground(QColor("#2e7d32"))
                if mine:
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)
                table.setItem(r, c, item)
        ok = [x for x in records if x.outcome == lh.OUTCOME_SUCCESS]
        failed = len(records) - len(ok)
        active = sum(1 for x in ok if x.active(now))
        self.login_hist_summary.setText(
            f"{len(ok)} sign-in(s), {active} active now"
            + (f", {failed} refused attempt(s)" if failed else "")
            + (" (latest 500)" if len(records) >= 500 else "")
        )

    def _security_page(self, title_text: str, cards: list[tuple[str, str]]) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel(title_text)
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        for heading, body in cards:
            v.addWidget(_section_card(heading, body))
        v.addStretch(1)
        return page

    def _build_security_holes(self) -> QWidget:
        """Security Holes: open services, firewall gaps, known vulnerabilities, old software, weak logins."""
        from pfsense_checker.security_holes_page import SecurityHolesPage

        def seen() -> list:
            session = getattr(self, "session", None)  # the Login to Routers screen, once it has been opened
            return session.seen_devices() if session is not None else []

        self.security_holes = SecurityHolesPage(site=lambda: self._live_site, seen=seen)
        return self.security_holes

    def _build_pentesting(self) -> QWidget:
        return self._security_page(
            "Pentesting",
            [
                (
                    "What this section is for",
                    "Active, authorised tests against your own network: confirm "
                    "that what the configs claim is blocked really is blocked, "
                    "from a chosen source VLAN to a chosen target.",
                ),
                (
                    "Scope and authorisation",
                    "Tests will only run against subnets and devices on this "
                    "site, after you confirm the scope for each run, and every "
                    "run is logged. Some defences react to tests — pfSense "
                    "sshguard blocked this PC after repeated SSH probes — so "
                    "test windows should be agreed with whoever runs the network.",
                ),
                ("Status", "Not built yet — no tests run from this page."),
            ],
        )

    def _build_log_analysis(self) -> QWidget:
        """Logs → Log Analysis: drop log files in for a summary (log_analysis_page.py)."""
        from pfsense_checker.log_analysis_page import LogAnalysisPage

        self.log_analysis = LogAnalysisPage(site=lambda: self._live_site)
        return self.log_analysis

    def _build_device_logs(self) -> QWidget:
        """Logs → Device Logs: automatic router log downloads over SSH."""
        from pfsense_checker import device_logs as dl

        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("Device Logs")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        blurb = QLabel(
            "Router logs downloaded over SSH from every pfSense / OPNsense and MikroTik with SSH "
            "set up on Login to Routers: pfSense's /var/log files (system, filter, DHCP, auth, "
            "OpenVPN, gateways…) and MikroTik's log. Only what is new is fetched each time, with "
            "one login per device. Files are kept in data/device_logs/<device>/<date>/, and each "
            "download is listed in the database."
        )
        blurb.setWordWrap(True)
        blurb.setStyleSheet("color: #555;")
        v.addWidget(blurb)

        mgr = self.device_logs
        row = QHBoxLayout()
        self.dlog_enabled = QCheckBox("Download automatically every")
        self.dlog_enabled.setChecked(mgr.settings.enabled)
        row.addWidget(self.dlog_enabled)
        self.dlog_hours = QSpinBox()
        self.dlog_hours.setRange(1, 168)
        self.dlog_hours.setSuffix(" hours")
        self.dlog_hours.setValue(mgr.settings.hours)
        row.addWidget(self.dlog_hours)
        self.dlog_connect = QCheckBox("and after each Connect / Load Config")
        self.dlog_connect.setChecked(mgr.settings.on_connect)
        row.addWidget(self.dlog_connect)
        row.addStretch(1)
        v.addLayout(row)

        def save() -> None:
            mgr.apply_settings(dl.LogSettings(self.dlog_enabled.isChecked(), self.dlog_hours.value(),
                                              self.dlog_connect.isChecked()))
            self._dlog_refresh()

        for w in (self.dlog_enabled, self.dlog_connect):
            w.toggled.connect(lambda _on: save())
        self.dlog_hours.valueChanged.connect(lambda _v: save())

        btns = QHBoxLayout()
        now_btn = QPushButton("Download now")
        now_btn.setToolTip("Fetch new log lines from every eligible device now")
        now_btn.clicked.connect(lambda: (mgr.run_all("manual"), self._dlog_refresh()))
        btns.addWidget(now_btn)
        folder_btn = QPushButton("Open log folder")
        folder_btn.clicked.connect(self._dlog_open_folder)
        btns.addWidget(folder_btn)
        btns.addStretch(1)
        v.addLayout(btns)
        self.dlog_status = QLabel()
        self.dlog_status.setWordWrap(True)
        self.dlog_status.setStyleSheet("color: #37474f;")
        v.addWidget(self.dlog_status)

        self.dlog_table = QTableWidget(0, 6)
        self.dlog_table.setHorizontalHeaderLabels(["When", "Device", "Log", "New lines", "Bytes", "Trigger"])
        self.dlog_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.dlog_table.horizontalHeader().setStretchLastSection(True)
        self.dlog_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.dlog_table.setToolTip("Double-click a row to open that log file")
        self.dlog_table.cellDoubleClicked.connect(self._dlog_open_row)
        v.addWidget(self.dlog_table, 1)
        mgr.device_done.connect(lambda _r: self._dlog_refresh())
        mgr.status.connect(lambda text: self.dlog_status.setText(text))
        self._dlog_refresh()
        return page

    def _dlog_refresh(self) -> None:
        from pfsense_checker import device_logs as dl

        if not hasattr(self, "dlog_table"):
            return
        mgr = self.device_logs
        devices = [d.name for d in getattr(self._live_site, "devices", []) or [] if dl.eligible(d)]
        last = mgr.last_scheduled_run() or "not yet"
        where = ", ".join(devices) if devices else "none yet (set up SSH on Login to Routers)"
        if not self.dlog_status.text() or not mgr.busy():
            text = f"Devices: {where}. Last scheduled run: {last}."
            held = mgr.paused_devices()
            if held:  # a login failed there: no automatic retries (firewalls block repeated failures)
                text += ("\nPaused after a failed login, not tried automatically: "
                         + "; ".join(f"{n} — {why}" for n, why in held.items())
                         + ". Fix the login, then Connect to it on Login to Routers to resume.")
            self.dlog_status.setText(text)
        try:
            rows = [(str(r[0])[:19], r[1], r[2], r[3], r[4], r[5], r[6]) for r in dl.recent_index(200)]
        except Exception:  # noqa: BLE001 - database offline: this session's downloads
            rows = [(datetime.fromtimestamp(r.started).strftime("%Y-%m-%d %H:%M:%S"), r.device, c.log,
                     c.lines, c.bytes, r.source, c.path) for r in mgr.history for c in r.chunks]
        t = self.dlog_table
        t.setRowCount(len(rows))
        for i, (when, dev, log, lines, size, source, path) in enumerate(rows):
            for j, val in enumerate((when, dev, log, lines, size, source)):
                item = QTableWidgetItem(str(val))
                item.setData(Qt.ItemDataRole.UserRole, path)
                t.setItem(i, j, item)

    def _dlog_open_folder(self) -> None:
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices

        from pfsense_checker import device_logs as dl

        dl.LOG_ROOT.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(dl.LOG_ROOT)))

    def _dlog_open_row(self, row: int, _col: int) -> None:
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices

        item = self.dlog_table.item(row, 0)
        path = item.data(Qt.ItemDataRole.UserRole) if item else ""
        if path and Path(path).is_file():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _build_dns_leakage(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        title = QLabel("DNS Leakage")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        blurb = QLabel(
            "Where DNS from each VLAN really goes. Build the test package, run it on a computer "
            "in each VLAN (it picks the VLAN from its own address), and open the reports here — "
            "or run it on this PC. It checks the resolvers the computer uses, whether plain DNS "
            "to public resolvers gets out, is blocked or is redirected to your resolver, "
            "DNS-over-TLS / DNS-over-HTTPS, the Firefox DoH canary, and where DNS leaves from."
        )
        blurb.setWordWrap(True)
        blurb.setStyleSheet("color: #555;")
        v.addWidget(blurb)

        build = QGroupBox("1. Build the test package")
        bl = QVBoxLayout(build)
        src_row = QHBoxLayout()
        src_row.addWidget(QLabel("VLANs from:"))
        self.dl_source = QComboBox()
        self.dl_source.setMinimumWidth(420)
        self.dl_source.currentIndexChanged.connect(self._dl_source_changed)
        src_row.addWidget(self.dl_source, stretch=1)
        btn_src = QPushButton("Refresh")
        btn_src.clicked.connect(self._dl_refresh_sources)
        src_row.addWidget(btn_src)
        bl.addLayout(src_row)
        self.dl_profiles = QTableWidget(0, 4)
        self.dl_profiles.setHorizontalHeaderLabels(["VLAN / interface", "Subnet", "Expected resolver(s)", "From"])
        self.dl_profiles.verticalHeader().setVisible(False)
        self.dl_profiles.horizontalHeader().setStretchLastSection(True)
        for col, width in enumerate((300, 140, 200)):
            self.dl_profiles.setColumnWidth(col, width)
        self.dl_profiles.setToolTip("Untick a row to leave that VLAN out. Expected resolvers can be edited.")
        self.dl_profiles.setMinimumHeight(160)
        bl.addWidget(self.dl_profiles)
        eg_row = QHBoxLayout()
        eg_row.addWidget(QLabel("Expected DNS egress (optional):"))
        self.dl_egress = QLineEdit()
        self.dl_egress.setPlaceholderText(
            "public IPs DNS should leave from, e.g. your VPN exit — blank = just report it"
        )
        eg_row.addWidget(self.dl_egress, stretch=1)
        bl.addLayout(eg_row)
        b_row = QHBoxLayout()
        btn_build = QPushButton("Build package…")
        btn_build.setStyleSheet(_primary_btn())
        btn_build.clicked.connect(self._dl_build)
        b_row.addWidget(btn_build)
        self.dl_build_status = QLabel("")
        self.dl_build_status.setWordWrap(True)
        self.dl_build_status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        b_row.addWidget(self.dl_build_status, stretch=1)
        bl.addLayout(b_row)
        v.addWidget(build)

        res = QGroupBox("2. Results")
        rl = QVBoxLayout(res)
        r_row = QHBoxLayout()
        self.dl_run_btn = QPushButton("Run on this PC")
        self.dl_run_btn.setToolTip("Run the same test from this computer, using the VLAN profiles above")
        self.dl_run_btn.clicked.connect(self._dl_run_here)
        r_row.addWidget(self.dl_run_btn)
        btn_open = QPushButton("Open reports…")
        btn_open.clicked.connect(self._dl_open_reports)
        r_row.addWidget(btn_open)
        btn_clear = QPushButton("Clear")
        btn_clear.clicked.connect(lambda: self.dl_results.clear())
        r_row.addWidget(btn_clear)
        self.dl_run_status = QLabel("")
        self.dl_run_status.setWordWrap(True)
        r_row.addWidget(self.dl_run_status, stretch=1)
        rl.addLayout(r_row)
        self.dl_results = QTreeWidget()
        self.dl_results.setHeaderLabels(["Computer / check", "Result", "Detail", "Fix"])
        for col, width in enumerate((330, 70, 520)):
            self.dl_results.setColumnWidth(col, width)
        self.dl_results.setWordWrap(True)
        self.dl_results.setAlternatingRowColors(False)
        rl.addWidget(self.dl_results, stretch=1)
        v.addWidget(res, stretch=1)
        self._dl_worker: QThread | None = None
        self._dl_refresh_sources()
        return page

    # ---- DNS Leakage ------------------------------------------------------

    _DL_COLOURS = {"pass": "#c8e6c9", "warn": "#fff3cd", "fail": "#ffcdd2", "info": "#e3f2fd", "skip": "#eeeeee"}

    def _dl_refresh_sources(self) -> None:
        current = self.dl_source.currentData()
        self.dl_source.blockSignals(True)
        self.dl_source.clear()
        rows = self._ts_device_rows()
        for label, path in rows:
            self.dl_source.addItem(label, path)
        if not rows:
            self.dl_source.addItem("No loaded configs — Load Config on Login to Routers", "")
        # Firewalls first: they usually hold the per-VLAN resolver.
        idx = self.dl_source.findData(current) if current else -1
        if idx < 0:
            idx = next((i for i in range(self.dl_source.count())
                        if "pfsense" in self.dl_source.itemText(i).lower()
                        or "opnsense" in self.dl_source.itemText(i).lower()), 0)
        self.dl_source.setCurrentIndex(idx)
        self.dl_source.blockSignals(False)
        self._dl_source_changed()

    def _dl_source_changed(self, *_args) -> None:  # noqa: ANN002
        from pfsense_checker import dns_leak_builder

        table = self.dl_profiles
        table.setRowCount(0)
        path = self.dl_source.currentData()
        if not path:
            return
        try:
            profiles = dns_leak_builder.profiles_from_config(troubleshoot.load_result(path))
        except Exception as exc:  # noqa: BLE001
            self.dl_build_status.setText(f"Could not read that config: {exc}")
            return
        table.setRowCount(len(profiles))
        for r, p in enumerate(profiles):
            first = QTableWidgetItem(p["label"])
            first.setFlags(first.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            first.setCheckState(Qt.CheckState.Checked)
            table.setItem(r, 0, first)
            for c, text in ((1, p["subnet"]), (3, p.get("source", ""))):
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                table.setItem(r, c, item)
            exp = QTableWidgetItem(", ".join(p["expected_resolvers"]))
            if not p["expected_resolvers"]:
                exp.setBackground(QColor("#fff3cd"))
            table.setItem(r, 2, exp)

    def _dl_profiles(self) -> list[dict]:
        from pfsense_checker import dns_leak_builder

        out = []
        t = self.dl_profiles
        for r in range(t.rowCount()):
            first = t.item(r, 0)
            if first is None or first.checkState() != Qt.CheckState.Checked:
                continue
            out.append({
                "label": first.text(),
                "subnet": t.item(r, 1).text() if t.item(r, 1) else "",
                "expected_resolvers": dns_leak_builder._ips(  # noqa: SLF001
                    dns_leak_builder._split(t.item(r, 2).text() if t.item(r, 2) else "")  # noqa: SLF001
                ),
            })
        return out

    def _dl_egress_list(self) -> list[str]:
        from pfsense_checker import dns_leak_builder

        return dns_leak_builder._ips(dns_leak_builder._split(self.dl_egress.text()))  # noqa: SLF001

    def _dl_build(self) -> None:
        from pfsense_checker import dns_leak_builder

        profiles = self._dl_profiles()
        if not profiles:
            self.dl_build_status.setText("Tick at least one VLAN.")
            return
        default = PROJECT_ROOT / "data" / "dnsleak_packages"
        folder = QFileDialog.getExistingDirectory(self, "Save the DNS leak test package in", str(default))
        if not folder:
            return
        site = self.dl_source.currentText().split("  —  ")[0]
        try:
            path = dns_leak_builder.build_package(
                folder, profiles, site=site, expected_egress=self._dl_egress_list()
            )
        except Exception as exc:  # noqa: BLE001
            self.dl_build_status.setText(f"Build failed: {exc}")
            return
        self.dl_build_status.setText(
            f"Built {path} — {len(profiles)} VLAN profile(s). Copy it to a computer in each "
            "VLAN, unzip, run run_dns_leak.cmd (Windows) or run_dns_leak.sh."
        )
        app_log.get_logger("dns_leak").info("Built DNS leak package %s (%d profiles)", path, len(profiles))

    def _dl_run_here(self) -> None:
        if self._dl_worker is not None and self._dl_worker.isRunning():
            return
        config = {
            "site": self.dl_source.currentText().split("  —  ")[0],
            "profiles": self._dl_profiles(),
            "expected_egress": self._dl_egress_list(),
        }
        worker = _DnsLeakWorker(config)
        worker.done.connect(self._dl_run_done)
        worker.failed.connect(self._dl_run_failed)
        self._dl_worker = worker
        self.dl_run_btn.setEnabled(False)
        self.dl_run_status.setText("Testing DNS from this PC… (about 20 seconds)")
        worker.start()

    def _dl_run_done(self, report: dict) -> None:
        from pfsense_checker import dns_leak

        self.dl_run_btn.setEnabled(True)
        try:
            path = dns_leak.save_report(report, PROJECT_ROOT / "data" / "dnsleak_results")
            saved = f" Saved {path.name}."
        except OSError as exc:
            saved = f" Not saved: {exc}"
        self.dl_run_status.setText(f"Done in {report.get('seconds')} s: {report.get('result', '').upper()}.{saved}")
        self._dl_add_report(report)

    def _dl_run_failed(self, error: str) -> None:
        self.dl_run_btn.setEnabled(True)
        self.dl_run_status.setText(f"Test failed: {error}")

    def _dl_open_reports(self) -> None:
        from pfsense_checker import dns_leak_builder

        paths, _ = QFileDialog.getOpenFileNames(
            self, "Open DNS leak reports", str(PROJECT_ROOT / "data" / "dnsleak_results"),
            "DNS leak reports (*.json)",
        )
        bad = []
        for p in paths:
            try:
                self._dl_add_report(dns_leak_builder.load_report(p))
            except (OSError, ValueError) as exc:
                bad.append(f"{Path(p).name}: {exc}")
        if bad:
            self.dl_run_status.setText("Skipped: " + "; ".join(bad))
        elif paths:
            self.dl_run_status.setText(f"Opened {len(paths)} report(s).")

    def _dl_add_report(self, report: dict) -> None:
        when = str(report.get("started", ""))[:19].replace("T", " ")
        top = QTreeWidgetItem([
            f"{report.get('host', '?')} · {report.get('label', '?')} {report.get('subnet', '')}".strip(),
            str(report.get("result", "")).upper(),
            f"{when} UTC · {report.get('os', '')} · addresses {', '.join(report.get('addresses', []))} · "
            f"resolvers {', '.join(report.get('resolvers', [])) or '?'}",
            "",
        ])
        font = top.font(0)
        font.setBold(True)
        top.setFont(0, font)
        colour = QColor(self._DL_COLOURS.get(report.get("result", ""), "#ffffff"))
        top.setBackground(1, colour)
        for c in report.get("checks", []):
            child = QTreeWidgetItem([c.get("title", ""), c.get("status", "").upper(), c.get("detail", ""),
                                     c.get("fix", "")])
            child.setBackground(1, QColor(self._DL_COLOURS.get(c.get("status", ""), "#ffffff")))
            child.setToolTip(2, c.get("detail", ""))
            child.setToolTip(3, c.get("fix", ""))
            top.addChild(child)
        self.dl_results.insertTopLevelItem(0, top)
        top.setExpanded(True)

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
                "Live logs from pfSense and MikroTik",
                "One receiver for everything the routers send: RFC 3164 / RFC 5424 "
                "syslog over UDP, and a newline-delimited log file over TCP. Send "
                "logs here has what to enter on pfSense and the commands for a "
                "MikroTik. pfSense filter lines are shown in plain words. Lines are "
                "shown, never executed. UDP/514 usually needs Administrator on "
                "Windows, so use a high port such as 59000 or 5514.",
            )
        )

        from pfsense_checker import log_pipeline
        from pfsense_checker.mikrotik_log_box import MikrotikLogBox

        # Log Pipeline was a second receiver on its own port: carry that port over, once.
        merged_note = log_pipeline.merge_into_syslog()
        settings = syslog_recv.load_settings()
        self.syslog_tabs = QTabWidget()
        msg_tab, set_tab, send_tab = QWidget(), QWidget(), QWidget()
        msg_l, set_l, send_l = QVBoxLayout(msg_tab), QVBoxLayout(set_tab), QVBoxLayout(send_tab)
        self.syslog_tabs.addTab(msg_tab, "Messages")
        self.syslog_tabs.addTab(set_tab, "Settings")
        self.syslog_tabs.addTab(send_tab, "Send logs here")
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

        set_l.addWidget(box)

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
        send_l.addWidget(dest)
        self.syslog_mikrotik = MikrotikLogBox(
            site=lambda: self._live_site,
            bind=self._syslog_current_bind_host,
            port=settings.udp_port,
        )
        self.syslog_udp_port.valueChanged.connect(self.syslog_mikrotik.set_port)
        self.syslog_mikrotik.copied.connect(self._syslog_note)
        send_l.addWidget(self.syslog_mikrotik)
        send_l.addStretch(1)

        src_row = QHBoxLayout()
        src_row.addWidget(QLabel("Attached sources:"))
        self.syslog_sources = QLabel("—")
        self.syslog_sources.setWordWrap(True)
        self.syslog_sources.setStyleSheet("color: #555;")
        src_row.addWidget(self.syslog_sources, stretch=1)
        set_l.addLayout(src_row)
        set_l.addStretch(1)

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
        if merged_note:
            self._syslog_note(merged_note)
        v.addWidget(self.syslog_tabs, stretch=1)

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
        msg_l.addLayout(filt)

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
        msg_l.addWidget(self.syslog_table, stretch=1)
        self._syslog_ai_workers: list[QThread] = []

        self._syslog_receiver: syslog_recv.SyslogReceiver | None = None
        self._syslog_buffer = syslog_recv.SyslogBuffer(settings.memory_lines)
        self._syslog_saved_bind = settings.bind_host
        self._syslog_fill_iface_combo()
        self.syslog_bind.currentIndexChanged.connect(self._syslog_refresh_listen_hint)
        self.syslog_bind.currentIndexChanged.connect(lambda _i: self.syslog_mikrotik.refresh())
        self.syslog_mikrotik.refresh()  # the adapter list is filled now: follow the one it is bound to
        self._syslog_refresh_sources()
        self._syslog_refresh_listen_hint()
        py_footer = QLabel(f"Running on Python {sys.version.split()[0]}")
        py_footer.setStyleSheet("color: #757575;")
        v.addWidget(py_footer)
        if settings.auto_start:
            QTimer.singleShot(0, self._syslog_start)
        return page

    def _syslog_note(self, text: str) -> None:
        """A blue line in the status label (not shown over a running listener's counters)."""
        recv = getattr(self, "_syslog_receiver", None)
        if recv is not None and recv.isRunning():
            return
        self.syslog_status.setText(text)
        self.syslog_status.setStyleSheet("color: #1565c0;")

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
        from pfsense_checker import log_pipeline

        table = self.syslog_table
        row = table.rowCount()
        table.insertRow(row)
        # A pfSense filter line is a row of comma-separated fields: show it in plain words.
        decoded = log_pipeline.filter_text(msg.raw or msg.message) if msg.accepted else ""
        values = [
            msg.received_at,
            msg.source_ip,
            self._syslog_filter_value(msg, "device"),
            msg.severity_name,
            msg.facility_name,
            msg.hostname or "—",
            msg.app_name or "—",
            (
                (decoded or msg.message)
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
            elif decoded and col == len(values) - 1:
                item.setToolTip(msg.message)  # the line as the firewall sent it
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
        self._refresh_loaded_configs()
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


class _DnsLeakWorker(QThread):
    """Run the DNS leak test from this PC off the UI thread."""

    done = Signal(dict)
    failed = Signal(str)

    def __init__(self, config: dict) -> None:
        super().__init__()
        self._config = config

    def run(self) -> None:  # noqa: D102
        from pfsense_checker import dns_leak

        try:
            report = dns_leak.run(self._config)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))
            return
        self.done.emit(report)


class _TroubleshootWorker(QThread):
    """Ask Ollama about a described problem off the UI thread."""

    done = Signal(str)
    failed = Signal(str)
    partial = Signal(str)  # answer so far
    thinking = Signal(int)  # thinking chunks so far

    def __init__(
        self, context: str, problem: str, iface: str, *, url: str, model: str, think: bool = True
    ) -> None:
        super().__init__()
        self._args = (context, problem, iface)
        self._url = url
        self._model = model
        self._think = think
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:  # noqa: D102
        try:
            reply = troubleshoot.ask(
                *self._args,
                model=self._model,
                base_url=self._url,
                think=self._think,
                on_text=self.partial.emit,
                on_thinking=self.thinking.emit,
                should_stop=lambda: self._stop,
            )
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))
            return
        self.done.emit(reply)


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
    if kind == "persist_active":
        return (
            base
            + " background-color: rgba(106, 27, 154, 220);"
            + " border: 1px solid rgb(74, 20, 140);"
            + " color: white; }"
            + "QPushButton:hover { background-color: rgba(123, 31, 162, 240); }"
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
