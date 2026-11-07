"""Qt6 GUI for comprehensive pfSense configuration checking."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

from PySide6.QtCore import QEvent, QEventLoop, QSize, Qt, QThread, QTimer, Signal
from PySide6.QtGui import (
    QAction,
    QCloseEvent,
    QColor,
    QDragEnterEvent,
    QDragMoveEvent,
    QDropEvent,
    QFont,
    QIcon,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QStackedWidget,
    QTabWidget,
    QTableWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from pfsense_checker import ai, app_log
from pfsense_checker.beacon_builder import build_bundle, default_config
from pfsense_checker.branding import (
    NAV_TREE_STYLE,
    STATUS_BAR_FAIL,
    STATUS_BAR_OK,
    STATUS_BAR_TEXT,
    render_logo_pixmap,
    status_bar_stylesheet,
    status_chip_style,
)
from pfsense_checker.busy import (
    busy_cursor,
    busy_hub,
    busy_message,
    is_busy,
    show_busy_while,
)

from pfsense_checker.checker import check_file
from pfsense_checker.discovery import infer_links, infer_links_for_site
from pfsense_checker.file_drop import FileDropRouter
from pfsense_checker.home_screen import HomeScreen
from pfsense_checker.models import CheckResult, Severity
from pfsense_checker.paths import (
    SAVED_EXPERIMENTAL_TOPOLOGY_PATH,
    SAVED_TOPOLOGY_PATH,
    ensure_data_dir,
)
from pfsense_checker.excel_layout import (
    import_physical_layout_summary,
    import_physical_layout_xlsx,
)
from pfsense_checker.resiliency import (
    DEEP_DIVE_CATEGORIES,
    ResiliencyReport,
    analyze_site,
    build_ai_context as build_resiliency_ai_context,
    enrich_report_with_ollama,
)
from pfsense_checker.routeros_rest import (
    collect_all,
    collect_export,
    probe_connection,
    save_device_credentials,
)
from pfsense_checker.topology_site import (
    CONFIG_SOURCE_MIKROTIK_REST,
    DEVICE_KINDS,
    DEVICE_MODELS,
    DEVICE_ROLES,
    LINK_KINDS,
    VPN_KINDS,
    ConfigSource,
    Device,
    EgressPath,
    Link,
    SiteBridge,
    SiteTopology,
    SiteVlan,
    VpnAgreement,
    default_ports_for_model,
    device_from_result,
    enrich_from_result,
    example_crs_site,
    kind_for_model,
    match_device_for_result,
    _csv_list,
)

CONFIG_FILE_SUFFIXES = {".xml", ".conf", ".rsc", ".routeros", ".backup"}


def _config_files_in_folder(folder: Path) -> list[Path]:
    """Return supported config files below folder in stable path order."""
    return sorted(
        (
            path
            for path in folder.rglob("*")
            if path.is_file() and path.suffix.lower() in CONFIG_FILE_SUFFIXES
        ),
        key=lambda path: str(path).casefold(),
    )
from pfsense_checker.site_canvas import SiteTopologyView
from pfsense_checker.viz import (
    COLOR_ERROR,
    COLOR_INFO,
    COLOR_MUTED,
    COLOR_OK,
    COLOR_WARN,
    KIND_COLORS,
    BarChartView,
    DonutChartView,
    KpiCard,
    TimeSeriesChartView,
    TopologyView,
    epoch_seconds,
)

SEVERITY_COLORS = {
    Severity.ERROR: QColor("#c62828"),
    Severity.WARNING: QColor("#ef6c00"),
    Severity.INFO: QColor("#1565c0"),
}
SEVERITY_BG = {
    Severity.ERROR: QColor("#ffebee"),
    Severity.WARNING: QColor("#fff3e0"),
    Severity.INFO: QColor("#e3f2fd"),
}
SEVERITY_ORDER = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.INFO: 2}


def _device_config_label(d: Device) -> str:
    src = d.ensure_config_source()
    if src is None:
        return d.notes or ""
    bits: list[str] = []
    if src.backup_artifact:
        bits.append(f"backup:{Path(src.backup_artifact).name}")
    if src.path:
        bits.append(Path(src.path).name)
    if src.host:
        bits.append(f"rest:{src.host}")
    status = src.display_status()
    if status:
        bits.append(f"[{status}]")
    if d.notes and d.notes not in " ".join(bits):
        bits.append(d.notes)
    return " · ".join(bits) if bits else (d.config_file or "")


def _table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    t.setAlternatingRowColors(True)
    t.verticalHeader().setVisible(False)
    t.horizontalHeader().setStretchLastSection(True)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    return t


def _fill(table: QTableWidget, rows: list[list[str]]) -> None:
    table.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, val in enumerate(row):
            table.setItem(r, c, QTableWidgetItem(val))
    table.resizeColumnsToContents()


class CheckWorker(QThread):
    finished_ok = Signal(object)
    failed = Signal(str)

    def __init__(self, path: Path) -> None:
        super().__init__()
        self.path = path

    def run(self) -> None:
        try:
            self.finished_ok.emit(check_file(self.path))
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class _AiWorker(QThread):
    done = Signal(str)
    failed = Signal(str)

    def __init__(
        self,
        context: str,
        question: str,
        *,
        provider: str,
        api_key: str = "",
        model: str = "",
        ollama_url: str = "",
    ) -> None:
        super().__init__()
        self._context = context
        self._question = question
        self._provider = provider
        self._api_key = api_key
        self._model = model
        self._ollama_url = ollama_url

    def run(self) -> None:
        try:
            if self._provider == "Ollama (local)":
                reply = ai.ask_ollama(
                    self._context,
                    self._question,
                    model=self._model,
                    base_url=self._ollama_url,
                    api_key=self._api_key,
                )
            else:
                reply = ai.ask_advisor(
                    self._context,
                    self._question,
                    api_key=self._api_key,
                    bot_name=self._model,
                )
            self.done.emit(reply)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("pfSense Config Checker")
        self.setAcceptDrops(True)

        self._current_path: Path | None = None
        self._worker: CheckWorker | None = None
        self._result: CheckResult | None = None
        self._live_site = SiteTopology()
        self._experimental_site = SiteTopology(name="Experimental")
        self._topology_mode = "live"  # live | experimental
        self._site = self._live_site
        self._site_path: Path | None = None
        self._experimental_path: Path | None = None
        self._resiliency: ResiliencyReport | None = None
        self._monitor_timer = QTimer(self)
        self._monitor_timer.timeout.connect(self.refresh_monitor)
        self._ollama_status_timer = QTimer(self)
        self._ollama_status_timer.timeout.connect(self._refresh_ollama_status)
        self._beacon_status_timer = QTimer(self)
        self._beacon_status_timer.timeout.connect(self._refresh_beacon_status)
        self._db_status_timer = QTimer(self)
        self._db_status_timer.timeout.connect(self._refresh_db_status)
        self._auth_username: str = ""
        self._auth_user = None
        self._context_module = "Login to Routers"
        self._context_capabilities = (
            "SSH login · LAN search · topology map · save connectivity"
        )
        self._context_action = "—"
        self._context_action_level = "neutral"  # success | problem | failed | neutral

        self._build_toolbar()
        self._build_ui()
        self._file_drop = FileDropRouter(self, self._on_files_dropped)
        self._build_statusbar()
        self._apply_startup_geometry()
        self._refresh_context_status()
        QTimer.singleShot(0, self._refresh_ollama_status)
        QTimer.singleShot(0, self._refresh_beacon_status)
        QTimer.singleShot(0, self._refresh_db_status)
        self._ollama_status_timer.start(30_000)
        self._beacon_status_timer.start(15_000)
        self._db_status_timer.start(20_000)

    def set_authenticated_user(self, user) -> None:
        """Record the signed-in user and show them on the status bar.

        Accepts an ``auth.AuthUser`` or a username string.
        """
        from pfsense_checker import auth as auth_mod

        if isinstance(user, auth_mod.AuthUser):
            self._auth_user = user
            self._auth_username = user.username
        else:
            self._auth_username = (user or "").strip()
            self._auth_user = auth_mod.AuthUser(username=self._auth_username)
        label = getattr(self, "_user_status", None)
        if label is not None:
            label.hide()
        if self._auth_username:
            from pfsense_checker import version as ver

            self.setWindowTitle(
                f"pfSense Config Checker {ver.full_version()} — {self._auth_username}"
            )
        if hasattr(self, "home_screen"):
            self.home_screen.set_current_user(self._auth_user)
        self._refresh_context_status()

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        """Shut secondary windows (console pop-out) when the main GUI closes."""
        home = getattr(self, "home_screen", None)
        if home is not None:
            closer = getattr(home, "close_console_popout", None)
            if callable(closer):
                closer()
            stop_sys = getattr(home, "stop_syslog_receiver", None)
            if callable(stop_sys):
                stop_sys()
        super().closeEvent(event)

    def _apply_startup_geometry(self) -> None:
        """Open inside the work area; maximize so the status bar stays on-screen."""
        screen = QApplication.primaryScreen()
        avail = screen.availableGeometry() if screen is not None else None
        if avail is not None:
            # Leave headroom for window chrome so the status bar is not clipped.
            width = min(1600, avail.width())
            height = min(900, max(500, avail.height() - 48))
            self.resize(width, height)
            frame = self.frameGeometry()
            frame.moveCenter(avail.center())
            self.move(
                max(avail.x(), frame.x()),
                max(avail.y(), frame.y()),
            )
        else:
            self.resize(1280, 800)
        # Fit after the native frame exists (title bar / borders).
        QTimer.singleShot(0, self._fit_to_available_desktop)

    def _fit_to_available_desktop(self) -> None:
        """Maximize within the OS work area; never cover the taskbar."""
        self._ensure_status_bar_visible()
        if not self.isMaximized():
            self.showMaximized()
        self._sync_max_button()
        QTimer.singleShot(0, self._clamp_frame_to_available)

    def _ensure_status_bar_visible(self) -> None:
        """Status bar must remain visible and keep a reserved height."""
        sb = self.statusBar()
        sb.setVisible(True)
        sb.show()
        if sb.minimumHeight() < 28:
            sb.setMinimumHeight(28)

    def _clamp_frame_to_available(self) -> None:
        """If the outer frame spills past the work area, shrink/move it back."""
        self._ensure_status_bar_visible()
        if self.isMaximized():
            # Maximized should already respect the work area on Windows.
            # If the status bar was still clipped, fall back to a manual fit.
            screen = self.screen() or QApplication.primaryScreen()
            if screen is None:
                return
            avail = screen.availableGeometry()
            frame = self.frameGeometry()
            if frame.bottom() <= avail.bottom() and frame.height() <= avail.height():
                return
            self.showNormal()
        screen = self.screen() or QApplication.primaryScreen()
        if screen is None:
            return
        avail = screen.availableGeometry()
        frame = self.frameGeometry()
        chrome_w = max(0, frame.width() - self.width())
        chrome_h = max(0, frame.height() - self.height())
        target_w = min(self.width(), max(640, avail.width() - chrome_w))
        target_h = min(self.height(), max(480, avail.height() - chrome_h))
        if target_w != self.width() or target_h != self.height():
            self.resize(target_w, target_h)
        frame = self.frameGeometry()
        x = frame.x()
        y = frame.y()
        if frame.right() > avail.right():
            x = avail.right() - frame.width() + 1
        if frame.bottom() > avail.bottom():
            y = avail.bottom() - frame.height() + 1
        if frame.left() < avail.left():
            x = avail.left()
        if frame.top() < avail.top():
            y = avail.top()
        if (x, y) != (frame.x(), frame.y()):
            self.move(x, y)
        self._ensure_status_bar_visible()

    def _toggle_maximize(self) -> None:
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()
        self._sync_max_button()
        QTimer.singleShot(0, self._clamp_frame_to_available)

    def _build_toolbar(self) -> None:
        tb = self.addToolBar("Main")
        tb.setMovable(False)
        tb.setIconSize(QSize(120, 32))

        from pfsense_checker.branding import render_logo_pixmap

        logo_pix = render_logo_pixmap(width=160)
        if logo_pix is not None:
            logo = QLabel()
            logo.setPixmap(
                logo_pix.scaledToWidth(110, Qt.TransformationMode.SmoothTransformation)
            )
            logo.setToolTip("NetCheck")
            logo.setContentsMargins(4, 2, 10, 2)
            tb.addWidget(logo)
            tb.addSeparator()

        home_action = QAction("Home…", self)
        home_action.setToolTip(
            "Back to the home GUI (File / Folder Ops holds Open Config, "
            "Open Folder, Re-check, Export)"
        )
        home_action.triggered.connect(self.show_home_screen)
        tb.addAction(home_action)

        # File shortcuts stay global; buttons live under File / Folder Ops.
        open_action = QAction("Open Config…", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_file)
        self.addAction(open_action)

        open_folder_action = QAction("Open Folder…", self)
        open_folder_action.setShortcut("Ctrl+Shift+O")
        open_folder_action.setToolTip(
            "Import all supported configs in a folder into the topology"
        )
        open_folder_action.triggered.connect(self.open_folder)
        self.addAction(open_folder_action)

        self.recheck_action = QAction("Re-check", self)
        self.recheck_action.setShortcut("F5")
        self.recheck_action.setEnabled(False)
        self.recheck_action.triggered.connect(self.recheck)
        self.addAction(self.recheck_action)

        export_action = QAction("Export Report…", self)
        export_action.setShortcut("Ctrl+S")
        export_action.triggered.connect(self.export_report)
        self.addAction(export_action)

        spacer = QWidget()
        spacer.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        tb.addWidget(spacer)

        win_style = (
            "QPushButton {"
            " min-width: 36px; max-width: 36px;"
            " min-height: 26px; max-height: 26px;"
            " padding: 0;"
            " font-size: 14px;"
            " border: 1px solid #bbb;"
            " border-radius: 3px;"
            " background: #f5f5f5;"
            "}"
            "QPushButton:hover { background: #e8e8e8; }"
            "QPushButton#winClose:hover {"
            " background: #e53935; color: white; border-color: #c62828;"
            "}"
        )
        win_row = QWidget()
        win_lay = QHBoxLayout(win_row)
        win_lay.setContentsMargins(4, 0, 6, 0)
        win_lay.setSpacing(4)

        btn_min = QPushButton("─")
        btn_min.setToolTip("Minimize")
        btn_min.setStyleSheet(win_style)
        btn_min.clicked.connect(self.showMinimized)
        win_lay.addWidget(btn_min)

        self._btn_max = QPushButton("□")
        self._btn_max.setToolTip("Maximize")
        self._btn_max.setStyleSheet(win_style)
        self._btn_max.clicked.connect(self._toggle_maximize)
        win_lay.addWidget(self._btn_max)

        btn_close = QPushButton("×")
        btn_close.setObjectName("winClose")
        btn_close.setToolTip("Close")
        btn_close.setStyleSheet(win_style)
        btn_close.clicked.connect(self.close)
        win_lay.addWidget(btn_close)

        tb.addWidget(win_row)
        self._sync_max_button()

    def _sync_max_button(self) -> None:
        if not hasattr(self, "_btn_max"):
            return
        if self.isMaximized():
            self._btn_max.setText("❐")
            self._btn_max.setToolTip("Restore")
        else:
            self._btn_max.setText("□")
            self._btn_max.setToolTip("Maximize")

    def changeEvent(self, event) -> None:  # type: ignore[override]
        if event.type() == QEvent.Type.WindowStateChange:
            self._sync_max_button()
            QTimer.singleShot(0, self._clamp_frame_to_available)
        super().changeEvent(event)

    def _build_ui(self) -> None:
        self._stack = QStackedWidget()
        self.setCentralWidget(self._stack)

        # Page 0: home hub (feature sections)
        self.home_screen = HomeScreen()
        self.home_screen.open_workspace.connect(self._enter_workspace)
        self.home_screen.load_site_requested.connect(self._home_load_topology)
        self.home_screen.save_topology_requested.connect(self._home_save_topology)
        self.home_screen.load_live_topology_requested.connect(self._home_load_live_topology)
        self.home_screen.save_live_topology_requested.connect(self._home_save_live_topology)
        self.home_screen.open_folder_requested.connect(self._home_open_folder)
        self.home_screen.open_config_requested.connect(self._home_open_config)
        self.home_screen.config_pulled_for_check.connect(self._on_config_pulled_for_check)
        self.home_screen.recheck_requested.connect(self.recheck)
        self.home_screen.export_report_requested.connect(self.export_report)
        self.home_screen.ssh_summary_changed.connect(self._update_ssh_summary)
        self.home_screen.ollama_status_changed.connect(self._refresh_ollama_status)
        self.home_screen.db_status_changed.connect(self._on_db_status_changed)
        self.home_screen.section_changed.connect(self._on_home_section_changed)
        self.home_screen.site_changed.connect(self._on_live_site_changed)
        self.home_screen.topology_mode_requested.connect(self._set_topology_mode)
        self.home_screen.config_menu_opened.connect(self._ensure_workspace)
        self._stack.addWidget(self.home_screen)

        # Config Check workspace (path bar, summary, tabs). It lives inside
        # Home as a page; Home's sliding menu lists its tabs under Config Check.
        central = QWidget()
        self.home_screen.attach_workspace(central)

        main_col = QVBoxLayout(central)
        main_col.setContentsMargins(0, 0, 0, 0)
        path_row = QHBoxLayout()
        self.path_label = QLabel(
            "Drop a pfSense config.xml or MikroTik .rsc here, or Open a file"
        )
        self.path_label.setWordWrap(True)
        path_row.addWidget(self.path_label, stretch=1)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self.open_file)
        path_row.addWidget(browse)
        main_col.addLayout(path_row)

        self.summary_label = QLabel("")
        self.summary_label.setWordWrap(True)
        self.summary_label.setStyleSheet("font-weight: bold; padding: 4px 0;")
        main_col.addWidget(self.summary_label)

        self.tabs = QTabWidget()
        self.tabs.tabBar().hide()
        self.tabs.setDocumentMode(True)
        self.tabs.setStyleSheet("QTabWidget::pane { border: 0; }")
        main_col.addWidget(self.tabs, stretch=1)

        # Workspace tabs are built on first open — keeps Home launch snappy.
        self._workspace_built = False

        self._stack.setCurrentIndex(0)
        self._try_autoload_saved_topology()
        self._sync_home_sites()

    def _sync_workspace_nav(self) -> None:
        """List the workspace tabs under Config Check in Home's menu."""
        if not hasattr(self, "tabs"):
            return
        self.home_screen.set_config_tabs(
            [self.tabs.tabText(i) for i in range(self.tabs.count())]
        )

    def _ensure_workspace(self) -> None:
        """Lazily construct the full analysis tab set."""
        if getattr(self, "_workspace_built", False):
            return
        self._workspace_built = True
        self._build_dashboard_tab()
        self._build_topology_tab()
        self._build_site_tab()
        self._build_resiliency_tab()
        self._build_findings_tab()
        self._build_interfaces_tab()
        self._build_virtual_tab()
        self._build_rules_tab()
        self._build_vpn_tab()
        self._build_services_net_tab()
        self._build_packages_tab()
        self._build_monitor_tab()
        self._build_beacon_creator_tab()
        self._build_ai_tab()
        self._build_report_tab()
        self._sync_workspace_nav()
        if self._result is not None:
            # Re-apply last check into newly built tabs when opening mid-session.
            try:
                self._render_findings(self._result)
            except Exception:  # noqa: BLE001
                pass
        self._refresh_site()

    # --- home screen plumbing ---

    def _sync_home_sites(self) -> None:
        # Live mode: Topology Builder + preview + Login all share _live_site.
        # Experimental mode: Builder/preview use _experimental_site; Login stays on live.
        self.home_screen.set_sites(
            live=self._live_site,
            topology=self._live_site
            if self._topology_mode == "live"
            else self._experimental_site,
            mode=self._topology_mode,
        )

    def _on_live_site_changed(self) -> None:
        """Login mutated topology — keep MainWindow._live_site on the same object."""
        session_site = getattr(self.home_screen.session, "_site", None)
        if session_site is not None and session_site is not self._live_site:
            self._live_site = session_site
        if self._topology_mode == "live":
            self._site = self._live_site
            self._refresh_site()
        else:
            self._sync_home_sites()

    def _set_topology_mode(self, mode: str) -> None:
        if mode not in ("live", "experimental"):
            return
        if mode == self._topology_mode:
            # Re-assert shared live object even if already on this mode
            if mode == "live":
                self._site = self._live_site
            self._sync_home_sites()
            return
        self._topology_mode = mode
        if mode == "live":
            self._site = self._live_site
        else:
            # Seed experimental from a *copy* of live once if still empty —
            # never alias live (experimental edits must not touch Login).
            if not self._experimental_site.devices and self._live_site.devices:
                self._experimental_site = SiteTopology.from_dict(
                    self._live_site.to_dict()
                )
                base = self._experimental_site.name or "Site"
                if "experimental" not in base.lower():
                    self._experimental_site.name = f"{base} (Experimental)"
            self._site = self._experimental_site
        if getattr(self, "site_name_edit", None) is not None:
            self.site_name_edit.setText(self._site.name)
        self._refresh_site()
        self._sync_home_sites()
        label = (
            "Live (= Login to Routers)"
            if mode == "live"
            else "Experimental (sandbox)"
        )
        self.statusBar().showMessage(f"Topology mode: {label}", 4000)

    def _replace_active_site(self, site: SiteTopology, *, path: Path | None = None) -> None:
        """Assign a newly loaded site into the active mode bucket."""
        if self._topology_mode == "live":
            self._live_site = site
            self._site_path = path
        else:
            self._experimental_site = site
            self._experimental_path = path
        self._site = site

    def _enter_workspace(self, tab_name: str = "") -> None:
        app_log.get_logger("nav").debug("Workspace tab: %s", tab_name or "(current)")
        self._ensure_workspace()
        self._stack.setCurrentIndex(0)
        if tab_name:
            self._goto_tab(tab_name)
        current = (
            self.tabs.tabText(self.tabs.currentIndex())
            if hasattr(self, "tabs") and self.tabs.count()
            else ""
        )
        self.home_screen.show_workspace_page(current)
        title = tab_name or (
            self.tabs.tabText(self.tabs.currentIndex())
            if hasattr(self, "tabs") and self.tabs.count()
            else "Workspace"
        )
        self._context_module = f"Workspace · {title}"
        self._context_capabilities = (
            "Dashboard · findings · topology · monitor · AI · report — "
            "pick another section on the left to leave"
        )
        self._refresh_context_status()
        if hasattr(self, "tabs"):
            try:
                self.tabs.currentChanged.disconnect(self._on_workspace_tab_changed)
            except (TypeError, RuntimeError):
                pass
            self.tabs.currentChanged.connect(self._on_workspace_tab_changed)

    def show_home_screen(self) -> None:
        self._sync_home_sites()
        self._stack.setCurrentIndex(0)
        key = self.home_screen.current_section_key()
        if not key or key.startswith("config.tab:"):
            # Home leaves the Config Check workspace for the landing section.
            self.home_screen.show_section("login")
            return
        from pfsense_checker.home_screen import section_capabilities

        self._on_home_section_changed(
            key, self.home_screen.nav.label(key), section_capabilities(key)
        )

    def _on_workspace_tab_changed(self, index: int) -> None:
        if not hasattr(self, "tabs") or index < 0:
            return
        title = self.tabs.tabText(index)
        self._context_module = f"Workspace · {title}"
        self._context_capabilities = "Analysis workspace tab"
        self._refresh_context_status()
        if self.home_screen.current_section_key().startswith("config.tab:"):
            self.home_screen.nav.select("config.tab:" + title)

    def _on_home_section_changed(self, key: str, title: str, capabilities: str) -> None:
        self._context_module = title or key
        self._context_capabilities = capabilities or ""
        self._refresh_context_status()

    def _refresh_context_status(self) -> None:
        """Bottom-left: User | module — capabilities | Status: last action (colored)."""
        label = getattr(self, "_context_status", None)
        if label is None:
            return
        user = self._auth_username or "—"
        role = ""
        if self._auth_user is not None:
            role = getattr(self._auth_user, "role", "") or ""
        user_bit = f"User: {user}" + (f" ({role})" if role else "")
        module = getattr(self, "_context_module", "") or "—"
        caps = getattr(self, "_context_capabilities", "") or ""
        module_bit = f"{module} — {caps}" if caps else module
        action = (getattr(self, "_context_action", "") or "—").strip() or "—"
        level = getattr(self, "_context_action_level", "neutral") or "neutral"
        color = {
            "success": STATUS_BAR_OK,
            "problem": STATUS_BAR_FAIL,
            "failed": STATUS_BAR_FAIL,
            "neutral": STATUS_BAR_TEXT,
        }.get(level, STATUS_BAR_TEXT)
        # Escape HTML in dynamic bits
        from html import escape

        plain = f"{user_bit}  |  {module_bit}  |  Status: {action}"
        html = (
            f'<span style="color:{STATUS_BAR_TEXT};">{escape(user_bit)}</span>'
            f'  |  <span style="color:{STATUS_BAR_TEXT};">{escape(module_bit)}</span>'
            f'  |  Status: <span style="color:{color}; font-weight:600;">'
            f"{escape(action)}</span>"
        )
        label.setTextFormat(Qt.TextFormat.RichText)
        label.setText(html)
        label.setToolTip(plain)

    def _set_context_action(self, text: str, level: str = "neutral") -> None:
        """Update the Status: segment of the left context strip."""
        self._context_action = (text or "—").strip() or "—"
        self._context_action_level = level if level in {
            "success", "problem", "failed", "neutral"
        } else "neutral"
        self._refresh_context_status()

    @staticmethod
    def _infer_action_level(text: str) -> str:
        t = (text or "").lower()
        if any(
            x in t
            for x in (
                "fail",
                "error",
                "unreachable",
                "denied",
                "invalid",
                "refused",
            )
        ):
            return "failed"
        if any(
            x in t
            for x in (
                "banner",
                "partial",
                "warn",
                "problem",
                "no reply",
                "timeout",
                "reachable",
            )
        ):
            return "problem"
        if any(
            x in t
            for x in (
                "connected",
                "success",
                "loaded",
                "saved",
                "ok",
                "exported",
            )
        ):
            return "success"
        return "neutral"

    # Back-compat alias for anything still calling the old name
    def show_session_screen(self) -> None:
        self.home_screen.show_section("login")
        self.show_home_screen()

    def _active_topology_path(self) -> Path:
        if self._topology_mode == "experimental":
            return SAVED_EXPERIMENTAL_TOPOLOGY_PATH
        return SAVED_TOPOLOGY_PATH

    def _home_load_live_topology(self) -> None:
        """Login panel: always load the live topology slot."""
        prev = self._topology_mode
        self._topology_mode = "live"
        self._site = self._live_site
        self._home_load_topology()
        if prev != "live":
            self._topology_mode = prev
            self._site = (
                self._live_site if prev == "live" else self._experimental_site
            )
            self._refresh_site()
        self._sync_home_sites()

    def _home_save_live_topology(self) -> None:
        """Login panel: always save the live topology slot."""
        prev = self._topology_mode
        self._topology_mode = "live"
        self._site = self._live_site
        self._home_save_topology()
        if prev != "live":
            self._topology_mode = prev
            self._site = (
                self._live_site if prev == "live" else self._experimental_site
            )
        self._sync_home_sites()

    def _home_load_topology(self) -> None:
        """Load the saved topology slot for the active mode."""
        path = self._active_topology_path()
        mode_label = "live" if self._topology_mode == "live" else "experimental"
        if not path.is_file():
            QMessageBox.information(
                self,
                "Load Topology",
                f"No saved {mode_label} topology yet.\n\n"
                f"Use Save Topology to store one at:\n{path}",
            )
            return
        try:
            site = SiteTopology.load(path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            QMessageBox.critical(self, "Load Topology", str(exc))
            return
        self._replace_active_site(site, path=path)
        if getattr(self, "site_name_edit", None) is not None:
            self.site_name_edit.setText(self._site.name)
        self._refresh_site()
        self._sync_home_sites()
        self.statusBar().showMessage(f"Loaded {mode_label} topology from {path}", 5000)

    def _home_save_topology(self) -> None:
        """Overwrite the saved topology slot for the active mode."""
        path = self._active_topology_path()
        mode_label = "live" if self._topology_mode == "live" else "experimental"
        if path.is_file():
            reply = QMessageBox.question(
                self,
                "Save Topology",
                f"Only one {mode_label} topology is kept here.\n\n"
                f"Overwrite the existing save?\n{path}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        try:
            ensure_data_dir()
            if getattr(self, "site_name_edit", None) is not None:
                self._site_name_changed()
            self._site.save(path)
            if self._topology_mode == "live":
                self._site_path = path
            else:
                self._experimental_path = path
        except OSError as exc:
            QMessageBox.critical(self, "Save Topology", str(exc))
            return
        self.statusBar().showMessage(f"Saved {mode_label} topology to {path}", 5000)
        QMessageBox.information(
            self,
            "Save Topology",
            f"{mode_label.capitalize()} topology saved.\n\n{path}",
        )

    def _try_autoload_saved_topology(self) -> None:
        path = SAVED_TOPOLOGY_PATH
        if path.is_file():
            try:
                self._live_site = SiteTopology.load(path)
                self._site_path = path
            except (OSError, ValueError, json.JSONDecodeError):
                pass
        exp = SAVED_EXPERIMENTAL_TOPOLOGY_PATH
        if exp.is_file():
            try:
                self._experimental_site = SiteTopology.load(exp)
                self._experimental_path = exp
            except (OSError, ValueError, json.JSONDecodeError):
                pass
        self._site = (
            self._live_site
            if self._topology_mode == "live"
            else self._experimental_site
        )

    def _home_open_folder(self) -> None:
        self.open_folder()
        self._sync_home_sites()
        self._enter_workspace("Dashboard")

    def _home_open_config(self) -> None:
        self.open_file()
        if self._result is not None:
            self._enter_workspace("Dashboard")

    def _on_config_pulled_for_check(self, path_str: str) -> None:
        path = Path(path_str)
        if not path.is_file():
            QMessageBox.warning(
                self,
                "Config Check",
                f"Pulled config file not found:\n{path_str}",
            )
            return
        self.load_path(path)
        self._enter_workspace("Dashboard")

    def _goto_tab(self, tab_name: str) -> None:
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == tab_name:
                self.tabs.setCurrentIndex(i)
                return

    def _update_ssh_summary(self, text: str) -> None:
        """Map SSH / session events into the left Status: segment (colored)."""
        raw = (text or "").strip()
        # Normalize older "SSH: …" prefixes into a clean status phrase.
        display = raw
        if display.lower().startswith("ssh:"):
            display = display.split(":", 1)[1].strip()
        if display.lower().startswith("ssh "):
            display = display[4:].strip()
        # Prefer a stable phrasing for connect success.
        low = display.lower()
        if low.startswith("connected to "):
            display = f"SSH connected to {display[len('connected to '):]}"
        elif "login failed" in low:
            display = display if display.lower().startswith("ssh") else f"SSH {display}"
        elif display and not display.lower().startswith("ssh"):
            # Keep generic summaries like "2/3 connected"
            if "connected" in low and "/" in display:
                display = f"SSH {display}"
        level = self._infer_action_level(raw or display)
        self._set_context_action(display or "—", level)
        # Legacy label (hidden) kept in sync for any external readers.
        legacy = getattr(self, "_ssh_summary", None)
        if legacy is not None:
            legacy.setText(raw or "SSH: not connected")

    def _set_db_status_label(
        self,
        connected: bool,
        text: str | None = None,
        tooltip: str | None = None,
    ) -> None:
        label = getattr(self, "_db_status", None)
        if label is None:
            return
        from pfsense_checker import postgres_db as pg

        settings = pg.load_settings()
        label.setText(text or pg.status_bar_text(connected, settings))
        label.setToolTip(tooltip or pg.status_bar_tooltip(connected, settings))
        if connected:
            label.setStyleSheet(status_chip_style(STATUS_BAR_OK))
        else:
            label.setStyleSheet(status_chip_style(STATUS_BAR_FAIL))

    def _on_db_status_changed(self, connected: bool, text: str, tooltip: str) -> None:
        self._set_db_status_label(connected, text, tooltip)

    def _refresh_db_status(self) -> None:
        """Probe configured PostgreSQL off the UI thread for the status bar."""
        if getattr(self, "_db_status", None) is None:
            return
        if getattr(self, "_db_probe_worker", None) is not None:
            if self._db_probe_worker.isRunning():
                return

        class _DbProbe(QThread):
            finished_ok = Signal(bool, str, str)  # connected, text, tooltip

            def run(self) -> None:  # noqa: D102
                from pfsense_checker import postgres_db as pg

                ok, settings, detail = pg.probe_connection(timeout=2)
                short = detail.split(",")[0] if ok and detail else detail
                self.finished_ok.emit(
                    ok,
                    pg.status_bar_text(ok, settings),
                    pg.status_bar_tooltip(ok, settings, detail=short),
                )

        worker = _DbProbe()
        self._db_probe_worker = worker
        worker.finished_ok.connect(self._on_db_status_changed)
        # Clear our reference before deleteLater — otherwise the next timer
        # tick calls isRunning() on a deleted C++ object (libshiboken crash).
        worker.finished.connect(lambda: setattr(self, "_db_probe_worker", None))
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def _set_ollama_status_label(self, connected: bool) -> None:
        label = getattr(self, "_ollama_status", None)
        if label is None:
            return
        if connected:
            label.setText("Ollama Connected")
            label.setStyleSheet(status_chip_style(STATUS_BAR_OK))
        else:
            label.setText("Ollama Not Connected")
            label.setStyleSheet(status_chip_style(STATUS_BAR_FAIL))

    def _set_beacon_status_label(
        self, online: int | None, total: int | None = None
    ) -> None:
        """Update status-bar beacon count: None Seen (red) or N Seen (green)."""
        label = getattr(self, "_beacon_status", None)
        if label is None:
            return
        if online is None or int(online) <= 0:
            label.setText("Beacons: None Seen")
            label.setStyleSheet(status_chip_style(STATUS_BAR_FAIL))
            if online is None:
                label.setToolTip("No beacons seen — collector unreachable or not running")
            else:
                total_n = int(total) if total is not None else 0
                label.setToolTip(
                    f"0 online / {total_n} registered with the collector"
                    if total_n
                    else "No beacons reporting"
                )
            return
        count = int(online)
        label.setText(f"Beacons: {count} Seen")
        label.setStyleSheet(status_chip_style(STATUS_BAR_OK))
        total_n = int(total) if total is not None else count
        label.setToolTip(f"{count} online / {total_n} registered with the collector")

    def _collector_endpoint_for_status(self) -> tuple[str, str]:
        """Prefer Live Monitor fields, then Subnet Health settings, then default."""
        if hasattr(self, "monitor_url"):
            url = self.monitor_url.text().strip()
            token = (
                self.monitor_token.text().strip()
                if hasattr(self, "monitor_token")
                else ""
            )
            if url:
                return url, token
        sh = getattr(self.home_screen, "sh_collector", None)
        if sh is not None:
            token_w = getattr(self.home_screen, "sh_token", None)
            return sh.text().strip(), (
                token_w.text().strip() if token_w is not None else ""
            )
        from pfsense_checker import subnet_health

        settings = subnet_health.load_settings()
        return settings.collector_url, settings.collector_token

    def _refresh_beacon_status(self) -> None:
        """Probe the collector off the UI thread for online beacon count."""
        if getattr(self, "_beacon_status", None) is None:
            return
        if getattr(self, "_beacon_probe_worker", None) is not None:
            if self._beacon_probe_worker.isRunning():
                return
        url, token = self._collector_endpoint_for_status()
        if not url:
            self._set_beacon_status_label(None)
            return

        class _BeaconProbe(QThread):
            finished_ok = Signal(object)  # (online, total) | None

            def __init__(self, base_url: str, bearer: str) -> None:
                super().__init__()
                self._url = base_url
                self._token = bearer

            def run(self) -> None:  # noqa: D102
                import urllib.error
                import urllib.request

                req = urllib.request.Request(
                    self._url.rstrip("/") + "/api/beacons",
                    headers={
                        "Accept": "application/json",
                        "User-Agent": "NetCheck-StatusBar/1.0",
                        **(
                            {"Authorization": f"Bearer {self._token}"}
                            if self._token
                            else {}
                        ),
                    },
                    method="GET",
                )
                try:
                    with urllib.request.urlopen(req, timeout=2.0) as resp:
                        payload = json.loads(resp.read().decode("utf-8"))
                except (
                    OSError,
                    urllib.error.URLError,
                    json.JSONDecodeError,
                    UnicodeDecodeError,
                ):
                    self.finished_ok.emit(None)
                    return
                if isinstance(payload, dict):
                    beacons = payload.get("beacons") or payload.get("items") or []
                elif isinstance(payload, list):
                    beacons = payload
                else:
                    beacons = []
                beacons = [b for b in beacons if isinstance(b, dict)]
                online = sum(1 for b in beacons if b.get("online"))
                self.finished_ok.emit((online, len(beacons)))

        worker = _BeaconProbe(url, token)
        self._beacon_probe_worker = worker
        worker.finished_ok.connect(self._on_beacon_probe_done)
        worker.finished.connect(
            lambda: setattr(self, "_beacon_probe_worker", None)
        )
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def _on_beacon_probe_done(self, payload: object) -> None:
        if payload is None:
            self._set_beacon_status_label(None)
            return
        if isinstance(payload, tuple) and len(payload) == 2:
            online, total = payload
            self._set_beacon_status_label(int(online), int(total))

    def _refresh_ollama_status(self) -> None:
        """Probe local Ollama off the UI thread and update the status-bar."""
        if getattr(self, "_ollama_status", None) is None:
            return
        if not ai.is_ollama_enabled():
            self._set_ollama_status_label(False)
            return
        if getattr(self, "_ollama_probe_worker", None) is not None:
            if self._ollama_probe_worker.isRunning():
                return
        url, _ = ai.load_ollama_settings()

        class _OllamaProbe(QThread):
            finished_ok = Signal(bool)

            def __init__(self, base_url: str) -> None:
                super().__init__()
                self._url = base_url

            def run(self) -> None:  # noqa: D102
                try:
                    ai.list_ollama_models(self._url, timeout=2)
                    self.finished_ok.emit(True)
                except (RuntimeError, ValueError, OSError, TimeoutError):
                    self.finished_ok.emit(False)

        worker = _OllamaProbe(url)
        self._ollama_probe_worker = worker
        worker.finished_ok.connect(self._set_ollama_status_label)
        worker.finished.connect(
            lambda: setattr(self, "_ollama_probe_worker", None)
        )
        worker.finished.connect(worker.deleteLater)
        worker.start()

    @staticmethod
    def _accent_button_style(r: int, g: int, b: int) -> str:
        """Button motif: 50% opaque fill, solid bright 1px outline, same hue."""
        return (
            f"QPushButton {{"
            f" padding: 2px 18px;"
            f" background-color: rgba({r}, {g}, {b}, 128);"
            f" border: 1px solid rgb({r}, {g}, {b});"
            f" border-radius: 3px;"
            f" color: white;"
            f" font-weight: bold;"
            f" }}"
            f"QPushButton:hover {{ background-color: rgba({r}, {g}, {b}, 178); }}"
            f"QPushButton:pressed {{ background-color: rgb({r}, {g}, {b}); }}"
        )

    def _build_statusbar(self) -> None:
        """Always-visible status bar with context (left) + status chips (right)."""
        from PySide6.QtGui import QFont

        sb = self.statusBar()
        sb.setSizeGripEnabled(True)
        sb.setVisible(True)
        sb.setMinimumHeight(28)
        bar_font = QFont()
        bar_font.setPointSize(9)
        bar_font.setWeight(QFont.Weight.DemiBold)
        sb.setFont(bar_font)
        sb.setStyleSheet(status_bar_stylesheet())

        # Bottom-left: User | module — capabilities | Status: last action (colored).
        self._context_status = QLabel("User: —  |  —  |  Status: —")
        self._context_status.setFont(bar_font)
        self._context_status.setTextFormat(Qt.TextFormat.RichText)
        self._context_status.setStyleSheet(
            "padding: 0 10px; background: transparent; font-size: 9pt; font-weight: 600;"
        )
        self._context_status.setMinimumWidth(360)
        sb.addWidget(self._context_status, 1)
        self._refresh_context_status()

        # Permanent so it stays visible while QStatusBar.showMessage() is up.
        self._busy_progress = QProgressBar()
        self._busy_progress.setObjectName("busyProgress")
        self._busy_progress.setFixedWidth(140)
        self._busy_progress.setMaximumHeight(18)
        self._busy_progress.setTextVisible(False)
        self._busy_progress.setRange(0, 1)
        self._busy_progress.setValue(0)
        self._busy_progress.setToolTip("")
        sb.addPermanentWidget(self._busy_progress)
        busy_hub().busy_changed.connect(self._set_busy_progress)
        busy_hub().busy_message.connect(self._set_busy_message)
        self._set_busy_progress(is_busy())

        self._ollama_status = QLabel("Ollama Not Connected")
        self._ollama_status.setFont(bar_font)
        self._set_ollama_status_label(False)
        sb.addPermanentWidget(self._ollama_status)

        self._db_status = QLabel("DB: —")
        self._db_status.setFont(bar_font)
        self._set_db_status_label(False)
        sb.addPermanentWidget(self._db_status)

        # Kept for compatibility but hidden — user lives in the left context strip.
        self._user_status = QLabel("User: —")
        self._user_status.hide()

        self._beacon_status = QLabel("Beacons: —")
        self._beacon_status.setFont(bar_font)
        self._set_beacon_status_label(None)
        sb.addPermanentWidget(self._beacon_status)

        # SSH / last action lives in the left Status: segment (not a right chip).
        self._ssh_summary = QLabel("SSH: not connected")
        self._ssh_summary.hide()

        ai_help_btn = QPushButton("AI Help")
        ai_help_btn.setFont(bar_font)
        ai_help_btn.setToolTip("Open the AI Advisor")
        ai_help_btn.setStyleSheet(self._accent_button_style(21, 101, 192))
        ai_help_btn.clicked.connect(self._open_ai_help)
        sb.addPermanentWidget(ai_help_btn)

        help_btn = QPushButton("Help")
        help_btn.setFont(bar_font)
        help_btn.setToolTip("How this window is organised")
        help_btn.setStyleSheet(
            "QPushButton {"
            " padding: 2px 18px;"
            " background-color: #fbc02d;"
            " border: 1px solid #f9a825;"
            " border-radius: 3px;"
            " color: #212121;"
            " font-weight: bold;"
            "}"
            "QPushButton:hover { background-color: #fdd835; }"
            "QPushButton:pressed { background-color: #f9a825; }"
        )
        help_btn.clicked.connect(self._show_main_help)
        sb.addPermanentWidget(help_btn)

        close_btn = QPushButton("Close")
        close_btn.setFont(bar_font)
        close_btn.setToolTip("Close pfSense Config Checker")
        close_btn.setStyleSheet(self._accent_button_style(198, 40, 40))
        close_btn.clicked.connect(self.close)
        sb.addPermanentWidget(close_btn)

    def _set_busy_progress(self, active: bool) -> None:
        """Indeterminate progress bar while background work runs."""
        bar = getattr(self, "_busy_progress", None)
        if bar is None:
            return
        if active:
            bar.setRange(0, 0)
            bar.setToolTip(busy_message() or "Working…")
        else:
            bar.setRange(0, 1)
            bar.setValue(0)
            bar.setToolTip("")
            self.statusBar().clearMessage()

    def _set_busy_message(self, message: str) -> None:
        bar = getattr(self, "_busy_progress", None)
        if bar is not None and is_busy():
            bar.setToolTip(message or "Working…")
        if message:
            self.statusBar().showMessage(message)
        elif not is_busy():
            self.statusBar().clearMessage()

    def _open_ai_help(self) -> None:
        self._enter_workspace("AI Advisor")
        if hasattr(self, "ai_question"):
            self.ai_question.setFocus()

    def _show_main_help(self) -> None:
        body = (
            "<p><b>NetCheck</b></p>"
            "<p><b>Home</b> is the main section list (Login, Log Pipeline, Syslog, Setup). "
            "The sidebar that lists Dashboard, Topology, and Findings is only the "
            "<b>OPNsense/pfSense Config Checker</b>.</p>"
            "<p><b>Config</b><br/>"
            "Drop a <code>config.xml</code> or a RouterOS <code>.rsc</code>. "
            "PASS means no warnings. EXPOSED means the review failed. "
            "The attack-surface note under the cards is the assessment.</p>"
            "<p><b>Findings</b><br/>"
            "Right-click a row: Explain Issue, Explain Severity, Suggest Fix, "
            "What Breaks if Removed. Save Analysis writes that window to a text file.</p>"
            "<p><b>Topology</b><br/>"
            "One physical NIC fans out to every VLAN on that port. "
            "The label is the port name. OPT15 and the other assignment ids are on the second line.</p>"
            "<p><b>Log Pipeline</b><br/>"
            "Home → Log Pipeline listens for a pfSense stream. "
            "The incoming port defaults to 59000.</p>"
            "<p><b>AI Help</b> opens the advisor. This Help button is the map of the window.</p>"
        )
        box = QMessageBox(self)
        box.setWindowTitle("NetCheck — Help")
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setText(body)
        box.setIcon(QMessageBox.Icon.Information)
        box.exec()

    def _build_dashboard_tab(self) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        page = QWidget()
        scroll.setWidget(page)
        v = QVBoxLayout(page)

        # KPI cards
        self.kpi_cards: dict[str, KpiCard] = {}
        kpi_defs = [
            ("verdict", "Result"),
            ("errors", "Errors"),
            ("warnings", "Warnings"),
            ("interfaces", "Interfaces"),
            ("virtual", "Bridges/VLAN/LAGG"),
            ("fw", "Firewall rules"),
            ("vpn", "VPN endpoints"),
            ("packages", "Packages"),
        ]
        grid_top = QGridLayout()
        grid_top.setSpacing(8)
        for idx, (key, caption) in enumerate(kpi_defs):
            card = KpiCard(caption)
            self.kpi_cards[key] = card
            grid_top.addWidget(card, idx // 4, idx % 4)
        v.addLayout(grid_top)

        assess_title = QLabel("Attack surface")
        assess_title.setStyleSheet("font-weight: bold; font-size: 13px; padding-top: 8px;")
        v.addWidget(assess_title)
        self.assessment_view = QTextEdit()
        self.assessment_view.setReadOnly(True)
        self.assessment_view.setMinimumHeight(220)
        self.assessment_view.setFont(QFont("Consolas", 10))
        self.assessment_view.setPlaceholderText(
            "Drop a config to assess management exposure, WAN rules, NAT, VPN crypto, DNS, and logging."
        )
        v.addWidget(self.assessment_view)

        # Charts grid
        charts = QGridLayout()
        charts.setSpacing(8)
        self.donut_sev = DonutChartView("Findings by severity")
        self.bar_cat = BarChartView("Findings by category")
        self.donut_iface = DonutChartView("Interface status")
        self.bar_kind = BarChartView("Interfaces by kind")
        charts.addWidget(self.donut_sev, 0, 0)
        charts.addWidget(self.bar_cat, 0, 1)
        charts.addWidget(self.donut_iface, 1, 0)
        charts.addWidget(self.bar_kind, 1, 1)
        v.addLayout(charts)
        v.addStretch(1)

        self.tabs.addTab(scroll, "Dashboard")

    def _build_topology_tab(self) -> None:
        page = QWidget()
        v = QVBoxLayout(page)

        legend = QLabel(self._topology_legend_html())
        legend.setTextFormat(Qt.TextFormat.RichText)
        v.addWidget(legend)

        controls = QHBoxLayout()
        btn_auto = QPushButton("Auto-layout (no crossings)")
        btn_auto.setToolTip(
            "Reorder nodes with a layered barycentre layout so links cross as little as possible."
        )
        btn_auto.clicked.connect(self._topology_auto_layout)
        btn_reset = QPushButton("Reset positions")
        btn_reset.clicked.connect(self._topology_reset)
        self.topology_lock = QCheckBox("Lock nodes")
        self.topology_lock.toggled.connect(self._topology_lock_toggled)
        controls.addWidget(btn_auto)
        controls.addWidget(btn_reset)
        controls.addWidget(self.topology_lock)
        controls.addStretch(1)
        v.addLayout(controls)

        from PySide6.QtWidgets import QSplitter

        from pfsense_checker.viz import SegmentationMatrix

        self.topology_view = TopologyView()
        self.segmentation_matrix = SegmentationMatrix()
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.topology_view)
        split.addWidget(self.segmentation_matrix)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        v.addWidget(split, stretch=1)

        hint = QLabel(
            "One physical NIC fans out to every VLAN on that port. "
            "The label is the port name, not the OPT assignment. "
            "Drag a card vertically to edit. Dimmed cards are disabled interfaces. "
            "The badge on each subnet says how many other inside subnets its rules let it reach "
            "(red: any protocol, amber: some services, green: isolated); hover for the list. "
            "The matrix below shows every pair."
        )
        hint.setStyleSheet("color: #607d8b; font-size: 11px;")
        hint.setWordWrap(True)
        v.addWidget(hint)

        self.tabs.addTab(page, "Topology")

    def _topology_auto_layout(self) -> None:
        self.topology_view.apply_auto_layout()
        self.statusBar().showMessage("Topology auto-layout applied", 3000)

    def _topology_reset(self) -> None:
        self.topology_view.reset_layout()
        self.statusBar().showMessage("Topology positions reset", 3000)

    def _topology_lock_toggled(self, locked: bool) -> None:
        self.topology_view.set_locked(locked)

    def _topology_legend_html(self) -> str:
        parts = []
        for kind, color in KIND_COLORS.items():
            parts.append(
                f'<span style="color:{color};">&#9632;</span> {kind}'
            )
        return " &nbsp; ".join(parts)

    def _build_site_tab(self) -> None:
        page = QWidget()
        self.site_tab = page
        v = QVBoxLayout(page)

        intro = QLabel(
            "<b>Topology Builder</b> — Excel-style <b>physical layout</b>: "
            "ISP → Egress → Firewall → CRS328 → CRS109s, with SECPOL, port strips, "
            "and IF/NW/S-IP/DHCP VLAN cards. Lay down the base, then "
            "<b>Enrich from config</b>. <b>Load CRS example</b> matches your spreadsheet shape."
        )
        intro.setTextFormat(Qt.TextFormat.RichText)
        intro.setWordWrap(True)
        v.addWidget(intro)

        top = QHBoxLayout()
        top.addWidget(QLabel("Site:"))
        self.site_name_edit = QLineEdit(self._site.name)
        self.site_name_edit.editingFinished.connect(self._site_name_changed)
        top.addWidget(self.site_name_edit, stretch=1)
        for label, slot in (
            ("Load…", self.load_site),
            ("Save…", self.save_site),
            ("Import Excel…", self.import_excel_layout),
            ("Load CRS example", self.load_example_site),
        ):
            btn = QPushButton(label)
            btn.clicked.connect(slot)
            top.addWidget(btn)
        v.addLayout(top)

        enrich_row = QHBoxLayout()
        enrich_row.addWidget(QLabel("Enrich target:"))
        self.enrich_target = QComboBox()
        self.enrich_target.setEditable(True)
        self.enrich_target.addItem("(auto-match)")
        enrich_row.addWidget(self.enrich_target, stretch=1)
        self.enrich_create = QCheckBox("Create device if no match")
        self.enrich_create.setChecked(True)
        enrich_row.addWidget(self.enrich_create)
        btn_enrich = QPushButton("Enrich from loaded config")
        btn_enrich.clicked.connect(self.enrich_from_loaded_config)
        btn_enrich_files = QPushButton("Enrich from files…")
        btn_enrich_files.clicked.connect(self.enrich_from_files)
        btn_enrich_folder = QPushButton("Enrich from folder…")
        btn_enrich_folder.clicked.connect(self.open_folder)
        btn_attach = QPushButton("Attach loaded config to target")
        btn_attach.setToolTip(
            "Only bind the open config path to the selected device "
            "(for reliable auto-match later), without merging inventory yet."
        )
        btn_attach.clicked.connect(self.attach_config_to_target)
        btn_backup = QPushButton("Attach .backup…")
        btn_backup.setToolTip(
            "Attach a MikroTik binary .backup as restore evidence, then configure "
            "RouterOS 7 REST to collect a sanitized .rsc for analysis."
        )
        btn_backup.clicked.connect(self.attach_backup_to_target)
        btn_rest = QPushButton("Configure REST…")
        btn_rest.clicked.connect(self.configure_mikrotik_rest)
        btn_collect = QPushButton("Collect all configs")
        btn_collect.setToolTip("Refresh MikroTik REST exports for every attached device")
        btn_collect.clicked.connect(self.collect_all_configs)
        btn_detect_links = QPushButton("Auto-detect links")
        btn_detect_links.setToolTip(
            "Infer how devices are joined from uplink/port comments in attached configs"
        )
        btn_detect_links.clicked.connect(self.autodetect_links)
        btn_analyze = QPushButton("Analyze resiliency")
        btn_analyze.setToolTip(
            "Combine Topology Builder wiring with attached pfSense/MikroTik configs"
        )
        btn_analyze.clicked.connect(self.analyze_resiliency)
        enrich_row.addWidget(btn_enrich)
        enrich_row.addWidget(btn_enrich_files)
        enrich_row.addWidget(btn_enrich_folder)
        enrich_row.addWidget(btn_attach)
        enrich_row.addWidget(btn_backup)
        enrich_row.addWidget(btn_rest)
        enrich_row.addWidget(btn_collect)
        enrich_row.addWidget(btn_detect_links)
        enrich_row.addWidget(btn_analyze)
        v.addLayout(enrich_row)

        map_row = QHBoxLayout()
        map_row.addWidget(QLabel("Grid:"))
        self.site_grid = QSpinBox()
        self.site_grid.setRange(5, 80)
        self.site_grid.setValue(20)
        self.site_grid.setSuffix(" px")
        self.site_grid.valueChanged.connect(self._site_grid_changed)
        map_row.addWidget(self.site_grid)
        self.site_snap = QCheckBox("Snap to grid")
        self.site_snap.setChecked(True)
        self.site_snap.toggled.connect(self._site_snap_toggled)
        map_row.addWidget(self.site_snap)
        self.site_lock_map = QCheckBox("Lock map")
        self.site_lock_map.toggled.connect(self._site_lock_toggled)
        map_row.addWidget(self.site_lock_map)
        btn_arrange = QPushButton("Arrange by tier")
        btn_arrange.setToolTip("Re-place chassis left→right by role on the grid")
        btn_arrange.clicked.connect(self._site_arrange)
        map_row.addWidget(btn_arrange)
        map_row.addStretch(1)
        map_row.addWidget(QLabel("Ctrl+wheel zoom · drag chassis · stretch corner grip"))
        v.addLayout(map_row)

        self.site_view = SiteTopologyView()
        self.site_view.positions_changed.connect(self._site_positions_changed)
        self.site_view.links_changed.connect(self._site_links_changed)
        self.site_view.device_changed.connect(self._refresh_site)
        v.addWidget(self.site_view, stretch=2)

        editors = QTabWidget()
        editors.addTab(self._build_site_devices_editor(), "Devices")
        editors.addTab(self._build_site_links_editor(), "Links / Trunks")
        editors.addTab(self._build_site_vlans_editor(), "VLANs")
        editors.addTab(self._build_site_bridges_editor(), "Bridges")
        editors.addTab(self._build_site_vpn_editor(), "VPN Agreements")
        editors.addTab(self._build_site_egress_editor(), "Egress")
        v.addWidget(editors, stretch=1)

        self.site_warnings = QLabel("")
        self.site_warnings.setWordWrap(True)
        self.site_warnings.setStyleSheet("color: #ef6c00; font-size: 11px;")
        v.addWidget(self.site_warnings)

        self.tabs.addTab(page, "Topology Builder")
        self._refresh_site()

    def _build_site_devices_editor(self) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(4, 4, 4, 4)
        self.dev_table = _table(
            ["Name", "Kind", "Model", "Role", "SECPOL", "Pri", "Ports", "Hardware", "Config"]
        )
        layout.addWidget(self.dev_table)
        form = QHBoxLayout()
        self.dev_name = QLineEdit()
        self.dev_name.setPlaceholderText("Name e.g. CRS328-Core")
        self.dev_kind = QComboBox()
        self.dev_kind.addItems(DEVICE_KINDS)
        self.dev_kind.setCurrentText("switch")
        self.dev_model = QComboBox()
        self.dev_model.setEditable(True)
        self.dev_model.addItems(DEVICE_MODELS)
        self.dev_model.currentTextChanged.connect(self._dev_model_changed)
        self.dev_role = QComboBox()
        self.dev_role.setEditable(True)
        self.dev_role.addItems(DEVICE_ROLES)
        self.dev_role.setCurrentText("core-switch")
        self.dev_secpol = QLineEdit()
        self.dev_secpol.setPlaceholderText("SECPOL S5")
        self.dev_secpol.setMaximumWidth(70)
        self.dev_priority = QLineEdit()
        self.dev_priority.setPlaceholderText("Pri 0")
        self.dev_priority.setMaximumWidth(40)
        self.dev_ports = QLineEdit()
        self.dev_ports.setPlaceholderText("ports auto-filled from model (editable)")
        self.dev_hw = QLineEdit()
        self.dev_hw.setPlaceholderText("hardware e.g. Dell Optiplex")
        add = QPushButton("Add / Update")
        add.clicked.connect(self.add_device)
        rem = QPushButton("Remove")
        rem.clicked.connect(self.remove_device)
        for w in (
            self.dev_name, self.dev_kind, self.dev_model, self.dev_role,
            self.dev_secpol, self.dev_priority, self.dev_ports, self.dev_hw, add, rem,
        ):
            form.addWidget(w)
        layout.addLayout(form)
        hint = QLabel(
            "Network: mikrotik · juniper · ubiquiti · netgear · "
            "Endpoints: workstation / desktop / SFF · KVM · NAS · TV · video-box · game-console. "
            "Switches render as wide faceplates with discrete RJ45/SFP ports."
        )
        hint.setStyleSheet("color: #607d8b; font-size: 11px;")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        return box

    def _dev_model_changed(self, model: str) -> None:
        kind = kind_for_model(model)
        if kind:
            idx = self.dev_kind.findText(kind)
            if idx >= 0:
                self.dev_kind.setCurrentIndex(idx)
        ports = default_ports_for_model(model)
        if ports and not self.dev_ports.text().strip():
            self.dev_ports.setText(", ".join(ports))
        m = (model or "").upper()
        low = (model or "").lower()
        if "CRS109" in m or "GS105" in m or "GS108" in m:
            self.dev_role.setCurrentText("access-switch")
        elif any(x in m for x in ("CRS326", "CRS328", "CRS317", "GS724", "GS748", "GS324")):
            self.dev_role.setCurrentText("core-switch")
        elif "SRX" in m or "EDGEROUTER" in m:
            self.dev_role.setCurrentText("egress")
        elif kind in (
            "workstation", "desktop", "sff", "kvm", "nas",
            "tv", "video-box", "game-console",
        ):
            self.dev_role.setCurrentText(kind)
        elif "kvm" in low:
            self.dev_role.setCurrentText("kvm")
        elif any(x in low for x in ("nas", "synology", "qnap", "truenas")):
            self.dev_role.setCurrentText("nas")
        elif any(x in low for x in ("playstation", "xbox", "nintendo", "steam deck")):
            self.dev_role.setCurrentText("game-console")
        elif any(x in low for x in ("apple tv", "fire tv", "roku", "shield", "chromecast")):
            self.dev_role.setCurrentText("video-box")
        elif "tv" in low:
            self.dev_role.setCurrentText("tv")
        elif any(x in low for x in ("workstation",)):
            self.dev_role.setCurrentText("workstation")
        elif any(x in low for x in ("sff", "optiplex", "elitedesk", "nuc")):
            self.dev_role.setCurrentText("sff")
        elif "desktop" in low or "tower" in low:
            self.dev_role.setCurrentText("desktop")

    def _build_site_links_editor(self) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(4, 4, 4, 4)
        self.link_table = _table(
            ["A", "Port A", "B", "Port B", "Kind", "Speed", "VLANs", "Native", "Descr"]
        )
        layout.addWidget(self.link_table)
        form = QHBoxLayout()
        self.link_a_dev = QComboBox()
        self.link_a_dev.setEditable(True)
        self.link_a_port = QComboBox()
        self.link_a_port.setEditable(True)
        self.link_b_dev = QComboBox()
        self.link_b_dev.setEditable(True)
        self.link_b_port = QComboBox()
        self.link_b_port.setEditable(True)
        self.link_a_dev.currentTextChanged.connect(
            lambda: self._populate_ports(self.link_a_dev, self.link_a_port)
        )
        self.link_b_dev.currentTextChanged.connect(
            lambda: self._populate_ports(self.link_b_dev, self.link_b_port)
        )
        self.link_kind = QComboBox()
        self.link_kind.addItems(LINK_KINDS)
        self.link_kind.setCurrentText("trunk")
        self.link_speed = QLineEdit()
        self.link_speed.setPlaceholderText("1G / 10G")
        self.link_speed.setMaximumWidth(70)
        self.link_vlans = QLineEdit()
        self.link_vlans.setPlaceholderText("VLANs 10,20,30")
        self.link_native = QLineEdit()
        self.link_native.setPlaceholderText("native")
        self.link_native.setMaximumWidth(60)
        self.link_descr = QLineEdit()
        self.link_descr.setPlaceholderText("description")
        add = QPushButton("Add link")
        add.clicked.connect(self.add_link)
        rem = QPushButton("Remove")
        rem.clicked.connect(self.remove_link)
        for w in (
            QLabel("A:"), self.link_a_dev, self.link_a_port,
            QLabel("B:"), self.link_b_dev, self.link_b_port,
            self.link_kind, self.link_speed, self.link_vlans, self.link_native,
            self.link_descr, add, rem,
        ):
            form.addWidget(w)
        layout.addLayout(form)
        return box

    def _build_site_vlans_editor(self) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(4, 4, 4, 4)
        self.vlan_table = _table(
            ["ID", "Name", "IF", "NW", "S-IP", "DHCP", "Devices", "Gateway"]
        )
        layout.addWidget(self.vlan_table)
        form = QHBoxLayout()
        self.vlan_id = QLineEdit()
        self.vlan_id.setPlaceholderText("ID 10")
        self.vlan_id.setMaximumWidth(50)
        self.vlan_name = QLineEdit()
        self.vlan_name.setPlaceholderText("name LAN")
        self.vlan_if = QLineEdit()
        self.vlan_if.setPlaceholderText("IF E5-S5-VL10-LAN")
        self.vlan_subnet = QLineEdit()
        self.vlan_subnet.setPlaceholderText("NW 10.0.0.0/24")
        self.vlan_sip = QLineEdit()
        self.vlan_sip.setPlaceholderText("S-IP")
        self.vlan_sip.setMaximumWidth(110)
        self.vlan_dhcp = QLineEdit()
        self.vlan_dhcp.setPlaceholderText("DHCP pool")
        self.vlan_devices = QLineEdit()
        self.vlan_devices.setPlaceholderText("devices (comma)")
        self.vlan_gw = QComboBox()
        self.vlan_gw.setEditable(True)
        add = QPushButton("Add VLAN")
        add.clicked.connect(self.add_vlan)
        rem = QPushButton("Remove")
        rem.clicked.connect(self.remove_vlan)
        for w in (
            self.vlan_id, self.vlan_name, self.vlan_if, self.vlan_subnet,
            self.vlan_sip, self.vlan_dhcp, self.vlan_devices, self.vlan_gw, add, rem,
        ):
            form.addWidget(w)
        layout.addLayout(form)
        return box

    def _build_site_bridges_editor(self) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(4, 4, 4, 4)
        self.bridge_table = _table(["Name", "Devices", "Ports (Dev:port)", "VLAN", "Notes"])
        layout.addWidget(self.bridge_table)
        form = QHBoxLayout()
        self.br_name = QLineEdit()
        self.br_name.setPlaceholderText("bridge-lan")
        self.br_devices = QLineEdit()
        self.br_devices.setPlaceholderText("devices")
        self.br_ports = QLineEdit()
        self.br_ports.setPlaceholderText("CRS109:ether2, CRS328:ether1")
        self.br_vlan = QLineEdit()
        self.br_vlan.setPlaceholderText("VLAN")
        self.br_vlan.setMaximumWidth(60)
        self.br_notes = QLineEdit()
        add = QPushButton("Add bridge")
        add.clicked.connect(self.add_bridge)
        rem = QPushButton("Remove")
        rem.clicked.connect(self.remove_bridge)
        for w in (
            self.br_name, self.br_devices, self.br_ports, self.br_vlan,
            self.br_notes, add, rem,
        ):
            form.addWidget(w)
        layout.addLayout(form)
        return box

    def _build_site_vpn_editor(self) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(4, 4, 4, 4)
        self.vpn_site_table = _table(
            ["Name", "Kind", "A", "B", "Local EP", "Remote EP", "Networks", "Notes"]
        )
        layout.addWidget(self.vpn_site_table)
        form = QHBoxLayout()
        self.vpn_name = QLineEdit()
        self.vpn_name.setPlaceholderText("HQ-to-Remote")
        self.vpn_kind = QComboBox()
        self.vpn_kind.addItems(VPN_KINDS)
        self.vpn_a = QComboBox()
        self.vpn_a.setEditable(True)
        self.vpn_b = QComboBox()
        self.vpn_b.setEditable(True)
        self.vpn_local = QLineEdit()
        self.vpn_local.setPlaceholderText("local endpoint")
        self.vpn_remote = QLineEdit()
        self.vpn_remote.setPlaceholderText("remote endpoint")
        self.vpn_nets = QLineEdit()
        self.vpn_nets.setPlaceholderText("networks 10.99.0.0/24,…")
        self.vpn_notes = QLineEdit()
        add = QPushButton("Add VPN")
        add.clicked.connect(self.add_vpn_agreement)
        rem = QPushButton("Remove")
        rem.clicked.connect(self.remove_vpn_agreement)
        for w in (
            self.vpn_name, self.vpn_kind, self.vpn_a, self.vpn_b,
            self.vpn_local, self.vpn_remote, self.vpn_nets, self.vpn_notes, add, rem,
        ):
            form.addWidget(w)
        layout.addLayout(form)
        return box

    def _build_site_egress_editor(self) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(4, 4, 4, 4)
        self.egress_table = _table(
            ["Name", "Device", "Uplink port", "Upstream", "WAN", "Default for", "Notes"]
        )
        layout.addWidget(self.egress_table)
        form = QHBoxLayout()
        self.eg_name = QLineEdit()
        self.eg_name.setPlaceholderText("Primary-WAN")
        self.eg_device = QComboBox()
        self.eg_device.setEditable(True)
        self.eg_port = QLineEdit()
        self.eg_port.setPlaceholderText("igb0")
        self.eg_port.setMaximumWidth(80)
        self.eg_up = QComboBox()
        self.eg_up.setEditable(True)
        self.eg_wan = QLineEdit()
        self.eg_wan.setPlaceholderText("WAN subnet / dhcp")
        self.eg_default = QLineEdit()
        self.eg_default.setPlaceholderText("VLANs / all")
        self.eg_notes = QLineEdit()
        add = QPushButton("Add egress")
        add.clicked.connect(self.add_egress)
        rem = QPushButton("Remove")
        rem.clicked.connect(self.remove_egress)
        for w in (
            self.eg_name, self.eg_device, self.eg_port, self.eg_up,
            self.eg_wan, self.eg_default, self.eg_notes, add, rem,
        ):
            form.addWidget(w)
        layout.addLayout(form)
        return box

    # --- site topology actions ---

    def _site_name_changed(self) -> None:
        self._site.name = self.site_name_edit.text().strip() or "My Site"

    def _device_names(self) -> list[str]:
        return [d.name for d in self._site.devices]

    def _populate_ports(self, dev_combo: QComboBox, port_combo: QComboBox) -> None:
        name = dev_combo.currentText().strip()
        dev = self._site.device(name)
        current = port_combo.currentText()
        port_combo.blockSignals(True)
        port_combo.clear()
        if dev:
            port_combo.addItems(dev.ports)
        port_combo.setEditText(current)
        port_combo.blockSignals(False)

    def _sync_device_combos(self) -> None:
        names = self._device_names()
        combos = [
            self.link_a_dev, self.link_b_dev, self.vlan_gw,
            self.vpn_a, self.vpn_b, self.eg_device, self.eg_up,
        ]
        for combo in combos:
            current = combo.currentText()
            combo.blockSignals(True)
            combo.clear()
            combo.addItems(names)
            combo.setEditText(current)
            combo.blockSignals(False)
        self._populate_ports(self.link_a_dev, self.link_a_port)
        self._populate_ports(self.link_b_dev, self.link_b_port)

        current = self.enrich_target.currentText()
        self.enrich_target.blockSignals(True)
        self.enrich_target.clear()
        self.enrich_target.addItem("(auto-match)")
        self.enrich_target.addItems(names)
        if current and current != "(auto-match)" and current in names:
            self.enrich_target.setCurrentText(current)
        elif current == "(auto-match)" or not current:
            self.enrich_target.setCurrentIndex(0)
        else:
            self.enrich_target.setEditText(current)
        self.enrich_target.blockSignals(False)

    def _enrich_target_name(self) -> str | None:
        text = self.enrich_target.currentText().strip()
        if not text or text == "(auto-match)":
            return None
        return text

    def enrich_from_loaded_config(self) -> None:
        if not self._result:
            QMessageBox.information(
                self,
                "Enrich",
                "Open a pfSense or MikroTik config first, then enrich the base topology.",
            )
            return
        report = enrich_from_result(
            self._site,
            self._result,
            device_name=self._enrich_target_name(),
            create_if_missing=self.enrich_create.isChecked(),
        )
        self._refresh_site()
        self._show_enrichment_report(report)

    def enrich_from_files(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Enrich topology from config files",
            "",
            "Configs (*.xml *.conf *.rsc *.routeros *.backup);;All Files (*)",
        )
        if not paths:
            return
        reports = []
        errors = []
        for path_str in paths:
            path = Path(path_str)
            if path.suffix.lower() == ".backup":
                target = self._enrich_target_name()
                if not target and len(paths) == 1:
                    errors.append(
                        f"{path_str}: select an Enrich target before attaching .backup"
                    )
                    continue
                if target:
                    dev = self._site.device(target)
                    if dev:
                        dev.attach_local_config(path)
                        errors.append(f"INFO {path.name}: attached backup → {target} (configure REST next)")
                        continue
                errors.append(f"{path_str}: could not attach .backup")
                continue
            try:
                result = check_file(path)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{path_str}: {exc}")
                continue
            reports.append(
                enrich_from_result(
                    self._site,
                    result,
                    device_name=self._enrich_target_name() if len(paths) == 1 else None,
                    create_if_missing=self.enrich_create.isChecked(),
                )
            )
        self._refresh_site()
        lines = [r.summary() for r in reports]
        if errors:
            lines.append("Errors:")
            lines.extend(errors)
        QMessageBox.information(
            self,
            "Enrichment",
            "\n".join(lines) if lines else "No changes.",
        )
        self.statusBar().showMessage(f"Enriched from {len(reports)} file(s)", 6000)

    def attach_config_to_target(self) -> None:
        if not self._result or not self._result.path:
            QMessageBox.information(self, "Attach", "Open a config file first.")
            return
        name = self._enrich_target_name()
        if not name:
            matched = match_device_for_result(self._site, self._result)
            if matched:
                name = matched.name
            else:
                QMessageBox.information(
                    self,
                    "Attach",
                    "Pick an Enrich target device (not auto-match), or name the "
                    "device to match the config hostname.",
                )
                return
        dev = self._site.device(name)
        if not dev:
            QMessageBox.information(self, "Attach", f"Device '{name}' not found.")
            return
        path = self._result.path
        if path.suffix.lower() == ".backup":
            dev.attach_local_config(path)
            self._refresh_site()
            self._mikrotik_rest_dialog(dev)
            return
        dev.attach_local_config(path)
        self._refresh_site()
        self.statusBar().showMessage(f"Attached {path.name} → {name}", 5000)

    def attach_backup_to_target(self) -> None:
        name = self._enrich_target_name()
        if not name:
            QMessageBox.information(
                self,
                "Attach .backup",
                "Select an Enrich target MikroTik device first.",
            )
            return
        dev = self._site.device(name)
        if not dev:
            QMessageBox.information(self, "Attach .backup", f"Device '{name}' not found.")
            return
        path_str, _ = QFileDialog.getOpenFileName(
            self,
            "Attach MikroTik .backup (restore evidence)",
            "",
            "MikroTik backup (*.backup);;All Files (*)",
        )
        if not path_str:
            return
        path = Path(path_str)
        if path.suffix.lower() != ".backup":
            QMessageBox.warning(
                self,
                "Attach .backup",
                "Expected a *.backup file. Binary backups cannot be parsed directly; "
                "they are kept as restore evidence while analysis uses a live REST export.",
            )
        dev.attach_local_config(path)
        if (dev.kind or "").lower() not in ("mikrotik",):
            dev.kind = "mikrotik"
        self._refresh_site()
        QMessageBox.information(
            self,
            "Attach .backup",
            f"Attached {path.name} to {dev.name} as restore evidence.\n\n"
            "Next: configure RouterOS 7 REST (HTTPS) so a sanitized .rsc export "
            "can be collected for analysis. The binary backup itself is not parsed.",
        )
        self._mikrotik_rest_dialog(dev)

    def configure_mikrotik_rest(self) -> None:
        name = self._enrich_target_name()
        if not name:
            QMessageBox.information(
                self, "REST", "Select an Enrich target device first."
            )
            return
        dev = self._site.device(name)
        if not dev:
            QMessageBox.information(self, "REST", f"Device '{name}' not found.")
            return
        self._mikrotik_rest_dialog(dev)

    def _mikrotik_rest_dialog(self, dev: Device) -> None:
        src = dev.ensure_config_source() or ConfigSource(
            source_type=CONFIG_SOURCE_MIKROTIK_REST
        )
        dlg = QDialog(self)
        dlg.setWindowTitle(f"MikroTik REST — {dev.name}")
        form = QFormLayout(dlg)
        host = QLineEdit(src.host or dev.mgmt_ip or "")
        port = QSpinBox()
        port.setRange(1, 65535)
        port.setValue(int(src.port or 443))
        user = QLineEdit(src.username or "admin")
        password = QLineEdit()
        password.setEchoMode(QLineEdit.EchoMode.Password)
        password.setPlaceholderText("(stored in Windows Credential Manager)")
        verify = QCheckBox("Verify TLS certificate")
        verify.setChecked(bool(src.verify_tls) and not src.allow_insecure_tls)
        insecure = QCheckBox("Allow insecure TLS (self-signed) — not recommended")
        insecure.setChecked(bool(src.allow_insecure_tls))
        ca = QLineEdit(src.ca_path or "")
        ca.setPlaceholderText("Optional CA certificate path")
        note = QLabel(
            "Passwords are saved via Windows Credential Manager and never written "
            "into the site JSON. Analysis uses a sanitized /export (hide-sensitive)."
        )
        note.setWordWrap(True)
        form.addRow(note)
        if src.backup_artifact:
            form.addRow("Backup artifact:", QLabel(src.backup_artifact))
        form.addRow("Host / IP:", host)
        form.addRow("HTTPS port:", port)
        form.addRow("Username:", user)
        form.addRow("Password:", password)
        form.addRow(verify)
        form.addRow(insecure)
        form.addRow("CA path:", ca)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel
        )
        test_btn = buttons.addButton(
            "Test connection", QDialogButtonBox.ButtonRole.ActionRole
        )
        collect_btn = buttons.addButton(
            "Collect export", QDialogButtonBox.ButtonRole.ActionRole
        )
        form.addRow(buttons)

        def _apply_fields() -> None:
            allow_insec = insecure.isChecked()
            save_device_credentials(
                dev,
                host=host.text().strip(),
                username=user.text().strip(),
                password=password.text(),
                port=port.value(),
                verify_tls=verify.isChecked() and not allow_insec,
                allow_insecure_tls=allow_insec,
                ca_path=ca.text().strip(),
            )
            # If password blank but credentials already stored, keep ref and update meta
            if not password.text():
                src2 = dev.config_source
                if src2:
                    src2.host = host.text().strip()
                    src2.port = port.value()
                    src2.username = user.text().strip()
                    src2.verify_tls = verify.isChecked() and not allow_insec
                    src2.allow_insecure_tls = allow_insec
                    src2.ca_path = ca.text().strip()
                    src2.source_type = CONFIG_SOURCE_MIKROTIK_REST

        def on_test() -> None:
            try:
                if password.text():
                    _apply_fields()
                else:
                    # Update metadata without rewriting password
                    if not dev.config_source:
                        QMessageBox.information(
                            dlg, "Test", "Enter a password once to store credentials."
                        )
                        return
                    dev.config_source.host = host.text().strip()
                    dev.config_source.port = port.value()
                    dev.config_source.username = user.text().strip()
                    allow_insec = insecure.isChecked()
                    dev.config_source.verify_tls = verify.isChecked() and not allow_insec
                    dev.config_source.allow_insecure_tls = allow_insec
                    dev.config_source.ca_path = ca.text().strip()
                ok, msg = probe_connection(dev.config_source)  # type: ignore[arg-type]
                if ok:
                    QMessageBox.information(dlg, "Test", msg)
                else:
                    QMessageBox.warning(dlg, "Test failed", msg)
            except Exception as exc:  # noqa: BLE001
                QMessageBox.critical(dlg, "Test failed", str(exc))

        def on_collect() -> None:
            try:
                if password.text():
                    _apply_fields()
                elif not (dev.config_source and dev.config_source.credential_ref):
                    QMessageBox.information(
                        dlg, "Collect", "Enter and save a password first."
                    )
                    return
                else:
                    allow_insec = insecure.isChecked()
                    assert dev.config_source is not None
                    dev.config_source.host = host.text().strip()
                    dev.config_source.port = port.value()
                    dev.config_source.username = user.text().strip()
                    dev.config_source.verify_tls = verify.isChecked() and not allow_insec
                    dev.config_source.allow_insecure_tls = allow_insec
                    dev.config_source.ca_path = ca.text().strip()
                res = collect_export(dev, cache_base=Path("data"))
                if res.ok:
                    QMessageBox.information(
                        dlg,
                        "Collect",
                        f"Export saved to:\n{res.path}\n"
                        f"({res.bytes_read} bytes, hash {res.export_hash[:12]}…)\n"
                        f"Remote cleanup: {'yes' if res.cleaned_remote else 'no'}",
                    )
                    self._refresh_site()
                else:
                    QMessageBox.warning(dlg, "Collect failed", res.error)
            except Exception as exc:  # noqa: BLE001
                QMessageBox.critical(dlg, "Collect failed", str(exc))

        def on_save() -> None:
            if not host.text().strip() or not user.text().strip():
                QMessageBox.information(dlg, "Save", "Host and username are required.")
                return
            if not password.text() and not (
                dev.config_source and dev.config_source.credential_ref
            ):
                QMessageBox.information(
                    dlg, "Save", "Enter a password to store in Credential Manager."
                )
                return
            if password.text():
                _apply_fields()
            else:
                allow_insec = insecure.isChecked()
                assert dev.config_source is not None
                dev.config_source.host = host.text().strip()
                dev.config_source.port = port.value()
                dev.config_source.username = user.text().strip()
                dev.config_source.verify_tls = verify.isChecked() and not allow_insec
                dev.config_source.allow_insecure_tls = allow_insec
                dev.config_source.ca_path = ca.text().strip()
                dev.config_source.source_type = CONFIG_SOURCE_MIKROTIK_REST
            self._refresh_site()
            dlg.accept()

        test_btn.clicked.connect(on_test)
        collect_btn.clicked.connect(on_collect)
        buttons.accepted.connect(on_save)
        buttons.rejected.connect(dlg.reject)
        dlg.exec()

    def collect_all_configs(self) -> None:
        targets = [
            d
            for d in self._site.devices
            if d.ensure_config_source()
            and (
                d.config_source.source_type == CONFIG_SOURCE_MIKROTIK_REST
                or (d.config_source and d.config_source.host)
            )
        ]
        if not targets:
            QMessageBox.information(
                self,
                "Collect",
                "No MikroTik REST sources configured. "
                "Attach a .backup or Configure REST on a device first.",
            )
            return
        results = collect_all(targets, cache_base=Path("data"))
        lines = []
        ok_n = 0
        for name, res in results.items():
            if res.ok:
                ok_n += 1
                lines.append(f"OK  {name}: {res.path}")
            else:
                lines.append(f"ERR {name}: {res.error}")
        self._refresh_site()
        QMessageBox.information(
            self,
            "Collect all",
            f"{ok_n}/{len(results)} succeeded.\n\n" + "\n".join(lines),
        )
        self.statusBar().showMessage(
            f"Collected {ok_n}/{len(results)} MikroTik export(s)", 6000
        )

    def autodetect_links(self) -> None:
        """Infer device joins from attached configs (port comments / uplinks)."""
        report = infer_links_for_site(self._site)
        self._refresh_site()
        msg = report.summary()
        if report.notes:
            msg += "\n" + "\n".join(report.notes)
        QMessageBox.information(self, "Auto-detect Links", msg)
        self.statusBar().showMessage(
            f"Auto-detect links — {len(report.links_added)} added", 6000
        )

    def analyze_resiliency(self) -> None:
        self._ensure_workspace()
        self.statusBar().showMessage("Analyzing site resiliency…")
        try:
            with busy_cursor():
                report = analyze_site(self._site)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Resiliency", str(exc))
            return
        self._resiliency = report
        self._render_resiliency(report)
        # Jump to Resiliency tab
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == "Resiliency":
                self.tabs.setCurrentIndex(i)
                break
        self._refresh_ai_context()
        if self._result is not None:
            self._render_report(self._result)
        self.statusBar().showMessage(
            f"Resiliency — {report.error_count} errors, "
            f"{report.warning_count} warnings, {report.info_count} info",
            8000,
        )
        self._start_resiliency_ollama_deep_dive()

    def _start_resiliency_ollama_deep_dive(self) -> None:
        """If Ollama is available, enrich the current resiliency report off-thread."""
        report = self._resiliency
        if report is None:
            return
        if not ai.is_ollama_enabled():
            if hasattr(self, "res_ai_note"):
                self.res_ai_note.setPlainText(
                    "Ollama deep dive skipped (Ollama disabled in Setup)."
                )
            self.statusBar().showMessage("Ollama deep dive skipped", 4000)
            return
        if getattr(self, "_res_ollama_worker", None) is not None:
            if self._res_ollama_worker.isRunning():
                return

        url, model = ai.load_ollama_settings()
        api_key = ai.load_ollama_api_key()

        class _ResOllamaWorker(QThread):
            finished_ok = Signal(object)
            failed = Signal(str)

            def __init__(self, base: ResiliencyReport) -> None:
                super().__init__()
                self._base = base

            def run(self) -> None:  # noqa: D102
                try:
                    # Quick probe
                    ai.list_ollama_models(url, api_key=api_key, timeout=3)
                    enriched = enrich_report_with_ollama(
                        self._base,
                        model=model,
                        base_url=url,
                        api_key=api_key,
                    )
                    self.finished_ok.emit(enriched)
                except Exception as exc:  # noqa: BLE001
                    self.failed.emit(str(exc))

        if hasattr(self, "res_ai_note"):
            self.res_ai_note.setPlainText(
                "Ollama deep dive running for Loops / RST / Unbound / NAT / Firewall…"
            )
        self.statusBar().showMessage("Ollama deep dive running…")
        worker = _ResOllamaWorker(report)
        self._res_ollama_worker = worker
        worker.finished_ok.connect(self._on_resiliency_ollama_done)
        worker.failed.connect(self._on_resiliency_ollama_failed)
        show_busy_while(worker)
        worker.start()

    def _on_resiliency_ollama_done(self, report: object) -> None:
        if not isinstance(report, ResiliencyReport):
            return
        self._resiliency = report
        self._render_resiliency(report)
        self._update_resiliency_ai_note()
        self._refresh_ai_context()
        self.statusBar().showMessage(
            f"Resiliency + Ollama — {report.error_count} errors, "
            f"{report.warning_count} warnings, {report.info_count} info",
            8000,
        )

    def _on_resiliency_ollama_failed(self, message: str) -> None:
        if hasattr(self, "res_ai_note"):
            self.res_ai_note.setPlainText(f"Ollama deep dive skipped: {message}")
        self.statusBar().showMessage("Ollama deep dive skipped", 5000)

    def _resiliency_section_clicked(self, section: str) -> None:
        """Section strip: All | Loops | RST | Unbound | NAT | Firewall."""
        self._res_section = section
        if section == "All":
            self.res_cat.setCurrentText("All categories")
        else:
            # Prefer exact category match when present; otherwise keep filter text.
            idx = self.res_cat.findText(section)
            if idx >= 0:
                self.res_cat.setCurrentIndex(idx)
            else:
                self.res_cat.setCurrentText("All categories")
                self.res_search.setText(section)
        self._apply_resiliency_filter()
        self._update_resiliency_ai_note()

    def _update_resiliency_ai_note(self) -> None:
        if not hasattr(self, "res_ai_note"):
            return
        report = self._resiliency
        section = getattr(self, "_res_section", "All") or "All"
        if report is None:
            self.res_ai_note.clear()
            return
        notes = report.deep_dive_notes or {}
        if section == "All":
            if not notes:
                self.res_ai_note.setPlainText(
                    "No Ollama deep-dive notes yet. Run Analyze now "
                    "(Ollama must be enabled and reachable)."
                )
                return
            chunks = [f"## {cat}\n{text}" for cat, text in notes.items()]
            self.res_ai_note.setPlainText("\n\n".join(chunks))
            return
        text = notes.get(section, "")
        if text:
            self.res_ai_note.setPlainText(text)
        else:
            self.res_ai_note.setPlainText(
                f"No Ollama note for {section} yet."
            )

    def _render_resiliency(self, report: ResiliencyReport) -> None:
        s = report.summary
        if report.error_count:
            self.res_kpi["verdict"].set_value("FAIL", COLOR_ERROR)
        elif report.warning_count:
            self.res_kpi["verdict"].set_value("WARN", COLOR_WARN)
        else:
            self.res_kpi["verdict"].set_value("PASS", COLOR_OK)
        self.res_kpi["errors"].set_value(
            str(report.error_count),
            COLOR_ERROR if report.error_count else COLOR_OK,
        )
        self.res_kpi["warnings"].set_value(
            str(report.warning_count),
            COLOR_WARN if report.warning_count else COLOR_OK,
        )
        self.res_kpi["devices"].set_value(
            f"{s.get('with_config', 0)}/{s.get('devices', 0)}", COLOR_INFO
        )
        self.res_kpi["incomplete"].set_value(
            "YES" if s.get("incomplete") else "NO",
            COLOR_WARN if s.get("incomplete") else COLOR_OK,
        )

        cats = sorted({f.category for f in report.findings})
        current = self.res_cat.currentText()
        self.res_cat.blockSignals(True)
        self.res_cat.clear()
        self.res_cat.addItem("All categories")
        self.res_cat.addItems(cats)
        if current in cats:
            self.res_cat.setCurrentText(current)
        self.res_cat.blockSignals(False)
        self._apply_resiliency_filter()
        self._update_resiliency_ai_note()

    def _apply_resiliency_filter(self) -> None:
        report = self._resiliency
        if report is None:
            _fill(self.res_table, [])
            return
        sev = self.res_sev.currentText()
        cat = self.res_cat.currentText()
        q = self.res_search.text().strip().lower()
        rows = []
        self._res_filtered: list = []
        for f in sorted(report.findings, key=lambda x: SEVERITY_ORDER[x.severity]):
            if sev == "Errors" and f.severity is not Severity.ERROR:
                continue
            if sev == "Warnings" and f.severity is not Severity.WARNING:
                continue
            if sev == "Info" and f.severity is not Severity.INFO:
                continue
            if cat not in ("", "All categories") and f.category != cat:
                continue
            blob = " ".join(
                [
                    f.message,
                    f.impact,
                    f.remediation,
                    f.evidence,
                    " ".join(f.devices),
                    f.vlan,
                ]
            ).lower()
            if q and q not in blob:
                continue
            self._res_filtered.append(f)
            rows.append(
                [
                    f.severity.value.upper(),
                    f.category,
                    ", ".join(f.devices),
                    f.vlan,
                    f.message,
                    f.impact,
                    f.remediation,
                    f.certainty,
                ]
            )
        _fill(self.res_table, rows)
        for r, f in enumerate(self._res_filtered):
            color = SEVERITY_BG.get(f.severity)
            if color:
                for c in range(self.res_table.columnCount()):
                    item = self.res_table.item(r, c)
                    if item:
                        item.setBackground(color)

    def _resiliency_selection_changed(self) -> None:
        rows = self.res_table.selectionModel().selectedRows()
        if not rows or not getattr(self, "_res_filtered", None):
            return
        idx = rows[0].row()
        if idx < 0 or idx >= len(self._res_filtered):
            return
        f = self._res_filtered[idx]
        detail = (
            f"Severity: {f.severity.value}\n"
            f"Category: {f.category}\n"
            f"Devices: {', '.join(f.devices) or '-'}\n"
            f"Path: {' → '.join(f.path) or '-'}\n"
            f"VLAN: {f.vlan or '-'}\n"
            f"Certainty: {f.certainty}\n\n"
            f"Message:\n{f.message}\n\n"
            f"Evidence:\n{f.evidence or '(none)'}\n\n"
            f"Impact:\n{f.impact or '(none)'}\n\n"
            f"Remediation:\n{f.remediation or '(none)'}"
        )
        note = ""
        report = self._resiliency
        if report is not None and f.category in (report.deep_dive_notes or {}):
            note = (
                "\n\n--- AI deep dive ("
                + f.category
                + ") ---\n"
                + (report.deep_dive_notes.get(f.category) or "")[:2000]
            )
        self.res_detail.setPlainText(detail + note)
        self.site_view.highlight_devices(f.devices, path=f.path)

    def _clear_resiliency_highlight(self) -> None:
        self.site_view.clear_highlight()
        self.res_table.clearSelection()
        self.res_detail.clear()

    def _show_enrichment_report(self, report) -> None:  # noqa: ANN001
        msg = report.summary()
        if report.notes:
            msg += "\n" + "\n".join(report.notes)
        detail_bits = []
        if report.ports_added:
            detail_bits.append("Ports: " + ", ".join(report.ports_added[:20]))
        if report.vlans_added:
            detail_bits.append("New VLANs: " + ", ".join(report.vlans_added))
        if report.vlans_updated:
            detail_bits.append("Updated VLANs: " + ", ".join(report.vlans_updated))
        if report.bridges_added:
            detail_bits.append("Bridges: " + ", ".join(report.bridges_added))
        if report.vpn_added:
            detail_bits.append("VPN: " + ", ".join(report.vpn_added))
        if report.egress_added:
            detail_bits.append("Egress: " + ", ".join(report.egress_added))
        if detail_bits:
            msg += "\n\n" + "\n".join(detail_bits)
        QMessageBox.information(self, "Enrichment", msg)
        self.statusBar().showMessage(report.summary(), 7000)

    def import_current_as_device(self) -> None:
        """Create/update a device from the loaded config (additive merge of ports)."""
        if not self._result:
            QMessageBox.information(
                self, "Import", "Open a pfSense or MikroTik config first."
            )
            return
        self._site.add_or_update_device(device_from_result(self._result))
        self._refresh_site()

    def add_device(self) -> None:
        name = self.dev_name.text().strip()
        if not name:
            QMessageBox.information(self, "Device", "Enter a device name.")
            return
        ports = _csv_list(self.dev_ports.text())
        model = self.dev_model.currentText().strip()
        kind = self.dev_kind.currentText()
        if not ports:
            ports = default_ports_for_model(model)
        if not kind or kind == "switch":
            kind = kind_for_model(model) or kind
        self._site.add_or_update_device(
            Device(
                name=name,
                kind=kind,
                model=model,
                role=self.dev_role.currentText().strip(),
                secpol=self.dev_secpol.text().strip(),
                priority=self.dev_priority.text().strip(),
                hardware=self.dev_hw.text().strip(),
                ports=ports,
            )
        )
        self.dev_name.clear()
        self.dev_ports.clear()
        self.dev_secpol.clear()
        self.dev_priority.clear()
        self.dev_hw.clear()
        self._refresh_site()

    def remove_device(self) -> None:
        row = self.dev_table.currentRow()
        if row < 0 or row >= len(self._site.devices):
            return
        self._site.remove_device(self._site.devices[row].name)
        self._refresh_site()

    def _site_grid_changed(self, value: int) -> None:
        self._site.grid_size = value
        self.site_view.set_grid_size(value)

    def _site_snap_toggled(self, enabled: bool) -> None:
        self.site_view.set_snap(enabled)

    def _site_lock_toggled(self, locked: bool) -> None:
        self.site_view.set_locked(locked)

    def _site_arrange(self) -> None:
        self.site_view.arrange_by_tier()
        self.statusBar().showMessage("Arranged chassis by tier on grid", 4000)

    def _site_positions_changed(self) -> None:
        # Positions already written into Device.x/y by the canvas.
        self.statusBar().showMessage("Map positions updated (save site to keep)", 2500)

    def _site_links_changed(self) -> None:
        """Refresh the Links table after a port→port drag on the map."""
        if not hasattr(self, "link_table") or self._site is None:
            return
        _fill(
            self.link_table,
            [
                [
                    l.a_device, l.a_port, l.b_device, l.b_port, l.kind,
                    l.speed, ", ".join(l.vlans), l.native_vlan, l.descr,
                ]
                for l in self._site.links
            ],
        )
        self.statusBar().showMessage(
            "Port link added on map (save site to keep)", 3500
        )

    def load_example_site(self) -> None:
        self._replace_active_site(example_crs_site(), path=None)
        self.site_name_edit.setText(self._site.name)
        self._refresh_site()
        self.statusBar().showMessage("Loaded CRS109 → CRS328 → pfSense example", 5000)

    def import_excel_layout(self) -> None:
        from pfsense_checker.module_required import ensure_feature

        if not ensure_feature(
            self,
            "excel",
            purpose="Import Physical Layout Excel",
        ):
            return
        path_str, _ = QFileDialog.getOpenFileName(
            self,
            "Import Physical Layout Excel",
            "",
            "Excel (*.xlsx *.xlsm);;All Files (*)",
        )
        if not path_str:
            return
        try:
            site = import_physical_layout_xlsx(path_str)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Excel Import Failed", str(exc))
            return
        self._replace_active_site(site, path=None)
        self.site_name_edit.setText(self._site.name)
        self._refresh_site()
        summary = import_physical_layout_summary(site)
        QMessageBox.information(
            self,
            "Excel Import",
            f"Imported physical layout from:\n{path_str}\n\n{summary}\n\n"
            "Review links/VLANs — Excel drawings don't encode every cable, "
            "so trunks are inferred from device roles. Enrich from configs next.",
        )
        self.statusBar().showMessage(f"Imported Excel layout — {summary}", 8000)

    def add_link(self) -> None:
        a = self.link_a_dev.currentText().strip()
        b = self.link_b_dev.currentText().strip()
        if not a or not b:
            QMessageBox.information(self, "Link", "Choose both devices.")
            return
        self._site.links.append(
            Link(
                a_device=a,
                a_port=self.link_a_port.currentText().strip(),
                b_device=b,
                b_port=self.link_b_port.currentText().strip(),
                kind=self.link_kind.currentText(),
                speed=self.link_speed.text().strip(),
                descr=self.link_descr.text().strip(),
                vlans=_csv_list(self.link_vlans.text()),
                native_vlan=self.link_native.text().strip(),
            )
        )
        self.link_speed.clear()
        self.link_vlans.clear()
        self.link_native.clear()
        self.link_descr.clear()
        self._refresh_site()

    def remove_link(self) -> None:
        row = self.link_table.currentRow()
        if row < 0 or row >= len(self._site.links):
            return
        del self._site.links[row]
        self._refresh_site()

    def add_vlan(self) -> None:
        vid = self.vlan_id.text().strip()
        if not vid:
            QMessageBox.information(self, "VLAN", "Enter a VLAN ID.")
            return
        self._site.vlans.append(
            SiteVlan(
                id=vid,
                name=self.vlan_name.text().strip(),
                if_label=self.vlan_if.text().strip(),
                subnet=self.vlan_subnet.text().strip(),
                s_ip=self.vlan_sip.text().strip(),
                dhcp_pool=self.vlan_dhcp.text().strip(),
                devices=_csv_list(self.vlan_devices.text()),
                gateway=self.vlan_gw.currentText().strip(),
            )
        )
        self.vlan_id.clear()
        self.vlan_name.clear()
        self.vlan_if.clear()
        self.vlan_subnet.clear()
        self.vlan_sip.clear()
        self.vlan_dhcp.clear()
        self.vlan_devices.clear()
        self._refresh_site()

    def remove_vlan(self) -> None:
        row = self.vlan_table.currentRow()
        if row < 0 or row >= len(self._site.vlans):
            return
        del self._site.vlans[row]
        self._refresh_site()

    def add_bridge(self) -> None:
        name = self.br_name.text().strip()
        if not name:
            QMessageBox.information(self, "Bridge", "Enter a bridge name.")
            return
        self._site.bridges.append(
            SiteBridge(
                name=name,
                devices=_csv_list(self.br_devices.text()),
                ports=_csv_list(self.br_ports.text()),
                vlan=self.br_vlan.text().strip(),
                notes=self.br_notes.text().strip(),
            )
        )
        self.br_name.clear()
        self.br_devices.clear()
        self.br_ports.clear()
        self.br_vlan.clear()
        self.br_notes.clear()
        self._refresh_site()

    def remove_bridge(self) -> None:
        row = self.bridge_table.currentRow()
        if row < 0 or row >= len(self._site.bridges):
            return
        del self._site.bridges[row]
        self._refresh_site()

    def add_vpn_agreement(self) -> None:
        name = self.vpn_name.text().strip()
        if not name:
            QMessageBox.information(self, "VPN", "Enter a VPN agreement name.")
            return
        self._site.vpn.append(
            VpnAgreement(
                name=name,
                kind=self.vpn_kind.currentText(),
                a_device=self.vpn_a.currentText().strip(),
                b_device=self.vpn_b.currentText().strip(),
                local_endpoint=self.vpn_local.text().strip(),
                remote_endpoint=self.vpn_remote.text().strip(),
                networks=_csv_list(self.vpn_nets.text()),
                notes=self.vpn_notes.text().strip(),
            )
        )
        self.vpn_name.clear()
        self.vpn_local.clear()
        self.vpn_remote.clear()
        self.vpn_nets.clear()
        self.vpn_notes.clear()
        self._refresh_site()

    def remove_vpn_agreement(self) -> None:
        row = self.vpn_site_table.currentRow()
        if row < 0 or row >= len(self._site.vpn):
            return
        del self._site.vpn[row]
        self._refresh_site()

    def add_egress(self) -> None:
        name = self.eg_name.text().strip()
        if not name:
            QMessageBox.information(self, "Egress", "Enter an egress path name.")
            return
        self._site.egress.append(
            EgressPath(
                name=name,
                device=self.eg_device.currentText().strip(),
                uplink_port=self.eg_port.text().strip(),
                upstream=self.eg_up.currentText().strip(),
                wan_subnet=self.eg_wan.text().strip(),
                default_for=_csv_list(self.eg_default.text()),
                notes=self.eg_notes.text().strip(),
            )
        )
        self.eg_name.clear()
        self.eg_port.clear()
        self.eg_wan.clear()
        self.eg_default.clear()
        self.eg_notes.clear()
        self._refresh_site()

    def remove_egress(self) -> None:
        row = self.egress_table.currentRow()
        if row < 0 or row >= len(self._site.egress):
            return
        del self._site.egress[row]
        self._refresh_site()

    def load_site(self) -> None:
        path_str, _ = QFileDialog.getOpenFileName(
            self, "Load Site Topology", "", "Site JSON (*.json);;All Files (*)"
        )
        if not path_str:
            return
        try:
            self._replace_active_site(
                SiteTopology.load(path_str), path=Path(path_str)
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            QMessageBox.critical(self, "Load Failed", str(exc))
            return
        self.site_name_edit.setText(self._site.name)
        self._refresh_site()
        self.statusBar().showMessage(f"Loaded site from {path_str}", 5000)

    def save_site(self) -> None:
        self._site_name_changed()
        default = str(self._site_path or "site_topology.json")
        path_str, _ = QFileDialog.getSaveFileName(
            self, "Save Site Topology", default, "Site JSON (*.json);;All Files (*)"
        )
        if not path_str:
            return
        try:
            self._site.save(path_str)
            self._site_path = Path(path_str)
        except OSError as exc:
            QMessageBox.critical(self, "Save Failed", str(exc))
            return
        self.statusBar().showMessage(f"Saved site to {path_str}", 5000)

    def _refresh_site(self) -> None:
        if not getattr(self, "_workspace_built", False):
            if getattr(self, "home_screen", None) is not None:
                self._sync_home_sites()
            return
        _fill(
            self.dev_table,
            [
                [
                    d.name, d.kind, d.model, d.role, d.secpol, d.priority,
                    ", ".join(d.ports[:12]) + ("…" if len(d.ports) > 12 else ""),
                    d.hardware,
                    _device_config_label(d),
                ]
                for d in self._site.devices
            ],
        )
        _fill(
            self.link_table,
            [
                [
                    l.a_device, l.a_port, l.b_device, l.b_port, l.kind,
                    l.speed, ", ".join(l.vlans), l.native_vlan, l.descr,
                ]
                for l in self._site.links
            ],
        )
        _fill(
            self.vlan_table,
            [
                [
                    v.id, v.name, v.if_label, v.subnet, v.s_ip, v.dhcp_pool,
                    ", ".join(v.devices), v.gateway,
                ]
                for v in self._site.vlans
            ],
        )
        _fill(
            self.bridge_table,
            [
                [b.name, ", ".join(b.devices), ", ".join(b.ports), b.vlan, b.notes]
                for b in self._site.bridges
            ],
        )
        _fill(
            self.vpn_site_table,
            [
                [
                    v.name, v.kind, v.a_device, v.b_device,
                    v.local_endpoint, v.remote_endpoint,
                    ", ".join(v.networks), v.notes,
                ]
                for v in self._site.vpn
            ],
        )
        _fill(
            self.egress_table,
            [
                [
                    e.name, e.device, e.uplink_port, e.upstream,
                    e.wan_subnet, ", ".join(e.default_for), e.notes,
                ]
                for e in self._site.egress
            ],
        )
        self._sync_device_combos()
        self.site_grid.blockSignals(True)
        self.site_grid.setValue(int(self._site.grid_size or 20))
        self.site_grid.blockSignals(False)
        self.site_view.set_grid_size(self._site.grid_size)
        self.site_view.set_snap(self.site_snap.isChecked())
        self.site_view.render_site(self._site)
        problems = self._site.validate()
        self.site_warnings.setText("  ·  ".join(problems) if problems else "")
        if getattr(self, "home_screen", None) is not None:
            self._sync_home_sites()

    def _build_resiliency_tab(self) -> None:
        page = QWidget()
        v = QVBoxLayout(page)

        intro = QLabel(
            "<b>Site Resiliency</b> — combines Topology Builder wiring with every "
            "attached pfSense XML and MikroTik REST export. "
            "Binary <code>.backup</code> files are restore evidence only; analysis "
            "uses the live sanitized export."
        )
        intro.setTextFormat(Qt.TextFormat.RichText)
        intro.setWordWrap(True)
        v.addWidget(intro)

        self.res_kpi: dict[str, KpiCard] = {}
        kpi_row = QHBoxLayout()
        for key, caption in (
            ("verdict", "Result"),
            ("errors", "Errors"),
            ("warnings", "Warnings"),
            ("devices", "Devices w/ config"),
            ("incomplete", "Incomplete"),
        ):
            card = KpiCard(caption)
            self.res_kpi[key] = card
            kpi_row.addWidget(card)
        v.addLayout(kpi_row)

        # Deep-dive section strip
        self._res_section = "All"
        section_row = QHBoxLayout()
        section_row.addWidget(QLabel("Deep dive:"))
        self._res_section_btns: dict[str, QPushButton] = {}
        for label in ("All", *DEEP_DIVE_CATEGORIES):
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setChecked(label == "All")
            btn.clicked.connect(
                lambda _checked=False, s=label: self._resiliency_section_clicked(s)
            )
            self._res_section_btns[label] = btn
            section_row.addWidget(btn)
        section_row.addStretch(1)
        v.addLayout(section_row)

        controls = QHBoxLayout()
        self.res_sev = QComboBox()
        self.res_sev.addItems(["All", "Errors", "Warnings", "Info"])
        self.res_sev.currentIndexChanged.connect(self._apply_resiliency_filter)
        controls.addWidget(QLabel("Severity:"))
        controls.addWidget(self.res_sev)
        self.res_cat = QComboBox()
        self.res_cat.addItem("All categories")
        self.res_cat.currentIndexChanged.connect(self._apply_resiliency_filter)
        controls.addWidget(QLabel("Category:"))
        controls.addWidget(self.res_cat)
        self.res_search = QLineEdit()
        self.res_search.setPlaceholderText("Filter text…")
        self.res_search.textChanged.connect(self._apply_resiliency_filter)
        controls.addWidget(self.res_search, stretch=1)
        btn_run = QPushButton("Analyze now")
        btn_run.clicked.connect(self.analyze_resiliency)
        controls.addWidget(btn_run)
        btn_clear = QPushButton("Clear highlight")
        btn_clear.clicked.connect(self._clear_resiliency_highlight)
        controls.addWidget(btn_clear)
        v.addLayout(controls)

        self.res_table = _table(
            [
                "Severity",
                "Category",
                "Devices",
                "VLAN",
                "Message",
                "Impact",
                "Remediation",
                "Certainty",
            ]
        )
        self.res_table.itemSelectionChanged.connect(self._resiliency_selection_changed)
        v.addWidget(self.res_table, stretch=1)

        self.res_detail = QTextEdit()
        self.res_detail.setReadOnly(True)
        self.res_detail.setMaximumHeight(120)
        self.res_detail.setPlaceholderText("Select a finding for evidence / path details")
        v.addWidget(self.res_detail)

        self.res_ai_note = QTextEdit()
        self.res_ai_note.setReadOnly(True)
        self.res_ai_note.setMaximumHeight(140)
        self.res_ai_note.setPlaceholderText(
            "Ollama deep-dive notes for the selected section appear here "
            "when Ollama is enabled and Analyze finishes."
        )
        v.addWidget(self.res_ai_note)

        self.tabs.addTab(page, "Resiliency")

    def _build_findings_tab(self) -> None:
        page = QWidget()
        v = QVBoxLayout(page)

        controls = QHBoxLayout()
        self.sev_filter = QComboBox()
        self.sev_filter.addItems(["All", "Errors", "Warnings", "Info"])
        self.sev_filter.currentIndexChanged.connect(self._apply_finding_filter)
        controls.addWidget(QLabel("Severity:"))
        controls.addWidget(self.sev_filter)

        self.cat_filter = QComboBox()
        self.cat_filter.addItem("All categories")
        self.cat_filter.currentIndexChanged.connect(self._apply_finding_filter)
        controls.addWidget(QLabel("Category:"))
        controls.addWidget(self.cat_filter)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter text…")
        self.search.textChanged.connect(self._apply_finding_filter)
        controls.addWidget(self.search, stretch=1)
        v.addLayout(controls)

        self.findings_table = _table(["Severity", "Category", "Path", "Line", "Message"])
        self.findings_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.findings_table.customContextMenuRequested.connect(self._findings_context_menu)
        v.addWidget(self.findings_table)
        self.tabs.addTab(page, "Findings")

    def _build_interfaces_tab(self) -> None:
        self.iface_table = _table(
            ["Name", "Enabled", "Device", "Kind", "IPv4", "IPv6", "Bridge member of", "Description"]
        )
        self.tabs.addTab(self.iface_table, "Interfaces")

    def _build_virtual_tab(self) -> None:
        page = QWidget()
        v = QVBoxLayout(page)
        v.addWidget(QLabel("Bridges"))
        self.bridge_table = _table(["Bridge", "Members", "STP", "Assigned as", "Description"])
        v.addWidget(self.bridge_table)
        v.addWidget(QLabel("VLANs"))
        self.vlan_table = _table(["Tag", "Parent if", "VLAN if", "Assigned as", "Description"])
        v.addWidget(self.vlan_table)
        v.addWidget(QLabel("LAGGs"))
        self.lagg_table = _table(["LAGG", "Proto", "Members", "Assigned as", "Description"])
        v.addWidget(self.lagg_table)
        self.tabs.addTab(page, "Bridges/VLANs/LAGG")

    def _build_rules_tab(self) -> None:
        page = QWidget()
        v = QVBoxLayout(page)
        v.addWidget(QLabel("Firewall rules"))
        self.filter_table = _table(
            ["#", "Type", "Interface", "Source", "Destination", "Disabled", "Description"]
        )
        v.addWidget(self.filter_table)
        v.addWidget(QLabel("NAT rules"))
        self.nat_table = _table(["Kind", "Interface", "Target/External", "Disabled", "Description"])
        v.addWidget(self.nat_table)
        self.tabs.addTab(page, "Firewall/NAT")

    def _build_vpn_tab(self) -> None:
        self.vpn_table = _table(["Kind", "Name", "Interface", "Disabled", "Details"])
        self.tabs.addTab(self.vpn_table, "VPN")

    def _build_services_net_tab(self) -> None:
        page = QWidget()
        v = QVBoxLayout(page)
        v.addWidget(QLabel("Gateways"))
        self.gw_table = _table(["Name", "Interface", "Gateway", "Proto", "Default", "Disabled"])
        v.addWidget(self.gw_table)
        v.addWidget(QLabel("DHCP scopes"))
        self.dhcp_table = _table(["Interface", "Family", "Enabled", "From", "To", "Static maps"])
        v.addWidget(self.dhcp_table)
        v.addWidget(QLabel("Static routes / Virtual IPs / Aliases (counts in Overview)"))
        self.route_table = _table(["Type", "A", "B", "C", "Disabled"])
        v.addWidget(self.route_table)
        self.tabs.addTab(page, "Routing/DHCP")

    def _build_packages_tab(self) -> None:
        page = QWidget()
        v = QVBoxLayout(page)
        v.addWidget(QLabel("Installed packages"))
        self.pkg_table = _table(["Name", "Version", "Enabled", "State detail", "Description"])
        v.addWidget(self.pkg_table)
        v.addWidget(QLabel("Registered services"))
        self.svc_table = _table(["Name", "Executable", "Enabled", "Description"])
        v.addWidget(self.svc_table)
        self.tabs.addTab(page, "Packages/Services")

    def _build_monitor_tab(self) -> None:
        page = QWidget()
        v = QVBoxLayout(page)

        tip = QLabel(
            "Continuous monitoring: corridor beacons (one per subnet, or one trunked host "
            "with multiple VLAN/dhcp configs) POST ping + DHCP results to the collector. "
            "Start collector with  python run_collector.py  then run beacons with "
            "python run_beacon.py --config samples/beacon_lan.json"
        )
        tip.setWordWrap(True)
        tip.setStyleSheet("color: #555; padding-bottom: 4px;")
        v.addWidget(tip)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Collector:"))
        self.monitor_url = QLineEdit("http://127.0.0.1:8787")
        controls.addWidget(self.monitor_url, stretch=1)
        controls.addWidget(QLabel("Token:"))
        self.monitor_token = QLineEdit()
        self.monitor_token.setEchoMode(QLineEdit.EchoMode.Password)
        self.monitor_token.setPlaceholderText("(optional)")
        self.monitor_token.setMaximumWidth(160)
        controls.addWidget(self.monitor_token)

        self.monitor_fails_only = QCheckBox("Fails only")
        controls.addWidget(self.monitor_fails_only)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_monitor)
        controls.addWidget(refresh_btn)

        self.monitor_auto = QCheckBox("Auto-refresh")
        self.monitor_auto.toggled.connect(self._toggle_monitor_auto)
        controls.addWidget(self.monitor_auto)

        controls.addWidget(QLabel("every"))
        self.monitor_interval = QSpinBox()
        self.monitor_interval.setRange(5, 600)
        self.monitor_interval.setValue(15)
        self.monitor_interval.setSuffix(" s")
        self.monitor_interval.valueChanged.connect(self._update_monitor_interval)
        controls.addWidget(self.monitor_interval)
        v.addLayout(controls)

        self.monitor_status = QLabel("Not connected")
        v.addWidget(self.monitor_status)

        # KPI cards for live status
        self.monitor_kpis: dict[str, KpiCard] = {}
        kpi_row = QHBoxLayout()
        for key, caption in [
            ("beacons", "Beacons"),
            ("online", "Online"),
            ("ping", "Ping OK/Fail (1h)"),
            ("dhcp", "DHCP OK/Fail (1h)"),
        ]:
            card = KpiCard(caption)
            self.monitor_kpis[key] = card
            kpi_row.addWidget(card)
        v.addLayout(kpi_row)

        charts_row = QHBoxLayout()
        self.monitor_latency_chart = TimeSeriesChartView("Ping latency (recent)", "ms")
        self.monitor_status_donut = DonutChartView("Recent probe status")
        charts_row.addWidget(self.monitor_latency_chart, stretch=2)
        charts_row.addWidget(self.monitor_status_donut, stretch=1)
        v.addLayout(charts_row)

        v.addWidget(QLabel("Beacons"))
        self.beacon_table = _table(
            [
                "Beacon",
                "Site",
                "Host",
                "Online",
                "Last seen",
                "Ping OK/Fail",
                "DHCP OK/Fail",
                "Last message",
            ]
        )
        v.addWidget(self.beacon_table)

        v.addWidget(QLabel("Recent probe results"))
        self.probe_table = _table(
            ["Time", "Beacon", "Kind", "Status", "Target", "Subnet", "Latency ms", "Message"]
        )
        v.addWidget(self.probe_table)

        self.tabs.addTab(page, "Live Monitor")

    def _build_beacon_creator_tab(self) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        page = QWidget()
        scroll.setWidget(page)
        outer = QVBoxLayout(page)

        intro = QLabel(
            "Generate a self-contained, stdlib-only beacon bundle (no pip needed on the "
            "target). Choose target OSes and deploy the produced folder/zip. DHCP probes "
            "require admin/root on the beacon host."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #555;")
        outer.addWidget(intro)

        # --- Identity / collector ---
        ident = QGroupBox("Beacon identity & collector")
        form = QFormLayout(ident)
        self.bc_id = QLineEdit("beacon-01")
        self.bc_hostname = QLineEdit()
        self.bc_hostname.setPlaceholderText("(defaults to the host's name)")
        self.bc_site = QLineEdit()
        self.bc_collector = QLineEdit("http://COLLECTOR_HOST:8787")
        self.bc_token = QLineEdit()
        self.bc_token.setPlaceholderText("(optional, must match collector --token)")
        form.addRow("Beacon ID", self.bc_id)
        form.addRow("Hostname", self.bc_hostname)
        form.addRow("Site", self.bc_site)
        form.addRow("Collector URL", self.bc_collector)
        form.addRow("Token", self.bc_token)
        outer.addWidget(ident)

        # --- Timing ---
        timing = QGroupBox("Timing")
        trow = QHBoxLayout(timing)
        self.bc_interval = QSpinBox()
        self.bc_interval.setRange(10, 3600)
        self.bc_interval.setValue(60)
        self.bc_interval.setSuffix(" s interval")
        self.bc_ping_count = QSpinBox()
        self.bc_ping_count.setRange(1, 10)
        self.bc_ping_count.setValue(2)
        self.bc_ping_count.setPrefix("ping x")
        self.bc_ping_timeout = QDoubleSpinBox()
        self.bc_ping_timeout.setRange(0.5, 30.0)
        self.bc_ping_timeout.setValue(2.0)
        self.bc_ping_timeout.setSuffix(" s ping t/o")
        self.bc_dhcp_timeout = QDoubleSpinBox()
        self.bc_dhcp_timeout.setRange(1.0, 60.0)
        self.bc_dhcp_timeout.setValue(5.0)
        self.bc_dhcp_timeout.setSuffix(" s dhcp t/o")
        self.bc_dhcp_release = QCheckBox("DHCP decline offer (don't hold lease)")
        self.bc_dhcp_release.setChecked(True)
        for w in (self.bc_interval, self.bc_ping_count, self.bc_ping_timeout, self.bc_dhcp_timeout):
            trow.addWidget(w)
        trow.addWidget(self.bc_dhcp_release)
        outer.addWidget(timing)

        # --- Ping targets ---
        ping_box = QGroupBox("Ping targets")
        pv = QVBoxLayout(ping_box)
        self.bc_ping_table = QTableWidget(0, 3)
        self.bc_ping_table.setHorizontalHeaderLabels(["Host/IP", "Subnet label", "Interface"])
        self.bc_ping_table.horizontalHeader().setStretchLastSection(True)
        pv.addWidget(self.bc_ping_table)
        pbtns = QHBoxLayout()
        add_ping = QPushButton("Add row")
        add_ping.clicked.connect(lambda: self._bc_add_ping_row())
        del_ping = QPushButton("Remove selected")
        del_ping.clicked.connect(lambda: self._bc_del_rows(self.bc_ping_table))
        pbtns.addWidget(add_ping)
        pbtns.addWidget(del_ping)
        pbtns.addStretch(1)
        pv.addLayout(pbtns)
        outer.addWidget(ping_box)

        # --- DHCP targets ---
        dhcp_box = QGroupBox("DHCP probe targets (bind UDP/68 — needs admin/root)")
        dv = QVBoxLayout(dhcp_box)
        self.bc_dhcp_table = QTableWidget(0, 4)
        self.bc_dhcp_table.setHorizontalHeaderLabels(
            ["Subnet label", "Interface", "Bind IP", "Enabled (yes/no)"]
        )
        self.bc_dhcp_table.horizontalHeader().setStretchLastSection(True)
        dv.addWidget(self.bc_dhcp_table)
        dbtns = QHBoxLayout()
        add_dhcp = QPushButton("Add row")
        add_dhcp.clicked.connect(lambda: self._bc_add_dhcp_row())
        del_dhcp = QPushButton("Remove selected")
        del_dhcp.clicked.connect(lambda: self._bc_del_rows(self.bc_dhcp_table))
        dbtns.addWidget(add_dhcp)
        dbtns.addWidget(del_dhcp)
        dbtns.addStretch(1)
        dv.addLayout(dbtns)
        outer.addWidget(dhcp_box)

        # --- Targets + output ---
        gen = QGroupBox("Generate")
        gv = QVBoxLayout(gen)
        os_row = QHBoxLayout()
        os_row.addWidget(QLabel("Target OS:"))
        self.bc_os_checks: dict[str, QCheckBox] = {}
        for key, label in [
            ("windows", "Windows"),
            ("macos", "macOS"),
            ("linux", "Linux (Kubuntu/Debian)"),
            ("bsd", "BSD (FreeBSD)"),
        ]:
            cb = QCheckBox(label)
            cb.setChecked(True)
            self.bc_os_checks[key] = cb
            os_row.addWidget(cb)
        os_row.addStretch(1)
        gv.addLayout(os_row)

        out_row = QHBoxLayout()
        out_row.addWidget(QLabel("Output folder:"))
        self.bc_outdir = QLineEdit(str((Path.cwd() / "beacons").resolve()))
        out_row.addWidget(self.bc_outdir, stretch=1)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._bc_pick_outdir)
        out_row.addWidget(browse)
        self.bc_zip = QCheckBox("Also .zip")
        self.bc_zip.setChecked(True)
        out_row.addWidget(self.bc_zip)
        gv.addLayout(out_row)

        action_row = QHBoxLayout()
        load_btn = QPushButton("Load config…")
        load_btn.clicked.connect(self._bc_load_config)
        save_btn = QPushButton("Save config…")
        save_btn.clicked.connect(self._bc_save_config)
        prefill_btn = QPushButton("Prefill from checked config")
        prefill_btn.clicked.connect(self._bc_prefill_from_result)
        gen_btn = QPushButton("Generate bundle(s)")
        gen_btn.setStyleSheet("font-weight: bold;")
        gen_btn.clicked.connect(self._bc_generate)
        action_row.addWidget(load_btn)
        action_row.addWidget(save_btn)
        action_row.addWidget(prefill_btn)
        action_row.addStretch(1)
        action_row.addWidget(gen_btn)
        gv.addLayout(action_row)

        self.bc_output = QTextEdit()
        self.bc_output.setReadOnly(True)
        self.bc_output.setFont(QFont("Consolas", 9))
        self.bc_output.setMaximumHeight(160)
        self.bc_output.setPlaceholderText("Generation output…")
        gv.addWidget(self.bc_output)
        outer.addWidget(gen)
        outer.addStretch(1)

        # seed with defaults
        self._bc_apply_config(default_config("beacon-01"))
        self.tabs.addTab(scroll, "Beacon Creator")

    def _bc_add_ping_row(self, host: str = "", subnet: str = "", iface: str = "") -> None:
        t = self.bc_ping_table
        r = t.rowCount()
        t.insertRow(r)
        t.setItem(r, 0, QTableWidgetItem(host))
        t.setItem(r, 1, QTableWidgetItem(subnet))
        t.setItem(r, 2, QTableWidgetItem(iface))

    def _bc_add_dhcp_row(
        self, subnet: str = "", iface: str = "", bind_ip: str = "0.0.0.0", enabled: bool = True
    ) -> None:
        t = self.bc_dhcp_table
        r = t.rowCount()
        t.insertRow(r)
        t.setItem(r, 0, QTableWidgetItem(subnet))
        t.setItem(r, 1, QTableWidgetItem(iface))
        t.setItem(r, 2, QTableWidgetItem(bind_ip))
        t.setItem(r, 3, QTableWidgetItem("yes" if enabled else "no"))

    def _bc_del_rows(self, table: QTableWidget) -> None:
        for idx in sorted({i.row() for i in table.selectedIndexes()}, reverse=True):
            table.removeRow(idx)

    def _bc_pick_outdir(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Choose output folder", self.bc_outdir.text())
        if d:
            self.bc_outdir.setText(d)

    def _bc_apply_config(self, cfg: dict) -> None:
        self.bc_id.setText(str(cfg.get("beacon_id", "")))
        self.bc_hostname.setText(str(cfg.get("hostname", "")))
        self.bc_site.setText(str(cfg.get("site", "")))
        self.bc_collector.setText(str(cfg.get("collector_url", "")))
        self.bc_token.setText(str(cfg.get("token", "")))
        self.bc_interval.setValue(int(cfg.get("interval_sec", 60)))
        self.bc_ping_count.setValue(int(cfg.get("ping_count", 2)))
        self.bc_ping_timeout.setValue(float(cfg.get("ping_timeout", 2.0)))
        self.bc_dhcp_timeout.setValue(float(cfg.get("dhcp_timeout", 5.0)))
        self.bc_dhcp_release.setChecked(bool(cfg.get("dhcp_release_offer", True)))

        self.bc_ping_table.setRowCount(0)
        for target in cfg.get("ping_targets") or []:
            if isinstance(target, str):
                self._bc_add_ping_row(target)
            else:
                self._bc_add_ping_row(
                    target.get("host", ""), target.get("subnet", ""), target.get("interface", "")
                )
        self.bc_dhcp_table.setRowCount(0)
        for target in cfg.get("dhcp_targets") or []:
            if isinstance(target, str):
                self._bc_add_dhcp_row(subnet=target)
            else:
                self._bc_add_dhcp_row(
                    target.get("subnet", ""),
                    target.get("interface", ""),
                    target.get("bind_ip", "0.0.0.0"),
                    bool(target.get("enabled", True)),
                )

    def _bc_collect_config(self) -> dict:
        ping_targets = []
        for r in range(self.bc_ping_table.rowCount()):
            host = self._cell(self.bc_ping_table, r, 0)
            if not host:
                continue
            ping_targets.append(
                {
                    "host": host,
                    "subnet": self._cell(self.bc_ping_table, r, 1),
                    "interface": self._cell(self.bc_ping_table, r, 2),
                }
            )
        dhcp_targets = []
        for r in range(self.bc_dhcp_table.rowCount()):
            subnet = self._cell(self.bc_dhcp_table, r, 0)
            iface = self._cell(self.bc_dhcp_table, r, 1)
            if not subnet and not iface:
                continue
            dhcp_targets.append(
                {
                    "subnet": subnet,
                    "interface": iface,
                    "bind_ip": self._cell(self.bc_dhcp_table, r, 2) or "0.0.0.0",
                    "enabled": self._cell(self.bc_dhcp_table, r, 3).strip().lower()
                    in ("yes", "true", "1", "y"),
                }
            )
        return {
            "beacon_id": self.bc_id.text().strip() or "beacon-01",
            "hostname": self.bc_hostname.text().strip(),
            "site": self.bc_site.text().strip(),
            "version": "1.1.0",
            "collector_url": self.bc_collector.text().strip(),
            "token": self.bc_token.text().strip(),
            "interval_sec": self.bc_interval.value(),
            "ping_count": self.bc_ping_count.value(),
            "ping_timeout": self.bc_ping_timeout.value(),
            "dhcp_timeout": self.bc_dhcp_timeout.value(),
            "dhcp_release_offer": self.bc_dhcp_release.isChecked(),
            "ping_targets": ping_targets,
            "dhcp_targets": dhcp_targets,
        }

    @staticmethod
    def _cell(table: QTableWidget, row: int, col: int) -> str:
        item = table.item(row, col)
        return item.text().strip() if item else ""

    def _bc_prefill_from_result(self) -> None:
        if not self._result:
            QMessageBox.information(
                self, "Prefill", "Check a pfSense config first (Dashboard/Findings)."
            )
            return
        result = self._result
        self.bc_site.setText(result.hostname or self.bc_site.text())
        self.bc_ping_table.setRowCount(0)
        self.bc_dhcp_table.setRowCount(0)
        for i in result.interfaces:
            if not i.enabled:
                continue
            gw_ip = i.ipaddr if i.ipaddr and i.ipaddr not in ("dhcp", "pppoe") else ""
            subnet_label = (
                f"{i.ipaddr}/{i.subnet}" if i.subnet and gw_ip else (i.name)
            )
            if gw_ip:
                self._bc_add_ping_row(gw_ip, subnet_label, i.name)
        # DHCP rows from scopes
        for scope in result.dhcp_scopes:
            if scope.get("family") != "v4":
                continue
            self._bc_add_dhcp_row(
                subnet=scope.get("interface", ""),
                iface=scope.get("interface", ""),
                enabled=scope.get("enabled") == "yes",
            )
        if self.bc_ping_table.rowCount() == 0:
            self._bc_add_ping_row("1.1.1.1", "wan", "wan")
        self.bc_output.setPlainText(
            "Prefilled ping/DHCP targets from the loaded pfSense config. "
            "Review and set the collector URL before generating."
        )

    def _bc_load_config(self) -> None:
        path_str, _ = QFileDialog.getOpenFileName(
            self, "Load beacon config", "", "JSON (*.json);;All Files (*)"
        )
        if not path_str:
            return
        try:
            cfg = json.loads(Path(path_str).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            QMessageBox.critical(self, "Load failed", str(exc))
            return
        self._bc_apply_config(cfg)
        self.bc_output.setPlainText(f"Loaded {path_str}")

    def _bc_save_config(self) -> None:
        cfg = self._bc_collect_config()
        path_str, _ = QFileDialog.getSaveFileName(
            self, "Save beacon config", f"beacon_{cfg['beacon_id']}.json",
            "JSON (*.json);;All Files (*)"
        )
        if not path_str:
            return
        try:
            Path(path_str).write_text(json.dumps(cfg, indent=2), encoding="utf-8")
            self.bc_output.setPlainText(f"Saved config to {path_str}")
        except OSError as exc:
            QMessageBox.critical(self, "Save failed", str(exc))

    def _bc_generate(self) -> None:
        cfg = self._bc_collect_config()
        targets = [k for k, cb in self.bc_os_checks.items() if cb.isChecked()]
        if not targets:
            QMessageBox.warning(self, "Generate", "Select at least one target OS.")
            return
        if not cfg["collector_url"] or "COLLECTOR_HOST" in cfg["collector_url"]:
            resp = QMessageBox.question(
                self,
                "Collector URL",
                "Collector URL still looks like a placeholder. Generate anyway?",
            )
            if resp != QMessageBox.StandardButton.Yes:
                return
        try:
            res = build_bundle(
                cfg, targets, Path(self.bc_outdir.text().strip() or "beacons"),
                make_zip=self.bc_zip.isChecked(),
            )
        except (ValueError, OSError) as exc:
            QMessageBox.critical(self, "Generation failed", str(exc))
            return

        lines = [
            f"Bundle: {res.bundle_dir}",
            f"Zip:    {res.zip_path or '(none)'}",
            f"Targets: {', '.join(targets)}",
            "",
            "Files:",
        ]
        lines += [f"  {f}" for f in res.files]
        if res.warnings:
            lines += ["", "Warnings:"] + [f"  {w}" for w in res.warnings]
        self.bc_output.setPlainText("\n".join(lines))
        self.statusBar().showMessage(f"Beacon bundle generated at {res.bundle_dir}", 8000)

    def _build_ai_tab(self) -> None:
        page = QWidget()
        self.ai_tab = page
        v = QVBoxLayout(page)

        blurb = QLabel(
            "Ask a local <b>Ollama</b> model or a Poe bot to prioritise and explain "
            "the findings. "
            "<b>Only redacted findings are sent</b> — never raw config, secrets, keys "
            "or hashes. Ollama stays on your configured local endpoint. Nothing is "
            "sent until you click <b>Ask Advisor</b>."
        )
        blurb.setTextFormat(Qt.TextFormat.RichText)
        blurb.setWordWrap(True)
        v.addWidget(blurb)

        ollama_url, ollama_model = ai.load_ollama_settings()
        ollama_on = ai.is_ollama_enabled()

        cfg = QHBoxLayout()
        cfg.addWidget(QLabel("Provider:"))
        self.ai_provider = QComboBox()
        self.ai_provider.addItems(["Ollama (local)", "Poe"])
        if not ollama_on:
            self.ai_provider.setCurrentText("Poe")
        self.ai_provider.currentTextChanged.connect(self._ai_provider_changed)
        cfg.addWidget(self.ai_provider)
        cfg.addWidget(QLabel("Model / bot:"))
        self.ai_bot = QComboBox()
        self.ai_bot.setEditable(True)
        self.ai_bot.addItem(ollama_model)
        cfg.addWidget(self.ai_bot, stretch=1)
        self.ai_refresh_models = QPushButton("Refresh models")
        self.ai_refresh_models.clicked.connect(self._ai_refresh_ollama_models)
        cfg.addWidget(self.ai_refresh_models)
        v.addLayout(cfg)

        connection = QHBoxLayout()
        connection.addWidget(QLabel("Ollama URL:"))
        self.ai_ollama_url = QLineEdit(ollama_url)
        self.ai_ollama_url.setPlaceholderText(ai.DEFAULT_OLLAMA_URL)
        connection.addWidget(self.ai_ollama_url, stretch=1)
        self.ai_key = QLineEdit()
        self.ai_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.ai_key.setPlaceholderText("API key (Ollama optional / Poe required)")
        self.ai_key.setText(ai.load_ollama_api_key() or ai.load_api_key())
        connection.addWidget(QLabel("API key:"))
        connection.addWidget(self.ai_key, stretch=1)
        self.ai_save_key = QPushButton("Save key")
        self.ai_save_key.clicked.connect(self._ai_save_key)
        connection.addWidget(self.ai_save_key)
        self.ai_save_ollama = QPushButton("Save Ollama")
        self.ai_save_ollama.clicked.connect(self._ai_save_ollama)
        connection.addWidget(self.ai_save_ollama)
        v.addLayout(connection)

        qrow = QHBoxLayout()
        qrow.addWidget(QLabel("Question:"))
        self.ai_question = QLineEdit()
        self.ai_question.setPlaceholderText(
            "e.g. What are the top 3 risks and how do I fix them?"
        )
        qrow.addWidget(self.ai_question, stretch=1)
        self.ai_ask = QPushButton("Ask Advisor")
        self.ai_ask.clicked.connect(self.ask_ai)
        qrow.addWidget(self.ai_ask)
        v.addLayout(qrow)

        split = QHBoxLayout()
        ctx_box = QGroupBox("Exactly what will be sent (redacted)")
        ctx_l = QVBoxLayout(ctx_box)
        self.ai_context = QTextEdit()
        self.ai_context.setReadOnly(True)
        self.ai_context.setFont(QFont("Consolas", 9))
        ctx_l.addWidget(self.ai_context)
        split.addWidget(ctx_box, stretch=1)

        ans_box = QGroupBox("Advisor response")
        ans_l = QVBoxLayout(ans_box)
        self.ai_answer = QTextEdit()
        self.ai_answer.setReadOnly(True)
        ans_l.addWidget(self.ai_answer)
        split.addWidget(ans_box, stretch=1)
        v.addLayout(split, stretch=1)

        if not ai.is_available():
            self.ai_answer.setPlainText(
                "Ollama is ready to use. Poe is unavailable because fastapi-poe "
                "is not installed."
            )

        self._ai_provider_changed(self.ai_provider.currentText())
        self.tabs.addTab(page, "AI Advisor")

    def _ai_provider_changed(self, provider: str) -> None:
        ollama = provider == "Ollama (local)"
        self.ai_ollama_url.setEnabled(ollama)
        self.ai_refresh_models.setEnabled(ollama)
        self.ai_save_ollama.setEnabled(ollama)
        self.ai_key.setEnabled(True)
        self.ai_save_key.setEnabled(True)
        # Swap the key field when switching providers so each stays distinct.
        if ollama:
            self.ai_key.setPlaceholderText("Ollama API key (optional for local)")
            self.ai_key.setText(ai.load_ollama_api_key())
        else:
            self.ai_key.setPlaceholderText("Poe API key — sk-poe-…")
            self.ai_key.setText(ai.load_api_key())
        current = self.ai_bot.currentText().strip()
        self.ai_bot.blockSignals(True)
        self.ai_bot.clear()
        if ollama:
            _, saved_model = ai.load_ollama_settings()
            self.ai_bot.addItem(
                current if current and current not in {
                    "GPT-4o-mini", "GPT-4o", "Claude-3.5-Sonnet",
                    "Llama-3.1-405B",
                } else saved_model
            )
        else:
            self.ai_bot.addItems(
                ["GPT-4o-mini", "GPT-4o", "Claude-3.5-Sonnet", "Llama-3.1-405B"]
            )
            self.ai_bot.setCurrentText(
                current if current.startswith(("GPT", "Claude", "Llama")) else ai.DEFAULT_BOT
            )
        self.ai_bot.blockSignals(False)

    def _ai_refresh_ollama_models(self) -> None:
        url = self.ai_ollama_url.text().strip() or ai.DEFAULT_OLLAMA_URL
        try:
            models = ai.list_ollama_models(
                url, api_key=self.ai_key.text().strip() or ai.load_ollama_api_key()
            )
        except (RuntimeError, ValueError) as exc:
            QMessageBox.warning(self, "Ollama", str(exc))
            return
        if not models:
            QMessageBox.information(
                self,
                "Ollama",
                "Ollama is reachable, but it has no installed models. "
                "Run: ollama pull llama3.2",
            )
            return
        current = self.ai_bot.currentText()
        self.ai_bot.clear()
        self.ai_bot.addItems(models)
        if current in models:
            self.ai_bot.setCurrentText(current)
        self.statusBar().showMessage(
            f"Found {len(models)} local Ollama model(s)", 4000
        )
        self._refresh_ollama_status()

    def _ai_save_ollama(self) -> None:
        try:
            ai.save_ollama_settings(
                self.ai_ollama_url.text().strip(),
                self.ai_bot.currentText().strip(),
                api_key=self.ai_key.text().strip(),
            )
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, "Save Failed", str(exc))
            return
        self.statusBar().showMessage("Ollama settings saved", 4000)
        self._refresh_ollama_status()
    def _ai_save_key(self) -> None:
        key = self.ai_key.text().strip()
        if not key:
            QMessageBox.information(self, "API key", "Enter a key first.")
            return
        try:
            if self.ai_provider.currentText() == "Ollama (local)":
                url, model = ai.load_ollama_settings()
                ai.save_ollama_settings(
                    self.ai_ollama_url.text().strip() or url,
                    self.ai_bot.currentText().strip() or model,
                    api_key=key,
                )
                self.statusBar().showMessage(
                    "Ollama API key saved to secrets.local.json", 4000
                )
            else:
                ai.save_api_key(key)
                self.statusBar().showMessage(
                    "Poe API key saved to secrets.local.json", 4000
                )
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, "Save Failed", str(exc))
            return

    def _refresh_ai_context(self) -> None:
        if not hasattr(self, "ai_context"):
            return
        parts: list[str] = []
        if self._result is not None:
            parts.append(ai.build_findings_context(self._result))
        if self._resiliency is not None:
            parts.append(build_resiliency_ai_context(self._resiliency))
        if not parts:
            self.ai_context.setPlainText(
                "(open a config and/or run Analyze resiliency to build the context)"
            )
            return
        self.ai_context.setPlainText("\n\n".join(parts))

    def ask_ai(self) -> None:
        if self._result is None and self._resiliency is None:
            QMessageBox.information(
                self,
                "AI Advisor",
                "Open a config and/or run Analyze resiliency first.",
            )
            return
        provider = self.ai_provider.currentText()
        key = self.ai_key.text().strip()
        if provider == "Poe":
            from pfsense_checker.module_required import ensure_feature

            if not ensure_feature(
                self,
                "ai_poe",
                purpose="use Poe AI Advisor",
            ):
                return
            key = key or ai.load_api_key()
            if not ai.is_available():
                QMessageBox.information(
                    self,
                    "AI Advisor",
                    "Poe requires fastapi-poe. Install/load it under "
                    "Home → Python Modules, or select Ollama (local).",
                )
                return
            if not key:
                QMessageBox.information(
                    self, "AI Advisor", "No Poe API key set. Enter one and Save key."
                )
                return
        else:
            if not ai.is_ollama_enabled():
                QMessageBox.information(
                    self,
                    "AI Advisor",
                    "Ollama is disabled. Enable it under Home → Ollama, then try again.",
                )
                return
            key = key or ai.load_ollama_api_key()
        model = self.ai_bot.currentText().strip()
        if not model:
            QMessageBox.information(
                self, "AI Advisor", "Select or enter a model / bot name."
            )
            return
        parts: list[str] = []
        if self._result is not None:
            parts.append(ai.build_findings_context(self._result))
        if self._resiliency is not None:
            parts.append(build_resiliency_ai_context(self._resiliency))
        context = "\n\n".join(parts)
        self.ai_context.setPlainText(context)
        self.ai_ask.setEnabled(False)
        self.ai_answer.setPlainText("Contacting advisor…")
        self.statusBar().showMessage("Asking AI advisor…")

        self._ai_worker = _AiWorker(
            context=context,
            question=self.ai_question.text().strip(),
            provider=provider,
            api_key=key,
            model=model,
            ollama_url=self.ai_ollama_url.text().strip() or ai.DEFAULT_OLLAMA_URL,
        )
        self._ai_worker.done.connect(self._ai_done)
        self._ai_worker.failed.connect(self._ai_failed)
        show_busy_while(self._ai_worker)
        self._ai_worker.start()

    def _ai_done(self, reply: str) -> None:
        self.ai_answer.setPlainText(reply)
        self.ai_ask.setEnabled(True)
        self.statusBar().showMessage("AI advisor responded", 4000)

    def _ai_failed(self, message: str) -> None:
        self.ai_answer.setPlainText(f"Request failed:\n\n{message}")
        self.ai_ask.setEnabled(True)
        self.statusBar().showMessage("AI advisor error", 4000)

    def _build_report_tab(self) -> None:
        self.report = QTextEdit()
        self.report.setReadOnly(True)
        self.report.setFont(QFont("Consolas", 10))
        self.report.setPlaceholderText("Full text report…")
        self.tabs.addTab(self.report, "Report")

    def _toggle_monitor_auto(self, enabled: bool) -> None:
        if enabled:
            self._monitor_timer.start(self.monitor_interval.value() * 1000)
            self.refresh_monitor()
        else:
            self._monitor_timer.stop()

    def _update_monitor_interval(self, value: int) -> None:
        if self._monitor_timer.isActive():
            self._monitor_timer.start(value * 1000)

    def _collector_get(self, path: str) -> dict:
        base = self.monitor_url.text().strip().rstrip("/")
        url = f"{base}{path}"
        headers = {"User-Agent": "pfsense-checker-gui/1.0"}
        token = self.monitor_token.text().strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def refresh_monitor(self) -> None:
        try:
            beacons_payload = self._collector_get("/api/beacons")
            fails = "1" if self.monitor_fails_only.isChecked() else "0"
            results_payload = self._collector_get(f"/api/results?limit=150&fails_only={fails}")
        except urllib.error.URLError as exc:
            self.monitor_status.setText(f"Collector unreachable: {exc}")
            self.monitor_status.setStyleSheet("color: #c62828;")
            self._set_beacon_status_label(None)
            return
        except Exception as exc:  # noqa: BLE001
            self.monitor_status.setText(f"Monitor error: {exc}")
            self.monitor_status.setStyleSheet("color: #c62828;")
            self._set_beacon_status_label(None)
            return

        beacons = beacons_payload.get("beacons") or []
        results = results_payload.get("results") or []
        online = sum(1 for b in beacons if b.get("online"))
        self._set_beacon_status_label(online, len(beacons))
        self.monitor_status.setText(
            f"Connected — {len(beacons)} beacon(s), {online} online, "
            f"{len(results)} recent probe(s) shown"
        )
        self.monitor_status.setStyleSheet("color: #2e7d32;")

        self._render_monitor_charts(beacons, results)

        _fill(
            self.beacon_table,
            [
                [
                    b.get("beacon_id", ""),
                    b.get("site", ""),
                    b.get("hostname", ""),
                    "yes" if b.get("online") else "NO",
                    b.get("last_seen", ""),
                    f"{b.get('ping_ok', 0)}/{b.get('ping_fail', 0)}",
                    f"{b.get('dhcp_ok', 0)}/{b.get('dhcp_fail', 0)}",
                    b.get("last_message", ""),
                ]
                for b in beacons
            ],
        )
        # Attach beacon_id into result rows for display (API results don't include it —
        # re-fetch with detail from store shape). Results already have no beacon field;
        # show blank if missing.
        rows = []
        for r in results:
            rows.append(
                [
                    r.get("ts", ""),
                    r.get("beacon_id", ""),
                    r.get("kind", ""),
                    r.get("status", ""),
                    r.get("target", ""),
                    r.get("subnet", ""),
                    "" if r.get("latency_ms") is None else str(r.get("latency_ms")),
                    r.get("message", ""),
                ]
            )
        _fill(self.probe_table, rows)

    def _render_monitor_charts(self, beacons: list[dict], results: list[dict]) -> None:
        online = sum(1 for b in beacons if b.get("online"))
        ping_ok = sum(int(b.get("ping_ok", 0)) for b in beacons)
        ping_fail = sum(int(b.get("ping_fail", 0)) for b in beacons)
        dhcp_ok = sum(int(b.get("dhcp_ok", 0)) for b in beacons)
        dhcp_fail = sum(int(b.get("dhcp_fail", 0)) for b in beacons)

        self.monitor_kpis["beacons"].set_value(str(len(beacons)), COLOR_INFO)
        self.monitor_kpis["online"].set_value(
            f"{online}/{len(beacons)}", COLOR_OK if online == len(beacons) and beacons else COLOR_WARN
        )
        self.monitor_kpis["ping"].set_value(
            f"{ping_ok}/{ping_fail}", COLOR_OK if ping_fail == 0 else COLOR_WARN
        )
        self.monitor_kpis["dhcp"].set_value(
            f"{dhcp_ok}/{dhcp_fail}", COLOR_OK if dhcp_fail == 0 else COLOR_WARN
        )

        # Status donut across recent probes
        ok = sum(1 for r in results if r.get("status") == "ok")
        fail = sum(1 for r in results if r.get("status") in ("fail",))
        err = sum(1 for r in results if r.get("status") in ("error", "warn", "skipped"))
        self.monitor_status_donut.set_data(
            [("ok", ok, COLOR_OK), ("fail", fail, COLOR_ERROR), ("other", err, COLOR_WARN)]
        )

        # Latency time series grouped by target (ping only)
        import time as _time

        now = _time.time()
        series: dict[str, list[tuple[float, float]]] = {}
        for r in results:
            if r.get("kind") != "ping" or r.get("latency_ms") is None:
                continue
            ep = epoch_seconds(r.get("ts", ""))
            if ep is None:
                continue
            seconds_ago = -(now - ep)  # negative = older, 0 = now
            label = r.get("target", "?")
            series.setdefault(label, []).append((seconds_ago, float(r["latency_ms"])))
        for pts in series.values():
            pts.sort(key=lambda p: p[0])
        self.monitor_latency_chart.set_series(series)

    # --- drag & drop ---

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        # Qt registers its OLE drop target during show. Re-apply after that
        # so an elevated window can still take Explorer drops.
        QTimer.singleShot(0, self._install_os_file_drop)

    def _install_os_file_drop(self) -> None:
        from pfsense_checker.file_drop import enable_os_file_drop

        enable_os_file_drop(self, self._on_files_dropped)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802
        from pfsense_checker.file_drop import accept_file_drag

        if not accept_file_drag(event):
            event.ignore()

    def dragMoveEvent(self, event: QDragMoveEvent) -> None:  # noqa: N802
        from pfsense_checker.file_drop import accept_file_drag

        if not accept_file_drag(event):
            event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802
        from pfsense_checker.file_drop import paths_from_mime

        paths = paths_from_mime(event.mimeData())
        if not paths:
            event.ignore()
            return
        event.setDropAction(Qt.DropAction.CopyAction)
        event.accept()
        self._on_files_dropped(paths)

    def _on_files_dropped(self, paths: list[Path]) -> None:
        if not paths:
            return
        path = paths[0]
        if path.suffix.lower() == ".backup":
            QMessageBox.information(
                self,
                "MikroTik .backup",
                "Binary .backup files cannot be parsed as configs.\n\n"
                "Use Topology Builder → Attach .backup… on a MikroTik device, "
                "then Configure REST to collect a sanitized live export for analysis.",
            )
            return
        if path.is_file():
            self._enter_workspace("Dashboard")
            self.load_path(path)
        elif path.is_dir():
            self._enter_workspace("Dashboard")
            self.import_config_folder(path)

    # --- actions ---

    def open_file(self) -> None:
        path_str, _ = QFileDialog.getOpenFileName(
            self,
            "Open pfSense or MikroTik Config",
            "",
            "Configs (*.xml *.conf *.rsc *.routeros *.backup);;"
            "pfSense/OPNsense XML (*.xml);;"
            "MikroTik RouterOS (*.rsc *.routeros);;"
            "MikroTik backup (*.backup);;"
            "All Files (*)",
        )
        if path_str:
            path = Path(path_str)
            if path.suffix.lower() == ".backup":
                QMessageBox.information(
                    self,
                    "MikroTik .backup",
                    "Binary .backup files cannot be parsed as configs.\n\n"
                    "Use Topology Builder → Attach .backup… on a MikroTik device, "
                    "then Configure REST to collect a sanitized live export for analysis.",
                )
                return
            self.load_path(path)

    def open_folder(self) -> None:
        folder_str = QFileDialog.getExistingDirectory(
            self,
            "Open Config Folder",
            "",
            QFileDialog.Option.ShowDirsOnly,
        )
        if folder_str:
            self.import_config_folder(Path(folder_str))

    def import_config_folder(self, folder: Path) -> None:
        """Import every supported config below folder, join devices, and analyze.

        Each config becomes (or updates) its own topology device — matching is
        strict (config path / hostname) so five configs never collapse into one
        chassis. Afterwards links are auto-detected from port comments and a
        full cross-device consistency analysis runs.
        """
        self._ensure_workspace()
        paths = _config_files_in_folder(folder)
        if not paths:
            QMessageBox.information(
                self,
                "Open Config Folder",
                "No supported config files were found.\n\n"
                "Supported: *.xml, *.conf, *.rsc, *.routeros, and *.backup.",
            )
            self.statusBar().showMessage("No configs found in selected folder", 5000)
            return

        reports = []
        errors: list[str] = []
        backups = 0
        results_by_device: dict[str, CheckResult] = {}
        with busy_cursor():
            for path in paths:
                if path.suffix.lower() == ".backup":
                    backups += 1
                    continue
                try:
                    result = check_file(path)
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"{path}: {exc}")
                    continue
                report = enrich_from_result(
                    self._site,
                    result,
                    create_if_missing=True,
                    strict_match=True,
                )
                reports.append(report)
                dev = self._site.device(report.device_name)
                if dev is not None:
                    dev.attach_local_config(path)
                    results_by_device[dev.name] = result

            # Auto-detect how the devices are joined (uplinks / port comments)
            link_report = infer_links(self._site, results_by_device)

        self._refresh_site()
        self.site_view.arrange_by_tier()
        self.path_label.setText(f"Config folder: {folder}")

        lines = [
            f"Found {len(paths)} supported file(s) in {folder}.",
            f"Imported {len(reports)} config(s) as devices: "
            + ", ".join(r.device_name for r in reports),
            f"Links: {link_report.summary()}",
        ]
        if link_report.notes:
            lines.extend(link_report.notes)
        if backups:
            lines.append(
                f"Skipped {backups} binary .backup file(s); attach these to a "
                "MikroTik device and configure REST collection."
            )
        if errors:
            lines.append(f"{len(errors)} file(s) could not be imported:")
            lines.extend(errors[:12])
            if len(errors) > 12:
                lines.append(f"…and {len(errors) - 12} more.")
        QMessageBox.information(self, "Config Folder Import", "\n".join(lines))

        # Load the firewall (or first) config into the single-device views too
        primary = next(
            (
                p
                for p in paths
                if p.suffix.lower() in (".xml", ".conf")
            ),
            next((p for p in paths if p.suffix.lower() != ".backup"), None),
        )
        if primary is not None:
            self.load_path(primary)

        # Cross-device consistency / anomaly analysis across all imports
        if results_by_device:
            self.analyze_resiliency()
        self.statusBar().showMessage(
            f"Imported {len(reports)}/{len(paths)} config(s) from {folder.name} — "
            f"{len(link_report.links_added)} link(s) auto-detected",
            8000,
        )

    def recheck(self) -> None:
        if self._current_path:
            self.load_path(self._current_path)

    def export_report(self) -> None:
        self._ensure_workspace()
        text = self.report.toPlainText().strip()
        if not text:
            QMessageBox.information(self, "Export", "Nothing to export yet.")
            return
        path_str, _ = QFileDialog.getSaveFileName(
            self, "Export Report", "pfsense_check_report.txt", "Text Files (*.txt);;All Files (*)"
        )
        if not path_str:
            return
        try:
            Path(path_str).write_text(text, encoding="utf-8")
            self.statusBar().showMessage(f"Report saved to {path_str}", 5000)
        except OSError as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))

    def load_path(self, path: Path) -> None:
        app_log.get_logger("config").info("Config check: %s", path)
        self._ensure_workspace()
        self._current_path = path
        self.path_label.setText(str(path))
        self.recheck_action.setEnabled(True)
        self.home_screen.set_recheck_enabled(True)
        self.statusBar().showMessage(f"Checking {path.name}…")
        self.summary_label.setText("Checking…")

        if self._worker and self._worker.isRunning():
            self._worker.wait(2000)
        self._worker = CheckWorker(path)
        self._worker.finished_ok.connect(self._on_result)
        self._worker.failed.connect(self._on_failure)
        show_busy_while(self._worker)
        self._worker.start()

    def _on_failure(self, message: str) -> None:
        app_log.get_logger("config").error("Config check failed: %s", message)
        self.summary_label.setText("Check failed")
        self.statusBar().showMessage("Error")
        QMessageBox.critical(self, "Check Failed", message)

    # --- rendering ---

    def _on_result(self, result: CheckResult) -> None:
        self._result = result
        self._render_summary(result)
        self._render_dashboard(result)
        if hasattr(self, "tabs") and self.tabs.count():
            self.tabs.setCurrentIndex(0)
            self._sync_workspace_nav()
        self._render_topology(result)
        self._render_findings(result)
        self._render_interfaces(result)
        self._render_virtual(result)
        self._render_rules(result)
        self._render_vpn(result)
        self._render_services_net(result)
        self._render_packages(result)
        self._render_report(result)
        self._refresh_ai_context()
        self.statusBar().showMessage(
            f"Done — {result.error_count} errors, {result.warning_count} warnings, "
            f"{result.info_count} info"
        )

    def _render_summary(self, result: CheckResult) -> None:
        posture = str(result.summary.get("posture") or "")
        if posture == "PASS" or (not posture and result.ok and not result.warning_count):
            verdict, color = "PASS — no exposure found", "#2e7d32"
        elif posture == "EXPOSED" or (not posture and result.ok and result.warning_count):
            verdict = f"EXPOSED — {result.warning_count} warning(s)"
            color = "#ef6c00"
        elif result.valid_xml or result.source_type == "mikrotik":
            verdict = f"FAIL — {result.error_count} error(s), {result.warning_count} warning(s)"
            color = "#c62828" if result.error_count else "#ef6c00"
        else:
            verdict, color = "Invalid XML", "#c62828"

        s = result.summary
        host = result.hostname or "(unknown host)"
        badge = "MikroTik RouterOS" if result.source_type == "mikrotik" else "pfSense/OPNsense"
        self.summary_label.setText(
            f"[{badge}]  ·  {verdict}  ·  {host}  ·  v{result.version or '?'}  ·  "
            f"{s.get('interfaces_total', 0)} ifaces "
            f"({s.get('interfaces_enabled', 0)}↑/{s.get('interfaces_disabled', 0)}↓)  ·  "
            f"{s.get('bridges', 0)} bridges  ·  {s.get('vlans', 0)} VLANs  ·  "
            f"{s.get('laggs', 0)} LAGGs  ·  {s.get('filter_rules', 0)} fw rules  ·  "
            f"{s.get('nat_rules', 0)} NAT  ·  {s.get('vpn', 0)} VPN  ·  "
            f"{s.get('packages', 0)} pkgs ({s.get('packages_disabled', 0)} off)"
        )
        self.summary_label.setStyleSheet(
            f"font-weight: bold; padding: 4px 0; color: {color};"
        )

    def _render_dashboard(self, result: CheckResult) -> None:
        s = result.summary
        posture = str(s.get("posture") or "")
        if not posture:
            if result.error_count or (result.source_type != "mikrotik" and not result.valid_xml):
                posture = "FAIL" if result.valid_xml or result.source_type == "mikrotik" else "INVALID"
            elif result.warning_count:
                posture = "EXPOSED"
            else:
                posture = "PASS"
        if posture == "PASS":
            self.kpi_cards["verdict"].set_value("PASS", COLOR_OK)
        elif posture == "EXPOSED":
            self.kpi_cards["verdict"].set_value("EXPOSED", COLOR_WARN)
        elif posture == "INVALID":
            self.kpi_cards["verdict"].set_value("INVALID", COLOR_ERROR)
        else:
            self.kpi_cards["verdict"].set_value("FAIL", COLOR_ERROR)
        if hasattr(self, "assessment_view"):
            self.assessment_view.setPlainText(
                str(s.get("assessment") or "No attack-surface assessment for this file.")
            )

        self.kpi_cards["errors"].set_value(
            str(result.error_count), COLOR_ERROR if result.error_count else COLOR_OK
        )
        self.kpi_cards["warnings"].set_value(
            str(result.warning_count), COLOR_WARN if result.warning_count else COLOR_OK
        )
        self.kpi_cards["interfaces"].set_value(
            f"{s.get('interfaces_enabled', 0)}/{s.get('interfaces_total', 0)}", COLOR_INFO
        )
        self.kpi_cards["virtual"].set_value(
            f"{s.get('bridges', 0)}/{s.get('vlans', 0)}/{s.get('laggs', 0)}", COLOR_INFO
        )
        self.kpi_cards["fw"].set_value(str(s.get("filter_rules", 0)), COLOR_INFO)
        self.kpi_cards["vpn"].set_value(str(s.get("vpn", 0)), COLOR_INFO)
        self.kpi_cards["packages"].set_value(
            f"{s.get('packages', 0)}"
            + (f" ({s.get('packages_disabled', 0)}✕)" if s.get("packages_disabled") else ""),
            COLOR_INFO,
        )

        self.donut_sev.set_data(
            [
                ("Errors", result.error_count, COLOR_ERROR),
                ("Warnings", result.warning_count, COLOR_WARN),
                ("Info", result.info_count, COLOR_INFO),
            ]
        )

        cat_counts: dict[str, int] = {}
        for f in result.findings:
            cat_counts[f.category or "Other"] = cat_counts.get(f.category or "Other", 0) + 1
        cat_palette = [
            "#1565c0", "#c62828", "#2e7d32", "#ef6c00", "#6a1b9a",
            "#00838f", "#ad1457", "#5d4037", "#455a64", "#f9a825",
        ]
        self.bar_cat.set_data(
            [
                (cat, count, cat_palette[i % len(cat_palette)])
                for i, (cat, count) in enumerate(sorted(cat_counts.items()))
            ]
        )

        enabled = s.get("interfaces_enabled", 0)
        disabled = s.get("interfaces_disabled", 0)
        self.donut_iface.set_data(
            [("Enabled", enabled, COLOR_OK), ("Disabled", disabled, COLOR_MUTED)]
        )

        kind_counts: dict[str, int] = {}
        for i in result.interfaces:
            kind_counts[i.kind] = kind_counts.get(i.kind, 0) + 1
        self.bar_kind.set_data(
            [
                (kind, count, KIND_COLORS.get(kind, "#616161"))
                for kind, count in sorted(kind_counts.items())
            ]
        )

    def _render_topology(self, result: CheckResult) -> None:
        self.topology_view.render_topology(result)
        self.segmentation_matrix.set_segmentation(self.topology_view.segmentation)

    def _render_findings(self, result: CheckResult) -> None:
        cats = sorted({f.category for f in result.findings if f.category})
        self.cat_filter.blockSignals(True)
        self.cat_filter.clear()
        self.cat_filter.addItem("All categories")
        self.cat_filter.addItems(cats)
        self.cat_filter.blockSignals(False)
        self._apply_finding_filter()

    def _apply_finding_filter(self) -> None:
        if not self._result:
            return
        sev_map = {
            "Errors": Severity.ERROR,
            "Warnings": Severity.WARNING,
            "Info": Severity.INFO,
        }
        sev = sev_map.get(self.sev_filter.currentText())
        cat = self.cat_filter.currentText()
        needle = self.search.text().strip().lower()

        findings = sorted(
            self._result.findings, key=lambda f: SEVERITY_ORDER[f.severity]
        )
        rows = []
        for f in findings:
            if sev and f.severity is not sev:
                continue
            if cat not in ("All categories", "") and f.category != cat:
                continue
            if needle and needle not in f.message.lower() and needle not in f.path.lower():
                continue
            rows.append(f)

        self._visible_findings = rows
        self.findings_table.setRowCount(len(rows))
        for r, f in enumerate(rows):
            sev_item = QTableWidgetItem(f.severity.value.upper())
            sev_item.setForeground(SEVERITY_COLORS[f.severity])
            sev_item.setBackground(SEVERITY_BG[f.severity])
            self.findings_table.setItem(r, 0, sev_item)
            self.findings_table.setItem(r, 1, QTableWidgetItem(f.category))
            self.findings_table.setItem(r, 2, QTableWidgetItem(f.path))
            self.findings_table.setItem(
                r, 3, QTableWidgetItem(str(f.line) if f.line is not None else "")
            )
            self.findings_table.setItem(r, 4, QTableWidgetItem(f.message))
        self.findings_table.resizeColumnsToContents()

    def _findings_context_menu(self, pos) -> None:  # noqa: ANN001
        row = self.findings_table.rowAt(pos.y())
        findings = getattr(self, "_visible_findings", [])
        if row < 0 or row >= len(findings):
            return
        finding = findings[row]
        menu = QMenu(self.findings_table)
        choices = (
            ("Explain Issue", "issue"),
            ("Explain Severity", "severity"),
            ("Suggest Fix", "fix"),
            ("What Breaks if Removed", "removal"),
        )
        actions = {menu.addAction(label): (label, kind) for label, kind in choices}
        picked = menu.exec(self.findings_table.viewport().mapToGlobal(pos))
        if picked not in actions:
            return
        title, kind = actions[picked]
        from pfsense_checker.finding_analysis import analyse

        text = analyse(finding, self._result, kind)
        self._show_finding_analysis(title, text, finding, kind)

    def _show_finding_analysis(self, title: str, text: str, finding, kind: str) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle(title)
        dlg.resize(780, 560)
        dlg.setModal(False)
        layout = QVBoxLayout(dlg)
        view = QTextEdit()
        view.setReadOnly(True)
        view.setFont(QFont("Consolas", 10))
        view.setPlainText(text)
        layout.addWidget(view, stretch=1)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        save = QPushButton("Save Analysis")
        save.clicked.connect(
            lambda: self._save_finding_analysis(dlg, view.toPlainText(), finding, kind)
        )
        buttons.addWidget(save)
        close = QPushButton("Close")
        close.clicked.connect(dlg.close)
        buttons.addWidget(close)
        layout.addLayout(buttons)
        held = getattr(self, "_finding_analysis_dialogs", None)
        if held is None:
            self._finding_analysis_dialogs = []
            held = self._finding_analysis_dialogs
        held.append(dlg)
        dlg.finished.connect(lambda: held.remove(dlg) if dlg in held else None)
        dlg.show()

    def _save_finding_analysis(self, parent: QWidget, text: str, finding, kind: str) -> None:
        from pfsense_checker.finding_analysis import suggested_filename

        body = (text or "").strip()
        if not body:
            QMessageBox.information(parent, "Save Analysis", "There is no analysis to save.")
            return
        result = getattr(self, "_result", None)
        name = suggested_filename(finding, kind, result)
        start = name
        current = getattr(self, "_current_path", None)
        if current is not None:
            start = str(Path(current).parent / name)
        path_str, _ = QFileDialog.getSaveFileName(
            parent,
            "Save Analysis",
            start,
            "Text Files (*.txt);;All Files (*)",
        )
        if not path_str:
            return
        try:
            Path(path_str).write_text(body + "\n", encoding="utf-8")
        except OSError as exc:
            QMessageBox.critical(parent, "Save Analysis", str(exc))
            return
        self.statusBar().showMessage(f"Analysis saved to {path_str}", 5000)

    def _render_interfaces(self, result: CheckResult) -> None:
        rows = [
            [
                i.name.upper(),
                "yes" if i.enabled else "no",
                i.device,
                i.kind,
                f"{i.ipaddr}/{i.subnet}" if i.subnet and i.ipaddr not in ("dhcp", "") else i.ipaddr,
                f"{i.ipaddrv6}/{i.subnetv6}" if i.subnetv6 else i.ipaddrv6,
                i.bridge_of,
                i.descr,
            ]
            for i in result.interfaces
        ]
        _fill(self.iface_table, rows)

    def _render_virtual(self, result: CheckResult) -> None:
        _fill(
            self.bridge_table,
            [
                [b.bridgeif, ", ".join(b.members), "yes" if b.stp_enabled else "no",
                 b.assigned_as, b.descr]
                for b in result.bridges
            ],
        )
        _fill(
            self.vlan_table,
            [[v.tag, v.if_parent, v.vlanif, v.assigned_as, v.descr] for v in result.vlans],
        )
        _fill(
            self.lagg_table,
            [[lg.laggif, lg.proto, ", ".join(lg.members), lg.assigned_as, lg.descr]
             for lg in result.laggs],
        )

    def _render_rules(self, result: CheckResult) -> None:
        _fill(
            self.filter_table,
            [
                [str(r.index + 1), r.type, r.interface, r.source, r.destination,
                 "yes" if r.disabled else "", r.descr]
                for r in result.filter_rules
            ],
        )
        _fill(
            self.nat_table,
            [
                [r.kind, r.interface, r.destination, "yes" if r.disabled else "", r.descr]
                for r in result.nat_rules
            ],
        )

    def _render_vpn(self, result: CheckResult) -> None:
        _fill(
            self.vpn_table,
            [
                [v.kind, v.name, v.interface, "yes" if v.disabled else "", v.details]
                for v in result.vpn
            ],
        )

    def _render_services_net(self, result: CheckResult) -> None:
        _fill(
            self.gw_table,
            [
                [g.get("name", ""), g.get("interface", ""), g.get("gateway", ""),
                 g.get("ipprotocol", ""), g.get("default", ""), g.get("disabled", "")]
                for g in result.gateways
            ],
        )
        _fill(
            self.dhcp_table,
            [
                [d["interface"], d["family"], d["enabled"], d["from"], d["to"], d["staticmaps"]]
                for d in result.dhcp_scopes
            ],
        )
        route_rows = []
        for r in result.static_routes:
            route_rows.append(["route", r.get("network", ""), r.get("gateway", ""),
                               r.get("descr", ""), r.get("disabled", "")])
        for vip in result.virtual_ips:
            route_rows.append(["vip", vip.get("mode", ""), vip.get("interface", ""),
                               vip.get("subnet", ""), ""])
        for al in result.aliases:
            route_rows.append(["alias", al.get("name", ""), al.get("type", ""),
                               al.get("address", ""), ""])
        _fill(self.route_table, route_rows)

    def _render_packages(self, result: CheckResult) -> None:
        _fill(
            self.pkg_table,
            [
                [
                    p.name,
                    p.version,
                    {True: "yes", False: "no", None: "?"}[p.enabled],
                    p.notes,
                    p.descr.splitlines()[0] if p.descr else "",
                ]
                for p in result.packages
            ],
        )
        _fill(
            self.svc_table,
            [
                [s.name, s.executable,
                 {True: "yes", False: "no", None: "?"}[s.enabled], s.description]
                for s in result.services
            ],
        )

    def _render_report(self, result: CheckResult) -> None:
        s = result.summary
        lines: list[str] = []
        lines.append("=" * 60)
        lines.append("pfSense Configuration Check Report")
        lines.append("=" * 60)
        lines.append(f"File:        {result.path}")
        lines.append(f"Valid XML:   {result.valid_xml}")
        lines.append(f"Root:        {result.root_tag or '(none)'}")
        lines.append(f"Version:     {result.version or '(unknown)'}")
        lines.append(f"Hostname:    {result.hostname or '(unknown)'}"
                     + (f".{result.domain}" if result.domain else ""))
        posture = str(s.get("posture") or ("PASS" if result.ok and not result.warning_count else "FAIL"))
        lines.append(
            f"Result:      {posture} "
            f"({result.error_count} errors, {result.warning_count} warnings, "
            f"{result.info_count} info)"
        )
        assessment = str(s.get("assessment") or "").strip()
        if assessment:
            lines.append("")
            lines.append("-- Attack surface --")
            lines.append(assessment)
        lines.append("")
        lines.append("-- Inventory --")
        lines.append(
            f"Interfaces: {s.get('interfaces_total', 0)} "
            f"({s.get('interfaces_enabled', 0)} enabled, "
            f"{s.get('interfaces_disabled', 0)} disabled)"
        )
        for i in result.interfaces:
            lines.append(f"    {i.summary_line()}")
        lines.append(f"Bridges: {len(result.bridges)}")
        for b in result.bridges:
            lines.append(
                f"    {b.bridgeif} members=[{', '.join(b.members)}] "
                f"stp={'on' if b.stp_enabled else 'off'} assigned={b.assigned_as or '-'}"
            )
        lines.append(f"VLANs: {len(result.vlans)}")
        for v in result.vlans:
            lines.append(f"    tag={v.tag} parent={v.if_parent} vlanif={v.vlanif}")
        lines.append(f"LAGGs: {len(result.laggs)}")
        for lg in result.laggs:
            lines.append(f"    {lg.laggif} proto={lg.proto} members=[{', '.join(lg.members)}]")
        lines.append(f"Firewall rules: {len(result.filter_rules)} "
                     f"({sum(1 for r in result.filter_rules if r.disabled)} disabled)")
        lines.append(f"NAT rules: {len(result.nat_rules)}")
        lines.append(f"VPN endpoints: {len(result.vpn)}")
        for v in result.vpn:
            lines.append(f"    {v.kind}: {v.name} "
                         f"{'[disabled]' if v.disabled else ''} {v.details}")
        lines.append(f"Gateways: {len(result.gateways)}")
        lines.append(f"DHCP scopes: {len(result.dhcp_scopes)}")
        lines.append(f"Virtual IPs: {len(result.virtual_ips)}")
        lines.append(f"Aliases: {len(result.aliases)}")
        lines.append(f"Certificates: CA={result.certs.get('ca', 0)} "
                     f"cert={result.certs.get('cert', 0)} crl={result.certs.get('crl', 0)}")
        lines.append(f"Users: {', '.join(s.get('users', [])) or '(none)'}")
        lines.append(f"Packages: {len(result.packages)} "
                     f"({s.get('packages_disabled', 0)} disabled)")
        for p in result.packages:
            state = {True: "enabled", False: "DISABLED", None: "unknown"}[p.enabled]
            lines.append(f"    {p.name} {p.version} [{state}] — {p.notes}")
        lines.append(f"Services: {len(result.services)}")
        for svc in result.services:
            state = {True: "enabled", False: "stopped", None: "?"}[svc.enabled]
            lines.append(f"    {svc.name} [{state}] {svc.executable}")
        lines.append("")
        lines.append("-- Findings --")
        for f in sorted(result.findings, key=lambda x: SEVERITY_ORDER[x.severity]):
            lines.append(f.label())
        if self._resiliency is not None:
            lines.append("")
            lines.append("-- Site Resiliency --")
            rs = self._resiliency.summary
            lines.append(
                f"Devices with config: {rs.get('with_config', 0)}/{rs.get('devices', 0)} · "
                f"incomplete={rs.get('incomplete', False)} · "
                f"{self._resiliency.error_count} errors, "
                f"{self._resiliency.warning_count} warnings, "
                f"{self._resiliency.info_count} info"
            )
            for f in sorted(
                self._resiliency.findings, key=lambda x: SEVERITY_ORDER[x.severity]
            ):
                lines.append(
                    f"[{f.severity.value.upper()}] [{f.category}] "
                    f"({', '.join(f.devices) or '-'}) {f.message}"
                )
                if f.remediation:
                    lines.append(f"    → {f.remediation}")
        self.report.setPlainText("\n".join(lines))


def run_app() -> int:
    import sys

    # Windows taskbar: use our AppUserModelID so the icon isn't python.exe's.
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "PFSenseChecker.NetCheck"
            )
        except Exception:  # noqa: BLE001
            pass

    app = QApplication(sys.argv)
    app.setApplicationName("pfSense Config Checker")
    app.setOrganizationName("PFSenseChecker")

    from pfsense_checker import app_log

    app_log.configure()
    app_log.install_crash_hooks()
    from pfsense_checker.console_window import close_companion, open_companion

    # Subscribe before splash so startup lines are kept. Stay hidden until
    # the splash is gone so it does not cover the animation.
    open_companion(show=False)
    from pfsense_checker import openobserve

    openobserve.start_shipper()
    _boot_log = app_log.get_logger("app")
    try:
        from pfsense_checker.onepassword import is_elevated

        _elevated = is_elevated()
    except Exception:  # noqa: BLE001
        _elevated = "unknown"
    _boot_log.info("NetCheck starting elevated=%s", _elevated)
    _boot_log.debug(
        "Python %s · Qt app created · argv=%s", sys.version.split()[0], sys.argv
    )

    root = Path(__file__).resolve().parent.parent
    icon_path = root / "NetCheck.ico"
    icon = QIcon(str(icon_path)) if icon_path.is_file() else QIcon()
    if not icon.isNull():
        app.setWindowIcon(icon)

    # Animated splash first, then login, then main window.
    splash = None
    try:
        from pfsense_checker.splash import AnimatedSplash

        splash = AnimatedSplash(root / "A-Netcheck.svg")
        splash.show()
        splash.start()
        app.processEvents()
        # Keep splash on screen until the bar slide finishes (animation needs
        # a running event loop — a single processEvents() is not enough).
        hold = QEventLoop()
        QTimer.singleShot(splash.duration_ms + 200, hold.quit)
        hold.exec()
    except Exception:  # noqa: BLE001
        splash = None

    # Login gate between splash and main window.
    from pfsense_checker.login_screen import run_login_gate

    if splash is not None:
        splash.hide()
        app.processEvents()

    open_companion(show=True, activate=False)
    _boot_log.debug("Showing login gate")
    user = run_login_gate()
    if user is None:
        app_log.get_logger("app").info("Login cancelled — exiting")
        close_companion()
        if splash is not None:
            splash.close()
        return 0

    if splash is not None:
        splash.show()
        splash.raise_()
        app.processEvents()

    # Modules the operator ticked Loaded (Python Modules) survive log-in /
    # log-out: import them again now.
    try:
        from pfsense_checker import python_modules as _pm

        for _name, _res in _pm.load_saved_modules().items():
            if _res == "ok":
                app_log.get_logger("modules").info("Loaded at login: %s", _name)
            else:
                app_log.get_logger("modules").warning("Load at login %s: %s", _name, _res)
    except Exception as _exc:  # noqa: BLE001
        app_log.get_logger("modules").error("Load saved modules failed: %s", _exc)

    import time as _time

    t_build = _time.perf_counter()
    window = MainWindow()
    window.set_authenticated_user(user)
    build_ms = (_time.perf_counter() - t_build) * 1000.0
    _boot_log.debug("Main window built in %.0f ms", build_ms)
    if not icon.isNull():
        window.setWindowIcon(icon)

    def _shutdown_secondary() -> None:
        close_companion()
        home = getattr(window, "home_screen", None)
        if home is not None:
            closer = getattr(home, "close_console_popout", None)
            if callable(closer):
                closer()
            stop_sys = getattr(home, "stop_syslog_receiver", None)
            if callable(stop_sys):
                stop_sys()

    app.aboutToQuit.connect(_shutdown_secondary)

    def _reveal() -> None:
        window.show()
        if splash is not None:
            splash.finish(window)
        if len(sys.argv) > 1:
            candidate = Path(sys.argv[1])
            if candidate.is_file():
                window.home_screen.show_section("config")
                window._enter_workspace("Dashboard")
                window.load_path(candidate)

    if splash is not None:
        # Reveal as soon as the window is ready, but keep a minimum so
        # the slide-in is visible if login was fast.
        min_splash_ms = splash.duration_ms
        remaining = max(0, int(min_splash_ms - build_ms))
        QTimer.singleShot(remaining, _reveal)
    else:
        _reveal()

    return app.exec()
