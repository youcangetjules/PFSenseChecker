"""Database home section — PostgreSQL login, browse, SQL, schema graph.

UX inspired by Workflow Manager's MySQL admin (table list + data/structure/query
tabs + relationship canvas), scaled down for NetCheck.
"""

from __future__ import annotations

import math
from typing import Any

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGraphicsEllipseItem,
    QGraphicsLineItem,
    QGraphicsScene,
    QGraphicsSimpleTextItem,
    QGraphicsView,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from pfsense_checker import app_log, netcheck_schema, postgres_db as pg


def _primary_btn() -> str:
    return (
        "QPushButton {"
        " padding: 4px 14px; font-weight: bold;"
        " background-color: rgba(21, 101, 192, 200);"
        " border: 1px solid rgb(13, 71, 161); border-radius: 3px;"
        " color: white; }"
        "QPushButton:hover { background-color: rgba(25, 118, 210, 230); }"
        "QPushButton:disabled { background-color: #90a4ae; border-color: #78909c; }"
    )


class _SchemaCanvas(QGraphicsView):
    """Minimal table/FK graph (inspired by MySQL admin schema visualiser)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setBackgroundBrush(QColor("#f5f7f8"))
        self._nodes: dict[str, tuple[float, float]] = {}

    def clear_schema(self) -> None:
        self._scene.clear()
        self._nodes.clear()

    def draw_schema(
        self,
        tables: list[str],
        fks: list[pg.ForeignKeyInfo],
    ) -> None:
        self.clear_schema()
        if not tables:
            tip = self._scene.addSimpleText("No tables in this schema")
            tip.setBrush(QColor("#666"))
            return
        n = len(tables)
        cols = max(1, int(math.ceil(math.sqrt(n))))
        gap_x, gap_y = 180.0, 110.0
        radius = 36.0
        for i, name in enumerate(tables):
            row, col = divmod(i, cols)
            x = col * gap_x + 40
            y = row * gap_y + 40
            self._nodes[name] = (x, y)
            ellipse = QGraphicsEllipseItem(x - radius, y - radius, radius * 2, radius * 2)
            ellipse.setBrush(QColor("#1565c0"))
            ellipse.setPen(QPen(QColor("#0d47a1")))
            self._scene.addItem(ellipse)
            label = QGraphicsSimpleTextItem(name)
            label.setBrush(QColor("white"))
            br = label.boundingRect()
            label.setPos(x - br.width() / 2, y - br.height() / 2)
            self._scene.addItem(label)

        for fk in fks:
            a = self._nodes.get(fk.table)
            b = self._nodes.get(fk.foreign_table)
            if not a or not b:
                continue
            line = QGraphicsLineItem(a[0], a[1], b[0], b[1])
            line.setPen(QPen(QColor("#ef6c00"), 2))
            line.setZValue(-1)
            self._scene.addItem(line)
            mid = QGraphicsSimpleTextItem(f"{fk.column}→{fk.foreign_column}")
            mid.setBrush(QColor("#555"))
            mid.setPos((a[0] + b[0]) / 2, (a[1] + b[1]) / 2)
            self._scene.addItem(mid)

        self._scene.setSceneRect(self._scene.itemsBoundingRect().adjusted(-20, -20, 20, 20))


class _ConnectWorker(QThread):
    finished_ok = Signal(str)
    failed = Signal(str)

    def __init__(self, settings: pg.PostgresSettings) -> None:
        super().__init__()
        self._settings = settings

    def run(self) -> None:  # noqa: D102
        try:
            version = pg.test_connection(self._settings)
            self.finished_ok.emit(version)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class DatabaseScreen(QWidget):
    """PostgreSQL login + basic management / visualisation."""

    status_changed = Signal(str)
    # connected, status-bar text, tooltip
    db_status_changed = Signal(bool, str, str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._settings = pg.load_settings()
        self._conn: Any | None = None
        self._worker: QThread | None = None
        self._build()

    # ------------------------------------------------------------------ UI

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        title = QLabel("Database")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        root.addWidget(title)
        blurb = QLabel(
            "Persist NetCheck data in PostgreSQL. Connect with login options below, "
            "then browse tables, run SQL, and inspect foreign-key relationships."
        )
        blurb.setWordWrap(True)
        blurb.setStyleSheet("color: #444;")
        root.addWidget(blurb)

        if not pg.psycopg_available():
            warn = QLabel(
                'PostgreSQL driver missing — install with:  pip install "psycopg[binary]"'
            )
            warn.setStyleSheet("color: #c62828; font-weight: bold;")
            warn.setWordWrap(True)
            root.addWidget(warn)

        root.addWidget(self._build_login_box())

        self.split = QSplitter(Qt.Orientation.Horizontal)
        self.split.addWidget(self._build_table_panel())
        self.split.addWidget(self._build_workspace())
        self.split.setStretchFactor(0, 0)
        self.split.setStretchFactor(1, 1)
        self.split.setSizes([260, 700])
        root.addWidget(self.split, stretch=1)

        self.db_status = QLabel("Not connected")
        self.db_status.setStyleSheet("color: #555;")
        root.addWidget(self.db_status)
        self._set_connected_ui(False)
        self._emit_db_status(False)

    def _emit_db_status(self, connected: bool, *, detail: str = "") -> None:
        s = self._settings.normalised() if self._settings else pg.load_settings()
        text = pg.status_bar_text(connected, s)
        tip = pg.status_bar_tooltip(connected, s, detail=detail)
        self.db_status_changed.emit(connected, text, tip)

    def _build_login_box(self) -> QWidget:
        box = QGroupBox("PostgreSQL login")
        form = QFormLayout(box)
        s = self._settings

        self.pg_host = QLineEdit(s.host)
        form.addRow("Host:", self.pg_host)
        self.pg_port = QSpinBox()
        self.pg_port.setRange(1, 65535)
        self.pg_port.setValue(s.port)
        form.addRow("Port:", self.pg_port)
        self.pg_database = QLineEdit(s.database)
        form.addRow("Database:", self.pg_database)
        self.pg_user = QLineEdit(s.username)
        form.addRow("Username:", self.pg_user)
        self.pg_password = QLineEdit(s.password)
        self.pg_password.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Password:", self.pg_password)
        self.pg_save_pw = QCheckBox("Save password in secrets.local.json")
        self.pg_save_pw.setChecked(s.save_password)
        form.addRow(self.pg_save_pw)

        self.pg_ssl = QComboBox()
        self.pg_ssl.addItems(["prefer", "disable", "allow", "require"])
        idx = self.pg_ssl.findText(s.sslmode)
        self.pg_ssl.setCurrentIndex(idx if idx >= 0 else 0)
        form.addRow("SSL mode:", self.pg_ssl)

        self.pg_schema = QLineEdit(s.schema)
        form.addRow("Schema:", self.pg_schema)

        row = QHBoxLayout()
        self.btn_connect = QPushButton("Connect")
        self.btn_connect.setStyleSheet(_primary_btn())
        self.btn_connect.clicked.connect(self._connect)
        row.addWidget(self.btn_connect)
        self.btn_disconnect = QPushButton("Disconnect")
        self.btn_disconnect.clicked.connect(self._disconnect)
        row.addWidget(self.btn_disconnect)
        btn_save = QPushButton("Save login")
        btn_save.clicked.connect(self._save_login)
        row.addWidget(btn_save)
        # What the live connection really is: logged in? encrypted?
        self.login_state = QLabel()
        self.login_state.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        row.addWidget(self.login_state)
        self._show_login_state(None)
        row.addStretch(1)
        form.addRow(row)
        return box

    def _build_table_panel(self) -> QWidget:
        panel = QWidget()
        v = QVBoxLayout(panel)
        v.setContentsMargins(0, 0, 0, 0)
        hdr = QHBoxLayout()
        hdr.addWidget(QLabel("Tables"))
        btn_refresh = QPushButton("Refresh")
        btn_refresh.clicked.connect(self.refresh_tables)
        hdr.addWidget(btn_refresh)
        btn_schema = QPushButton("Ensure schema")
        btn_schema.setToolTip(
            "Create NetCheck topology, config, and connectivity tables if missing"
        )
        btn_schema.clicked.connect(self._ensure_schema_clicked)
        hdr.addWidget(btn_schema)
        v.addLayout(hdr)
        self.table_tree = QTreeWidget()
        self.table_tree.setHeaderLabels(["Table", "≈ Rows"])
        self.table_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table_tree.itemSelectionChanged.connect(self._on_table_selected)
        v.addWidget(self.table_tree, stretch=1)
        ops = QHBoxLayout()
        btn_create = QPushButton("Create…")
        btn_create.clicked.connect(self._create_table)
        ops.addWidget(btn_create)
        btn_drop = QPushButton("Drop…")
        btn_drop.clicked.connect(self._drop_table)
        ops.addWidget(btn_drop)
        v.addLayout(ops)
        return panel

    def _build_workspace(self) -> QWidget:
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_data_tab(), "Table Data")
        self.tabs.addTab(self._build_structure_tab(), "Structure")
        self.tabs.addTab(self._build_query_tab(), "Query")
        self.tabs.addTab(self._build_schema_tab(), "Relationships")
        return self.tabs

    def _build_data_tab(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        row = QHBoxLayout()
        self.data_limit = QSpinBox()
        self.data_limit.setRange(10, 5000)
        self.data_limit.setValue(200)
        row.addWidget(QLabel("Limit:"))
        row.addWidget(self.data_limit)
        btn = QPushButton("Reload")
        btn.clicked.connect(self._load_selected_data)
        row.addWidget(btn)
        row.addStretch(1)
        v.addLayout(row)
        self.data_table = QTableWidget(0, 0)
        self.data_table.horizontalHeader().setStretchLastSection(True)
        self.data_table.setAlternatingRowColors(True)
        v.addWidget(self.data_table, stretch=1)
        return page

    def _build_structure_tab(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        self.structure_table = QTableWidget(0, 5)
        self.structure_table.setHorizontalHeaderLabels(
            ["Column", "Type", "Nullable", "Default", "PK"]
        )
        self.structure_table.horizontalHeader().setStretchLastSection(True)
        v.addWidget(self.structure_table, stretch=1)
        return page

    def _build_query_tab(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        split = QSplitter(Qt.Orientation.Vertical)
        self.sql_edit = QPlainTextEdit()
        self.sql_edit.setPlaceholderText(
            "SELECT * FROM public.devices LIMIT 50;\n"
            "-- or INSERT / UPDATE / DDL…"
        )
        self.sql_edit.setFont(QFont("Consolas", 10))
        split.addWidget(self.sql_edit)
        self.sql_results = QTableWidget(0, 0)
        self.sql_results.horizontalHeader().setStretchLastSection(True)
        split.addWidget(self.sql_results)
        split.setSizes([160, 240])
        v.addWidget(split, stretch=1)
        row = QHBoxLayout()
        btn_run = QPushButton("Execute")
        btn_run.setStyleSheet(_primary_btn())
        btn_run.clicked.connect(self._execute_sql)
        row.addWidget(btn_run)
        btn_clear = QPushButton("Clear")
        btn_clear.clicked.connect(self.sql_edit.clear)
        row.addWidget(btn_clear)
        row.addStretch(1)
        self.sql_message = QLabel("")
        self.sql_message.setStyleSheet("color: #555;")
        row.addWidget(self.sql_message)
        v.addLayout(row)
        return page

    def _build_schema_tab(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        row = QHBoxLayout()
        btn = QPushButton("Refresh relationships")
        btn.clicked.connect(self._refresh_schema)
        row.addWidget(btn)
        row.addStretch(1)
        v.addLayout(row)
        self.schema_canvas = _SchemaCanvas()
        v.addWidget(self.schema_canvas, stretch=1)
        return page

    # -------------------------------------------------------------- connection

    def _settings_from_ui(self) -> pg.PostgresSettings:
        return pg.PostgresSettings(
            host=self.pg_host.text().strip(),
            port=int(self.pg_port.value()),
            database=self.pg_database.text().strip(),
            username=self.pg_user.text().strip(),
            password=self.pg_password.text(),
            sslmode=self.pg_ssl.currentText(),
            schema=self.pg_schema.text().strip() or "public",
            save_password=self.pg_save_pw.isChecked(),
        )

    def _show_login_state(self, sec: pg.ConnectionSecurity | None) -> None:
        mode = self._settings.sslmode if self._settings else "prefer"
        text, color, tip = pg.security_summary(sec, mode)
        self.login_state.setText(text)
        self.login_state.setToolTip(tip)
        self.login_state.setStyleSheet(
            f"color: {color}; font-weight: 600; padding-left: 10px;"
        )

    def _refresh_login_state(self) -> None:
        if self._conn is None:
            self._show_login_state(None)
            return
        try:
            sec = pg.connection_security(self._conn)
        except Exception as exc:  # noqa: BLE001
            app_log.get_logger("database").warning("Login state check failed: %s", exc)
            self._show_login_state(None)
            return
        self._show_login_state(sec)
        app_log.get_logger("database").info(
            "Postgres login %s@%s ssl=%s %s",
            sec.user, sec.database, sec.ssl, sec.protocol,
        )

    def _save_login(self) -> None:
        settings = self._settings_from_ui()
        try:
            pg.save_settings(settings)
        except OSError as exc:
            QMessageBox.critical(self, "Database", str(exc))
            return
        self._settings = settings
        self.db_status.setText("Login settings saved.")
        self.db_status.setStyleSheet("color: #1565c0;")
        app_log.get_logger("database").info(
            "Postgres settings saved host=%s db=%s user=%s",
            settings.host,
            settings.database,
            settings.username,
        )

    def _connect(self) -> None:
        from pfsense_checker.module_required import ensure_feature

        if not ensure_feature(
            self,
            "postgres",
            purpose="connect to PostgreSQL",
        ):
            return
        if self._worker and self._worker.isRunning():
            return
        settings = self._settings_from_ui()
        self._settings = settings
        self.btn_connect.setEnabled(False)
        self.db_status.setText("Connecting…")
        self.db_status.setStyleSheet("color: #555;")
        worker = _ConnectWorker(settings)
        self._worker = worker
        worker.finished_ok.connect(self._on_connected)
        worker.failed.connect(self._on_connect_failed)
        worker.finished.connect(lambda: self.btn_connect.setEnabled(True))
        worker.start()

    def _on_connected(self, version: str) -> None:
        try:
            # Keep a live connection for the session
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:  # noqa: BLE001
                    pass
            import psycopg

            self._conn = psycopg.connect(self._settings.dsn(), autocommit=True)
        except Exception as exc:  # noqa: BLE001
            self._on_connect_failed(str(exc))
            return
        if self.pg_save_pw.isChecked():
            try:
                pg.save_settings(self._settings)
            except OSError:
                pass
        short = version.split(",")[0] if version else "connected"
        self._refresh_login_state()
        self.db_status.setText(f"Connected — {short}")
        self.db_status.setStyleSheet("color: #2e7d32;")
        self.status_changed.emit(f"Postgres: {self._settings.database}@{self._settings.host}")
        self._emit_db_status(True, detail=short)
        self._set_connected_ui(True)
        try:
            n = netcheck_schema.ensure_schema(self._conn)
            app_log.get_logger("database").info(
                "NetCheck schema ensured (%s statements)", n
            )
        except Exception as exc:  # noqa: BLE001
            app_log.get_logger("database").error("Schema ensure failed: %s", exc)
            QMessageBox.warning(
                self,
                "Database",
                f"Connected, but creating NetCheck tables failed:\n\n{exc}",
            )
        self.refresh_tables()
        self._refresh_schema()
        app_log.get_logger("database").info(
            "Postgres connected %s@%s/%s",
            self._settings.username,
            self._settings.host,
            self._settings.database,
        )

    def _on_connect_failed(self, msg: str) -> None:
        self._show_login_state(None)
        self.db_status.setText(f"Connection failed: {msg}")
        self.db_status.setStyleSheet("color: #c62828;")
        self.status_changed.emit("Postgres: not connected")
        self._emit_db_status(False, detail=msg)
        app_log.get_logger("database").error("Postgres connect failed: %s", msg)
        QMessageBox.warning(self, "Database", msg)

    def _disconnect(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:  # noqa: BLE001
                pass
            self._conn = None
        self._show_login_state(None)
        self._set_connected_ui(False)
        self.table_tree.clear()
        self.data_table.setRowCount(0)
        self.data_table.setColumnCount(0)
        self.structure_table.setRowCount(0)
        self.schema_canvas.clear_schema()
        self.db_status.setText("Disconnected")
        self.db_status.setStyleSheet("color: #555;")
        self.status_changed.emit("Postgres: not connected")
        self._emit_db_status(False)

    def _set_connected_ui(self, on: bool) -> None:
        self.btn_disconnect.setEnabled(on)
        self.split.setEnabled(on)

    def _require_conn(self) -> Any | None:
        if self._conn is None:
            QMessageBox.information(self, "Database", "Connect to PostgreSQL first.")
            return None
        return self._conn

    # --------------------------------------------------------------- tables

    def _ensure_schema_clicked(self) -> None:
        conn = self._require_conn()
        if conn is None:
            return
        try:
            n = netcheck_schema.ensure_schema(conn)
            tables = netcheck_schema.list_netcheck_tables(conn)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Ensure schema", str(exc))
            return
        self.refresh_tables()
        self._refresh_schema()
        QMessageBox.information(
            self,
            "Ensure schema",
            f"Applied {n} DDL statements.\n"
            f"NetCheck tables present: {len(tables)}/{len(netcheck_schema.EXPECTED_TABLES)}",
        )

    def refresh_tables(self) -> None:
        conn = self._require_conn()
        if conn is None:
            return
        schema = self.pg_schema.text().strip() or "public"
        try:
            tables = pg.list_tables(conn, schema)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Database", str(exc))
            return
        self.table_tree.clear()
        for t in tables:
            item = QTreeWidgetItem([t.name, "" if t.approx_rows is None else str(t.approx_rows)])
            item.setData(0, Qt.ItemDataRole.UserRole, t.schema)
            item.setToolTip(0, t.comment or t.qualified)
            self.table_tree.addTopLevelItem(item)
        self.db_status.setText(f"Connected — {len(tables)} table(s) in {schema}")

    def _selected_table(self) -> tuple[str, str] | None:
        items = self.table_tree.selectedItems()
        if not items:
            return None
        item = items[0]
        schema = item.data(0, Qt.ItemDataRole.UserRole) or (
            self.pg_schema.text().strip() or "public"
        )
        return str(schema), item.text(0)

    def _on_table_selected(self) -> None:
        self._load_selected_data()
        self._load_selected_structure()

    def _fill_grid(self, table: QTableWidget, result: pg.QueryResult) -> None:
        table.clear()
        table.setColumnCount(len(result.columns))
        table.setHorizontalHeaderLabels(result.columns)
        table.setRowCount(len(result.rows))
        for r, row in enumerate(result.rows):
            for c, val in enumerate(row):
                table.setItem(r, c, QTableWidgetItem(pg.cell_to_str(val)))

    def _load_selected_data(self) -> None:
        conn = self._require_conn()
        sel = self._selected_table()
        if conn is None or sel is None:
            return
        schema, name = sel
        try:
            result = pg.fetch_table_rows(
                conn, schema, name, limit=int(self.data_limit.value())
            )
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Database", str(exc))
            return
        self._fill_grid(self.data_table, result)
        self.tabs.setCurrentIndex(0)

    def _load_selected_structure(self) -> None:
        conn = self._require_conn()
        sel = self._selected_table()
        if conn is None or sel is None:
            return
        schema, name = sel
        try:
            cols = pg.describe_table(conn, schema, name)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Database", str(exc))
            return
        self.structure_table.setRowCount(len(cols))
        for r, col in enumerate(cols):
            values = [
                col.name,
                col.data_type,
                "YES" if col.is_nullable else "NO",
                col.column_default or "",
                "PK" if col.is_primary else "",
            ]
            for c, text in enumerate(values):
                self.structure_table.setItem(r, c, QTableWidgetItem(text))

    def _execute_sql(self) -> None:
        conn = self._require_conn()
        if conn is None:
            return
        sql = self.sql_edit.toPlainText()
        try:
            result = pg.execute_sql(conn, sql)
        except Exception as exc:  # noqa: BLE001
            self.sql_message.setText(str(exc))
            self.sql_message.setStyleSheet("color: #c62828;")
            app_log.get_logger("database").error("SQL failed: %s", exc)
            QMessageBox.warning(self, "Query", str(exc))
            return
        if result.is_select:
            self._fill_grid(self.sql_results, result)
        else:
            self.sql_results.setRowCount(0)
            self.sql_results.setColumnCount(0)
            self.refresh_tables()
        self.sql_message.setText(result.message)
        self.sql_message.setStyleSheet("color: #2e7d32;")
        app_log.get_logger("database").info("SQL ok: %s", result.message)

    def _refresh_schema(self) -> None:
        conn = self._require_conn()
        if conn is None:
            return
        schema = self.pg_schema.text().strip() or "public"
        try:
            tables = [t.name for t in pg.list_tables(conn, schema)]
            fks = pg.list_foreign_keys(conn, schema)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Database", str(exc))
            return
        self.schema_canvas.draw_schema(tables, fks)

    def _create_table(self) -> None:
        conn = self._require_conn()
        if conn is None:
            return
        schema = self.pg_schema.text().strip() or "public"
        name, ok = QInputDialog.getText(self, "Create table", "Table name:")
        if not ok or not name.strip():
            return
        default_cols = "id SERIAL PRIMARY KEY,\n  name TEXT NOT NULL,\n  created_at TIMESTAMPTZ DEFAULT now()"
        cols, ok = QInputDialog.getMultiLineText(
            self,
            "Create table",
            f'Column definitions for "{schema}.{name.strip()}":',
            default_cols,
        )
        if not ok:
            return
        try:
            sql = pg.create_table_sql(schema, name.strip(), cols)
            pg.execute_sql(conn, sql)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Create table", str(exc))
            return
        self.refresh_tables()
        self.db_status.setText(f"Created {schema}.{name.strip()}")

    def _drop_table(self) -> None:
        conn = self._require_conn()
        sel = self._selected_table()
        if conn is None or sel is None:
            QMessageBox.information(self, "Drop table", "Select a table first.")
            return
        schema, name = sel
        reply = QMessageBox.question(
            self,
            "Drop table",
            f'Drop table "{schema}.{name}"?\nThis cannot be undone.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            pg.drop_table(conn, schema, name)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Drop table", str(exc))
            return
        self.refresh_tables()
        self.data_table.setRowCount(0)
        self.structure_table.setRowCount(0)
        self.db_status.setText(f"Dropped {schema}.{name}")

    def closeEvent(self, event) -> None:  # noqa: N802
        self._disconnect()
        super().closeEvent(event)
