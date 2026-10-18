"""Setup page for the OpenObserve ingest and search API."""

from __future__ import annotations

from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from pfsense_checker import openobserve

_PRIMARY = (
    "QPushButton { padding: 4px 18px;"
    " background-color: rgba(21, 101, 192, 128);"
    " border: 1px solid rgb(21, 101, 192); border-radius: 3px;"
    " color: white; font-weight: bold; }"
    "QPushButton:hover { background-color: rgba(21, 101, 192, 178); }"
)


class _Job(QThread):
    succeeded = Signal(str)
    failed = Signal(str)

    def __init__(self, fn, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._fn = fn

    def run(self) -> None:  # noqa: D102
        try:
            self.succeeded.emit(self._fn())
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class OpenObserveScreen(QWidget):
    """Configure the OpenObserve URL and run a read-only search."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._job: _Job | None = None
        self._build()

    def _build(self) -> None:
        settings = openobserve.load_settings()
        root = QVBoxLayout(self)
        title = QLabel("Setup — OpenObserve")
        font = QFont()
        font.setPointSize(13)
        font.setBold(True)
        title.setFont(font)
        root.addWidget(title)

        intro = QLabel(
            "Ingest NetCheck app logs and accepted router syslog into an "
            "OpenObserve stream, and run a read-only SQL search. The password "
            "or token is stored in the OS keyring, not in the settings file "
            "and not in PostgreSQL."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #444;")
        root.addWidget(intro)

        box = QGroupBox("Connection")
        form = QFormLayout(box)

        self.enabled = QCheckBox("Send logs to OpenObserve")
        self.enabled.setChecked(settings.enabled)
        form.addRow(self.enabled)

        self.base_url = QLineEdit(settings.base_url)
        self.base_url.setPlaceholderText(openobserve.DEFAULT_URL)
        form.addRow("Server URL:", self.base_url)

        self.organization = QLineEdit(settings.organization)
        form.addRow("Organization:", self.organization)

        self.stream = QLineEdit(settings.stream)
        form.addRow("Stream:", self.stream)

        self.username = QLineEdit(settings.username)
        self.username.setPlaceholderText("root@example.com — blank if you use a Bearer token")
        form.addRow("User:", self.username)

        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        if openobserve.password_is_stored(settings.username):
            self.password.setPlaceholderText(
                "Stored in the OS keyring — leave blank to keep it"
            )
        else:
            self.password.setPlaceholderText("Password, or a token if User is blank")
        form.addRow("Password / token:", self.password)

        self.clear_password = QCheckBox("Remove the stored password")
        form.addRow(self.clear_password)

        self.ship_app_logs = QCheckBox("Ship NetCheck app logs")
        self.ship_app_logs.setChecked(settings.ship_app_logs)
        form.addRow(self.ship_app_logs)

        self.ship_syslog = QCheckBox("Ship accepted router syslog")
        self.ship_syslog.setChecked(settings.ship_syslog)
        form.addRow(self.ship_syslog)
        root.addWidget(box)

        actions = QHBoxLayout()
        test_btn = QPushButton("Test connection")
        test_btn.clicked.connect(self._test)
        actions.addWidget(test_btn)
        save_btn = QPushButton("Save")
        save_btn.setStyleSheet(_PRIMARY)
        save_btn.clicked.connect(self._save)
        actions.addWidget(save_btn)
        actions.addStretch(1)
        root.addLayout(actions)

        query_box = QGroupBox("Search")
        query_form = QFormLayout(query_box)
        self.sql = QLineEdit(f"SELECT * FROM {settings.stream}")
        query_form.addRow("SQL:", self.sql)
        self.time_range = QComboBox()
        for label, minutes in (
            ("15 minutes", 15),
            ("1 hour", 60),
            ("6 hours", 360),
            ("24 hours", 1440),
            ("7 days", 10080),
        ):
            self.time_range.addItem(label, minutes)
        query_form.addRow("Time range:", self.time_range)
        run_btn = QPushButton("Run query")
        run_btn.clicked.connect(self._query)
        query_form.addRow(run_btn)
        root.addWidget(query_box)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setStyleSheet("color: #455a64;")
        root.addWidget(self.status)

        self.results = QPlainTextEdit()
        self.results.setReadOnly(True)
        self.results.setPlaceholderText("Query hits appear here.")
        root.addWidget(self.results, stretch=1)

        err = openobserve.last_error()
        if err:
            self.status.setText(err)

    def _settings_from_form(self) -> openobserve.OpenObserveSettings:
        return openobserve.OpenObserveSettings(
            enabled=self.enabled.isChecked(),
            base_url=self.base_url.text().strip() or openobserve.DEFAULT_URL,
            organization=self.organization.text().strip() or openobserve.DEFAULT_ORG,
            stream=self.stream.text().strip() or openobserve.DEFAULT_STREAM,
            username=self.username.text().strip(),
            ship_app_logs=self.ship_app_logs.isChecked(),
            ship_syslog=self.ship_syslog.isChecked(),
        )

    def _typed_password(self) -> str | None:
        text = self.password.text()
        return text if text else None

    def _save(self) -> None:
        try:
            settings = self._settings_from_form()
            openobserve.save_settings(settings)
            if self.clear_password.isChecked():
                openobserve.clear_password(settings.username)
                self.clear_password.setChecked(False)
                self.password.setPlaceholderText("Password, or a token if User is blank")
            elif self.password.text():
                openobserve.store_password(settings.username, self.password.text())
                self.password.clear()
                self.password.setPlaceholderText(
                    "Stored in the OS keyring — leave blank to keep it"
                )
            openobserve.start_shipper()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "OpenObserve", str(exc))
            return
        warning = openobserve.credential_transport_warning(settings.base_url)
        self.status.setStyleSheet("color: #1565c0;")
        self.status.setText(
            "Saved. Shipping uses these settings."
            + (f"\n{warning}" if warning else "")
        )
        self.sql.setText(f"SELECT * FROM {settings.stream}")

    def _test(self) -> None:
        settings = self._settings_from_form()
        password = self._typed_password()

        def run() -> str:
            return openobserve.test_connection(settings, password=password)

        self._start(run, "Testing OpenObserve…")

    def _query(self) -> None:
        settings = self._settings_from_form()
        password = self._typed_password()
        sql = self.sql.text()
        minutes = int(self.time_range.currentData() or 15)

        def run() -> str:
            payload = openobserve.search(
                sql, settings, minutes=minutes, password=password
            )
            return openobserve.format_search_result(payload)

        self._start(run, "Running query…")

    def _start(self, fn, pending: str) -> None:
        if self._job is not None and self._job.isRunning():
            self.status.setText("Wait for the current OpenObserve call to finish.")
            return
        self.status.setStyleSheet("color: #455a64;")
        self.status.setText(pending)
        job = _Job(fn, self)
        job.succeeded.connect(self._show_ok)
        job.failed.connect(self._show_err)
        self._job = job
        job.start()

    def _show_ok(self, text: str) -> None:
        self.status.setStyleSheet("color: #2e7d32;")
        self.status.setText(text.split("\n", 1)[0])
        self.results.setPlainText(text)

    def _show_err(self, text: str) -> None:
        self.status.setStyleSheet("color: #c62828;")
        self.status.setText(text)
        self.results.setPlainText(text)
