"""Launcher / login gate shown after splash, before the main NetCheck window.

Layout
------
* **Login to main tool** — username / password (requires DB users).
* **Tools** — Beacon Creation, collector, config check (no app login).
* **Status bar** — PostgreSQL connectivity.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QStatusBar,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from pfsense_checker import app_log, auth, onepassword, postgres_db as pg
from pfsense_checker.busy import busy_cursor, show_busy_while
from pfsense_checker.branding import (
    STATUS_BAR_FAIL,
    STATUS_BAR_OK,
    STATUS_BAR_TEXT,
    render_logo_pixmap,
    status_bar_stylesheet,
    status_chip_style,
)
from pfsense_checker.paths import PROJECT_ROOT
from pfsense_checker.version import APP_NAME, VERSION, format_changelog


def _primary_btn_style() -> str:
    return (
        "QPushButton {"
        " padding: 8px 22px; font-weight: bold;"
        " background-color: #1565c0;"
        " border: 1px solid #0d47a1; border-radius: 3px;"
        " color: white; }"
        "QPushButton:hover {"
        " background-color: #42a5f5;"
        " border: 1px solid #90caf9;"
        "}"
        "QPushButton:pressed {"
        " background-color: #0d47a1;"
        " border: 1px solid #0d47a1;"
        "}"
        "QPushButton:disabled {"
        " background-color: #90a4ae; border-color: #78909c; color: #eceff1;"
        "}"
    )


def _tool_btn_style() -> str:
    return (
        "QPushButton {"
        " padding: 10px 18px; min-width: 160px;"
        " background-color: #f5f5f5;"
        " border: 1px solid #333; border-radius: 3px; }"
        "QPushButton:hover { background-color: #e3f2fd; border-color: #1565c0; }"
    )


def _secondary_btn_style() -> str:
    return (
        "QPushButton {"
        " padding: 6px 14px;"
        " background-color: #fafafa;"
        " border: 1px solid #9e9e9e; border-radius: 3px; }"
        "QPushButton:hover { background-color: #eeeeee; border-color: #616161; }"
    )


def _tinted_btn_style(
    bg: str, fg: str, border: str, hover_bg: str, pressed_bg: str
) -> str:
    """Solid button with a 1px 'electric' border in a vivid version of *bg*."""
    return (
        "QPushButton {"
        f" padding: 6px 14px; font-weight: 600;"
        f" background-color: {bg}; color: {fg};"
        f" border: 1px solid {border}; border-radius: 3px; }}"
        f"QPushButton:hover {{ background-color: {hover_bg}; }}"
        f"QPushButton:pressed {{ background-color: {pressed_bg}; }}"
    )


# Help / Options / Forgot Credentials on the login panel.
HELP_BTN_STYLE = _tinted_btn_style("#ffd54f", "#212121", "#ffea00", "#ffe082", "#ffca28")
OPTIONS_BTN_STYLE = _tinted_btn_style("#424242", "#ffffff", "#b0bec5", "#616161", "#212121")
FORGOT_BTN_STYLE = _tinted_btn_style("#1e88e5", "#ffffff", "#00b0ff", "#42a5f5", "#1565c0")
# Login / Cancel on the login panel (sizes set by _sync_action_button_pair).
LOGIN_BTN_STYLE = (
    "QPushButton {"
    " padding: 8px 22px; font-weight: bold;"
    " background-color: #1565c0; color: white;"
    " border: 1px solid #448aff; border-radius: 3px; }"
    "QPushButton:hover { background-color: #42a5f5; }"
    "QPushButton:pressed { background-color: #0d47a1; }"
)
CANCEL_BTN_STYLE = _tinted_btn_style("#ffffff", "#212121", "#333333", "#f5f5f5", "#e0e0e0")


def _sync_widths_to(reference: QPushButton, *others: QPushButton) -> None:
    """Give *others* the same fixed size as *reference* (its natural width)."""
    from PySide6.QtWidgets import QSizePolicy

    width = reference.sizeHint().width()
    for btn in (reference, *others):
        btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        btn.setFixedSize(width, _ACTION_BTN_H)


def _inline_btn_style() -> str:
    return (
        "QPushButton {"
        " padding: 4px 10px;"
        " background-color: #fafafa;"
        " border: 1px solid #9e9e9e; border-radius: 3px; }"
        "QPushButton:hover { background-color: #e3f2fd; border-color: #1565c0; }"
    )


def _password_with_button(edit: QLineEdit, button: QPushButton) -> QHBoxLayout:
    row = QHBoxLayout()
    row.setContentsMargins(0, 0, 0, 0)
    row.setSpacing(6)
    row.addWidget(edit, stretch=1)
    row.addWidget(button)
    return row


def _lock_enter_default(dialog: QDialog, primary: QPushButton) -> None:
    """Enter activates *primary* only.

    Qt dialogs give every button auto-default. Enter in a line edit then
    clicks the next auto-default button in the focus chain — the 1Password
    button sits in the password row, so it was stealing Enter from Login.
    """
    for button in dialog.findChildren(QPushButton):
        if button is primary:
            button.setAutoDefault(True)
            button.setDefault(True)
        else:
            button.setAutoDefault(False)
            button.setDefault(False)


class _OpLoadThread(QThread):
    """Read a 1Password login off the UI thread (the CLI can wait ~90s)."""

    done = Signal(object, str)

    def __init__(self, username: str) -> None:
        super().__init__()
        self._username = username
        self.cancel = threading.Event()

    def run(self) -> None:
        try:
            secret = onepassword.load_login(self._username, cancel=self.cancel)
        except onepassword.FillCancelled:
            return
        except onepassword.OnePasswordError as exc:
            self.done.emit(None, str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            self.done.emit(None, str(exc))
            return
        self.done.emit(secret, "")


def _begin_op_fill(dialog: QDialog, username: str, apply) -> None:
    """Start a fill. *apply(secret, error)* runs on the GUI thread."""
    worker = getattr(dialog, "_op_worker", None)
    if worker is not None and worker.isRunning():
        return
    button = getattr(dialog, "btn_fill_op", None)
    if isinstance(button, QPushButton):
        button.setEnabled(False)
    status = getattr(dialog, "status", None)
    if isinstance(status, QLabel):
        status.setStyleSheet("color: #1565c0; font-weight: normal;")
        status.setText("Waiting for 1Password. Unlock the app if it asks.")
    thread = _OpLoadThread(username)
    dialog._op_worker = thread  # type: ignore[attr-defined]

    def _finish(secret: object, error: str) -> None:
        if isinstance(button, QPushButton):
            button.setEnabled(True)
        try:
            if not dialog.isVisible():
                return
        except RuntimeError:
            return
        apply(secret, error)

    thread.done.connect(_finish)
    # Signing in or closing the dialog ends the unlock wait. Before this,
    # `op whoami` kept polling for up to 90 s after the user had signed in.
    dialog.finished.connect(lambda _code: thread.cancel.set())
    show_busy_while(thread, message="1Password")
    thread.finished.connect(thread.deleteLater)
    thread.start()
    app_log.get_logger("onepassword").info(
        "1Password fill started user=%s elevated=%s",
        (username or "").strip() or "(none)",
        onepassword.is_elevated(),
    )


def _onepassword_cli_hint() -> str:
    if onepassword.find_cli():
        return (
            "1Password CLI found. NetCheck will start the 1Password app if it "
            "is installed but not running. Unlock it when prompted."
        )
    return (
        "1Password CLI (op) was not found. Install it and enable "
        "Settings → Developer → Integrate with 1Password CLI."
    )


def _save_op_login(username: str, password: str) -> str:
    with busy_cursor("1Password"):
        return onepassword.save_login(username, password)


# Shared size for primary action + Cancel (Cancel is always rightmost).
_ACTION_BTN_W = 220
_ACTION_BTN_H = 36


def _sync_action_button_pair(primary: QPushButton, cancel: QPushButton) -> None:
    """Make *cancel* the same outer size as *primary* (Login is the reference)."""
    from PySide6.QtWidgets import QSizePolicy

    width = max(_ACTION_BTN_W, primary.sizeHint().width())
    for btn in (primary, cancel):
        btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        btn.setFixedSize(width, _ACTION_BTN_H)


def _action_button_row(
    *buttons: QPushButton,
) -> QHBoxLayout:
    """Stretch | …actions… | Cancel(rightmost). All buttons match the first (primary)."""
    row = QHBoxLayout()
    row.setSpacing(10)
    row.addStretch(1)
    for btn in buttons:
        row.addWidget(btn)
    if buttons:
        from PySide6.QtWidgets import QSizePolicy

        width = max(_ACTION_BTN_W, buttons[0].sizeHint().width())
        for btn in buttons:
            btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            btn.setFixedSize(width, _ACTION_BTN_H)
    return row


def _console_python() -> str:
    """Prefer python.exe when the GUI was started with pythonw (so tools get a console)."""
    exe = Path(sys.executable)
    if exe.name.lower() == "pythonw.exe":
        alt = exe.with_name("python.exe")
        if alt.is_file():
            return str(alt)
    return sys.executable


class LoginOptionsDialog(QDialog):
    """Pre-login options: PostgreSQL connection used by the auth gate."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("NetCheck — Options")
        self.setModal(True)
        self.setMinimumWidth(460)
        self._settings = pg.load_settings()
        self._build()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        tip = QLabel(
            "Database connection used for sign-in and NetCheck data. "
            "Changes apply immediately after Save."
        )
        tip.setWordWrap(True)
        tip.setStyleSheet("color: #555;")
        root.addWidget(tip)

        form = QFormLayout()
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
        root.addLayout(form)

        op_box = QGroupBox("1Password")
        op_form = QFormLayout(op_box)
        op_cfg = onepassword.load_settings()
        self.op_enabled = QCheckBox("Save and fill NetCheck sign-in via 1Password CLI")
        self.op_enabled.setChecked(op_cfg.enabled)
        op_form.addRow(self.op_enabled)
        self.op_vault = QLineEdit(op_cfg.vault)
        self.op_vault.setPlaceholderText("Optional — leave blank for the default vault")
        op_form.addRow("Vault:", self.op_vault)
        self.op_prefix = QLineEdit(op_cfg.title_prefix)
        self.op_prefix.setPlaceholderText(onepassword.DEFAULT_TITLE_PREFIX)
        op_form.addRow("Item title prefix:", self.op_prefix)
        self.op_status = QLabel(_onepassword_cli_hint())
        self.op_status.setWordWrap(True)
        self.op_status.setStyleSheet("color: #555;")
        op_form.addRow(self.op_status)
        root.addWidget(op_box)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        root.addWidget(self.status)

        row = QHBoxLayout()
        btn_test = QPushButton("Test connection")
        btn_test.clicked.connect(self._test)
        row.addWidget(btn_test)
        btn_op = QPushButton("Test 1Password")
        btn_op.clicked.connect(self._test_onepassword)
        row.addWidget(btn_op)
        row.addStretch(1)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        row.addWidget(buttons)
        root.addLayout(row)

    def _from_ui(self) -> pg.PostgresSettings:
        return pg.PostgresSettings(
            host=self.pg_host.text(),
            port=self.pg_port.value(),
            database=self.pg_database.text(),
            username=self.pg_user.text(),
            password=self.pg_password.text(),
            sslmode=self.pg_ssl.currentText(),
            save_password=self.pg_save_pw.isChecked(),
            connect_timeout=self._settings.connect_timeout,
            schema=self._settings.schema,
        ).normalised()

    def _test(self) -> None:
        settings = self._from_ui()
        try:
            version = pg.test_connection(settings)
            self.status.setStyleSheet("color: #2e7d32;")
            self.status.setText(f"Connected — {version}")
        except Exception as exc:  # noqa: BLE001
            self.status.setStyleSheet("color: #c62828;")
            self.status.setText(str(exc))

    def _op_from_ui(self) -> onepassword.OnePasswordSettings:
        return onepassword.OnePasswordSettings(
            enabled=self.op_enabled.isChecked(),
            vault=self.op_vault.text().strip(),
            title_prefix=self.op_prefix.text().strip()
            or onepassword.DEFAULT_TITLE_PREFIX,
        )

    def _test_onepassword(self) -> None:
        onepassword.save_settings(self._op_from_ui())
        try:
            with busy_cursor("1Password"):
                status = onepassword.cli_status()
        except onepassword.OnePasswordError as exc:
            self.op_status.setStyleSheet("color: #c62828;")
            self.op_status.setText(str(exc))
            return
        if status.ready:
            self.op_status.setStyleSheet("color: #2e7d32;")
            extra = f" — {status.account}" if status.account else ""
            self.op_status.setText(f"1Password CLI ready{extra}.")
        else:
            self.op_status.setStyleSheet("color: #c62828;")
            self.op_status.setText(status.error or "1Password is not ready.")

    def _save(self) -> None:
        settings = self._from_ui()
        try:
            pg.save_settings(settings)
            onepassword.save_settings(self._op_from_ui())
        except Exception as exc:  # noqa: BLE001
            self.status.setStyleSheet("color: #c62828;")
            self.status.setText(f"Save failed: {exc}")
            return
        self._settings = settings
        self.accept()


class ForgotCredentialsDialog(QDialog):
    """Guidance + local recovery for the designated super-admin account."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("NetCheck — Forgot credentials")
        self.setModal(True)
        self.setMinimumWidth(480)
        self._build()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        info = QLabel(
            f"<p><b>Regular accounts</b><br/>"
            f"Ask a NetCheck administrator to reset your password from "
            f"<i>Users</i> after they sign in.</p>"
            f"<p><b>Local recovery</b><br/>"
            f"If you administer this installation and cannot sign in, you can "
            f"set a temporary password for the designated super-admin "
            f"(<code>{auth.SUPER_ADMIN_USERNAME}</code>). You will be forced to "
            f"change it on the next login.</p>"
        )
        info.setWordWrap(True)
        info.setTextFormat(Qt.TextFormat.RichText)
        root.addWidget(info)

        form = QFormLayout()
        self.new_pw = QLineEdit()
        self.new_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_pw.setPlaceholderText("New temporary password")
        form.addRow("Temporary password:", self.new_pw)
        self.new_pw2 = QLineEdit()
        self.new_pw2.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_pw2.setPlaceholderText("Confirm temporary password")
        form.addRow("Confirm:", self.new_pw2)
        self.confirm = QCheckBox(
            f"I understand this resets {auth.SUPER_ADMIN_USERNAME} on this database"
        )
        form.addRow(self.confirm)
        root.addLayout(form)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setStyleSheet("color: #c62828;")
        root.addWidget(self.status)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Reset super-admin")
        buttons.accepted.connect(self._reset)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _reset(self) -> None:
        self.status.setText("")
        if not self.confirm.isChecked():
            self.status.setText("Tick the confirmation box to continue.")
            return
        pw = self.new_pw.text()
        if pw != self.new_pw2.text():
            self.status.setText("Passwords do not match.")
            return
        try:
            auth.ensure_super_admin(pw, must_change_password=True)
        except auth.AuthError as exc:
            self.status.setText(str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            self.status.setText(str(exc))
            return
        app_log.get_logger("auth").warning(
            "Super-admin password reset via Forgot Credentials (%s)",
            auth.SUPER_ADMIN_USERNAME,
        )
        QMessageBox.information(
            self,
            "Credentials reset",
            f"Temporary password set for {auth.SUPER_ADMIN_USERNAME}.\n"
            "Sign in with that password; you will be asked to change it.",
        )
        self.accept()


class ChangePasswordDialog(QDialog):
    """Forced (or optional) password change after sign-in."""

    def __init__(
        self,
        username: str,
        *,
        current_password: str = "",
        required: bool = True,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("NetCheck — Change password")
        self.setModal(True)
        self.setMinimumWidth(420)
        self._username = username
        self._required = required
        self._user: auth.AuthUser | None = None
        self._build(current_password)

    @property
    def user(self) -> auth.AuthUser | None:
        return self._user

    def _build(self, current_password: str) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        heading = QLabel("Choose a new password")
        hf = QFont()
        hf.setPointSize(12)
        hf.setBold(True)
        heading.setFont(hf)
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(heading)

        blurb = QLabel(
            f"Signed in as <b>{self._username}</b>. "
            + (
                "You must set a new password before continuing."
                if self._required
                else "Enter your current password and a new one."
            )
        )
        blurb.setWordWrap(True)
        blurb.setAlignment(Qt.AlignmentFlag.AlignCenter)
        blurb.setStyleSheet("color: #555;")
        root.addWidget(blurb)

        form = QFormLayout()
        self.current = QLineEdit()
        self.current.setEchoMode(QLineEdit.EchoMode.Password)
        self.current.setText(current_password)
        self.current.setPlaceholderText("Current password")
        self.current.setAccessibleName("Current password")
        btn_fill = QPushButton("1Password")
        btn_fill.setStyleSheet(_inline_btn_style())
        btn_fill.setToolTip("Fill the current password from 1Password")
        btn_fill.clicked.connect(self._fill_current_from_onepassword)
        self.btn_fill_op = btn_fill
        form.addRow("Current:", _password_with_button(self.current, btn_fill))
        self.new_pw = QLineEdit()
        self.new_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_pw.setPlaceholderText("New password (min 8 characters)")
        self.new_pw.setAccessibleName("New password")
        btn_gen = QPushButton("Generate")
        btn_gen.setStyleSheet(_inline_btn_style())
        btn_gen.setToolTip("Generate a strong password")
        btn_gen.clicked.connect(self._generate_password)
        form.addRow("New:", _password_with_button(self.new_pw, btn_gen))
        self.new_pw2 = QLineEdit()
        self.new_pw2.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_pw2.setPlaceholderText("Confirm new password")
        self.new_pw2.setAccessibleName("Confirm new password")
        form.addRow("Confirm:", self.new_pw2)
        self.save_op = QCheckBox("Save new password in 1Password")
        op_cfg = onepassword.load_settings()
        cli_found = bool(onepassword.find_cli())
        self.save_op.setChecked(bool(op_cfg.enabled and cli_found))
        self.save_op.setEnabled(op_cfg.enabled)
        if not op_cfg.enabled:
            self.save_op.setToolTip("Enable 1Password in Options first.")
        elif not cli_found:
            self.save_op.setToolTip(_onepassword_cli_hint())
        else:
            self.save_op.setToolTip(
                "Create or update the NetCheck login item in 1Password after save. "
                "The 1Password app may ask you to unlock."
            )
        form.addRow(self.save_op)
        root.addLayout(form)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setStyleSheet("color: #c62828;")
        root.addWidget(self.status)

        save = QPushButton("Save password")
        save.setStyleSheet(_primary_btn_style())
        save.clicked.connect(self._on_save)
        self._enter_button = save
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        root.addLayout(_action_button_row(save, cancel))
        _lock_enter_default(self, save)

        if current_password:
            self.new_pw.setFocus()
        else:
            self.current.setFocus()

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        primary = getattr(self, "_enter_button", None)
        if isinstance(primary, QPushButton):
            _lock_enter_default(self, primary)

    def _on_save(self) -> None:
        self.status.setText("")
        new1 = self.new_pw.text()
        new2 = self.new_pw2.text()
        if new1 != new2:
            self.status.setText("New passwords do not match")
            return
        try:
            self._user = auth.change_password(
                self._username,
                self.current.text(),
                new1,
            )
        except auth.AuthError as exc:
            self.status.setText(str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            self.status.setText(str(exc))
            return
        app_log.get_logger("auth").info(
            "Password changed for user=%s", self._username
        )
        if self.save_op.isChecked():
            try:
                title = _save_op_login(self._username, new1)
            except onepassword.OnePasswordError as exc:
                QMessageBox.warning(
                    self,
                    "1Password",
                    "The NetCheck password was changed, but 1Password was not "
                    f"updated:\n{exc}",
                )
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(
                    self,
                    "1Password",
                    "The NetCheck password was changed, but 1Password was not "
                    f"updated:\n{exc}",
                )
            else:
                app_log.get_logger("auth").info(
                    "Password saved to 1Password item=%s user=%s",
                    title,
                    self._username,
                )
        self.accept()

    def _fill_current_from_onepassword(self) -> None:
        def _apply(secret: object, error: str) -> None:
            self.status.setStyleSheet("color: #c62828; font-weight: normal;")
            if error:
                self.status.setText(error)
                app_log.get_logger("onepassword").warning(
                    "1Password fill failed: %s", error
                )
                return
            if not isinstance(secret, onepassword.LoginSecret):
                self.status.setText(
                    "No NetCheck login found in 1Password for this username."
                )
                app_log.get_logger("onepassword").warning(
                    "1Password fill found no item"
                )
                return
            self.current.setText(secret.password)
            self.status.setStyleSheet("color: #2e7d32; font-weight: normal;")
            self.status.setText("Current password filled from 1Password.")
            app_log.get_logger("onepassword").info(
                "1Password filled current password user=%s", self._username
            )

        _begin_op_fill(self, self._username, _apply)

    def _generate_password(self) -> None:
        pw = onepassword.generate_password()
        self.new_pw.setText(pw)
        self.new_pw2.setText(pw)
        self.new_pw2.setFocus()


class BeaconCreatorDialog(QDialog):
    """Standalone beacon bundle generator (no main-tool login)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("NetCheck — Beacon Creation")
        self.setModal(True)
        self.resize(720, 560)
        self._build()

    def _build(self) -> None:
        from pfsense_checker.beacon_builder import default_config

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        blurb = QLabel(
            "Generate a stdlib-only beacon bundle. No NetCheck sign-in required."
        )
        blurb.setWordWrap(True)
        blurb.setStyleSheet("color: #555;")
        root.addWidget(blurb)

        form = QFormLayout()
        cfg = default_config("beacon-01")
        self.bc_id = QLineEdit(str(cfg["beacon_id"]))
        self.bc_site = QLineEdit(str(cfg.get("site", "")))
        self.bc_collector = QLineEdit(str(cfg.get("collector_url", "")))
        self.bc_token = QLineEdit(str(cfg.get("token", "")))
        self.bc_token.setPlaceholderText("Optional — must match collector --token")
        form.addRow("Beacon ID:", self.bc_id)
        form.addRow("Site:", self.bc_site)
        form.addRow("Collector URL:", self.bc_collector)
        form.addRow("Token:", self.bc_token)
        root.addLayout(form)

        os_row = QHBoxLayout()
        os_row.addWidget(QLabel("Target OS:"))
        self.os_checks: dict[str, QCheckBox] = {}
        for key, label in (
            ("windows", "Windows"),
            ("macos", "macOS"),
            ("linux", "Linux"),
            ("bsd", "BSD"),
        ):
            cb = QCheckBox(label)
            cb.setChecked(True)
            self.os_checks[key] = cb
            os_row.addWidget(cb)
        os_row.addStretch(1)
        root.addLayout(os_row)

        out_row = QHBoxLayout()
        out_row.addWidget(QLabel("Output:"))
        self.outdir = QLineEdit(str((PROJECT_ROOT / "beacons").resolve()))
        out_row.addWidget(self.outdir, stretch=1)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        out_row.addWidget(browse)
        self.zip_cb = QCheckBox("Also .zip")
        self.zip_cb.setChecked(True)
        out_row.addWidget(self.zip_cb)
        root.addLayout(out_row)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 9))
        root.addWidget(self.output, stretch=1)

        gen = QPushButton("Generate bundle(s)")
        gen.setStyleSheet(_primary_btn_style())
        gen.clicked.connect(self._generate)
        close_btn = QPushButton("Cancel")
        close_btn.clicked.connect(self.reject)
        root.addLayout(_action_button_row(gen, close_btn))

    def _browse(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Output folder", self.outdir.text())
        if d:
            self.outdir.setText(d)

    def _generate(self) -> None:
        from pfsense_checker.beacon_builder import build_bundle, default_config

        targets = [k for k, cb in self.os_checks.items() if cb.isChecked()]
        if not targets:
            QMessageBox.warning(self, "Beacon Creation", "Select at least one OS.")
            return
        cfg = default_config(self.bc_id.text().strip() or "beacon-01")
        cfg["site"] = self.bc_site.text().strip()
        cfg["collector_url"] = self.bc_collector.text().strip()
        cfg["token"] = self.bc_token.text().strip()
        out = Path(self.outdir.text().strip() or (PROJECT_ROOT / "beacons"))
        try:
            result = build_bundle(
                cfg,
                targets,
                out,
                make_zip=self.zip_cb.isChecked(),
            )
        except Exception as exc:  # noqa: BLE001
            self.output.setPlainText(f"Failed: {exc}")
            return
        lines = [
            f"Bundle: {result.bundle_dir}",
            f"Files: {len(result.files)}",
        ]
        if result.zip_path:
            lines.append(f"Zip: {result.zip_path}")
        for w in result.warnings:
            lines.append(f"Warning: {w}")
        self.output.setPlainText("\n".join(lines))


class ConfigCheckDialog(QDialog):
    """Headless-style config report (no main-tool login)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("NetCheck — Check config")
        self.setModal(True)
        self.resize(800, 560)
        root = QVBoxLayout(self)
        row = QHBoxLayout()
        self.path = QLineEdit()
        self.path.setPlaceholderText("config.xml or MikroTik .rsc")
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        row.addWidget(self.path, stretch=1)
        row.addWidget(browse)
        root.addLayout(row)
        self.report = QTextEdit()
        self.report.setReadOnly(True)
        self.report.setFont(QFont("Consolas", 9))
        root.addWidget(self.report, stretch=1)
        close = QPushButton("Cancel")
        close.clicked.connect(self.reject)
        check = QPushButton("Check")
        check.setStyleSheet(_primary_btn_style())
        check.clicked.connect(self._run)
        root.addLayout(_action_button_row(check, close))

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open config",
            "",
            "Configs (*.xml *.rsc *.routeros);;All files (*)",
        )
        if path:
            self.path.setText(path)

    def _run(self) -> None:
        from pfsense_checker.cli import _text_report
        from pfsense_checker.checker import check_file

        path = self.path.text().strip()
        if not path:
            QMessageBox.warning(self, "Check config", "Choose a config file.")
            return
        try:
            result = check_file(path)
            self.report.setPlainText(_text_report(result))
        except Exception as exc:  # noqa: BLE001
            self.report.setPlainText(f"Failed: {exc}")


class LoginDialog(QDialog):
    """Launcher: login to main tool + tools that skip sign-in + DB status bar."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("NetCheck")
        # Window-modal, not application-modal, so the companion console stays
        # usable while 1Password waits for unlock.
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setFixedSize(1200, 800)
        self._user: auth.AuthUser | None = None
        self._password_used: str = ""
        self._bootstrap = False
        self._db_probe_worker: QThread | None = None
        self._build()
        self._prepare_mode()
        self._center_on_screen()
        self._refresh_db_status()
        self._db_timer = QTimer(self)
        self._db_timer.setInterval(5000)
        self._db_timer.timeout.connect(self._refresh_db_status)
        self._db_timer.start()

    def _center_on_screen(self) -> None:
        from PySide6.QtWidgets import QApplication

        screen = QApplication.primaryScreen()
        if screen is None:
            return
        geo = self.frameGeometry()
        geo.moveCenter(screen.availableGeometry().center())
        self.move(geo.topLeft())

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        primary = getattr(self, "_enter_button", None)
        if isinstance(primary, QPushButton):
            _lock_enter_default(self, primary)

    @property
    def user(self) -> auth.AuthUser | None:
        return self._user

    @property
    def password_used(self) -> str:
        return self._password_used

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(36, 28, 36, 16)
        layout.setSpacing(14)

        logo = render_logo_pixmap(width=800)
        if logo is not None:
            brand = QLabel()
            brand.setPixmap(logo)
            brand.setAlignment(Qt.AlignmentFlag.AlignCenter)
            brand.setStyleSheet("background: transparent;")
        else:
            brand = QLabel("NetCheck")
            bf = QFont()
            bf.setPointSize(100)
            bf.setBold(True)
            brand.setFont(bf)
            brand.setAlignment(Qt.AlignmentFlag.AlignCenter)
        # Centre the whole mark (A + netcheck) in the window — not just the pixmap
        # inside a left-docked label sized to the image.
        brand.setScaledContents(False)
        layout.addWidget(brand, 0, Qt.AlignmentFlag.AlignHCenter)

        # --- Login to main tool ---
        login_box = QGroupBox("Login to main tool")
        login_box.setStyleSheet(
            "QGroupBox { font-weight: bold; font-size: 13px; margin-top: 8px; }"
            "QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; }"
        )
        login_inner = QVBoxLayout(login_box)
        login_inner.setSpacing(10)

        self.heading = QLabel("Sign in to open the NetCheck workspace")
        self.heading.setStyleSheet("font-weight: normal; color: #555;")
        self.heading.setWordWrap(True)
        login_inner.addWidget(self.heading)

        form = QFormLayout()
        form.setSpacing(8)
        self.username = QLineEdit()
        self.username.setPlaceholderText("Username")
        self.username.setText(auth.SUPER_ADMIN_USERNAME)
        self.username.setMinimumHeight(28)
        self.username.setAccessibleName("Username")
        form.addRow("Username:", self.username)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Password")
        self.password.setMinimumHeight(28)
        self.password.setAccessibleName("Password")
        # True while the field still holds an unedited 1Password fill. Only
        # a flag: the password is not kept anywhere else.
        self._password_from_op = False
        self.password.textEdited.connect(self._on_password_edited)
        self.btn_fill_op = QPushButton("1Password")
        self.btn_fill_op.setStyleSheet(_inline_btn_style())
        self.btn_fill_op.setToolTip("Fill username and password from 1Password")
        self.btn_fill_op.clicked.connect(self._fill_from_onepassword)
        form.addRow("Password:", _password_with_button(self.password, self.btn_fill_op))
        self.password2 = QLineEdit()
        self.password2.setEchoMode(QLineEdit.EchoMode.Password)
        self.password2.setPlaceholderText("Confirm password")
        self.password2.setMinimumHeight(28)
        self.password2.setAccessibleName("Confirm password")
        self.password2_label = QLabel("Confirm:")
        form.addRow(self.password2_label, self.password2)
        login_inner.addLayout(form)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setStyleSheet("color: #c62828; font-weight: normal;")
        login_inner.addWidget(self.status)

        self.btn_help = QPushButton("Help")
        self.btn_options = QPushButton("Options")
        self.btn_forgot = QPushButton("Forgot Credentials")
        self.btn_help.setStyleSheet(HELP_BTN_STYLE)
        self.btn_options.setStyleSheet(OPTIONS_BTN_STYLE)
        self.btn_forgot.setStyleSheet(FORGOT_BTN_STYLE)
        for b in (self.btn_help, self.btn_options, self.btn_forgot):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
        # Forgot Credentials is the widest label: the other two match it.
        _sync_widths_to(self.btn_forgot, self.btn_help, self.btn_options)
        self.btn_help.clicked.connect(self._show_help)
        self.btn_options.clicked.connect(self._open_options)
        self.btn_forgot.clicked.connect(self._open_forgot_credentials)

        self.submit = QPushButton("Login to main tool")
        self.submit.setCursor(Qt.CursorShape.PointingHandCursor)
        self.submit.setStyleSheet(LOGIN_BTN_STYLE)
        self.submit.clicked.connect(self._on_submit)
        self._enter_button = self.submit
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setStyleSheet(CANCEL_BTN_STYLE)
        self.cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.cancel_btn.clicked.connect(self.reject)

        # One row: Help / Options / Forgot on the left, Login / Cancel on the right.
        pane_btns = QHBoxLayout()
        pane_btns.setSpacing(8)
        pane_btns.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        for b in (self.btn_help, self.btn_options, self.btn_forgot):
            pane_btns.addWidget(b, alignment=Qt.AlignmentFlag.AlignVCenter)
        pane_btns.addStretch(1)
        pane_btns.addWidget(self.submit, alignment=Qt.AlignmentFlag.AlignVCenter)
        pane_btns.addWidget(self.cancel_btn, alignment=Qt.AlignmentFlag.AlignVCenter)
        _sync_action_button_pair(self.submit, self.cancel_btn)
        login_inner.addLayout(pane_btns)
        layout.addWidget(login_box)

        # Push Tools dock to the bottom of the window (above status bar).
        layout.addStretch(1)

        # --- Tools (no login) ---
        tools_box = QGroupBox("Tools (no sign-in required)")
        tools_box.setStyleSheet(
            "QGroupBox { font-weight: bold; font-size: 13px; margin-top: 8px; }"
            "QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; }"
        )
        tools_inner = QVBoxLayout(tools_box)
        tip = QLabel(
            "These run without logging into the main tool. "
            "Use them for beacon bundles, the monitoring collector, or a quick config check."
        )
        tip.setWordWrap(True)
        tip.setStyleSheet("font-weight: normal; color: #555;")
        tools_inner.addWidget(tip)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)
        self.btn_beacon = QPushButton("Beacon Creation")
        self.btn_collector = QPushButton("Start Collector")
        self.btn_check = QPushButton("Check Config")
        for b in (self.btn_beacon, self.btn_collector, self.btn_check):
            b.setStyleSheet(_tool_btn_style())
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            btn_row.addWidget(b)
        btn_row.addStretch(1)
        tools_inner.addLayout(btn_row)
        layout.addWidget(tools_box)

        self.btn_beacon.clicked.connect(self._open_beacon_creator)
        self.btn_collector.clicked.connect(self._start_collector)
        self.btn_check.clicked.connect(self._open_config_check)

        root.addWidget(body, stretch=1)

        self.status_bar = QStatusBar()
        self.status_bar.setSizeGripEnabled(False)
        bar_font = QFont()
        bar_font.setPointSize(9)
        bar_font.setWeight(QFont.Weight.DemiBold)
        self.status_bar.setFont(bar_font)
        self.status_bar.setStyleSheet(status_bar_stylesheet())
        self._db_chip = QLabel("DB: …")
        self._db_chip.setFont(bar_font)
        self._db_chip.setStyleSheet(status_chip_style(STATUS_BAR_TEXT, extra_padding="2px 6px"))
        self.status_bar.addWidget(self._db_chip)
        root.addWidget(self.status_bar)
        _lock_enter_default(self, self.submit)

    def _refresh_db_status(self) -> None:
        """Probe PostgreSQL off the UI thread for the launcher status bar."""
        if getattr(self, "_db_probe_worker", None) is not None:
            if self._db_probe_worker.isRunning():
                return

        class _DbProbe(QThread):
            finished_ok = Signal(str, str, object)  # text, tip, color

            def run(self) -> None:  # noqa: D102
                try:
                    ok, settings, detail = pg.probe_connection(timeout=2)
                    text = pg.status_bar_text(ok, settings)
                    tip = pg.status_bar_tooltip(ok, settings, detail=detail)
                    color = STATUS_BAR_OK if ok else STATUS_BAR_FAIL
                except Exception as exc:  # noqa: BLE001
                    text = "DB: offline · probe failed"
                    tip = str(exc)
                    color = STATUS_BAR_FAIL
                self.finished_ok.emit(text, tip, color)

        worker = _DbProbe()
        self._db_probe_worker = worker
        worker.finished_ok.connect(self._apply_db_status)
        # Clear our reference before deleteLater — otherwise the next timer
        # tick calls isRunning() on a deleted C++ object (libshiboken crash).
        worker.finished.connect(lambda: setattr(self, "_db_probe_worker", None))
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def _apply_db_status(self, text: str, tip: str, color: object) -> None:
        self._db_chip.setText(text)
        self._db_chip.setToolTip(tip)
        self._db_chip.setStyleSheet(status_chip_style(color, extra_padding="2px 6px"))

    def _show_help(self) -> None:
        body = (
            f"<p><b>{APP_NAME} {VERSION}</b> — launcher help</p>"
            "<p><b>Login to main tool</b><br/>"
            "Sign in with your NetCheck username and password. Accounts live in "
            "the PostgreSQL <code>users</code> table (see status bar for DB status).</p>"
            "<p><b>Options</b><br/>"
            "Configure the database host, port, database name, and credentials "
            "used for authentication.</p>"
            "<p><b>Forgot Credentials</b><br/>"
            "Regular users: ask an administrator to reset your password. "
            f"Local recovery can reset the designated super-admin "
            f"(<code>{auth.SUPER_ADMIN_USERNAME}</code>).</p>"
            "<p><b>1Password</b><br/>"
            "Install the 1Password CLI (<code>op</code>) and the 1Password "
            "desktop app. NetCheck starts the app if it is installed but not "
            "running. Enable <i>Settings → Developer → Integrate with "
            "1Password CLI</i>. Use the <i>1Password</i> button to fill "
            "sign-in, and tick <i>Save new password in 1Password</i> when "
            "changing your password. Vault and item title are under Options.</p>"
            "<p><b>Console</b><br/>"
            "A companion window opens beside NetCheck and lists log lines, "
            "including 1Password CLI errors. Home → Console → Pop out raises it.</p>"
            "<p><b>Tools</b> at the bottom run without signing in "
            "(Beacon Creation, Collector, Check Config).</p>"
            f"<hr/><pre style='font-size: 9pt;'>{format_changelog(max_releases=1)}</pre>"
        )
        box = QMessageBox(self)
        box.setWindowTitle("NetCheck — Help")
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setText(body)
        box.setIcon(QMessageBox.Icon.Information)
        box.exec()

    def _open_options(self) -> None:
        if LoginOptionsDialog(self).exec() == QDialog.DialogCode.Accepted:
            self._refresh_db_status()
            self._prepare_mode()
            self.status_bar.showMessage("Database options saved", 4000)

    def _open_forgot_credentials(self) -> None:
        if ForgotCredentialsDialog(self).exec() == QDialog.DialogCode.Accepted:
            self.username.setText(auth.SUPER_ADMIN_USERNAME)
            self.password.clear()
            self.password.setFocus()
            self._prepare_mode()
            self.status.setStyleSheet("color: #2e7d32; font-weight: normal;")
            self.status.setText(
                f"Temporary password ready for {auth.SUPER_ADMIN_USERNAME} — sign in now."
            )

    def _fill_from_onepassword(self) -> None:
        def _apply(secret: object, error: str) -> None:
            self.status.setStyleSheet("color: #c62828; font-weight: normal;")
            if error:
                self.status.setText(error)
                app_log.get_logger("onepassword").warning(
                    "1Password fill failed: %s", error
                )
                return
            if not isinstance(secret, onepassword.LoginSecret):
                self.status.setText(
                    "No NetCheck login found in 1Password for this username. "
                    "Save one after a password change, or create an item tagged NetCheck."
                )
                app_log.get_logger("onepassword").warning(
                    "1Password fill found no item"
                )
                return
            if secret.username:
                self.username.setText(secret.username)
            self.password.setText(secret.password)
            self._password_from_op = True
            self.password.setFocus()
            self.status.setStyleSheet("color: #2e7d32; font-weight: normal;")
            self.status.setText("Filled from 1Password.")
            app_log.get_logger("onepassword").info(
                "1Password fill applied user=%s", secret.username
            )

        _begin_op_fill(self, self.username.text().strip(), _apply)

    def _on_password_edited(self, _text: str) -> None:
        self._password_from_op = False

    def _open_beacon_creator(self) -> None:
        BeaconCreatorDialog(self).exec()

    def _start_collector(self) -> None:
        from PySide6.QtWidgets import QInputDialog

        port, ok = QInputDialog.getInt(
            self, "Start Collector", "Listen port:", 8787, 1, 65535
        )
        if not ok:
            return
        script = PROJECT_ROOT / "run_collector.py"
        if not script.is_file():
            QMessageBox.warning(self, "Collector", f"Missing {script}")
            return
        from PySide6.QtCore import QProcess

        started = QProcess.startDetached(
            _console_python(),
            [str(script), "--host", "0.0.0.0", "--port", str(port)],
            str(PROJECT_ROOT),
        )
        if started:
            QMessageBox.information(
                self,
                "Collector",
                f"Collector started on port {port}.\n"
                "A console window should remain open while it runs.",
            )
            self.status_bar.showMessage(f"Collector started on :{port}", 5000)
        else:
            QMessageBox.warning(self, "Collector", "Failed to start collector process.")

    def _open_config_check(self) -> None:
        ConfigCheckDialog(self).exec()

    def _set_bootstrap_ui(self, bootstrap: bool) -> None:
        self._bootstrap = bootstrap
        self.password2.setVisible(bootstrap)
        self.password2_label.setVisible(bootstrap)
        if bootstrap:
            self.heading.setText(
                "No users yet — create the first administrator to unlock the main tool."
            )
            self.submit.setText("Create & login to main tool")
        else:
            self.heading.setText("Sign in to open the NetCheck workspace")
            self.submit.setText("Login to main tool")
        # Keep Cancel matched to Login width after label changes.
        _sync_action_button_pair(self.submit, self.cancel_btn)

    def _prepare_mode(self) -> None:
        try:
            auth.ensure_users_schema()
            empty = auth.user_count() == 0
        except auth.AuthError as exc:
            self.status.setText(str(exc))
            self.submit.setEnabled(False)
            self._set_bootstrap_ui(False)
            return
        except Exception as exc:  # noqa: BLE001
            self.status.setText(f"Database unavailable: {exc}")
            self.submit.setEnabled(False)
            self._set_bootstrap_ui(False)
            return
        self._set_bootstrap_ui(empty)

    def _on_submit(self) -> None:
        self.status.setStyleSheet("color: #c62828; font-weight: normal;")
        self.status.setText("")
        user = self.username.text().strip()
        pw = self.password.text()
        source = "1password" if self._password_from_op else "typed"
        try:
            if self._bootstrap:
                if pw != self.password2.text():
                    raise auth.AuthError("Passwords do not match")
                self._user = auth.bootstrap_admin_if_empty(user, pw)
                if self._user is None:
                    self._set_bootstrap_ui(False)
                    self._user = auth.authenticate(user, pw, source=source)
                else:
                    app_log.get_logger("auth").info(
                        "Bootstrapped admin user=%s", self._user.username
                    )
            else:
                self._user = auth.authenticate(user, pw, source=source)
        except auth.AuthError as exc:
            self.status.setText(str(exc))
            app_log.get_logger("auth").warning("Login failed: %s", exc)
            return
        except Exception as exc:  # noqa: BLE001
            self.status.setText(str(exc))
            app_log.get_logger("auth").error("Login error: %s", exc)
            return
        self._password_used = pw
        app_log.get_logger("auth").info("User signed in: %s", self._user.username)
        self._db_timer.stop()
        self.accept()

    def reject(self) -> None:
        self._db_timer.stop()
        super().reject()


def run_login_gate(parent: QWidget | None = None) -> auth.AuthUser | None:
    """Show the launcher (and forced password change if required)."""
    dlg = LoginDialog(parent)
    if dlg.exec() != QDialog.DialogCode.Accepted:
        return None
    user = dlg.user
    if user is None:
        return None
    # Re-read flag from DB (source of truth) — do not trust a stale in-memory value.
    must_change = bool(user.must_change_password)
    try:
        must_change = auth.user_must_change_password(user.username)
    except auth.AuthError:
        pass
    if must_change:
        app_log.get_logger("auth").info(
            "Forced password change required for user=%s", user.username
        )
        change = ChangePasswordDialog(
            user.username,
            current_password=dlg.password_used,
            required=True,
            parent=parent,
        )
        if change.exec() != QDialog.DialogCode.Accepted or change.user is None:
            app_log.get_logger("auth").info(
                "Password change cancelled for user=%s", user.username
            )
            return None
        # Final guarantee: flag must be clear after a successful change.
        try:
            if auth.user_must_change_password(user.username):
                auth.clear_must_change_password(user.username)
        except auth.AuthError as exc:
            app_log.get_logger("auth").error(
                "Could not clear must_change for user=%s: %s", user.username, exc
            )
        app_log.get_logger("auth").info(
            "Password change completed for user=%s (must_change cleared)",
            user.username,
        )
        return change.user
    return user
