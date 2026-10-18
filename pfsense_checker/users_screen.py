"""Users home section — list / create / reset accounts."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from pfsense_checker import app_log, auth
from pfsense_checker.login_screen import ChangePasswordDialog


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


class UsersScreen(QWidget):
    """Manage NetCheck user accounts (admins) / change own password (all)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._current: auth.AuthUser | None = None
        self._build()

    def set_current_user(self, user: auth.AuthUser | None) -> None:
        self._current = user
        self._apply_permissions()
        self.refresh()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        title = QLabel("Users")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        root.addWidget(title)

        self.blurb = QLabel(
            "Manage NetCheck sign-in accounts. Passwords are hashed with the "
            "app public key; the table never shows password hashes."
        )
        self.blurb.setWordWrap(True)
        self.blurb.setStyleSheet("color: #444;")
        root.addWidget(self.blurb)

        actions = QHBoxLayout()
        self.btn_refresh = QPushButton("Refresh")
        self.btn_refresh.clicked.connect(self.refresh)
        actions.addWidget(self.btn_refresh)
        self.btn_add = QPushButton("Add user…")
        self.btn_add.setStyleSheet(_primary_btn())
        self.btn_add.clicked.connect(self._add_user)
        actions.addWidget(self.btn_add)
        self.btn_reset = QPushButton("Reset password…")
        self.btn_reset.clicked.connect(self._reset_password)
        actions.addWidget(self.btn_reset)
        self.btn_role = QPushButton("Set role…")
        self.btn_role.clicked.connect(self._set_role)
        actions.addWidget(self.btn_role)
        self.btn_toggle = QPushButton("Enable / Disable")
        self.btn_toggle.clicked.connect(self._toggle_active)
        actions.addWidget(self.btn_toggle)
        actions.addStretch(1)
        self.btn_own = QPushButton("Change my password…")
        self.btn_own.clicked.connect(self._change_own_password)
        actions.addWidget(self.btn_own)
        root.addLayout(actions)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Username", "Role", "Active", "Must change PW", "Created"]
        )
        self.table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        root.addWidget(self.table, stretch=1)

        self.status = QLabel("")
        self.status.setStyleSheet("color: #555;")
        root.addWidget(self.status)
        self._apply_permissions()

    def _apply_permissions(self) -> None:
        can = bool(self._current and self._current.can_manage_users)
        for btn in (self.btn_add, self.btn_reset, self.btn_role, self.btn_toggle):
            btn.setEnabled(can)
        self.btn_own.setEnabled(self._current is not None)
        if self._current and not can:
            self.blurb.setText(
                f"Signed in as <b>{self._current.username}</b> "
                f"({self._current.role}). You can change your own password; "
                "user administration requires an admin account."
            )
        elif self._current:
            self.blurb.setText(
                f"Signed in as <b>{self._current.username}</b> "
                f"({self._current.role}). Create accounts, reset temporary "
                "passwords (forces change on next login), and enable/disable users."
            )

    def refresh(self) -> None:
        try:
            rows = auth.list_users()
        except auth.AuthError as exc:
            self.status.setText(str(exc))
            self.table.setRowCount(0)
            return
        except Exception as exc:  # noqa: BLE001
            self.status.setText(f"Could not load users: {exc}")
            self.table.setRowCount(0)
            return
        self.table.setRowCount(len(rows))
        for r, rec in enumerate(rows):
            values = [
                rec.username,
                rec.role,
                "yes" if rec.is_active else "no",
                "yes" if rec.must_change_password else "no",
                rec.created_at,
            ]
            for c, text in enumerate(values):
                item = QTableWidgetItem(text)
                if c == 2 and not rec.is_active:
                    item.setForeground(Qt.GlobalColor.red)
                self.table.setItem(r, c, item)
        self.status.setText(f"{len(rows)} user(s)")

    def _selected_username(self) -> str | None:
        rows = sorted({i.row() for i in self.table.selectedIndexes()})
        if not rows:
            return None
        item = self.table.item(rows[0], 0)
        return item.text().strip() if item else None

    def _require_admin(self) -> bool:
        if self._current and self._current.can_manage_users:
            return True
        QMessageBox.warning(
            self, "Users", "Administrator privileges are required for this action."
        )
        return False

    def _add_user(self) -> None:
        if not self._require_admin():
            return
        dlg = _AddUserDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            user = auth.create_user(
                dlg.username,
                dlg.password,
                role=dlg.role,
                must_change_password=True,
            )
        except auth.AuthError as exc:
            QMessageBox.warning(self, "Add user", str(exc))
            return
        app_log.get_logger("auth").info(
            "User created by=%s new=%s role=%s",
            self._current.username if self._current else "?",
            user.username,
            user.role,
        )
        self.refresh()
        QMessageBox.information(
            self,
            "Add user",
            f"Created {user.username} ({user.role}).\n"
            "They must change the temporary password on first login.",
        )

    def _reset_password(self) -> None:
        if not self._require_admin():
            return
        name = self._selected_username()
        if not name:
            QMessageBox.information(self, "Reset password", "Select a user first.")
            return
        pw, ok = QInputDialog.getText(
            self,
            "Reset password",
            f"Temporary password for {name} (min 8 characters):",
            QLineEdit.EchoMode.Password,
        )
        if not ok:
            return
        try:
            auth.admin_reset_password(name, pw)
        except auth.AuthError as exc:
            QMessageBox.warning(self, "Reset password", str(exc))
            return
        app_log.get_logger("auth").info(
            "Password reset by=%s target=%s",
            self._current.username if self._current else "?",
            name,
        )
        self.refresh()
        QMessageBox.information(
            self,
            "Reset password",
            f"Temporary password set for {name}. "
            "They must change it on next login.",
        )

    def _set_role(self) -> None:
        if not self._require_admin():
            return
        name = self._selected_username()
        if not name:
            QMessageBox.information(self, "Set role", "Select a user first.")
            return
        if name == auth.SUPER_ADMIN_USERNAME:
            QMessageBox.information(
                self, "Set role", "The super-admin account role is fixed."
            )
            return
        roles = [auth.ROLE_USER, auth.ROLE_ADMIN]
        if self._current and self._current.is_super_admin:
            roles.append(auth.ROLE_SUPER_ADMIN)
        role, ok = QInputDialog.getItem(
            self, "Set role", f"Role for {name}:", roles, 0, False
        )
        if not ok:
            return
        try:
            auth.set_user_role(name, role)
        except auth.AuthError as exc:
            QMessageBox.warning(self, "Set role", str(exc))
            return
        self.refresh()

    def _toggle_active(self) -> None:
        if not self._require_admin():
            return
        name = self._selected_username()
        if not name:
            QMessageBox.information(self, "Users", "Select a user first.")
            return
        rows = auth.list_users()
        current = next((r for r in rows if r.username == name), None)
        if current is None:
            return
        try:
            auth.set_user_active(name, not current.is_active)
        except auth.AuthError as exc:
            QMessageBox.warning(self, "Users", str(exc))
            return
        self.refresh()

    def _change_own_password(self) -> None:
        if self._current is None:
            return
        dlg = ChangePasswordDialog(
            self._current.username,
            required=False,
            parent=self,
        )
        if dlg.exec() == QDialog.DialogCode.Accepted:
            QMessageBox.information(self, "Users", "Password updated.")
            self.refresh()


class _AddUserDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add user")
        self.setModal(True)
        self.setMinimumWidth(360)
        self.username = ""
        self.password = ""
        self.role = auth.ROLE_USER

        root = QVBoxLayout(self)
        box = QGroupBox("New account")
        form = QFormLayout(box)
        self.user_edit = QLineEdit()
        form.addRow("Username:", self.user_edit)
        self.pw_edit = QLineEdit()
        self.pw_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Temp password:", self.pw_edit)
        self.pw2_edit = QLineEdit()
        self.pw2_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Confirm:", self.pw2_edit)
        self.role_combo = QComboBox()
        self.role_combo.addItems([auth.ROLE_USER, auth.ROLE_ADMIN])
        form.addRow("Role:", self.role_combo)
        root.addWidget(box)

        self.status = QLabel("")
        self.status.setStyleSheet("color: #c62828;")
        root.addWidget(self.status)

        row = QHBoxLayout()
        row.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        row.addWidget(cancel)
        save = QPushButton("Create")
        save.setStyleSheet(_primary_btn())
        save.clicked.connect(self._save)
        row.addWidget(save)
        root.addLayout(row)

    def _save(self) -> None:
        self.status.setText("")
        if self.pw_edit.text() != self.pw2_edit.text():
            self.status.setText("Passwords do not match")
            return
        self.username = self.user_edit.text().strip()
        self.password = self.pw_edit.text()
        self.role = self.role_combo.currentText()
        try:
            auth.validate_username(self.username)
            # Validate password length via hash_password rules without storing.
            if not self.password or len(self.password) < 8:
                raise auth.AuthError("Password must be at least 8 characters")
        except auth.AuthError as exc:
            self.status.setText(str(exc))
            return
        self.accept()
