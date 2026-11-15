"""Security Holes page: the list of weaknesses, what each means and how to close it."""

from __future__ import annotations

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from pfsense_checker import app_log, vuln_db
from pfsense_checker import security_holes as sh

SEVERITY_COLOUR = {sh.HIGH: "#c62828", sh.MEDIUM: "#ef6c00", sh.LOW: "#455a64"}
ALL_SEVERITIES = "All severities"
ALL_DEVICES = "All devices"
CURRENT_PRODUCTS = (("routeros", "MikroTik RouterOS"), ("pfsense-plus", "pfSense Plus"), ("pfsense-ce", "pfSense CE"))


def saved_username(device) -> str:  # noqa: ANN001
    from pfsense_checker import device_logs

    return (device_logs.login_details(device).username or "").strip()


def saved_password(device) -> str | None:  # noqa: ANN001
    """The password saved for the device's login (keyring), or None. Never logged or shown."""
    from pfsense_checker import device_logs
    from pfsense_checker.ssh_session import resolve_ssh_password

    try:
        ssh = device_logs.login_details(device)
        return resolve_ssh_password(ssh, (ssh.username or "").strip(), None)
    except Exception:  # noqa: BLE001 - no keyring, or the entry cannot be read: nothing to compare
        return None


class _CollectWorker(QThread):
    done = Signal(object)  # sh.Report
    failed = Signal(str)

    def __init__(self, job) -> None:  # noqa: ANN001
        super().__init__()
        self._job = job

    def run(self) -> None:  # noqa: D102
        try:
            self.done.emit(self._job())
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class SecurityHolesPage(QWidget):
    """Check now → findings by area → what it means and how to fix it."""

    def __init__(self, parent: QWidget | None = None, *, site=None, seen=None,  # noqa: ANN001, PLR0915
                 password_of=saved_password, username_of=saved_username) -> None:
        """*site*: callable → the Login to Routers site. *seen*: callable → hosts the sweep saw."""
        super().__init__(parent)
        self._site = site
        self._seen = seen
        self._password_of = password_of
        self._username_of = username_of
        self._worker: _CollectWorker | None = None
        self.report: sh.Report | None = None

        v = QVBoxLayout(self)
        title = QLabel("Security Holes")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        blurb = QLabel(
            "One list of weaknesses across the devices on Login to Routers: services and ports left open, "
            "firewall rules that let everything through, known vulnerabilities in the software each device "
            "runs, old software, and weak logins. It reads the saved configs, what the Login to Routers sweep "
            "saw and (if you tick the box) the saved logins. It does not contact any device and changes nothing."
        )
        blurb.setWordWrap(True)
        blurb.setStyleSheet("color: #555;")
        v.addWidget(blurb)

        row = QHBoxLayout()
        self.btn_check = QPushButton("Check now")
        self.btn_check.clicked.connect(lambda: self.check())
        row.addWidget(self.btn_check)
        self.btn_copy = QPushButton("Copy list")
        self.btn_copy.setToolTip("Copies every finding shown, with its fix, as text")
        self.btn_copy.clicked.connect(self.copy_list)
        self.btn_copy.setEnabled(False)
        row.addWidget(self.btn_copy)
        self.compare_passwords = QCheckBox("Compare saved passwords")
        self.compare_passwords.setToolTip(
            "Looks for a saved password that is a factory default, and for one password saved for several "
            "devices. The passwords are read from this PC's keyring and compared here. They are never "
            "shown, stored anywhere else, or written to a log."
        )
        row.addWidget(self.compare_passwords)
        row.addStretch(1)
        v.addLayout(row)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.TextFormat.RichText)
        self.status.setStyleSheet("font-weight: 600; color: #263238;")
        v.addWidget(self.status)

        filt = QHBoxLayout()
        filt.addWidget(QLabel("Show:"))
        self.f_severity = QComboBox()
        self.f_severity.addItem(ALL_SEVERITIES, "")
        for s in sh.SEVERITIES:
            self.f_severity.addItem(sh.SEVERITY_WORD[s], s)
        self.f_severity.currentIndexChanged.connect(self._fill)
        filt.addWidget(self.f_severity)
        self.f_device = QComboBox()
        self.f_device.setMinimumWidth(200)
        self.f_device.addItem(ALL_DEVICES, "")
        self.f_device.currentIndexChanged.connect(self._fill)
        filt.addWidget(self.f_device)
        self.f_text = QLineEdit()
        self.f_text.setClearButtonEnabled(True)
        self.f_text.setPlaceholderText("telnet, CVE, winbox, firewall…")
        self.f_text.textChanged.connect(self._fill)
        filt.addWidget(self.f_text, 1)
        v.addLayout(filt)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Weakness", "Device", "Severity"])
        self.tree.setColumnWidth(0, 470)
        self.tree.setColumnWidth(1, 170)
        self.tree.currentItemChanged.connect(self._show)
        from pfsense_checker.viz import SelectedWhiteTextDelegate

        self.tree.setItemDelegate(SelectedWhiteTextDelegate(self.tree))  # coloured rows stay readable when selected
        split.addWidget(self.tree)
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        self.detail_title = QLabel("Select a weakness.")
        self.detail_title.setWordWrap(True)
        self.detail_title.setTextFormat(Qt.TextFormat.RichText)
        rv.addWidget(self.detail_title)
        rv.addWidget(QLabel("What it means:"))
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        rv.addWidget(self.detail, 3)
        fix_row = QHBoxLayout()
        fix_row.addWidget(QLabel("How to close it:"))
        fix_row.addStretch(1)
        self.btn_copy_fix = QPushButton("Copy")
        self.btn_copy_fix.setEnabled(False)
        self.btn_copy_fix.clicked.connect(lambda: QGuiApplication.clipboard().setText(self.fix.toPlainText()))
        fix_row.addWidget(self.btn_copy_fix)
        rv.addLayout(fix_row)
        self.fix = QPlainTextEdit()
        self.fix.setReadOnly(True)
        self.fix.setFont(QFont("Consolas", 9))
        rv.addWidget(self.fix, 2)
        self.source = QLabel("")
        self.source.setStyleSheet("color: #78909c;")
        rv.addWidget(self.source)
        split.addWidget(right)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        v.addWidget(split, 1)

        self.tabs = QTabWidget()
        self.tabs.setMaximumHeight(230)
        ver = QWidget()
        hv = QHBoxLayout(ver)
        self.versions = QTableWidget(0, 5)
        self.versions.setHorizontalHeaderLabels(["Device", "Software", "Version", "Known vulnerabilities", "Note"])
        self.versions.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.versions.verticalHeader().setVisible(False)
        self.versions.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        hv.addWidget(self.versions, 3)
        side = QWidget()
        form = QFormLayout(side)
        hint = QLabel("Current release, as the vendor's site shows it. NetCheck does not look it up. "
                      "Devices on an older release are then listed under Software versions.")
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #555;")
        form.addRow(hint)
        self.current_edits: dict[str, QLineEdit] = {}
        saved = sh.load_current()
        for product, name in CURRENT_PRODUCTS:
            edit = QLineEdit(saved.get(product, ""))
            edit.setPlaceholderText("for example 7.22.3" if product == "routeros" else "not set")
            edit.editingFinished.connect(self._save_current)
            self.current_edits[product] = edit
            form.addRow(name + ":", edit)
        hv.addWidget(side, 2)
        self.tabs.addTab(ver, "Software versions")
        self.notes = QPlainTextEdit()
        self.notes.setReadOnly(True)
        self.tabs.addTab(self.notes, "Not checked")
        v.addWidget(self.tabs)

    # -- checking ----------------------------------------------------------- #

    def current(self) -> dict[str, str]:
        return {p: e.text().strip() for p, e in self.current_edits.items() if e.text().strip()}

    def _save_current(self) -> None:
        try:
            sh.save_current(self.current())
        except OSError as exc:
            self.status.setText(f"Could not save the current releases: {exc}")

    def showEvent(self, event) -> None:  # noqa: ANN001, N802
        super().showEvent(event)
        if self.report is None:
            self.check()

    def check(self, *, wait: bool = False) -> None:
        """Collect the weaknesses in the background (``wait=True``: now, for tests)."""
        if self._worker is not None and self._worker.isRunning():
            return
        site = self._site() if callable(self._site) else None
        seen = list(self._seen() or []) if callable(self._seen) else None
        password_of = self._password_of if self.compare_passwords.isChecked() else None
        current = self.current()
        username_of = self._username_of

        def job() -> sh.Report:
            return sh.collect(site, seen=seen, password_of=password_of, username_of=username_of, current=current)

        self.status.setText("Checking…")
        if wait:
            self._done(job())
            return
        self.btn_check.setEnabled(False)
        worker = _CollectWorker(job)
        self._worker = worker
        worker.done.connect(self._done)
        worker.failed.connect(lambda err: self.status.setText(f"The check failed: {err}"))
        worker.finished.connect(worker.deleteLater)
        worker.finished.connect(lambda: (setattr(self, "_worker", None), self.btn_check.setEnabled(True)))
        worker.start()

    # -- showing ------------------------------------------------------------ #

    def _done(self, report: sh.Report) -> None:
        self.report = report
        counts = " · ".join(
            f"<span style='color:{SEVERITY_COLOUR[s]};'>{report.count(s)} {s}</span>" for s in sh.SEVERITIES)
        if report.checked or report.holes:
            self.status.setText(f"{len(report.checked)} device config(s) checked · {len(report.holes)} "
                                f"weakness(es): {counts}")
        else:
            self.status.setText(report.summary())
        # Counts only: the findings themselves stay on this page.
        app_log.get_logger("security").info("Security Holes: %s", report.summary())
        keep = self.f_device.currentData()
        self.f_device.blockSignals(True)
        self.f_device.clear()
        self.f_device.addItem(ALL_DEVICES, "")
        for name in report.devices():
            self.f_device.addItem(name, name)
        self.f_device.setCurrentIndex(max(0, self.f_device.findData(keep)) if keep else 0)
        self.f_device.blockSignals(False)
        self.btn_copy.setEnabled(bool(report.holes))
        db = vuln_db.load()
        self.versions.setRowCount(len(report.versions))
        for r, row in enumerate(report.versions):
            known = (f"{row.known} that affect this version" if row.known else
                     ("none in NetCheck's list" if row.product else "not checked"))
            for c, text in enumerate((row.device, row.product_name, row.version, known, row.note)):
                item = QTableWidgetItem(text)
                if c == 3 and row.known:
                    item.setForeground(QColor(SEVERITY_COLOUR[sh.HIGH]))
                self.versions.setItem(r, c, item)
        self.versions.resizeColumnsToContents()
        self.versions.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.notes.setPlainText("\n".join(f"• {n}" for n in report.notes)
                                + f"\n\nNetCheck's vulnerability list: {db.count()} entries for "
                                  f"{', '.join(db.name(p) for p in sorted(db.entries))}. It is not a live feed: "
                                  f"add your own entries as JSON files in {vuln_db.USER_DIR}.")
        self.tabs.setTabText(1, f"Not checked ({len(report.notes)})")
        self._fill()

    def shown_holes(self) -> list[sh.Hole]:
        """The findings that pass the three filters."""
        if self.report is None:
            return []
        severity, device = self.f_severity.currentData(), self.f_device.currentData()
        words = self.f_text.text().lower().split()
        out = []
        for h in self.report.holes:
            text = f"{h.title} {h.device} {h.detail} {h.fix} {h.area}".lower()
            if (not severity or h.severity == severity) and (not device or h.device == device) \
                    and all(w in text for w in words):
                out.append(h)
        return out

    def _fill(self, *_args) -> None:  # noqa: ANN002
        self.tree.clear()
        bold = QFont()
        bold.setBold(True)
        shown = self.shown_holes()
        first = None
        for area in sh.AREAS:
            holes = [h for h in shown if h.area == area]
            if not holes:
                continue
            top = QTreeWidgetItem([f"{area} ({len(holes)})", "", ""])
            top.setFont(0, bold)
            self.tree.addTopLevelItem(top)
            for h in holes:
                child = QTreeWidgetItem([h.title, h.device, sh.SEVERITY_WORD[h.severity]])
                for col in (0, 2):
                    child.setForeground(col, QColor(SEVERITY_COLOUR[h.severity]))
                child.setToolTip(0, h.title)
                child.setData(0, Qt.ItemDataRole.UserRole, h)
                top.addChild(child)
                first = first or child
            top.setExpanded(True)
        if first is not None:
            self.tree.setCurrentItem(first)
        else:
            self._show(None)

    def _show(self, item: QTreeWidgetItem | None, _prev=None) -> None:  # noqa: ANN001
        hole = item.data(0, Qt.ItemDataRole.UserRole) if item is not None else None
        if hole is None:
            self.detail_title.setText("Select a weakness." if self.report and self.report.holes
                                      else "Nothing to show.")
            self.detail.clear()
            self.fix.clear()
            self.source.setText("")
            self.btn_copy_fix.setEnabled(False)
            return
        colour = SEVERITY_COLOUR[hole.severity]
        self.detail_title.setText(
            f"<b style='color:{colour};'>{sh.SEVERITY_WORD[hole.severity]}</b> · <b>{hole.device}</b><br/>{hole.title}")
        self.detail.setPlainText(hole.detail or hole.title)
        self.fix.setPlainText(hole.fix)
        self.btn_copy_fix.setEnabled(bool(hole.fix))
        self.source.setText(f"From: {hole.source}. NetCheck shows the fix; it does not apply it.")

    def copy_list(self) -> None:
        shown = self.shown_holes()
        if self.report is None or not shown:
            return
        part = sh.Report(holes=shown, checked=self.report.checked, notes=self.report.notes)
        QGuiApplication.clipboard().setText(part.text())
        self.status.setText(f"Copied {len(shown)} weakness(es) with their fixes.")
