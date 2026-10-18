"""Tests home section — discover and run the project's pytest suite."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from PySide6.QtCore import Qt, QProcess, Signal
from PySide6.QtGui import QFont, QTextCursor
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from pfsense_checker import app_log
from pfsense_checker.paths import PROJECT_ROOT

_TESTS_DIR = PROJECT_ROOT / "tests"
_SUMMARY_RE = re.compile(
    r"=+\s*(?P<body>.+?)\s*=+\s*$",
    re.MULTILINE,
)


def discover_test_files(tests_dir: Path | None = None) -> list[Path]:
    """Return ``test_*.py`` files under the project tests folder."""
    root = tests_dir or _TESTS_DIR
    if not root.is_dir():
        return []
    return sorted(root.glob("test_*.py"), key=lambda p: p.name.lower())


def _python_executable() -> str:
    """Prefer the active interpreter (venv) for running pytest."""
    return sys.executable or "python"


class TestsScreen(QWidget):
    """List unit-test modules and run pytest with live output."""

    status_changed = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._proc: QProcess | None = None
        self._build()
        self.refresh_list()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        title = QLabel("Tests")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        root.addWidget(title)

        blurb = QLabel(
            "Run NetCheck’s automated pytest suite against this interpreter. "
            "Select one or more modules, or run the full suite."
        )
        blurb.setWordWrap(True)
        blurb.setStyleSheet("color: #444;")
        root.addWidget(blurb)

        mid = QHBoxLayout()
        left = QVBoxLayout()
        left.addWidget(QLabel("Test modules"))
        self.list = QListWidget()
        self.list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        left.addWidget(self.list, stretch=1)

        sel_row = QHBoxLayout()
        btn_all = QPushButton("Select all")
        btn_all.clicked.connect(self.list.selectAll)
        sel_row.addWidget(btn_all)
        btn_none = QPushButton("Clear")
        btn_none.clicked.connect(self.list.clearSelection)
        sel_row.addWidget(btn_none)
        btn_refresh = QPushButton("Refresh list")
        btn_refresh.clicked.connect(self.refresh_list)
        sel_row.addWidget(btn_refresh)
        sel_row.addStretch(1)
        left.addLayout(sel_row)
        mid.addLayout(left, stretch=1)

        right = QVBoxLayout()
        self.chk_verbose = QCheckBox("Verbose (-v)")
        self.chk_verbose.setChecked(True)
        right.addWidget(self.chk_verbose)
        self.chk_failfast = QCheckBox("Stop on first failure (-x)")
        right.addWidget(self.chk_failfast)

        run_row = QHBoxLayout()
        self.btn_run_selected = QPushButton("Run selected")
        self.btn_run_selected.setStyleSheet(
            "QPushButton {"
            " padding: 4px 14px; font-weight: bold;"
            " background-color: rgba(21, 101, 192, 200);"
            " border: 1px solid rgb(13, 71, 161); border-radius: 3px;"
            " color: white; }"
            "QPushButton:hover { background-color: rgba(25, 118, 210, 230); }"
            "QPushButton:disabled { background-color: #90a4ae; border-color: #78909c; }"
        )
        self.btn_run_selected.clicked.connect(self._run_selected)
        run_row.addWidget(self.btn_run_selected)
        self.btn_run_all = QPushButton("Run all")
        self.btn_run_all.clicked.connect(self._run_all)
        run_row.addWidget(self.btn_run_all)
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop)
        run_row.addWidget(self.btn_stop)
        run_row.addStretch(1)
        right.addLayout(run_row)

        self.summary = QLabel("Ready.")
        self.summary.setWordWrap(True)
        self.summary.setStyleSheet("color: #555; font-weight: bold;")
        right.addWidget(self.summary)

        right.addWidget(QLabel("Output"))
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 10))
        self.output.setPlaceholderText("pytest output will appear here…")
        right.addWidget(self.output, stretch=1)
        mid.addLayout(right, stretch=2)
        root.addLayout(mid, stretch=1)

        tip = QLabel(f"Tests directory: {_TESTS_DIR}")
        tip.setStyleSheet("color: #777;")
        tip.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        root.addWidget(tip)

    def refresh_list(self) -> None:
        self.list.clear()
        files = discover_test_files()
        for path in files:
            item = QListWidgetItem(path.name)
            item.setData(Qt.ItemDataRole.UserRole, str(path))
            item.setToolTip(str(path))
            self.list.addItem(item)
        self.summary.setText(f"{len(files)} test module(s) found.")

    def _selected_paths(self) -> list[str]:
        paths: list[str] = []
        for item in self.list.selectedItems():
            p = item.data(Qt.ItemDataRole.UserRole)
            if p:
                paths.append(str(p))
        return paths

    def _run_selected(self) -> None:
        paths = self._selected_paths()
        if not paths:
            QMessageBox.information(
                self, "Tests", "Select one or more test modules, or use Run all."
            )
            return
        self._start_pytest(paths)

    def _run_all(self) -> None:
        if not _TESTS_DIR.is_dir():
            QMessageBox.warning(self, "Tests", f"Tests folder not found:\n{_TESTS_DIR}")
            return
        self._start_pytest([str(_TESTS_DIR)])

    def _start_pytest(self, targets: list[str]) -> None:
        if self._proc is not None and self._proc.state() != QProcess.ProcessState.NotRunning:
            QMessageBox.information(self, "Tests", "A test run is already in progress.")
            return

        args = ["-m", "pytest", "--tb=short"]
        if self.chk_verbose.isChecked():
            args.append("-v")
        if self.chk_failfast.isChecked():
            args.append("-x")
        args.extend(targets)

        self.output.clear()
        cmd_preview = " ".join([_python_executable(), *args])
        self.output.appendPlainText(f"$ {cmd_preview}\n")
        self.summary.setText("Running…")
        self.summary.setStyleSheet("color: #1565c0; font-weight: bold;")
        self._set_running(True)

        proc = QProcess(self)
        proc.setProgram(_python_executable())
        proc.setArguments(args)
        proc.setWorkingDirectory(str(PROJECT_ROOT))
        env = proc.processEnvironment()
        # Ensure UTF-8 output on Windows consoles.
        env.insert("PYTHONUTF8", "1")
        env.insert("PYTHONIOENCODING", "utf-8")
        proc.setProcessEnvironment(env)
        proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        proc.readyReadStandardOutput.connect(self._on_output)
        proc.finished.connect(self._on_finished)
        proc.errorOccurred.connect(self._on_error)
        self._proc = proc
        app_log.get_logger("tests").info("pytest start targets=%s", targets)
        proc.start()

    def _on_output(self) -> None:
        if self._proc is None:
            return
        data = bytes(self._proc.readAllStandardOutput()).decode("utf-8", errors="replace")
        if not data:
            return
        self.output.moveCursor(QTextCursor.MoveOperation.End)
        self.output.insertPlainText(data)
        self.output.moveCursor(QTextCursor.MoveOperation.End)

    def _on_finished(self, exit_code: int, _status) -> None:  # noqa: ANN001
        self._set_running(False)
        text = self.output.toPlainText()
        summary = self._extract_summary(text)
        if exit_code == 0:
            msg = summary or "All tests passed."
            self.summary.setText(f"Passed — {msg}")
            self.summary.setStyleSheet("color: #2e7d32; font-weight: bold;")
        else:
            msg = summary or f"Exit code {exit_code}"
            self.summary.setText(f"Failed — {msg}")
            self.summary.setStyleSheet("color: #c62828; font-weight: bold;")
        self.status_changed.emit(self.summary.text())
        app_log.get_logger("tests").info(
            "pytest finished exit=%s summary=%s", exit_code, msg
        )
        self._proc = None

    def _on_error(self, error) -> None:  # noqa: ANN001
        self._set_running(False)
        self.summary.setText(f"Could not start pytest: {error}")
        self.summary.setStyleSheet("color: #c62828; font-weight: bold;")
        self.output.appendPlainText(f"\nProcess error: {error}\n")
        self._proc = None

    def _stop(self) -> None:
        if self._proc is None:
            return
        self._proc.kill()
        self.summary.setText("Stopped.")
        self.summary.setStyleSheet("color: #ef6c00; font-weight: bold;")
        self._set_running(False)

    def _set_running(self, running: bool) -> None:
        self.btn_run_selected.setEnabled(not running)
        self.btn_run_all.setEnabled(not running)
        self.btn_stop.setEnabled(running)

    @staticmethod
    def _extract_summary(text: str) -> str:
        matches = list(_SUMMARY_RE.finditer(text))
        if not matches:
            return ""
        body = matches[-1].group("body").strip()
        return body
