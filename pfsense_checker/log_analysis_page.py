"""Logs → Log Analysis: drop log files in, read the summary, drill into the lines."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from pfsense_checker import ai, app_log, config_match
from pfsense_checker import log_analysis as la
from pfsense_checker.file_drop import accept_file_drag, paths_from_mime

SEVERITY_COLOUR = {la.ERROR: "#c62828", la.WARN: "#ef6c00", la.INFO: "#455a64"}
SEVERITY_WORD = {la.ERROR: "problem", la.WARN: "warning", la.INFO: "note"}
AI_QUESTION = (
    "These are router / firewall log lines grouped under one finding. Say in plain words what they show, "
    "the most likely cause, and what to check or change. Be specific and brief."
)
AI_MAX_LINES = 60
ALL_DEVICES = "All devices"
NO_SECOND = "— no second device —"
LINES_LABEL = "Log lines behind it:"
CONFIG_LABEL = "From the two configs:"


class _AnalyseWorker(QThread):
    done = Signal(object)  # la.Analysis
    failed = Signal(str)

    def __init__(self, paths: list[Path], extra=None) -> None:  # noqa: ANN001
        super().__init__()
        self._paths = paths
        self._extra = extra

    def run(self) -> None:  # noqa: D102
        try:
            self.done.emit(run_analysis(self._paths, self._extra))
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


def run_analysis(paths: list[Path], extra=None) -> la.Analysis:  # noqa: ANN001
    """Read the logs in *paths* (none: no logs), then put *extra*()'s findings first."""
    analysis = la.analyse_paths(paths) if paths else la.Analysis()
    if extra is not None:
        analysis.findings = [*extra(), *analysis.findings]
    return analysis


class _AskWorker(QThread):
    done = Signal(str)
    failed = Signal(str)

    def __init__(self, context: str, url: str, model: str) -> None:
        super().__init__()
        self._context, self._url, self._model = context, url, model

    def run(self) -> None:  # noqa: D102
        try:
            self.done.emit(ai.ask_ollama(self._context, AI_QUESTION, model=self._model, base_url=self._url))
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class LogAnalysisPage(QWidget):
    """Drop zone + findings tree + the lines behind the selected finding."""

    def __init__(self, parent: QWidget | None = None, *, site=None) -> None:  # noqa: ANN001
        """*site* is a callable returning the Login to Routers site (or None)."""
        super().__init__(parent)
        self.setAcceptDrops(True)
        self._site = site
        self._heading = ""  # which device(s) the shown analysis is about
        self.analysis: la.Analysis | None = None
        self._worker: _AnalyseWorker | None = None
        self._ask: _AskWorker | None = None
        v = QVBoxLayout(self)
        title = QLabel("Log Analysis")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        v.addWidget(title)
        blurb = QLabel(
            "Drop router log files or folders here: pfSense / OPNsense logs (filter, system, auth, DHCP, "
            "OpenVPN, gateways), MikroTik logs, or plain syslog text, also .gz / .bz2. NetCheck reads them "
            "on this PC and lists what stands out: failed and blocked logins, what the firewall blocks most, "
            "links that drop, Wi-Fi clients that will not stay connected, DHCP and VPN trouble, reboots and "
            "errors. Click a finding to see the lines behind it. Or choose a device below to read what "
            "NetCheck has downloaded from it; choose a second one to read both and to compare their "
            "configs where the two have to match."
        )
        blurb.setWordWrap(True)
        blurb.setStyleSheet("color: #555;")
        v.addWidget(blurb)

        self.drop = QLabel("Drop log files or folders here")
        self.drop.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.drop.setMinimumHeight(54)
        self.drop.setFrameShape(QFrame.Shape.StyledPanel)
        self.drop.setStyleSheet("QLabel { border: 2px dashed #90a4ae; border-radius: 6px; color: #546e7a;"
                                " background: #f5f7f8; font-weight: 600; }")
        v.addWidget(self.drop)

        row = QHBoxLayout()
        b_files = QPushButton("Open files…")
        b_files.clicked.connect(self._pick_files)
        row.addWidget(b_files)
        b_folder = QPushButton("Open folder…")
        b_folder.clicked.connect(self._pick_folder)
        row.addWidget(b_folder)
        row.addStretch(1)
        v.addLayout(row)

        pick = QHBoxLayout()
        pick.addWidget(QLabel("Device:"))
        self.device_a = QComboBox()
        self.device_a.setMinimumWidth(260)
        self.device_a.setToolTip("Whose downloaded logs to analyse (Logs → Device Logs downloads them)")
        self.device_a.currentIndexChanged.connect(self._device_changed)
        pick.addWidget(self.device_a)
        pick.addWidget(QLabel("Compare with:"))
        self.device_b = QComboBox()
        self.device_b.setMinimumWidth(260)
        self.device_b.setToolTip(
            "A second device. Their logs are read together and their saved configs are compared "
            "where the two have to match: cable ends, VLANs, addresses, the wireless controller."
        )
        pick.addWidget(self.device_b)
        self.btn_analyse = QPushButton("Analyse")
        self.btn_analyse.clicked.connect(self.analyse_selected)
        pick.addWidget(self.btn_analyse)
        pick.addStretch(1)
        v.addLayout(pick)
        self.refresh_devices()
        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setStyleSheet("font-weight: 600; color: #263238;")
        v.addWidget(self.status)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Finding", "Count"])
        self.tree.setColumnWidth(0, 430)
        self.tree.currentItemChanged.connect(self._show)
        from pfsense_checker.viz import SelectedWhiteTextDelegate

        self.tree.setItemDelegate(SelectedWhiteTextDelegate(self.tree))  # coloured rows stay readable when selected
        split.addWidget(self.tree)
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        self.detail = QLabel("Select a finding.")
        self.detail.setWordWrap(True)
        self.detail.setTextFormat(Qt.TextFormat.RichText)
        rv.addWidget(self.detail)
        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["What", "How many"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setMaximumHeight(240)
        rv.addWidget(self.table)
        lines_row = QHBoxLayout()
        self.lines_label = QLabel(LINES_LABEL)
        lines_row.addWidget(self.lines_label)
        lines_row.addStretch(1)
        self.ask_btn = QPushButton("Ask Ollama about this")
        self.ask_btn.setToolTip("Sends the finding and up to 60 of its lines to your local Ollama")
        self.ask_btn.clicked.connect(self._ask_ollama)
        self.ask_btn.setEnabled(False)
        lines_row.addWidget(self.ask_btn)
        rv.addLayout(lines_row)
        self.lines = QPlainTextEdit()
        self.lines.setReadOnly(True)
        self.lines.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.lines.setFont(QFont("Consolas", 9))
        rv.addWidget(self.lines, 1)
        split.addWidget(right)
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 3)
        v.addWidget(split, 1)

    # -- getting files in --------------------------------------------------- #

    def dragEnterEvent(self, event) -> None:  # noqa: ANN001, N802
        if not accept_file_drag(event):
            event.ignore()

    def dragMoveEvent(self, event) -> None:  # noqa: ANN001, N802
        if not accept_file_drag(event):
            event.ignore()

    def dropEvent(self, event) -> None:  # noqa: ANN001, N802
        paths = paths_from_mime(event.mimeData())
        if not paths:
            event.ignore()
            return
        event.setDropAction(Qt.DropAction.CopyAction)
        event.accept()
        self.analyse(paths)

    def _pick_files(self) -> None:
        names, _f = QFileDialog.getOpenFileNames(self, "Log files", "", "Logs (*.log *.txt *.gz *.bz2);;All files (*)")
        if names:
            self.analyse([Path(n) for n in names])

    def _pick_folder(self) -> None:
        name = QFileDialog.getExistingDirectory(self, "Folder of log files")
        if name:
            self.analyse([Path(name)])

    def analyse_downloaded(self) -> None:
        from pfsense_checker import device_logs

        if not device_logs.LOG_ROOT.is_dir():
            self.status.setText("Nothing has been downloaded from the routers yet (Logs → Device Logs).")
            return
        self.analyse([device_logs.LOG_ROOT])

    # -- choosing devices --------------------------------------------------- #

    def devices(self) -> list:
        """Devices on Login to Routers that have downloaded logs or a saved config."""
        from pfsense_checker import device_identity, device_logs

        site = self._site() if callable(self._site) else None
        out = []
        for dev in getattr(site, "devices", None) or []:
            if getattr(dev, "ignored", False):
                continue
            if device_logs.device_dir(dev.name).is_dir() or device_identity.config_path_for(dev):
                out.append(dev)
        return out

    def device_label(self, dev) -> str:  # noqa: ANN001
        from pfsense_checker import device_identity, device_logs

        label = config_match.label_of(dev)
        host = ((dev.ssh.host if getattr(dev, "ssh", None) else "") or getattr(dev, "mgmt_ip", "") or "").strip()
        if host and host != label:
            label += f"  —  {host}"
        lacks = [word for word, has in (("no logs", device_logs.device_dir(dev.name).is_dir()),
                                        ("no config", bool(device_identity.config_path_for(dev)))) if not has]
        return label + (f"  ({', '.join(lacks)})" if lacks else "")

    def refresh_devices(self) -> None:
        """Fill the two device lists, keeping what is selected."""
        keep_a, keep_b = self.device_a.currentData(), self.device_b.currentData()
        rows = [(self.device_label(d), d.name) for d in self.devices()]
        for combo, first, keep in ((self.device_a, ALL_DEVICES, keep_a), (self.device_b, NO_SECOND, keep_b)):
            combo.blockSignals(True)
            combo.clear()
            combo.addItem(first, "")
            for label, name in rows:
                combo.addItem(label, name)
            combo.setCurrentIndex(max(0, combo.findData(keep)) if keep else 0)
            combo.blockSignals(False)
        self._device_changed()

    def _device_changed(self) -> None:
        one = bool(self.device_a.currentData())
        self.device_b.setEnabled(one)  # a second device only makes sense next to a first
        if not one:
            self.device_b.setCurrentIndex(0)

    def showEvent(self, event) -> None:  # noqa: ANN001, N802
        super().showEvent(event)
        self.refresh_devices()  # devices and downloads may have changed since the page was built

    def analyse_selected(self) -> None:
        self.analyse_devices(self.device_a.currentData() or "", self.device_b.currentData() or "")

    def analyse_devices(self, name_a: str = "", name_b: str = "", *, wait: bool = False) -> None:
        """One device: its downloaded logs. Two: both logs, and their configs compared."""
        from pfsense_checker import device_logs

        if not name_a:
            self.analyse_downloaded()
            return
        site = self._site() if callable(self._site) else None
        by_name = {d.name: d for d in getattr(site, "devices", None) or []}
        dev_a, dev_b = by_name.get(name_a), by_name.get(name_b) if name_b != name_a else None
        if dev_a is None:
            self.status.setText(f"{name_a} is no longer on Login to Routers.")
            return
        chosen = [d for d in (dev_a, dev_b) if d is not None]
        paths = [device_logs.device_dir(d.name) for d in chosen if device_logs.device_dir(d.name).is_dir()]
        labels = [config_match.label_of(d) for d in chosen]
        without = [lab for lab, d in zip(labels, chosen) if not device_logs.device_dir(d.name).is_dir()]
        if dev_b is None and not paths:
            self.status.setText(f"No logs have been downloaded from {labels[0]} yet (Logs → Device Logs).")
            return
        heading = " ↔ ".join(labels) + "."
        if without:
            heading += f" No downloaded logs from {' or '.join(without)}."
        extra = (lambda: config_match.compare(dev_a, dev_b, site)) if dev_b is not None else None
        self.analyse(paths, wait=wait, extra=extra, heading=heading)

    def analyse(self, paths: list[Path], *, wait: bool = False, extra=None, heading: str = "") -> None:  # noqa: ANN001
        """Analyse *paths* in the background (``wait=True``: now, for tests).

        *extra* returns findings to put first (the config comparison of two devices).
        """
        if self._worker is not None and self._worker.isRunning():
            return
        self._heading = heading
        self.status.setText(f"Reading {len(paths)} item(s)…")
        self.drop.setText("Reading…")
        if wait:
            self._done(run_analysis(paths, extra))
            return
        worker = _AnalyseWorker(paths, extra)
        self._worker = worker
        worker.done.connect(self._done)
        worker.failed.connect(lambda err: self._failed(err))
        worker.finished.connect(worker.deleteLater)
        worker.finished.connect(lambda: setattr(self, "_worker", None))
        worker.start()

    def _failed(self, err: str) -> None:
        self.drop.setText("Drop log files or folders here")
        self.status.setText(f"Could not read the logs: {err}")

    # -- showing ------------------------------------------------------------ #

    def _done(self, analysis: la.Analysis) -> None:
        self.analysis = analysis
        self.drop.setText("Drop log files or folders here")
        config = [f for f in analysis.findings if f.area.startswith(config_match.AREA)]
        if config:
            logs = replace(analysis, findings=[f for f in analysis.findings if f not in config])
            text = (f"Configs: {sum(1 for f in config if f.severity == la.ERROR)} mismatch(es), "
                    f"{sum(1 for f in config if f.severity == la.WARN)} warning(s). Logs: {logs.summary()}")
        else:
            text = analysis.summary()
        if self._heading:
            text = f"{self._heading} {text}"
        if analysis.skipped:
            text += "  Left out: " + "; ".join(analysis.skipped[:4])
        if analysis.total_lines > analysis.kept_lines:
            text += f"  (Only the first {analysis.kept_lines:,} lines are kept for looking at.)"
        self.status.setText(text)
        app_log.get_logger("log_analysis").info("%s", text)
        self.tree.clear()
        bold = QFont()
        bold.setBold(True)
        first = None
        for area, findings in analysis.by_area().items():
            top = QTreeWidgetItem([area, ""])
            top.setFont(0, bold)
            self.tree.addTopLevelItem(top)
            for f in findings:
                child = QTreeWidgetItem([f.title, f"{f.count:,}"])
                child.setForeground(0, QColor(SEVERITY_COLOUR[f.severity]))
                child.setToolTip(0, f"{SEVERITY_WORD[f.severity]}: {f.detail}" if f.detail else SEVERITY_WORD[f.severity])
                child.setData(0, Qt.ItemDataRole.UserRole, f)
                child.setTextAlignment(1, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                top.addChild(child)
                first = first or child
            top.setExpanded(True)
        if first is not None:
            self.tree.setCurrentItem(first)
        else:
            self._show(None)

    def _show(self, item: QTreeWidgetItem | None, _prev=None) -> None:  # noqa: ANN001
        finding = item.data(0, Qt.ItemDataRole.UserRole) if item is not None else None
        self.table.setRowCount(0)
        self.lines.clear()
        self.ask_btn.setEnabled(False)
        if finding is None or self.analysis is None:
            self.detail.setText("Select a finding.")
            return
        colour = SEVERITY_COLOUR[finding.severity]
        self.detail.setText(
            f"<b style='color:{colour};'>{finding.title}</b> — {finding.count:,} "
            f"({SEVERITY_WORD[finding.severity]})<br/>{finding.detail}")
        self.table.setRowCount(len(finding.table))
        for r, (what, n) in enumerate(finding.table):
            self.table.setItem(r, 0, QTableWidgetItem(str(what)))
            cell = QTableWidgetItem(f"{n:,}")
            cell.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.table.setItem(r, 1, cell)
        from_config = bool(finding.notes) and not finding.lines
        self.lines_label.setText(CONFIG_LABEL if from_config else LINES_LABEL)
        self.lines.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth if from_config
                                   else QPlainTextEdit.LineWrapMode.NoWrap)  # sentences wrap; log lines do not
        self.lines.setPlainText(la.lines_text(self.analysis, finding))
        self.ask_btn.setEnabled(bool(finding.lines or finding.notes) and ai.is_ollama_enabled())
        self.ask_btn.setToolTip("Sends the finding and up to 60 of its lines to your local Ollama"
                                if ai.is_ollama_enabled() else "Ollama is switched off (Home → Ollama)")

    def ai_context(self, finding: la.Finding) -> str:
        """What is sent to Ollama for one finding."""
        assert self.analysis is not None
        table = "\n".join(f"  {n} × {what}" for what, n in finding.table[:12])
        return (f"Finding: {finding.title} ({finding.count} occurrences)\n{finding.detail}\n"
                f"Most frequent:\n{table}\n\nLog lines:\n{la.lines_text(self.analysis, finding, AI_MAX_LINES)}")

    def _ask_ollama(self) -> None:
        item = self.tree.currentItem()
        finding = item.data(0, Qt.ItemDataRole.UserRole) if item is not None else None
        if finding is None or self.analysis is None or (self._ask is not None and self._ask.isRunning()):
            return
        url, model = ai.load_ollama_settings()
        keep = self.lines.toPlainText()
        self.lines.setPlainText(f"Asking {model} at {url}…\n\n{keep}")
        worker = _AskWorker(self.ai_context(finding), url, model)
        self._ask = worker
        worker.done.connect(lambda reply: self.lines.setPlainText(f"Ollama ({model}):\n{reply}\n\n{'-' * 60}\n{keep}"))
        worker.failed.connect(lambda err: self.lines.setPlainText(f"Ollama request failed: {err}\n\n{keep}"))
        worker.finished.connect(worker.deleteLater)
        worker.finished.connect(lambda: setattr(self, "_ask", None))
        worker.start()
