"""Topology → Add Device: pick Manufacturer and Model from the device library.

Category and Search narrow the two lists: the library holds several hundred
models, from firewalls to smart plugs.
"""

from __future__ import annotations

import ipaddress
import re

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from pfsense_checker import device_library as dl
from pfsense_checker.topology_site import Device


ALL_CATEGORIES = "All categories"


def _default_name(model: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", model).strip("-") or "device"


class AddDeviceDialog(QDialog):
    """(Category, Search) → Manufacturer → Model → (name, management IP) → a ready topology device."""

    def __init__(self, existing_names: set[str], parent: QWidget | None = None,
                 library: dl.Library | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add Device")
        self.setMinimumWidth(560)
        self._existing = set(existing_names)
        self._library = library or dl.load_library()
        self._name_edited = False
        self._device: Device | None = None

        root = QVBoxLayout(self)
        form = QFormLayout()
        self.category = QComboBox()
        self.category.setMaxVisibleItems(20)
        self.category.addItem(ALL_CATEGORIES, "")
        for cat in self._library.categories():
            self.category.addItem(cat, cat)
        self.category.currentIndexChanged.connect(self._fill_vendors)
        form.addRow("Category:", self.category)
        self.search = QLineEdit()
        self.search.setClearButtonEnabled(True)
        self.search.setPlaceholderText("part of a maker, model or type: optiplex 9010, rs485, denon…")
        self.search.textChanged.connect(self._fill_vendors)
        form.addRow("Search:", self.search)
        self.vendor = QComboBox()
        self.vendor.setMaxVisibleItems(25)
        self.vendor.currentIndexChanged.connect(self._fill_models)
        form.addRow("Manufacturer:", self.vendor)
        self.model = QComboBox()
        self.model.setMaxVisibleItems(20)
        self.model.currentIndexChanged.connect(self._show_model)
        form.addRow("Model:", self.model)
        self.name = QLineEdit()
        self.name.textEdited.connect(self._on_name_edited)
        form.addRow("Name:", self.name)
        self.ip = QLineEdit()
        self.ip.setPlaceholderText("optional — management IP, used for Connect / Load Config")
        form.addRow("Management IP:", self.ip)
        root.addLayout(form)

        self.details = QLabel()
        self.details.setWordWrap(True)
        self.details.setStyleSheet("color: #37474f;")
        root.addWidget(self.details)
        self.ports = QPlainTextEdit()
        self.ports.setReadOnly(True)
        self.ports.setMaximumHeight(140)
        root.addWidget(self.ports)
        lib_note = QLabel(
            f"{self._library.count()} models from {len(self._library.models)} manufacturers, in "
            f"{len(self._library.files)} library file(s): built in, plus your own JSON files in "
            f"{dl.USER_DIR} (same format; they add models or replace built-in ones)."
            + (f"\nNot loaded: {'; '.join(self._library.errors)}" if self._library.errors else "")
        )
        lib_note.setWordWrap(True)
        lib_note.setStyleSheet("color: #78909c; font-size: 11px;")
        root.addWidget(lib_note)
        self.error = QLabel()
        self.error.setStyleSheet("color: #c62828;")
        root.addWidget(self.error)

        buttons = QHBoxLayout()
        open_lib = QPushButton("Open library folder")
        open_lib.clicked.connect(self._open_library_folder)
        buttons.addWidget(open_lib)
        buttons.addStretch(1)
        self.add_btn = QPushButton("Add device")
        self.add_btn.setDefault(True)
        self.add_btn.clicked.connect(self._accept)
        buttons.addWidget(self.add_btn)
        cancel = QPushButton("Cancel")  # rightmost
        cancel.clicked.connect(self.reject)
        buttons.addWidget(cancel)
        root.addLayout(buttons)
        self._fill_vendors()

    # ------------------------------------------------------------------ #

    def selected_spec(self) -> dl.ModelSpec | None:
        return self._library.get(self.vendor.currentText(), self.model.currentText())

    def _filter(self) -> tuple[str, str]:
        return str(self.category.currentData() or ""), self.search.text().strip()

    def _fill_vendors(self, *_args) -> None:  # noqa: ANN002
        """Manufacturers that have a model in the category that matches the search."""
        category, search = self._filter()
        keep = self.vendor.currentText()
        names = self._library.vendors(category, search)
        self.vendor.blockSignals(True)
        self.vendor.clear()
        self.vendor.addItems(names)
        if keep in names:
            self.vendor.setCurrentText(keep)
        self.vendor.blockSignals(False)
        self._fill_models()

    def _fill_models(self, *_args) -> None:  # noqa: ANN002
        category, search = self._filter()
        keep = self.model.currentText()
        specs = self._library.models_of(self.vendor.currentText(), category, search)
        self.model.blockSignals(True)
        self.model.clear()
        for spec in specs:
            self.model.addItem(spec.model)
        if keep in [s.model for s in specs]:
            self.model.setCurrentText(keep)
        self.model.blockSignals(False)
        self._show_model()

    def _show_model(self, *_args) -> None:  # noqa: ANN002
        spec = self.selected_spec()
        if spec is None:
            self.details.setText("Nothing in the library matches. Clear Search or choose All categories.")
            self.ports.clear()
            self.add_btn.setEnabled(False)
            return
        self.add_btn.setEnabled(True)
        bits = [b for b in (spec.category, spec.type, spec.summary()) if b]
        self.details.setText(" · ".join(bits) + (f"\n{spec.notes}" if spec.notes else ""))
        self.ports.setPlainText("\n".join(f"{p.name:<18} {p.media}" for p in spec.ports))
        if not self._name_edited:
            self.name.setText(dl.unique_name(self._existing, _default_name(spec.model)))

    def _on_name_edited(self, _text: str) -> None:
        self._name_edited = True

    def _open_library_folder(self) -> None:
        dl.USER_DIR.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(dl.USER_DIR)))

    def _accept(self) -> None:
        spec = self.selected_spec()
        name = self.name.text().strip()
        ip = self.ip.text().strip()
        if spec is None:
            return
        if not name:
            self.error.setText("Give the device a name.")
            return
        if name in self._existing:
            self.error.setText(f"There is already a device called {name}.")
            return
        if ip:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                self.error.setText(f"{ip} is not an IP address.")
                return
        self._device = dl.make_device(spec, name, mgmt_ip=ip)
        self.accept()

    def device(self) -> Device | None:
        return self._device


__all__ = ["AddDeviceDialog", "Qt"]
