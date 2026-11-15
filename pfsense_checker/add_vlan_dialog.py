"""Topology → right-click a port → Add VLAN to this port…"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from pfsense_checker import vlan_plan
from pfsense_checker.port_vlans import PortVlans, _vid_key


class AddVlanDialog(QDialog):
    """Pick a VLAN (known ones are listed; any id 1–4094 can be typed) and whether
    the port carries it tagged or untagged."""

    def __init__(self, device, port: str, existing: PortVlans | None, known: dict[str, str],  # noqa: ANN001
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Add VLAN to {port}")
        self.setMinimumWidth(460)
        self._device, self._port, self._existing = device, port, existing
        root = QVBoxLayout(self)
        have = ", ".join(existing.vlans) if existing is not None and existing.vlans else "none"
        intro = QLabel(f"<b>{device.name} · {port}</b><br/>VLANs on this port now: {have}")
        root.addWidget(intro)
        form = QFormLayout()
        self.vlan = QComboBox()
        self.vlan.setEditable(True)
        on_port = set(existing.vlans) if existing is not None else set()
        for vid in sorted(known, key=_vid_key):
            if vid not in on_port:
                name = known.get(vid, "")
                self.vlan.addItem(f"{vid} — {name}" if name and name != vid else vid, vid)
        self.vlan.setCurrentIndex(-1)
        self.vlan.setEditText("")
        self.vlan.lineEdit().setPlaceholderText("VLAN id (1–4094), or pick one used elsewhere on the map")
        form.addRow("VLAN:", self.vlan)
        modes = QHBoxLayout()
        self.tagged = QRadioButton("Tagged (trunk)")
        self.tagged.setChecked(True)
        self.untagged = QRadioButton("Untagged (access)")
        modes.addWidget(self.tagged)
        modes.addWidget(self.untagged)
        modes.addStretch(1)
        form.addRow("Carried:", modes)
        root.addLayout(form)
        note = QLabel("The VLAN is added to the map as planned (a hatched stripe). Nothing is changed on the "
                      "device: right-click the port → Show commands for planned VLANs for what to enter there.")
        note.setWordWrap(True)
        note.setStyleSheet("color: #607d8b;")
        root.addWidget(note)
        self.error = QLabel()
        self.error.setWordWrap(True)
        self.error.setStyleSheet("color: #c62828;")
        root.addWidget(self.error)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        add_btn = QPushButton("Add VLAN")
        add_btn.setDefault(True)
        add_btn.clicked.connect(self._accept)
        buttons.addWidget(add_btn)
        cancel = QPushButton("Cancel")  # rightmost
        cancel.clicked.connect(self.reject)
        buttons.addWidget(cancel)
        root.addLayout(buttons)

    def chosen_vid(self) -> str:
        idx = self.vlan.currentIndex()
        text = self.vlan.currentText().strip()
        if idx >= 0 and self.vlan.itemText(idx) == text:
            return str(self.vlan.itemData(idx))
        return vlan_plan.valid_vid(text.split("—")[0])

    def _accept(self) -> None:
        vid = self.chosen_vid()
        problem = vlan_plan.add(self._device, self._port, vid or self.vlan.currentText(), self.tagged.isChecked(),
                                self._existing)
        if problem:
            self.error.setText(problem)
            return
        self.accept()
