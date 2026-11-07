"""Shade form fields and table cells green (good to go) or red (error).

Used by the Beacon Creator syntax check. The reason goes in the tooltip.
"""

from __future__ import annotations

from PySide6.QtGui import QColor
from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QWidget

GOOD_BG = "#c8e6c9"
BAD_BG = "#ffcdd2"


def shade_widget(widget: QWidget, ok: bool | None, message: str = "") -> None:
    """ok=None clears the shading."""
    cls = type(widget).__name__
    if ok is None:
        widget.setStyleSheet("")
        widget.setToolTip("")
        return
    bg = GOOD_BG if ok else BAD_BG
    border = "#2e7d32" if ok else "#c62828"
    widget.setStyleSheet(f"{cls} {{ background: {bg}; border: 1px solid {border}; color: #000; }}")
    widget.setToolTip(message if ok else f"Error: {message}")


def shade_cell(table: QTableWidget, row: int, col: int, ok: bool | None, message: str = "") -> None:
    blocked = table.blockSignals(True)  # no itemChanged: callers re-check on edits
    try:
        item = table.item(row, col)
        if item is None:
            item = QTableWidgetItem("")
            table.setItem(row, col, item)
        if ok is None:
            item.setData(8, None)  # Qt.BackgroundRole
            item.setToolTip("")
        else:
            item.setBackground(QColor(GOOD_BG if ok else BAD_BG))
            item.setToolTip(message if ok else f"Error: {message}")
    finally:
        table.blockSignals(blocked)


def clear_table(table: QTableWidget) -> None:
    for r in range(table.rowCount()):
        for c in range(table.columnCount()):
            if table.item(r, c) is not None:
                shade_cell(table, r, c, None)
