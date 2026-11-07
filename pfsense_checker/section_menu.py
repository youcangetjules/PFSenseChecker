"""Two-level section menu that slides: main list → 20 % strip + submenu.

Picking a section that has children (Config Check, Setup) animates the main
list down to a narrow strip on the left with greyed text, and the submenu
fills the remaining 80 %. Picking a section without children slides back.
The strip stays clickable, so any main section is one click away.
"""

from __future__ import annotations

from PySide6.QtCore import QEasingCurve, Qt, QVariantAnimation, Signal
from PySide6.QtWidgets import (
    QLabel,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from pfsense_checker.branding import NAV_TREE_STYLE

MENU_WIDTH = 300
STRIP_RATIO = 0.2  # main list width when a submenu is open
SLIDE_MS = 220
_KEY = Qt.ItemDataRole.UserRole

_GREYED_STYLE = (
    NAV_TREE_STYLE
    + "QTreeWidget::item { color: #9e9e9e; }"
    + "QTreeWidget::item:selected { color: white; }"
)
_SUB_TITLE_STYLE = (
    "font-weight: bold; color: #1a237e; padding: 4px 6px 2px 6px;"
)


class SlidingSectionMenu(QWidget):
    """``section_selected(key)`` fires for every page the user picks."""

    section_selected = Signal(str)
    parent_opened = Signal(str)  # a section with children was opened

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedWidth(MENU_WIDTH)
        self._children: dict[str, list[tuple[str, str]]] = {}
        self._labels: dict[str, str] = {}
        self._parent_of: dict[str, str] = {}
        self._last_child: dict[str, str] = {}
        self._open_parent = ""
        self._t = 0.0  # 0 = main list full width, 1 = strip + submenu

        self.main = QTreeWidget(self)
        self.main.setHeaderHidden(True)
        self.main.setRootIsDecorated(False)
        self.main.setIndentation(0)
        self.main.setStyleSheet(NAV_TREE_STYLE)
        self.main.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.main.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.main.itemClicked.connect(self._on_main_clicked)

        self.sub_panel = QWidget(self)
        sub_lay = QVBoxLayout(self.sub_panel)
        sub_lay.setContentsMargins(4, 0, 0, 0)
        sub_lay.setSpacing(2)
        self.sub_title = QLabel("")
        self.sub_title.setStyleSheet(_SUB_TITLE_STYLE)
        self.sub_title.setWordWrap(True)
        sub_lay.addWidget(self.sub_title)
        self.sub = QTreeWidget()
        self.sub.setHeaderHidden(True)
        self.sub.setRootIsDecorated(False)
        self.sub.setIndentation(0)
        self.sub.setStyleSheet(NAV_TREE_STYLE)
        self.sub.itemClicked.connect(self._on_sub_clicked)
        sub_lay.addWidget(self.sub, stretch=1)
        self.sub_panel.hide()

        self._anim = QVariantAnimation(self)
        self._anim.setDuration(SLIDE_MS)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(self._apply)

    # ------------------------------------------------------------ building

    def set_sections(
        self, sections: list[tuple[str, str, list[tuple[str, str]] | None]]
    ) -> None:
        """(key, label, children or None) for each main section, in order."""
        self.main.clear()
        self._children.clear()
        self._labels.clear()
        self._parent_of.clear()
        for key, label, children in sections:
            item = QTreeWidgetItem([label])
            item.setData(0, _KEY, key)
            item.setToolTip(0, label)
            self.main.addTopLevelItem(item)
            self._labels[key] = label
            if children is not None:
                self.set_children(key, children)

    def set_children(self, parent_key: str, children: list[tuple[str, str]]) -> None:
        """Replace a section's submenu (for example after the workspace builds)."""
        for child_key, old_parent in list(self._parent_of.items()):
            if old_parent == parent_key:
                del self._parent_of[child_key]
        self._children[parent_key] = list(children)
        for child_key, label in children:
            self._parent_of[child_key] = parent_key
            self._labels[child_key] = label
        if self._open_parent == parent_key:
            current = self.current_key()
            self._fill_sub(parent_key)
            self._mark_sub(current)

    # ------------------------------------------------------------ queries

    def has_children(self, key: str) -> bool:
        return bool(self._children.get(key))

    def parent_of(self, key: str) -> str:
        return self._parent_of.get(key, "")

    def label(self, key: str) -> str:
        return self._labels.get(key, key)

    def is_open(self) -> bool:
        return bool(self._open_parent)

    def open_parent(self) -> str:
        return self._open_parent

    def current_key(self) -> str:
        if self._open_parent:
            item = self.sub.currentItem()
            if item is not None:
                return str(item.data(0, _KEY) or "")
        item = self.main.currentItem()
        return str(item.data(0, _KEY) or "") if item is not None else ""

    def first_child(self, key: str) -> str:
        children = self._children.get(key) or []
        return children[0][0] if children else key

    # ------------------------------------------------------------ actions

    def select(self, key: str, *, emit: bool = False, animate: bool = True) -> None:
        """Show *key* as current (a child opens its parent's submenu)."""
        parent = self._parent_of.get(key, "")
        if parent:
            self._mark_main(parent)
            self._open(parent, animate=animate)
            self._mark_sub(key)
            self._last_child[parent] = key
        elif self.has_children(key):
            child = self._last_child.get(key) or self.first_child(key)
            self.select(child, emit=emit, animate=animate)
            return
        else:
            self._mark_main(key)
            self._close(animate=animate)
        if emit:
            self.section_selected.emit(key)

    def _on_main_clicked(self, item: QTreeWidgetItem, _col: int) -> None:
        key = str(item.data(0, _KEY) or "")
        if self.has_children(key):
            self.parent_opened.emit(key)
            child = self._last_child.get(key) or self.first_child(key)
            self.select(child, emit=True)
        else:
            self.select(key, emit=True)

    def _on_sub_clicked(self, item: QTreeWidgetItem, _col: int) -> None:
        key = str(item.data(0, _KEY) or "")
        if key:
            self._last_child[self._open_parent] = key
            self.section_selected.emit(key)

    # ------------------------------------------------------------ internals

    def _mark_main(self, key: str) -> None:
        for i in range(self.main.topLevelItemCount()):
            item = self.main.topLevelItem(i)
            if item.data(0, _KEY) == key:
                self.main.blockSignals(True)
                self.main.setCurrentItem(item)
                self.main.blockSignals(False)
                return

    def _mark_sub(self, key: str) -> None:
        for i in range(self.sub.topLevelItemCount()):
            item = self.sub.topLevelItem(i)
            if item.data(0, _KEY) == key:
                self.sub.blockSignals(True)
                self.sub.setCurrentItem(item)
                self.sub.blockSignals(False)
                return

    def _fill_sub(self, parent_key: str) -> None:
        self.sub.blockSignals(True)
        self.sub.clear()
        for child_key, label in self._children.get(parent_key, []):
            item = QTreeWidgetItem([label])
            item.setData(0, _KEY, child_key)
            self.sub.addTopLevelItem(item)
        self.sub.blockSignals(False)
        self.sub_title.setText(self._labels.get(parent_key, parent_key))

    def _open(self, parent_key: str, *, animate: bool) -> None:
        if self._open_parent != parent_key:
            self._open_parent = parent_key
            self._fill_sub(parent_key)
        self._slide_to(1.0, animate)

    def _close(self, *, animate: bool) -> None:
        self._open_parent = ""
        self._slide_to(0.0, animate)

    def _slide_to(self, target: float, animate: bool) -> None:
        self._anim.stop()
        if not animate or not self.isVisible() or abs(self._t - target) < 1e-6:
            self._apply(target)
            return
        self._anim.setStartValue(self._t)
        self._anim.setEndValue(target)
        self._anim.start()

    def _apply(self, value) -> None:  # noqa: ANN001 — QVariant from the animation
        self._t = float(value)
        self._layout_children()
        opened = self._t > 0.5
        self.main.setStyleSheet(_GREYED_STYLE if opened else NAV_TREE_STYLE)
        self.sub_panel.setVisible(self._t > 0.01)

    def _layout_children(self) -> None:
        w, h = self.width(), self.height()
        main_w = int(round(w * (1.0 - (1.0 - STRIP_RATIO) * self._t)))
        self.main.setGeometry(0, 0, main_w, h)
        self.sub_panel.setGeometry(main_w, 0, max(0, w - main_w), h)

    def resizeEvent(self, event) -> None:  # noqa: N802, ANN001
        super().resizeEvent(event)
        self._layout_children()
