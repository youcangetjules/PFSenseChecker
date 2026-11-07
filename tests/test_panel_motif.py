"""Panel title pills follow the Lumen glass-chip motif (motifs.md §3)."""

from __future__ import annotations

from pfsense_checker import panel_motif as pm


def test_chip_values_match_the_motif() -> None:
    qss = pm.panel_title_qss()
    for value in ("rgba(255, 255, 255, 236)", "rgba(240, 246, 251, 196)", "rgba(205, 217, 229, 214)",
                  "rgba(120, 140, 160, 110)", "#22303c", "border-radius: 5px", "padding: 2px 9px",
                  "stop: 0.55", "margin-top: 12px", "font-weight: 600"):
        assert value in qss, value
    assert "font-size: 13px" in pm.panel_title_qss(font_size="13px")


def test_app_style_applies_once_and_keeps_contents_weight() -> None:
    from PySide6.QtWidgets import QApplication, QGroupBox, QLabel, QVBoxLayout

    app = QApplication.instance() or QApplication([])
    before = app.styleSheet()
    try:
        pm.apply_app_panel_titles(app)
        pm.apply_app_panel_titles(app)
        assert app.styleSheet().count("netcheck-panel-title-pill") == 1
        box = QGroupBox("Panel")
        label = QLabel("inside")
        QVBoxLayout(box).addWidget(label)
        box.show()
        QApplication.processEvents()
        assert box.font().weight() == 600
        assert label.font().weight() == 400  # contents keep their own weight
        box.close()
    finally:
        app.setStyleSheet(before)
