"""Panel title pills: the glass chip from the Lumen design motifs.

Source of truth: ``C:\\Lumen\\Workflow Manager\\docs\\motifs.md`` §3 ("Group
title — glass chip") and ``dialog_canvas_motif.dialog_panel_title_glass_qss``.

The title straddles the panel border, so a solid fill could only match one
side; the chip is a translucent 3-stop vertical gradient (Qt has no backdrop
blur), a soft edge, 5px corners, #22303c text, semi-bold (600). Qt ignores
font-weight on ``QGroupBox::title`` alone, so the weight sits on the
``QGroupBox``; ``margin-top: 12px`` is the strip the chip is laid out in.

Only the title pill changes: panel frames, fills and contents are left as they
are. (added 2026-11-07)
"""

from __future__ import annotations

PANEL_TITLE_GLASS_TOP = "rgba(255, 255, 255, 236)"
PANEL_TITLE_GLASS_MID = "rgba(240, 246, 251, 196)"
PANEL_TITLE_GLASS_BOTTOM = "rgba(205, 217, 229, 214)"
PANEL_TITLE_GLASS_BORDER = "rgba(120, 140, 160, 110)"
PANEL_TITLE_TEXT = "#22303c"
PANEL_TITLE_WEIGHT = 600
PANEL_TITLE_MARGIN_TOP_PX = 12


def panel_title_chip_qss(selector: str = "QGroupBox") -> str:
    """The glass chip for ``<selector>::title``."""
    return f"""
        {selector}::title {{
            subcontrol-origin: margin;
            left: 10px;
            padding: 2px 9px;
            border: 1px solid {PANEL_TITLE_GLASS_BORDER};
            border-radius: 5px;
            color: {PANEL_TITLE_TEXT};
            font-family: 'Segoe UI';
            font-weight: {PANEL_TITLE_WEIGHT};
            background-color: qlineargradient(
                x1: 0, y1: 0, x2: 0, y2: 1,
                stop: 0 {PANEL_TITLE_GLASS_TOP},
                stop: 0.55 {PANEL_TITLE_GLASS_MID},
                stop: 1 {PANEL_TITLE_GLASS_BOTTOM}
            );
        }}
    """


def panel_title_qss(*, font_size: str = "") -> str:
    """Group box rule (room for the chip, 600 weight) plus the chip itself.

    *font_size* keeps a box's own title size where it already had one.
    """
    size = f" font-size: {font_size};" if font_size else ""
    return (
        f"QGroupBox {{ margin-top: {PANEL_TITLE_MARGIN_TOP_PX}px; "
        f"font-weight: {PANEL_TITLE_WEIGHT};{size} }}\n" + panel_title_chip_qss()
    )


def apply_app_panel_titles(app) -> None:  # noqa: ANN001
    """Give every QGroupBox in the application the glass title pill."""
    current = app.styleSheet() or ""
    marker = "/* netcheck-panel-title-pill */"
    if marker in current:
        return
    app.setStyleSheet(f"{current}\n{marker}\n{panel_title_qss()}")
