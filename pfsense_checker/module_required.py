"""Remind the user to install/load a Python module before a feature runs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from PySide6.QtWidgets import QMessageBox, QWidget

from pfsense_checker import python_modules as pm

# Feature key -> distribution names from requirements.txt
FEATURE_MODULES: dict[str, tuple[str, ...]] = {
    "ssh": ("paramiko",),
    "snmp": ("pysnmp", "pysmi"),
    "mibs": ("pysnmp", "pysmi"),
    "redfish": ("redfish",),
    "http_api": ("httpx",),
    "topology_graph": ("networkx",),
    "topology_viz": ("networkx", "matplotlib"),
    "postgres": ("psycopg",),
    "excel": ("openpyxl",),
    "keyring": ("keyring",),
    "ai_poe": ("fastapi-poe",),
}


@dataclass(frozen=True)
class ModuleReadiness:
    """Whether a distribution is ready for use in this process."""

    dist_name: str
    import_name: str
    installed_version: str
    importable: bool
    loaded: bool

    @property
    def state(self) -> str:
        """``ready`` | ``not_loaded`` | ``missing``."""
        if not self.importable:
            return "missing"
        if not self.loaded:
            return "not_loaded"
        return "ready"


def readiness(dist_name: str) -> ModuleReadiness:
    """Inspect one requirements-style distribution name."""
    name = (dist_name or "").strip()
    imp = pm.import_name_for(name)
    return ModuleReadiness(
        dist_name=name,
        import_name=imp,
        installed_version=pm.installed_version(name),
        importable=pm.is_importable(imp),
        loaded=pm.is_loaded(imp),
    )


def modules_for_feature(feature: str) -> tuple[str, ...]:
    key = (feature or "").strip().lower()
    return FEATURE_MODULES.get(key, ())


def open_python_modules(parent: QWidget | None = None) -> bool:
    """Navigate the main window to Home → Python Modules."""
    widget: QWidget | None = parent
    while widget is not None:
        home = getattr(widget, "home_screen", None)
        if home is not None:
            show_home = getattr(widget, "show_home_screen", None)
            if callable(show_home):
                show_home()
            show = getattr(home, "show_section", None)
            if callable(show):
                show("modules")
                return True
        parent_obj = widget.parent()
        widget = parent_obj if isinstance(parent_obj, QWidget) else None
    return False


def _reminder_text(
    purpose: str,
    missing: list[ModuleReadiness],
    not_loaded: list[ModuleReadiness],
) -> str:
    lines: list[str] = []
    if purpose.strip():
        lines.append(f"You tried to: {purpose.strip()}")
        lines.append("")
    if missing:
        names = ", ".join(m.dist_name for m in missing)
        lines.append(
            f"Required module(s) not installed: {names}\n\n"
            "Open Home → Python Modules, tick Installed for each, "
            "then click Save/Commit."
        )
    if not_loaded:
        if lines:
            lines.append("")
        names = ", ".join(m.dist_name for m in not_loaded)
        lines.append(
            f"Required module(s) installed but not loaded: {names}\n\n"
            "Open Home → Python Modules, tick Loaded for each, "
            "then click Save/Commit — or choose Load now below."
        )
    return "\n".join(lines).strip()


def ensure_modules(
    parent: QWidget | None,
    dist_names: Iterable[str],
    *,
    purpose: str = "",
    offer_load: bool = True,
    quiet_load: bool = True,
) -> bool:
    """Return True if all modules are usable; otherwise remind and return False.

    Missing packages must be installed via Python Modules → Save/Commit.
    Installed-but-not-loaded packages are imported automatically when
    ``quiet_load`` is True (typical for Connect / Save). Set
    ``quiet_load=False`` to show an explicit Load now / Open Modules prompt.
    """
    names = [n.strip() for n in dist_names if (n or "").strip()]
    if not names:
        return True

    statuses = [readiness(n) for n in names]
    missing = [s for s in statuses if s.state == "missing"]
    not_loaded = [s for s in statuses if s.state == "not_loaded"]
    if not missing and not not_loaded:
        return True

    title = "Python module required"

    if missing:
        text = _reminder_text(purpose, missing, [])
        box = QMessageBox(parent)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle(title)
        box.setText(text)
        open_btn = box.addButton("Open Python Modules", QMessageBox.ButtonRole.AcceptRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.exec()
        if box.clickedButton() is open_btn:
            open_python_modules(parent)
        return False

    # Installed but not loaded yet in this process.
    if quiet_load:
        errors: list[str] = []
        for st in not_loaded:
            try:
                pm.import_now(st.import_name)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{st.dist_name}: {exc}")
        if errors:
            QMessageBox.warning(
                parent,
                title,
                "Could not load module(s) — use Home → Python Modules:\n\n"
                + "\n".join(errors),
            )
            return False
        return all(readiness(n).importable for n in names)

    text = _reminder_text(purpose, [], not_loaded)
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Information)
    box.setWindowTitle(title)
    box.setText(text)
    load_btn = None
    if offer_load:
        load_btn = box.addButton("Load now", QMessageBox.ButtonRole.AcceptRole)
    open_btn = box.addButton("Open Python Modules", QMessageBox.ButtonRole.ActionRole)
    box.addButton(QMessageBox.StandardButton.Cancel)
    box.exec()
    clicked = box.clickedButton()
    if load_btn is not None and clicked is load_btn:
        errors = []
        for st in not_loaded:
            try:
                pm.import_now(st.import_name)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{st.dist_name}: {exc}")
        if errors:
            QMessageBox.warning(
                parent,
                title,
                "Could not load module(s):\n\n" + "\n".join(errors),
            )
            return False
        return all(readiness(n).importable for n in names)
    if clicked is open_btn:
        open_python_modules(parent)
    return False


def ensure_feature(
    parent: QWidget | None,
    feature: str,
    *,
    purpose: str = "",
    offer_load: bool = True,
    quiet_load: bool = True,
) -> bool:
    """Like :func:`ensure_modules` using :data:`FEATURE_MODULES`."""
    mods = modules_for_feature(feature)
    if not mods:
        return True
    label = purpose or f"use the “{feature}” feature"
    return ensure_modules(
        parent,
        mods,
        purpose=label,
        offer_load=offer_load,
        quiet_load=quiet_load,
    )
