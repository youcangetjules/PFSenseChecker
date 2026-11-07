"""Python Modules: Available column and Loaded choices that survive logins."""

from __future__ import annotations

import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pfsense_checker import python_modules as pm  # noqa: E402


def test_availability_rules(monkeypatch) -> None:
    monkeypatch.setattr(pm, "_LOAD_ERRORS", {})
    ok, why = pm.availability(installed_version="", specifier=">=1", loaded=False, import_name="x")
    assert (ok, why) == (False, "Not installed")
    ok, why = pm.availability(installed_version="1.0", specifier=">=2", loaded=True, import_name="x")
    assert not ok and "does not meet >=2" in why
    ok, why = pm.availability(installed_version="2.1", specifier=">=2", loaded=False, import_name="x")
    assert not ok and "not loaded" in why
    ok, why = pm.availability(installed_version="2.1", specifier=">=2", loaded=True, import_name="x")
    assert ok and "Loaded and usable" in why
    pm._LOAD_ERRORS["y"] = "ImportError: DLL load failed"
    ok, why = pm.availability(installed_version="1.11", specifier=">=1.11", loaded=False, import_name="y")
    assert not ok and "DLL load failed" in why


def test_failed_import_is_recorded(monkeypatch) -> None:
    monkeypatch.setattr(pm, "_LOAD_ERRORS", {})
    try:
        pm.import_now("netcheck_no_such_module_xyz")
    except ImportError:
        pass
    assert "netcheck_no_such_module_xyz" in pm._LOAD_ERRORS


def test_loaded_choices_persist_and_only_allowlisted_load(tmp_path, monkeypatch) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("json5>=0.1\nPySide6>=6.6\n", encoding="utf-8")
    saved = tmp_path / "python_modules.json"
    pm.set_load_at_start("PySide6", True, saved)
    pm.set_load_at_start("json5", True, saved)
    pm.set_load_at_start("json5", False, saved)
    assert pm.load_at_start_names(saved) == ["PySide6"]
    # A hand-edited file asking for something outside requirements.txt.
    saved.write_text(json.dumps({"load_at_start": ["PySide6", "os"]}), encoding="utf-8")
    imported: list[str] = []
    monkeypatch.setattr(pm, "import_now", imported.append)
    results = pm.load_saved_modules(saved, req)
    assert imported == ["PySide6"]
    assert results == {"PySide6": "ok", "os": "skipped: not in requirements.txt"}


def test_modules_page_has_available_column(monkeypatch) -> None:
    from PySide6.QtWidgets import QApplication

    from pfsense_checker.home_screen import HomeScreen

    QApplication.instance() or QApplication([])
    rows = [
        pm.ModuleStatus("PySide6", "", ">=6.6.0", "6.8.0", True, True, "PySide6", "PySide6>=6.6.0",
                        available=True, available_reason="Loaded and usable"),
        pm.ModuleStatus("openpyxl", "", ">=3.1.0", "3.1.5", True, False, "openpyxl", "openpyxl>=3.1.0",
                        available=False, available_reason="Installed but not loaded"),
    ]
    monkeypatch.setattr(pm, "inspect_requirements", lambda path=None: rows)
    monkeypatch.setattr(pm, "load_at_start_names", lambda path=None: [])
    home = HomeScreen()
    home._ensure_page("modules")
    t = home.modules_table
    assert t.horizontalHeaderItem(5).text() == "Available"
    assert t.horizontalHeaderItem(6).text() == "Import name"
    assert t.item(0, 5).text() == "yes" and t.item(1, 5).text() == "no"
    assert t.item(1, 5).toolTip() == "Installed but not loaded"
    assert t.item(0, 6).text() == "PySide6"
    assert "1 available" in home.modules_summary.text()
