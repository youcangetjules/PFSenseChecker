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


def test_persist_changes_saves_loaded_ticks(tmp_path, monkeypatch) -> None:
    from PySide6.QtWidgets import QApplication, QMessageBox

    from pfsense_checker.home_screen import HomeScreen

    QApplication.instance() or QApplication([])
    saved = tmp_path / "python_modules.json"
    monkeypatch.setattr(pm, "LOAD_AT_START_PATH", saved)
    rows = [
        pm.ModuleStatus("PySide6", "", ">=6.6.0", "6.8.0", True, True, "PySide6", "PySide6>=6.6.0"),
        pm.ModuleStatus("openpyxl", "", ">=3.1.0", "3.1.5", True, False, "openpyxl", "openpyxl>=3.1.0"),
    ]
    monkeypatch.setattr(pm, "inspect_requirements", lambda path=None: rows)
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: None)
    home = HomeScreen()
    home._ensure_page("modules")
    assert home.btn_modules_persist.text() == "Persist Changes"
    # PySide6 is loaded but nothing is saved yet: persisting would change things.
    assert home.btn_modules_persist.isEnabled()

    imported: list[str] = []

    def fake_import(name):  # noqa: ANN001
        imported.append(name)
        rows[1] = pm.ModuleStatus("openpyxl", "", ">=3.1.0", "3.1.5", True, True,
                                  "openpyxl", "openpyxl>=3.1.0")

    monkeypatch.setattr(pm, "import_now", fake_import)
    load_box = home._modules_cell_checkbox(home.modules_table.cellWidget(1, 4))
    load_box.setChecked(True)  # tick openpyxl Loaded
    assert home.btn_modules_persist.isEnabled()
    home._modules_persist()
    assert imported == ["openpyxl"]  # loaded now as well as saved
    assert pm.load_at_start_names(saved) == ["PySide6", "openpyxl"]
    assert not home.btn_modules_persist.isEnabled()  # saved == ticks


def test_persist_skips_modules_that_fail_to_load(tmp_path, monkeypatch) -> None:
    from PySide6.QtWidgets import QApplication, QMessageBox

    from pfsense_checker.home_screen import HomeScreen

    QApplication.instance() or QApplication([])
    saved = tmp_path / "python_modules.json"
    monkeypatch.setattr(pm, "LOAD_AT_START_PATH", saved)
    rows = [
        pm.ModuleStatus("PySide6", "", ">=6.6.0", "6.8.0", True, True, "PySide6", "PySide6>=6.6.0"),
        pm.ModuleStatus("pygraphviz", "", ">=1.11", "1.11", True, False, "pygraphviz", "pygraphviz>=1.11"),
    ]
    monkeypatch.setattr(pm, "inspect_requirements", lambda path=None: rows)
    warnings: list[str] = []
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: None)
    monkeypatch.setattr(QMessageBox, "warning", lambda _p, _t, text: warnings.append(text))

    def boom(name):  # noqa: ANN001
        raise ImportError("DLL load failed")

    monkeypatch.setattr(pm, "import_now", boom)
    home = HomeScreen()
    home._ensure_page("modules")
    home._modules_cell_checkbox(home.modules_table.cellWidget(1, 4)).setChecked(True)
    home._modules_persist()
    assert pm.load_at_start_names(saved) == ["PySide6"]
    assert warnings and "pygraphviz" in warnings[0]


def test_needed_rows_are_shaded(monkeypatch) -> None:
    from PySide6.QtWidgets import QApplication

    from pfsense_checker.home_screen import HomeScreen

    QApplication.instance() or QApplication([])
    rows = [
        pm.ModuleStatus("PySide6", "", ">=6.6", "6.8", True, True, "PySide6", "PySide6>=6.6",
                        optional_note="Required. Qt GUI toolkit.", available=True),
        pm.ModuleStatus("paramiko", "", ">=3.4", "3.5", True, False, "paramiko", "paramiko>=3.4",
                        optional_note="Optional. SSH client.", available=False),
        pm.ModuleStatus("scapy", "", ">=2.5", "2.6", True, False, "scapy", "scapy>=2.5",
                        optional_note="Optional. Packet crafting. Not used by NetCheck yet.", available=False),
        pm.ModuleStatus("librouteros", "", ">=3.2", "3.4", True, True, "librouteros", "librouteros>=3.2",
                        optional_note="Optional. RouterOS API. Not used by NetCheck yet.", available=True),
    ]
    monkeypatch.setattr(pm, "inspect_requirements", lambda path=None: rows)
    monkeypatch.setattr(pm, "load_at_start_names", lambda path=None: [])
    home = HomeScreen()
    home._ensure_page("modules")
    t = home.modules_table
    assert t.item(0, 0).background().color().name() == "#e8f5e9"  # needed, loaded
    assert t.item(1, 0).background().color().name() == "#ffebee"  # needed, not loaded
    from PySide6.QtCore import Qt

    assert t.item(2, 0).background().style() == Qt.BrushStyle.NoBrush  # not needed: no shading
    assert t.item(1, 5).background().color().name() == "#ffcdd2"  # Available keeps its colour
    assert t.item(3, 0).background().color().name() == "#e3f2fd"  # loaded, not required: light blue


def test_unticking_loaded_applies_at_next_login(tmp_path, monkeypatch) -> None:
    from PySide6.QtWidgets import QApplication, QMessageBox

    from pfsense_checker.home_screen import HomeScreen

    QApplication.instance() or QApplication([])
    saved = tmp_path / "python_modules.json"
    monkeypatch.setattr(pm, "LOAD_AT_START_PATH", saved)
    pm.save_load_at_start(["requests", "graphviz"], saved)
    rows = [
        pm.ModuleStatus("requests", "", ">=2.31.0", "2.32.0", True, True, "requests", "requests>=2.31.0"),
        pm.ModuleStatus("graphviz", "", ">=0.20.0", "0.21", True, True, "graphviz", "graphviz>=0.20.0"),
    ]
    monkeypatch.setattr(pm, "inspect_requirements", lambda path=None: rows)
    asked: list[str] = []
    told: list[str] = []
    monkeypatch.setattr(QMessageBox, "question",
                        lambda _p, _t, text, *a, **k: asked.append(text) or QMessageBox.StandardButton.Yes)
    monkeypatch.setattr(QMessageBox, "information", lambda _p, _t, text, *a, **k: told.append(text))
    home = HomeScreen()
    home._ensure_page("modules")
    home._modules_cell_checkbox(home.modules_table.cellWidget(0, 4)).setChecked(False)  # untick requests
    home._modules_save_commit()
    assert "updated at your next login" in asked[0] and "requests" in asked[0]
    assert "Cannot unload" not in asked[0]
    assert pm.load_at_start_names(saved) == ["graphviz"]  # requests dropped for next login
    assert "next login" in told[-1]
