"""Tests for requirements.txt inspection helpers."""

from __future__ import annotations

from pathlib import Path

from pfsense_checker import python_modules


def test_parse_requirements_basic(tmp_path: Path) -> None:
    path = tmp_path / "requirements.txt"
    path.write_text(
        "# Optional AI\n"
        "fastapi-poe>=0.0.36\n"
        "psycopg[binary]>=3.1.0  # database\n"
        "\n"
        "PySide6>=6.6.0\n",
        encoding="utf-8",
    )
    entries = python_modules.parse_requirements(path)
    assert [e.name for e in entries] == ["fastapi-poe", "psycopg", "PySide6"]
    assert entries[0].specifier == ">=0.0.36"
    assert "Optional AI" in entries[0].optional_note
    assert entries[1].extras == "binary"
    assert entries[1].specifier == ">=3.1.0"


def test_import_name_aliases() -> None:
    assert python_modules.import_name_for("fastapi-poe") == "fastapi_poe"
    assert python_modules.import_name_for("openpyxl") == "openpyxl"
    assert python_modules.import_name_for("librouteros") == "librouteros"
    assert python_modules.import_name_for("junos-eznc") == "jnpr.junos"


def test_requirements_lists_vendor_sdks() -> None:
    rows = python_modules.inspect_requirements()
    by_name = {r.name.lower(): r for r in rows}
    assert "librouteros" in by_name
    assert "junos-eznc" in by_name
    assert by_name["librouteros"].import_name == "librouteros"
    assert by_name["junos-eznc"].import_name == "jnpr.junos"
    assert "MikroTik" in by_name["librouteros"].optional_note
    assert "Junos" in by_name["junos-eznc"].optional_note


def test_inspect_includes_pyside() -> None:
    rows = python_modules.inspect_requirements()
    by_name = {r.name.lower(): r for r in rows}
    assert "pyside6" in by_name
    # Running under the project venv should have PySide6 installed.
    assert by_name["pyside6"].installed_version
    assert by_name["pyside6"].importable


def test_home_section_includes_modules() -> None:
    from pfsense_checker.home_screen import SECTIONS

    assert ("modules", "Python Modules") in SECTIONS
