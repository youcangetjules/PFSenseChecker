"""Tests for optional-module readiness helpers."""

from __future__ import annotations

from pfsense_checker import module_required as mr
from pfsense_checker import python_modules


def test_feature_module_map() -> None:
    assert "paramiko" in mr.modules_for_feature("ssh")
    assert "pysnmp" in mr.modules_for_feature("mibs")
    assert "pysmi" in mr.modules_for_feature("snmp")
    assert mr.modules_for_feature("no-such-feature") == ()


def test_readiness_pyside_ready() -> None:
    st = mr.readiness("PySide6")
    assert st.importable
    assert st.state in ("ready", "not_loaded")
    assert st.import_name == "PySide6"


def test_readiness_missing_package() -> None:
    st = mr.readiness("definitely-not-a-real-pkg-xyzzy")
    assert st.state == "missing"
    assert not st.importable


def test_ensure_modules_empty_ok() -> None:
    assert mr.ensure_modules(None, []) is True


def test_import_name_matches_python_modules() -> None:
    for dist in ("paramiko", "pysnmp", "psycopg", "openpyxl", "fastapi-poe"):
        assert mr.readiness(dist).import_name == python_modules.import_name_for(dist)
