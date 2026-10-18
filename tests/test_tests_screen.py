"""Tests for the Tests home-section helpers."""

from __future__ import annotations

from pfsense_checker.home_screen import SECTIONS
from pfsense_checker.tests_screen import discover_test_files


def test_tests_section_in_nav() -> None:
    assert ("tests", "Tests") in SECTIONS


def test_discover_test_files() -> None:
    files = discover_test_files()
    names = {p.name for p in files}
    assert "test_speed_check.py" in names
    assert "test_auth.py" in names
