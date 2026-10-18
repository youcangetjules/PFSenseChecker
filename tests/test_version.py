"""Tests for version / changelog module."""

from __future__ import annotations

from pfsense_checker import version
from pfsense_checker.home_screen import SETUP_SUBSECTIONS


def test_version_string() -> None:
    assert version.__version__
    assert version.VERSION == version.__version__
    assert version.full_version() == f"{version.__version__}+{version.SEQUENCE}"
    assert version.SEQUENCE >= 1


def test_changelog_newest_first() -> None:
    assert version.CHANGELOG
    assert version.CHANGELOG[0].version == version.__version__
    text = version.format_changelog()
    assert version.__version__ in text
    assert "•" in text or "-" in text


def test_each_changelog_entry_has_notes() -> None:
    versions: list[str] = []
    for entry in version.CHANGELOG:
        assert entry.version
        assert entry.date
        assert entry.notes, f"{entry.version} missing notes"
        versions.append(entry.version)
    assert len(versions) == len(set(versions))


def test_setup_version_nav() -> None:
    assert ("setup.version", "Version") in SETUP_SUBSECTIONS


def test_decide_sequence_bumps_once() -> None:
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "hooks" / "bump_sequence.py"
    spec = importlib.util.spec_from_file_location("bump_sequence", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.decide_sequence(1, None) is None
    assert mod.decide_sequence(4, 4) == 5
    assert mod.decide_sequence(5, 4) is None
    try:
        mod.decide_sequence(9, 4)
    except ValueError:
        return
    raise AssertionError("expected ValueError")
