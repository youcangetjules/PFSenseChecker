"""MIB library settings helpers."""

from __future__ import annotations

from pfsense_checker import mib_libraries


def test_default_mib_dir_created() -> None:
    path = mib_libraries.ensure_default_mib_dir()
    assert path.is_dir()
    assert (path / "README.txt").is_file()


def test_load_settings_includes_default() -> None:
    cfg = mib_libraries.load_settings()
    assert cfg.search_paths
    assert any("mibs" in p.replace("\\", "/") for p in cfg.search_paths)
