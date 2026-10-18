from pathlib import Path

from pfsense_checker.gui import _config_files_in_folder


def test_config_files_in_folder_recurses_and_filters(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    expected = [
        tmp_path / "firewall.xml",
        nested / "router.RSC",
        nested / "restore.backup",
    ]
    for path in expected:
        path.write_text("test", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("ignore", encoding="utf-8")

    assert set(_config_files_in_folder(tmp_path)) == set(expected)
