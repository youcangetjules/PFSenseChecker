"""Headless CLI: text and JSON reports, exit codes per --fail-on."""

from __future__ import annotations

import json

from pfsense_checker import cli

GOOD = """<?xml version="1.0"?>
<pfsense><version>24.6</version>
<system><hostname>fw</hostname><domain>lan</domain></system>
<interfaces><lan><if>igb1</if><enable/><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan></interfaces>
</pfsense>"""


def _cfg(tmp_path, text: str = GOOD):  # noqa: ANN001, ANN202
    p = tmp_path / "config.xml"
    p.write_text(text, encoding="utf-8")
    return p


def test_text_report(tmp_path, capsys) -> None:
    code = cli.main([str(_cfg(tmp_path)), "--fail-on", "never"])
    out = capsys.readouterr().out
    assert code == 0
    assert "pfSense/OPNsense Configuration Check Report" in out
    assert "Hostname:  fw" in out and "-- Findings --" in out


def test_json_report(tmp_path, capsys) -> None:
    cli.main([str(_cfg(tmp_path)), "--json", "--fail-on", "never"])
    data = json.loads(capsys.readouterr().out)
    assert data["valid_xml"] is True
    assert {"errors", "warnings", "info", "findings", "summary"} <= set(data)
    assert all({"severity", "category", "message"} <= set(f) for f in data["findings"])


def test_exit_codes(tmp_path, capsys) -> None:
    broken = _cfg(tmp_path, "<pfsense><unclosed></pfsense>")
    assert cli.main([str(broken)]) == 1  # invalid XML is an error
    assert cli.main([str(broken), "--fail-on", "never"]) == 0
    good = _cfg(tmp_path)
    data_warn = cli.main([str(good), "--fail-on", "warning"])
    capsys.readouterr()
    import pfsense_checker.checker as checker

    result = checker.check_file(good)
    assert data_warn == (1 if (result.error_count or result.warning_count) else 0)
