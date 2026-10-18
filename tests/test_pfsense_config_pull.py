"""Tests for pfSense/OPNsense config.xml SSH pull helpers."""

from __future__ import annotations

from pfsense_checker.ssh_session import (
    PFSENSE_CONFIG_PATHS,
    detect_firewall_kind_from_xml,
    looks_like_firewall_config_xml,
)


def test_pfsense_config_paths_order() -> None:
    assert PFSENSE_CONFIG_PATHS[0] == "/cf/conf/config.xml"
    assert "/conf/config.xml" in PFSENSE_CONFIG_PATHS


def test_looks_like_pfsense_xml() -> None:
    xml = '<?xml version="1.0"?>\n<pfsense>\n  <version>23.1</version>\n</pfsense>\n'
    assert looks_like_firewall_config_xml(xml)
    assert detect_firewall_kind_from_xml(xml) == "pfsense"


def test_looks_like_opnsense_xml() -> None:
    xml = '<?xml version="1.0"?>\n<opnsense>\n  <theme>opnsense</theme>\n</opnsense>\n'
    assert looks_like_firewall_config_xml(xml)
    assert detect_firewall_kind_from_xml(xml) == "opnsense"


def test_rejects_non_firewall_xml() -> None:
    assert not looks_like_firewall_config_xml("<html><body>nope</body></html>")
    assert not looks_like_firewall_config_xml("")
    assert detect_firewall_kind_from_xml("<router/>") == ""


def test_permission_denied_message_is_actionable() -> None:
    from pfsense_checker.ssh_session import _format_pfsense_pull_error

    msg = _format_pfsense_pull_error(
        "PERMISSION_DENIED:/cf/conf/config.xml",
        "n1sfefBhxsH0",
    )
    assert "Permission denied" in msg
    assert "n1sfefBhxsH0" in msg
    assert "admin" in msg.lower() or "root" in msg.lower()


def test_pull_commands_use_bin_sh() -> None:
    from pfsense_checker.ssh_session import _pfsense_pull_commands

    cmds = _pfsense_pull_commands()
    assert cmds
    assert all(c.startswith("/bin/sh -c ") for c in cmds)
    assert "sudo -n" in cmds[1]


def test_extract_xml_after_sudo_lecture() -> None:
    from pfsense_checker.ssh_session import extract_firewall_config_xml

    noisy = (
        "We trust you have received the usual lecture from the local System\n"
        "Administrator.\n"
        "Password:\n"
        '<?xml version="1.0"?>\n'
        "<opnsense>\n  <theme>opnsense</theme>\n</opnsense>\n"
    )
    xml = extract_firewall_config_xml(noisy)
    assert xml.startswith("<?xml")
    assert "<opnsense>" in xml


def test_sudo_stdin_command_has_no_password_placeholder() -> None:
    from pfsense_checker.ssh_session import SUDO_PROMPT, _pfsense_sudo_stdin_command

    cmd = _pfsense_sudo_stdin_command()
    assert "sudo -S" in cmd
    assert SUDO_PROMPT in cmd
    assert "password" not in cmd.lower()
    assert "/cf/conf/config.xml" in cmd
