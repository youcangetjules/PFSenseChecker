"""Syslog receiver parser, settings, and allowlist tests."""

from __future__ import annotations

import json
from types import SimpleNamespace

from pfsense_checker.syslog_recv import (
    SyslogSettings,
    _pop_tcp_frame,
    attached_sources,
    canon_ip,
    load_settings,
    parse_syslog,
    save_settings,
)


def test_syslog_section_in_nav() -> None:
    from pathlib import Path

    text = Path("pfsense_checker/home_screen.py").read_text(encoding="utf-8")
    assert '("syslog", "Syslog")' in text


def test_syslog_start_button_active_label() -> None:
    from pathlib import Path

    text = Path("pfsense_checker/home_screen.py").read_text(encoding="utf-8")
    assert 'setText("Listener Active")' in text
    assert "_syslog_set_start_button" in text
    assert "_syslog_listener_btn" in text


def test_parse_rfc3164() -> None:
    raw = b"<34>Oct 11 22:14:15 firewall filterlog: 1000000103 rule deny"
    msg = parse_syslog(raw, source_ip="192.0.2.1", source_port=514)
    assert msg.facility_name == "auth"
    assert msg.severity_name == "crit"
    assert msg.hostname == "firewall"
    assert msg.app_name == "filterlog"
    assert "rule deny" in msg.message
    assert msg.source_ip == "192.0.2.1"


def test_parse_rfc5424() -> None:
    raw = (
        b"<165>1 2024-01-02T03:04:05Z core-sw app - - - "
        b"interface ether1 link down"
    )
    msg = parse_syslog(raw, source_ip="2001:db8::1")
    assert msg.facility_name == "local4"
    assert msg.severity_name == "notice"
    assert msg.hostname == "core-sw"
    assert msg.app_name == "app"
    assert msg.message == "interface ether1 link down"


def test_parse_without_pri() -> None:
    msg = parse_syslog("plain text from router")
    assert msg.pri == 13
    assert "plain text" in msg.message


def test_canon_ipv4_mapped() -> None:
    assert canon_ip("::ffff:192.0.2.9") == "192.0.2.9"
    assert canon_ip("192.0.2.9") == "192.0.2.9"


def test_attached_sources_from_site() -> None:
    site = SimpleNamespace(
        devices=[
            SimpleNamespace(
                name="fw",
                mgmt_ip="192.0.2.1",
                ssh=SimpleNamespace(host="192.0.2.1"),
            ),
            SimpleNamespace(
                name="sw",
                mgmt_ip="",
                ssh=SimpleNamespace(host="192.0.2.2"),
            ),
            SimpleNamespace(
                name="named-only",
                mgmt_ip="",
                ssh=SimpleNamespace(host="core.local"),
            ),
        ]
    )
    src = attached_sources(site)
    assert src["192.0.2.1"] == "fw"
    assert src["192.0.2.2"] == "sw"
    assert "core.local" not in src


def test_settings_roundtrip(tmp_path) -> None:
    path = tmp_path / "syslog.json"
    settings = SyslogSettings(udp_port=5514, attached_only=True, tcp_port=0)
    save_settings(settings, path)
    loaded = load_settings(path)
    assert loaded.udp_port == 5514
    assert loaded.attached_only is True


def test_tcp_newline_and_octet_frames() -> None:
    frame, rest = _pop_tcp_frame(b"<13>hello\n<13>next")
    assert frame == b"<13>hello"
    assert rest == b"<13>next"
    payload = b"<14>counted"
    counted = f"{len(payload)} ".encode("ascii") + payload + b"TAIL"
    frame, rest = _pop_tcp_frame(counted)
    assert frame == payload
    assert rest == b"TAIL"
    incomplete, rest2 = _pop_tcp_frame(b"40 <14>not-enough")
    assert incomplete is None


def test_cidr_in_bind_moves_to_extra_allow() -> None:
    from pfsense_checker.syslog_recv import SyslogSettings, normalize_bind_settings

    s, note = normalize_bind_settings(
        SyslogSettings(bind_host="222.10.50.0/24", extra_allow="")
    )
    assert s.bind_host == "0.0.0.0"
    assert "222.10.50.0/24" in s.extra_allow
    assert "network" in note.lower()
    from pfsense_checker.syslog_recv import parse_allow_networks, source_permitted

    nets = parse_allow_networks("222.10.50.0/24")
    attached = {"100.48.62.1": "guardian"}
    ok, label = source_permitted(
        "222.10.50.1", attached, nets, attached_only=True
    )
    assert ok is True
    assert "222.10.50.0/24" in label
    denied, _ = source_permitted(
        "203.0.113.9", attached, nets, attached_only=True
    )
    assert denied is False


def test_prefer_listen_ips_fiber_first() -> None:
    from pfsense_checker.syslog_recv import prefer_listen_ips

    ordered = prefer_listen_ips(
        ["100.48.62.40", "222.10.50.64", "192.168.1.10"],
        "222.10.50.0/24",
    )
    assert ordered[0] == "222.10.50.64"


def test_pick_listen_bind_fiber_not_hyperv() -> None:
    from pfsense_checker.lan_scan import LocalIpv4Nic
    from pfsense_checker.syslog_recv import order_listen_nics, pick_listen_bind

    nics = [
        LocalIpv4Nic("172.28.112.1", "vEthernet (Default Switch)", kind="virtual"),
        LocalIpv4Nic("222.10.50.25", "V2_S4_1G_FIB_VL630_LAN_Main", kind="lan"),
        LocalIpv4Nic("169.254.1.2", "WiFi", kind="link-local"),
    ]
    ordered = order_listen_nics(nics, "222.10.50.0/24")
    assert ordered[0].ip == "222.10.50.25"
    assert pick_listen_bind(nics, "222.10.50.0/24", "222.10.50.0/24") == "222.10.50.25"
    assert pick_listen_bind(nics, "0.0.0.0", "222.10.50.0/24") == "0.0.0.0"
    assert pick_listen_bind(nics, "222.10.50.25", "") == "222.10.50.25"


def test_load_settings_migrates_cidr_bind(tmp_path) -> None:
    path = tmp_path / "syslog.json"
    path.write_text(
        json.dumps({"bind_host": "222.10.50.0/24", "udp_port": 5514}),
        encoding="utf-8",
    )
    loaded = load_settings(path)
    assert loaded.bind_host == "0.0.0.0"
    assert "222.10.50.0/24" in loaded.extra_allow
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["bind_host"] == "0.0.0.0"
    assert "222.10.50.0/24" in saved["extra_allow"]


def test_syslog_message_type_strips_pid() -> None:
    from pfsense_checker.home_screen import _syslog_message_type
    from pfsense_checker.syslog_recv import parse_syslog

    msg = parse_syslog(
        b"<134>Oct 11 22:14:15 fw filterlog[20447]: blocked",
        source_ip="222.10.50.1",
    )
    assert msg.app_name == "filterlog[20447]"
    assert _syslog_message_type(msg) == "filterlog"


def test_syslog_listen_on_combo() -> None:
    from pathlib import Path

    text = Path("pfsense_checker/home_screen.py").read_text(encoding="utf-8")
    assert 'form.addRow("Listen on:", self.syslog_bind)' in text
    assert "_syslog_fill_iface_combo" in text
