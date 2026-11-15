"""Log Pipeline listen port and line formatting."""

from __future__ import annotations

import os
from pathlib import Path

from pfsense_checker import log_pipeline
from pfsense_checker.syslog_recv import SyslogMessage


def test_default_port_is_59000(tmp_path) -> None:
    settings = log_pipeline.load_settings(tmp_path / "missing.json")
    assert settings.port == 59000
    recv = log_pipeline.receiver_settings(settings)
    assert recv.udp_port == 59000
    assert recv.tcp_port == 59000
    assert recv.attached_only is False
    assert recv.file_enabled is False


def test_port_round_trip_and_reject_invalid(tmp_path) -> None:
    path = tmp_path / "log_pipeline.json"
    log_pipeline.save_settings(log_pipeline.LogPipelineSettings(port=5514), path)
    assert log_pipeline.load_settings(path).port == 5514
    log_pipeline.save_settings(log_pipeline.LogPipelineSettings(port=0), path)
    assert log_pipeline.load_settings(path).port == 59000
    assert log_pipeline.clamp_port("nope") == 59000
    assert log_pipeline.clamp_port(70000) == 59000
    assert log_pipeline.clamp_port(59000) == 59000


def test_filterlog_line_is_decoded() -> None:
    raw = (
        "<134>Oct 18 19:00:00 fw filterlog[123]: "
        "5,,,1000000103,igb0,match,block,in,4,0x0,,64,1,0,DF,6,tcp,60,"
        "192.0.2.10,198.51.100.20,44321,443,0,S,1,0,,"
    )
    msg = SyslogMessage(
        received_at="2026-10-18T19:00:00+00:00",
        source_ip="10.1.1.1",
        source_port=514,
        device_name="",
        pri=134,
        facility=16,
        severity=6,
        facility_name="local0",
        severity_name="info",
        timestamp="Oct 18 19:00:00",
        hostname="fw",
        app_name="filterlog",
        message=raw,
        raw=raw,
        accepted=True,
    )
    line = log_pipeline.format_message(msg)
    assert "block in igb0" in line
    assert "tcp" in line
    assert "192.0.2.10:44321 -> 198.51.100.20:443" in line


def test_filter_line_in_plain_words() -> None:
    line = ("filterlog[70]: 5,,,1000000103,igb3,match,block,in,4,0x0,,64,1,0,DF,6,tcp,60,"
            "203.0.113.9,100.48.62.1,44321,23,0,S,1,,64240,,mss")
    assert log_pipeline.filter_text(line) == "block in igb3  tcp  203.0.113.9:44321 -> 100.48.62.1:23"
    assert log_pipeline.filter_text("sshd[1]: Accepted publickey for ops") == ""
    assert log_pipeline.filter_text("") == ""


def test_pipeline_port_moves_into_syslog_once(tmp_path) -> None:
    """Log Pipeline was a second receiver on its own port; Syslog takes that port over, once."""
    from pfsense_checker import syslog_recv

    pipe, sys_path = tmp_path / "log_pipeline.json", tmp_path / "syslog.json"
    assert log_pipeline.merge_into_syslog(pipe, sys_path) == ""  # never used: nothing to move
    assert not sys_path.exists()

    syslog_recv.save_settings(syslog_recv.SyslogSettings(udp_port=5514, tcp_port=0, attached_only=True,
                                                         extra_allow="222.10.50.0/24"), sys_path)
    log_pipeline.save_settings(log_pipeline.LogPipelineSettings(port=59000), pipe)
    note = log_pipeline.merge_into_syslog(pipe, sys_path)
    assert "Listening port set to 59000, UDP and TCP (UDP was 5514)" in note
    merged = syslog_recv.load_settings(sys_path)
    assert (merged.udp_port, merged.tcp_port) == (59000, 59000)
    assert merged.attached_only and merged.extra_allow == "222.10.50.0/24"  # the rest is left alone
    assert not pipe.exists() and (tmp_path / "log_pipeline.json.merged").is_file()

    # A port chosen on the Syslog page afterwards is not overwritten again.
    merged.udp_port = 5515
    syslog_recv.save_settings(merged, sys_path)
    assert log_pipeline.merge_into_syslog(pipe, sys_path) == ""
    assert syslog_recv.load_settings(sys_path).udp_port == 5515


# --- MikroTik: commands that make a RouterOS device send its log here -------- #


class _Nic:
    def __init__(self, ip: str, cidr: str, kind: str = "lan", name: str = "") -> None:
        self.ip, self.cidr, self.kind, self.name = ip, cidr, kind, name or ip

    def label(self) -> str:
        return f"{self.name}  —  {self.ip}"


_NICS = [
    _Nic("172.27.224.1", "172.27.224.0/20", "virtual", "vEthernet (Default Switch)"),
    _Nic("222.10.50.25", "222.10.50.0/24", "lan", "Fiber"),
    _Nic("100.48.62.65", "100.48.62.0/24", "lan", "Backup"),
]


def test_mikrotik_commands_and_undo() -> None:
    lines = log_pipeline.mikrotik_commands("222.10.50.25", 59000)
    assert lines == [
        "/system logging action add name=netcheck target=remote remote=222.10.50.25 "
        "remote-port=59000 remote-protocol=udp remote-log-format=syslog",
        "/system logging add action=netcheck topics=info",
        "/system logging add action=netcheck topics=warning",
        "/system logging add action=netcheck topics=error",
        "/system logging add action=netcheck topics=critical",
    ]
    assert not any("debug" in line for line in lines)  # caps,debug would flood the stream
    assert "remote-port=5514" in log_pipeline.mikrotik_commands(" 222.10.50.25 ", 5514)[0]
    assert "remote-port=59000" in log_pipeline.mikrotik_commands("222.10.50.25", 0)[0]
    # Nothing half-formed: no address, a name, a loopback or extra words give no commands.
    for bad in ("", "this-pc", "127.0.0.1", "0.0.0.0", "1.2.3.4; /system reset-configuration", "fe80::1"):
        assert log_pipeline.mikrotik_commands(bad, 59000) == []
    assert log_pipeline.mikrotik_undo_commands() == [
        "/system logging remove [find action=netcheck]",
        "/system logging action remove [find name=netcheck]",
    ]
    # A CAPsMAN controller logs Wi-Fi clients connecting / disconnecting as caps,debug: one extra rule.
    wifi = log_pipeline.mikrotik_commands("222.10.50.25", 59000, wifi_clients=True)
    assert wifi[:-1] == lines and wifi[-1] == "/system logging add action=netcheck topics=caps,debug"
    assert sum("debug" in line for line in wifi) == 1  # no other debug topic
    assert log_pipeline.mikrotik_commands("nope", 59000, wifi_clients=True) == []


def test_pick_address_prefers_the_routers_network() -> None:
    pick = log_pipeline.pick_address
    assert pick(_NICS, ["222.10.50.2", "222.10.50.3"]) == "222.10.50.25"
    assert pick(_NICS, ["100.48.62.9"]) == "100.48.62.65"
    assert pick(_NICS, ["100.48.62.9", "222.10.50.2", "222.10.50.3"]) == "222.10.50.25"  # most routers
    assert pick(_NICS, ["222.10.1.5"]) == "222.10.50.25"  # none shared: first real LAN, not Hyper-V
    assert pick(_NICS, []) == "222.10.50.25"
    assert pick(_NICS[:1], []) == "172.27.224.1"
    assert pick([], ["222.10.50.2"]) == ""


def test_mikrotik_hosts_come_from_login_to_routers() -> None:
    from types import SimpleNamespace as NS

    site = NS(devices=[
        NS(name="crs328", kind="mikrotik", ignored=False, mgmt_ip="", ssh=NS(host="222.10.50.2")),
        NS(name="crs109", kind="MikroTik", ignored=False, mgmt_ip="222.10.50.3", ssh=None),
        NS(name="old", kind="mikrotik", ignored=True, mgmt_ip="222.10.50.9", ssh=None),
        NS(name="fw", kind="pfsense", ignored=False, mgmt_ip="100.48.62.1", ssh=None),
        NS(name="named", kind="mikrotik", ignored=False, mgmt_ip="", ssh=NS(host="switch.lan")),
    ])
    assert log_pipeline.mikrotik_hosts(site) == ["222.10.50.2", "222.10.50.3"]
    assert log_pipeline.mikrotik_hosts(None) == []


def test_routeros_syslog_line_is_readable() -> None:
    from pfsense_checker.syslog_recv import parse_syslog

    raw = "<30>Nov 15 20:01:02 CRS109-2 interface,info ether2 link down"
    line = log_pipeline.format_message(parse_syslog(raw, source_ip="222.10.50.3", source_port=514))
    assert "ether2 link down" in line and ("CRS109-2" in line or "222.10.50.3" in line)


def test_mikrotik_box(monkeypatch) -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from types import SimpleNamespace as NS

    from PySide6.QtGui import QGuiApplication
    from PySide6.QtWidgets import QApplication

    from pfsense_checker import mikrotik_log_box as mlb

    QApplication.instance() or QApplication([])
    monkeypatch.setattr(mlb, "local_ipv4_nics", lambda: list(_NICS))
    site = NS(devices=[NS(name="crs", kind="mikrotik", ignored=False, mgmt_ip="100.48.62.9", ssh=None)])
    said: list[str] = []
    box = mlb.MikrotikLogBox(site=lambda: site, port=59000)
    box.copied.connect(said.append)

    # The adapter on the MikroTik's network is chosen, not the first one listed.
    assert box.address.count() == 3 and box.chosen_address() == "100.48.62.65"
    assert "remote=100.48.62.65 remote-port=59000" in box.text.toPlainText()
    box.address.setCurrentIndex(1)
    box.set_port(5514)
    text = box.text.toPlainText()
    assert "remote=222.10.50.25 remote-port=5514" in text and "[find name=netcheck]" in text

    box.copy_commands()
    copied = QGuiApplication.clipboard().text()
    assert copied.splitlines() == log_pipeline.mikrotik_commands("222.10.50.25", 5514)
    assert "remove" not in copied  # Copy takes the commands, not the undo lines
    assert said[-1] == "Copied 5 MikroTik commands for 222.10.50.25:5514."
    box.copy_undo()
    assert QGuiApplication.clipboard().text().splitlines() == log_pipeline.mikrotik_undo_commands()

    # Wi-Fi client events are opt-in: off to start with, one more command when ticked.
    assert not box.wifi_clients.isChecked() and "caps" not in box.text.toPlainText()
    box.wifi_clients.setChecked(True)
    assert "topics=caps,debug" in box.text.toPlainText()
    assert box.text.toPlainText().index("topics=caps,debug") < box.text.toPlainText().index("# To stop sending")
    box.copy_commands()
    assert said[-1] == "Copied 6 MikroTik commands for 222.10.50.25:5514."
    assert QGuiApplication.clipboard().text().splitlines()[-1] == "/system logging add action=netcheck topics=caps,debug"
    box.wifi_clients.setChecked(False)
    assert "caps" not in box.text.toPlainText()
    box.copy_undo()  # the clipboard holds the undo lines again for the check below

    # A typed address is used; anything that is not an IPv4 address gives nothing to copy.
    box.address.setEditText("10.9.8.7")
    assert box.chosen_address() == "10.9.8.7" and box.btn_copy.isEnabled()
    box.address.setEditText("my-pc")
    assert not box.btn_copy.isEnabled() and box.text.toPlainText().startswith("#")
    box.copy_commands()
    assert QGuiApplication.clipboard().text().splitlines() == log_pipeline.mikrotik_undo_commands()

    # Reloading the adapters keeps the choice the operator made.
    box.address.setCurrentIndex(1)
    box.refresh(reload=True)
    assert box.chosen_address() == "222.10.50.25"

    # Devices that load after the box was built move an address NetCheck picked itself.
    late = NS(devices=[])
    box = mlb.MikrotikLogBox(site=lambda: late)
    assert box.chosen_address() == "222.10.50.25"  # no routers yet: first real LAN adapter
    late.devices.append(NS(name="crs", kind="mikrotik", ignored=False, mgmt_ip="100.48.62.9", ssh=None))
    box.show()
    assert box.chosen_address() == "100.48.62.65"
    box.hide()

    # A listener bound to one adapter only hears there: that address wins.
    bound = {"host": "0.0.0.0"}
    box = mlb.MikrotikLogBox(site=lambda: site, bind=lambda: bound["host"])
    assert box.chosen_address() == "100.48.62.65"
    bound["host"] = "222.10.50.25"
    box.refresh()
    assert box.chosen_address() == "222.10.50.25"


def test_syslog_page_holds_the_pipeline(tmp_path, monkeypatch) -> None:
    """One receiver page: tabs, the MikroTik commands on its port, filter lines in plain words."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from pfsense_checker import mikrotik_log_box as mlb
    from pfsense_checker import syslog_recv
    from pfsense_checker.home_screen import LOGS_SUBSECTIONS, HomeScreen

    QApplication.instance() or QApplication([])
    monkeypatch.setattr(mlb, "local_ipv4_nics", lambda: list(_NICS))
    # The pipeline was used on 59000; Syslog was saved on 5514 (conftest points both at tmp_path).
    syslog_recv.save_settings(syslog_recv.SyslogSettings(udp_port=5514, tcp_port=0))
    log_pipeline.save_settings(log_pipeline.LogPipelineSettings(port=59000), log_pipeline.SETTINGS_PATH)

    assert "log_pipeline" not in [k for k, _ in LOGS_SUBSECTIONS]
    home = HomeScreen()
    assert "log_pipeline" not in home._page_builders  # noqa: SLF001
    home.show_section("syslog")
    tabs = home.syslog_tabs
    assert [tabs.tabText(i) for i in range(tabs.count())] == ["Messages", "Settings", "Send logs here"]
    assert home.syslog_table.parentWidget() is tabs.widget(0)
    assert home.syslog_mikrotik.parentWidget() is tabs.widget(2)

    # The pipeline's port came over, and says so.
    assert (home.syslog_udp_port.value(), home.syslog_tcp_port.value()) == (59000, 59000)
    assert "Log Pipeline is now part of this page" in home.syslog_status.text()
    assert not log_pipeline.SETTINGS_PATH.exists()

    # The MikroTik commands follow the UDP port of the page.
    assert "remote-port=59000" in home.syslog_mikrotik.text.toPlainText()
    home.syslog_udp_port.setValue(5514)
    assert "remote-port=5514" in home.syslog_mikrotik.text.toPlainText()
    home.syslog_mikrotik.copy_undo()
    assert "Copied the 2 commands" in home.syslog_status.text()

    # A pfSense filter line is shown in plain words, the raw line in the tooltip.
    raw = ("<134>Nov 15 19:12:00 guardian filterlog[70]: 5,,,1000000103,igb3,match,block,in,4,0x0,,64,1,0,DF,"
           "6,tcp,60,203.0.113.9,100.48.62.1,44321,23,0,S,1,,64240,,mss")
    msg = syslog_recv.parse_syslog(raw, source_ip="222.10.50.1", source_port=514)
    home._syslog_on_message(msg)  # noqa: SLF001
    cell = home.syslog_table.item(home.syslog_table.rowCount() - 1, 7)
    assert cell.text() == "block in igb3  tcp  203.0.113.9:44321 -> 100.48.62.1:23"
    assert "1000000103" in cell.toolTip()
    plain = syslog_recv.parse_syslog("<30>Nov 15 20:01:02 CRS109-2 interface,info ether2 link down",
                                     source_ip="222.10.50.20", source_port=514)
    home._syslog_on_message(plain)  # noqa: SLF001
    assert "ether2 link down" in home.syslog_table.item(home.syslog_table.rowCount() - 1, 7).text()
