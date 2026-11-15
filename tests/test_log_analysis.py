"""Log Analysis: parse pfSense / MikroTik / syslog lines and pick out what matters."""

from __future__ import annotations

import gzip
from datetime import datetime

from pfsense_checker import log_analysis as la

PFSENSE = """\
Nov 15 19:08:40 guardian sshd[4410]: Failed password for admin from 222.10.50.25 port 51022 ssh2
Nov 15 19:08:44 guardian sshd[4410]: Connection closed by authenticating user admin 222.10.50.25 port 51022 [preauth]
Nov 15 19:08:48 guardian sshguard[901]: Attack from "222.10.50.25" on service SSH with danger 10.
Nov 15 19:08:49 guardian sshguard[901]: Blocking "222.10.50.25/32" for 120 secs (3 attacks in 9 secs, after 1 abuses over 9 secs.)
Nov 15 19:10:02 guardian sshd[4500]: Accepted publickey for ops from 222.10.50.30 port 40000 ssh2: ED25519 SHA256:abc
Nov 15 19:11:00 guardian php-fpm[355]: /index.php: webConfigurator authentication error for user 'admin' from: 222.10.50.77
Nov 15 19:12:00 guardian filterlog[70]: 5,,,1000000103,igb3,match,block,in,4,0x0,,64,1,0,DF,6,tcp,60,203.0.113.9,100.48.62.1,44321,23,0,S,1,,64240,,mss
Nov 15 19:12:01 guardian filterlog[70]: 5,,,1000000103,igb3,match,block,in,4,0x0,,64,2,0,DF,6,tcp,60,203.0.113.9,100.48.62.1,44322,23,0,S,1,,64240,,mss
Nov 15 19:12:02 guardian filterlog[70]: 5,,,1000000103,igb3,match,block,in,4,0x0,,64,3,0,none,17,udp,78,198.51.100.4,100.48.62.1,5353,53,58
Nov 15 19:12:03 guardian filterlog[70]: 80,,,1770001234,mce1,match,pass,in,4,0x0,,64,4,0,DF,6,tcp,60,222.10.50.25,1.1.1.1,50000,443,0,S,1,,64240,,mss
Nov 15 19:13:00 guardian dhcpd[800]: DHCPACK on 222.10.50.101 to aa:bb:cc:dd:ee:01 (laptop) via mce1.630
Nov 15 19:13:05 guardian dhcpd[800]: DHCPDISCOVER from aa:bb:cc:dd:ee:02 via mce1.630: network 222.10.50.0/24: no free leases
Nov 15 19:14:00 guardian openvpn[1200]: Inactivity timeout (--ping-restart), restarting
Nov 15 19:14:30 guardian openvpn[1200]: Initialization Sequence Completed
Nov 15 19:15:00 guardian dpinger[500]: WAN_DHCP 100.64.0.1: Alarm latency 0us stddev 0us loss 100%
Nov 15 19:16:00 guardian kernel: igb2: link state changed to DOWN
"""

MIKROTIK = """\
2026-11-09 11:44:01 caps,debug no suitable CAPsMAN
2026-11-09 11:44:15 caps,debug no suitable CAPsMAN
2026-11-09 11:44:28 caps,debug no suitable CAPsMAN
2026-11-09 11:44:42 caps,debug no suitable CAPsMAN
2026-11-09 11:44:55 caps,debug no suitable CAPsMAN
2026-11-09 12:00:00 caps,info C8:FF:77:A3:65:27@CRS109-W-3-1 reassociating
2026-11-09 12:00:01 caps,debug C8:FF:77:A3:65:27@CRS109-W-3-1 connected, signal strength -80
2026-11-09 12:01:00 caps,info CAP disconnected from CRS328-MASTER (::ffff:222.10.1.5:5246)
2026-11-09 12:02:00 interface,info ether2 link down
2026-11-09 12:02:05 interface,info ether2 link up (speed 1G, full duplex)
2026-11-09 12:03:00 system,info,account user admin logged in from 222.10.50.25 via ssh
2026-11-09 12:04:00 system,error,critical login failure for user admin from F4:E9:D4:A4:45:E0 via winbox
2026-11-09 12:05:00 warning denied winbox/dude connect from 222.10.50.25
2026-11-09 12:06:00 system,error,critical router was rebooted without proper shutdown
"""


def _finding(a: la.Analysis, title_part: str) -> la.Finding:
    return next(f for f in a.findings if title_part in f.title)


def test_line_formats() -> None:
    ln = la.parse_line("Nov 15 19:08:48 guardian sshd[123]: Failed password for admin from 1.2.3.4 port 5 ssh2", year=2026)
    assert (ln.host, ln.service, ln.vendor) == ("guardian", "sshd", "pfsense")
    assert ln.when == datetime(2026, 11, 15, 19, 8, 48) and ln.message.startswith("Failed password")
    ln = la.parse_line("2026-11-15T19:08:48.386741+00:00 guardian filterlog 12345 - - 5,,,1,igb3,match,block,in,4")
    assert ln.service == "filterlog" and ln.when == datetime(2026, 11, 15, 19, 8, 48) and ln.message.startswith("5,,,")
    ln = la.parse_line("2026-11-09 14:03:07 caps,debug no suitable CAPsMAN")
    assert (ln.vendor, ln.service, ln.topics) == ("mikrotik", "caps", "caps,debug")
    ln = la.parse_line("nov/09 14:03:07 system,info,account user admin logged in from 10.0.0.2 via ssh", year=2026)
    assert ln.when == datetime(2026, 11, 9, 14, 3, 7) and ln.service == "system"
    ln = la.parse_line(" 12 14:03:07 interface,info ether2 link down", day=datetime(2026, 11, 9))
    assert ln.when == datetime(2026, 11, 9, 14, 3, 7) and ln.message == "ether2 link down"
    assert la.parse_line("just some text").service == ""


def test_filterlog_fields() -> None:
    f = la.parse_filterlog("5,,,1000000103,igb3,match,block,in,4,0x0,,64,1,0,DF,6,tcp,60,203.0.113.9,100.48.62.1,44321,23,0,S")
    assert (f["action"], f["interface"], f["proto"], f["src"], f["dst"], f["dport"]) == (
        "block", "igb3", "tcp", "203.0.113.9", "100.48.62.1", "23")
    assert la.parse_filterlog("short,line") is None


def test_pfsense_findings(tmp_path) -> None:
    (tmp_path / "system.log").write_text(PFSENSE, encoding="utf-8")
    a = la.analyse_paths([tmp_path])
    assert a.total_lines == 16 and a.parsed_lines == 16 and a.hosts == {"guardian": 16}
    blocked = _finding(a, "blocked by login protection")
    assert blocked.severity == la.ERROR and blocked.table == [("222.10.50.25 for 120 s", 1)]
    failed = _finding(a, "Failed logins")
    assert failed.count == 3 and ("admin from 222.10.50.25", 2) in failed.table
    assert ("admin from 222.10.50.77", 1) in failed.table  # the web interface counts too
    assert _finding(a, "Successful logins").table == [("ops from 222.10.50.30 (publickey)", 1)]
    assert _finding(a, "Most-blocked source").table[0] == ("203.0.113.9", 2)
    assert dict(_finding(a, "Most-blocked destination ports").table) == {"23/tcp": 2, "53/udp": 1}
    assert _finding(a, "Passed connections").count == 1
    dhcp = _finding(a, "DHCP refusals")
    assert dhcp.severity == la.ERROR and dhcp.table == [("no free leases", 1)]
    assert _finding(a, "Addresses handed out").table == [("aa:bb:cc:dd:ee:01 → 222.10.50.101", 1)]
    assert _finding(a, "VPN errors").table == [("inactivity timeout", 1)]
    assert _finding(a, "Gateway alarms").table == [("WAN_DHCP (100.64.0.1) loss 100%", 1)]
    assert _finding(a, "Links that went down").table == [("igb2", 1)]
    # The lines behind a finding come back with their file and line number.
    text = la.lines_text(a, blocked)
    assert text.startswith("system.log:4  ") and "Blocking" in text
    assert a.findings[0].severity == la.ERROR and a.findings[-1].area == "Overview"  # worst first


def test_mikrotik_findings_and_device_from_folder(tmp_path) -> None:
    day = tmp_path / "crs109" / "2026-11-09"
    day.mkdir(parents=True)
    (day / "log.log").write_text(MIKROTIK, encoding="utf-8")
    a = la.analyse_paths([tmp_path])
    assert a.hosts == {"crs109": 14}  # MikroTik lines have no host: the device folder names it
    assert _finding(a, "No suitable CAPsMAN").count == 5
    wifi = _finding(a, "will not stay connected")
    assert wifi.table == [("C8:FF:77:A3:65:27 on CRS109-W-3-1 — 1 drops / reassociations, 1 connects", 2)]
    assert _finding(a, "lost their controller").count == 1
    assert _finding(a, "Links that went down").table == [("ether2", 1)]
    assert _finding(a, "Refused management").table == [("winbox/dude from 222.10.50.25", 1)]
    assert _finding(a, "Failed logins").table == [("admin from F4:E9:D4:A4:45:E0", 1)]
    assert _finding(a, "Successful logins").table == [("admin from 222.10.50.25 via ssh", 1)]
    reboot = _finding(a, "Reboots")
    assert reboot.severity == la.ERROR and reboot.table == [("unclean shutdown", 1)]
    assert "problem(s)" in a.summary() and "2026-11-09" in a.summary()


def test_compressed_and_oversize_files(tmp_path, monkeypatch) -> None:
    with gzip.open(tmp_path / "system.log.0.gz", "wt", encoding="utf-8") as fh:
        fh.write(PFSENSE)
    (tmp_path / "big.log").write_text("x" * 100, encoding="utf-8")
    (tmp_path / "picture.png").write_bytes(b"\x89PNG")  # not a log: left alone
    monkeypatch.setattr(la, "MAX_FILE_BYTES", 50)
    a = la.analyse_paths([tmp_path])
    assert a.skipped and "big.log" in a.skipped[0]
    monkeypatch.setattr(la, "MAX_FILE_BYTES", 10_000_000)
    a = la.analyse_paths([tmp_path])
    assert a.total_lines == 17 and len(a.files) == 2  # the .gz was read; the .png was not
    assert la.analyse_paths([tmp_path / "nothing-here"]).summary() == "No log lines found."


def test_page_shows_findings_and_lines(tmp_path, monkeypatch) -> None:
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication

    from pfsense_checker import log_analysis_page as lap

    QApplication.instance() or QApplication([])
    monkeypatch.setattr(lap.ai, "is_ollama_enabled", lambda: False)
    (tmp_path / "system.log").write_text(PFSENSE, encoding="utf-8")
    page = lap.LogAnalysisPage()
    page.analyse([tmp_path], wait=True)
    assert "1 file(s), 16 lines" in page.status.text() and "problem(s)" in page.status.text()
    areas = [page.tree.topLevelItem(i).text(0) for i in range(page.tree.topLevelItemCount())]
    assert areas[0] in ("Logins", "DHCP") and areas[-1] == "Overview"  # problems first, the overview last
    first = page.tree.currentItem().data(0, Qt.ItemDataRole.UserRole)
    assert first.severity == la.ERROR  # opens on the worst finding
    assert page.table.rowCount() == len(first.table) and page.lines.toPlainText().startswith("system.log:")
    assert not page.ask_btn.isEnabled()  # Ollama is off
    blocked = next(f for f in page.analysis.findings if "login protection" in f.title)
    context = page.ai_context(blocked)
    assert "Finding: Addresses blocked" in context and "Blocking" in context


def test_home_has_the_log_analysis_page() -> None:
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from pfsense_checker.home_screen import HomeScreen

    QApplication.instance() or QApplication([])
    home = HomeScreen()
    home._ensure_page("logs.analysis")  # noqa: SLF001
    assert home.log_analysis.acceptDrops() and home.log_analysis.drop.text().startswith("Drop log files")


def test_page_picks_one_device_or_two(tmp_path, monkeypatch) -> None:
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication

    from pfsense_checker import device_logs
    from pfsense_checker import log_analysis_page as lap
    from pfsense_checker.topology_site import Device, Link, SiteTopology
    from tests.test_config_match import CORE, EDGE

    QApplication.instance() or QApplication([])
    monkeypatch.setattr(lap.ai, "is_ollama_enabled", lambda: False)
    logs = tmp_path / "device_logs"
    monkeypatch.setattr(device_logs, "LOG_ROOT", logs)
    monkeypatch.setattr(device_logs, "device_dir", lambda name, root=None: logs / name)
    for name, text in (("core", MIKROTIK), ("edge", MIKROTIK.replace("ether2", "ether5"))):
        day = logs / name / "2026-11-09"
        day.mkdir(parents=True)
        (day / "log.log").write_text(text, encoding="utf-8")
    (tmp_path / "core.rsc").write_text(CORE, encoding="utf-8")
    (tmp_path / "edge.rsc").write_text(EDGE, encoding="utf-8")
    site = SiteTopology(name="t")
    site.devices = [
        Device(name="core", kind="mikrotik", mgmt_ip="222.10.50.5", config_file=str(tmp_path / "core.rsc")),
        Device(name="edge", kind="mikrotik", mgmt_ip="222.10.50.10", config_file=str(tmp_path / "edge.rsc")),
        Device(name="nolog", kind="mikrotik", config_file=str(tmp_path / "core.rsc")),
        Device(name="hidden", kind="mikrotik", ignored=True, config_file=str(tmp_path / "core.rsc")),
        Device(name="nothing", kind="mikrotik"),
    ]
    site.links = [Link(a_device="core", a_port="sfp7", b_device="edge", b_port="sfp1")]
    page = lap.LogAnalysisPage(site=lambda: site)

    # Both lists offer the devices by the name in their config; ignored and empty ones are left out.
    names = [page.device_a.itemText(i) for i in range(page.device_a.count())]
    assert names == ["All devices", "CORE  —  222.10.50.5", "EDGE  —  222.10.50.10", "CORE  (no logs)"]
    assert page.device_b.itemText(0) == lap.NO_SECOND and page.device_b.count() == 4
    assert not page.device_b.isEnabled()  # a second device needs a first

    # One device: only its logs.
    page.device_a.setCurrentIndex(2)
    assert page.device_b.isEnabled()
    page.analyse_devices("edge", wait=True)
    assert page.status.text().startswith("EDGE. 1 file(s), 14 lines")
    assert page.analysis.hosts == {"edge": 14}
    down = next(f for f in page.analysis.findings if "Links that went down" in f.title)
    assert down.table == [("ether5", 1)]
    assert not any(f.area.startswith("Config match") for f in page.analysis.findings)

    # Two devices: both logs, and the config comparison first.
    page.analyse_devices("core", "edge", wait=True)
    text = page.status.text()
    assert text.startswith("CORE ↔ EDGE. Configs: 2 mismatch(es), 1 warning(s). Logs: 2 file(s), 28 lines")
    assert page.analysis.hosts == {"core": 14, "edge": 14}
    assert page.tree.topLevelItem(0).text(0) == "Config match: CORE ↔ EDGE"
    first = page.tree.currentItem().data(0, Qt.ItemDataRole.UserRole)
    assert first.title.startswith("VLANs that do not match on the cable") and first.severity == la.ERROR
    assert page.lines.toPlainText().startswith("CORE sfp7")  # the two ends, where log lines would be
    assert page.lines_label.text() == lap.CONFIG_LABEL
    page.tree.setCurrentItem(page.tree.topLevelItem(page.tree.topLevelItemCount() - 2).child(0))
    assert page.lines_label.text() == lap.LINES_LABEL  # a log finding shows log lines again
    page.tree.setCurrentItem(page.tree.topLevelItem(0).child(0))
    assert "Finding: VLANs that do not match" in page.ai_context(first) and "EDGE sfp1" in page.ai_context(first)

    # A device without downloaded logs still has its config compared; alone it has nothing to read.
    page.analyse_devices("edge", "nolog", wait=True)
    assert "No downloaded logs from CORE." in page.status.text() and "Logs: 1 file(s), 14 lines" in page.status.text()
    page.analyse_devices("nolog", wait=True)
    assert page.status.text() == "No logs have been downloaded from CORE yet (Logs → Device Logs)."
    # The same device twice is one device.
    page.analyse_devices("edge", "edge", wait=True)
    assert page.status.text().startswith("EDGE. 1 file(s)")

    # The Analyse button uses what the two lists show; All devices reads every download.
    page.device_a.setCurrentIndex(1)
    page.device_b.setCurrentIndex(2)
    monkeypatch.setattr(page, "analyse_devices", lambda a="", b="", **_k: setattr(page, "_asked", (a, b)))
    page.analyse_selected()
    assert page._asked == ("core", "edge")  # noqa: SLF001
    page.device_a.setCurrentIndex(0)
    assert page.device_b.currentIndex() == 0 and not page.device_b.isEnabled()
