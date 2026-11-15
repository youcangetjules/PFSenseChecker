"""Security Holes: open services, firewall gaps, known vulnerabilities, old software, weak logins."""

from __future__ import annotations

import json
from types import SimpleNamespace as NS

from pfsense_checker import security_holes as sh
from pfsense_checker import vuln_db
from pfsense_checker.models import Finding, Severity
from pfsense_checker.net_discovery import SeenDevice
from pfsense_checker.topology_site import Device, SiteTopology

# Telnet and plain HTTP on, SSH open to any address, a firewall that drops nothing,
# SNMP with the default community, a SOCKS proxy, UPnP, and an old RouterOS 7.
EDGE = """\
# 2026-11-07 by RouterOS 7.5
# model = CRS109-8G-1S-2HnD
/interface bridge
add name=BR
/ip address
add address=10.0.0.2/24 interface=BR network=10.0.0.0
/ip firewall filter
add action=drop chain=input connection-state=invalid
add action=accept chain=input
add action=drop chain=input comment="default drop" disabled=yes
/ip service
set telnet address="" disabled=no port=23
set ftp address="" disabled=yes port=21
set www address="" disabled=no port=80
set ssh address="" disabled=no port=22
set winbox address=10.0.0.0/24 disabled=no port=8291
set api address="" disabled=yes port=8728
set api-ssl address="" disabled=yes port=8729
/ip ssh
set strong-crypto=no
/ip socks
set enabled=yes
/ip upnp
set enabled=yes
/ip dns
set allow-remote-requests=yes
/snmp
set enabled=yes
/snmp community
set [ find default=yes ] name=public
/tool mac-server
set allowed-interface-list=all
/tool mac-server mac-winbox
set allowed-interface-list=none
/system identity
set name=EDGE
"""

# Encrypted services only, limited to the management network, behind a final drop rule.
SAFE = """\
# 2026-11-07 by RouterOS 7.22.3
# model = CRS328-4C-20S-4S+
/interface bridge
add name=BR
/ip address
add address=10.0.0.1/24 interface=BR network=10.0.0.0
/ip firewall filter
add action=accept chain=input src-address=10.0.0.0/24
add action=drop chain=input
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set ssh address=10.0.0.0/24 disabled=no port=22
set winbox address=10.0.0.0/24 disabled=no port=8291
set api disabled=yes
set api-ssl disabled=yes
/ip ssh
set strong-crypto=yes
/snmp
set enabled=no
/tool mac-server
set allowed-interface-list=none
/tool mac-server mac-winbox
set allowed-interface-list=none
/system identity
set name=SAFE
"""

OLD = """\
# 2019-01-07 by RouterOS 6.40.5
# model = RB750Gr3
/interface bridge
add name=BR
/system identity
set name=OLD
"""


def _site(tmp_path, **configs: str) -> SiteTopology:
    site = SiteTopology(name="t")
    for name, text in configs.items():
        path = tmp_path / f"{name}.rsc"
        path.write_text(text, encoding="utf-8")
        site.devices.append(Device(name=name, kind="mikrotik", mgmt_ip=f"10.0.0.{len(site.devices) + 1}",
                                   config_file=str(path)))
    return site


def _titles(report: sh.Report, device: str = "") -> list[str]:
    return [h.title for h in report.holes if not device or h.device == device]


def _hole(report: sh.Report, part: str, device: str = "") -> sh.Hole:
    return next(h for h in report.holes if part in h.title and (not device or h.device == device))


# --------------------------------------------------------------------------- #
# The vulnerability list


def test_versions_and_ranges() -> None:
    assert vuln_db.parse_version("7.22.3 (stable)") == (7, 22, 3, 0)
    assert vuln_db.parse_version("OpenSSH_9.6p1") == (9, 6, 0, 0) and vuln_db.parse_version("none") == ()
    assert vuln_db.parse_version("7.9") < vuln_db.parse_version("7.9.1") < vuln_db.parse_version("7.10")
    db = vuln_db.load([vuln_db.BUILTIN_DIR])
    assert not db.errors and {"routeros", "openssh", "pfsense-ce", "pfsense-plus"} <= set(db.entries)
    ids = lambda product, version: [v.id for v in db.matches(product, version)]  # noqa: E731
    assert ids("routeros", "7.22.3") == []
    assert ids("routeros", "7.9") == ["CVE-2023-32154", "CVE-2023-41570"]  # high first, then medium
    assert ids("routeros", "7.9.1") == ["CVE-2023-41570"] and ids("routeros", "7.12") == []
    assert "CVE-2018-14847" in ids("routeros", "6.40.5") and "CVE-2018-14847" not in ids("routeros", "6.42.1")
    assert "CVE-2023-41570" not in ids("routeros", "6.40.5")  # a 7.x fault does not match 6.x
    assert ids("openssh", "9.3") == ["CVE-2024-6387", "CVE-2023-48795"] and ids("openssh", "9.8") == []
    assert ids("openssh", "8.4") == ["CVE-2023-48795"]  # regreSSHion starts at 8.5
    assert ids("pfsense-ce", "2.7.0") and not ids("pfsense-ce", "2.7.2")
    assert ids("pfsense-plus", "23.05.1") and not ids("pfsense-plus", "24.03")
    assert ids("routeros", "") == [] and ids("no-such-product", "1.0") == []


def test_your_own_entries_add_and_replace(tmp_path) -> None:
    builtin, user = tmp_path / "b", tmp_path / "u"
    builtin.mkdir()
    user.mkdir()
    entry = {"id": "X-1", "title": "old words", "severity": "low", "affected": [{"lt": "2.0"}], "fixed": "2.0"}
    (builtin / "acme.json").write_text(json.dumps({"product": "acme", "name": "Acme OS", "entries": [entry]}),
                                       encoding="utf-8")
    (user / "mine.json").write_text(json.dumps({"product": "acme", "name": "Acme OS", "entries": [
        {**entry, "title": "new words", "severity": "high"},
        {"id": "X-2", "title": "another", "severity": "medium", "affected": [{"ge": "1.5", "lt": "3.0"}]}]}),
        encoding="utf-8")
    (user / "broken.json").write_text("{not json", encoding="utf-8")
    (user / "norange.json").write_text(json.dumps({"product": "acme", "entries": [
        {"id": "X-3", "title": "t", "severity": "high", "affected": [{}]}]}), encoding="utf-8")
    db = vuln_db.load([builtin, user])
    assert [(v.id, v.title, v.severity) for v in db.matches("acme", "1.9")] == [
        ("X-1", "new words", "high"), ("X-2", "another", "medium")]
    assert len(db.errors) == 2 and "X-3" in " ".join(db.errors)  # a range with no bound is refused


# --------------------------------------------------------------------------- #
# MikroTik configs


def test_routeros_services_firewall_and_known_vulnerabilities(tmp_path) -> None:
    site = _site(tmp_path, edge=EDGE, safe=SAFE)
    report = sh.collect(site, db=vuln_db.load([vuln_db.BUILTIN_DIR]))
    assert report.checked == ["EDGE", "SAFE"]
    assert [h for h in report.holes if h.device == "SAFE"] == []  # nothing to say about the tidy one

    clear = _hole(report, "Unencrypted management services are on")
    assert clear.severity == sh.HIGH and clear.title.endswith("telnet, www")  # ftp and api are off
    assert clear.fix.startswith("/ip service disable telnet,www") and "port 23" in clear.detail
    anywhere = _hole(report, "accept connections from any address")
    assert anywhere.title.endswith(": ssh") and anywhere.severity == sh.MEDIUM  # winbox is limited already
    wall = _hole(report, "Nothing stops other networks reaching the device itself")
    assert wall.area == sh.FIREWALL and "10.0.0.0" in wall.detail and "default drop" in wall.detail
    assert _hole(report, "MAC Telnet is allowed on every interface").severity == sh.LOW
    assert _hole(report, "SSH accepts older, weaker encryption").fix == "/ip ssh set strong-crypto=yes"
    assert _hole(report, "default community name").severity == sh.MEDIUM
    assert _hole(report, "SOCKS proxy is switched on").severity == sh.HIGH
    assert _hole(report, "UPnP is switched on").severity == sh.MEDIUM
    assert _hole(report, "Answers DNS requests from any network").severity == sh.LOW

    known = [h for h in report.holes if h.area == sh.KNOWN]
    assert [h.title.split(":")[0] for h in known] == ["CVE-2023-32154", "CVE-2022-45315", "CVE-2023-41570"]
    assert "runs MikroTik RouterOS 7.5; it was fixed in 7.9.1" in known[0].detail
    assert known[0].fix == "Update to 7.9.1 or later."
    assert [(r.device, r.version, r.known) for r in report.versions] == [("EDGE", "7.5", 3), ("SAFE", "7.22.3", 0)]
    mixed = _hole(report, "versions differ between devices")
    assert mixed.device == sh.SEVERAL and "7.5 on EDGE" in mixed.detail and "7.22.3 on SAFE" in mixed.detail
    # Worst first within each area, areas in their fixed order.
    assert report.holes[0].area == sh.KNOWN and report.holes[0].severity == sh.HIGH
    assert list(report.by_area()) == [a for a in sh.AREAS if a in {h.area for h in report.holes}]
    assert "weakness(es): " in report.summary() and "[High] EDGE: Unencrypted" in report.text()


def test_a_fault_is_skipped_when_its_service_is_off(tmp_path) -> None:
    off = EDGE.replace("set www address=\"\" disabled=no", "set www address=\"\" disabled=yes") \
              .replace("/snmp\nset enabled=yes", "/snmp\nset enabled=no")
    report = sh.collect(_site(tmp_path, edge=off), db=vuln_db.load([vuln_db.BUILTIN_DIR]))
    assert [h.title.split(":")[0] for h in report.holes if h.area == sh.KNOWN] == ["CVE-2023-32154"]
    assert not any("community" in t for t in _titles(report))  # SNMP is off: its community does not matter


def test_old_release_line_current_release_and_unknown_services(tmp_path) -> None:
    site = _site(tmp_path, old=OLD, safe=SAFE)
    report = sh.collect(site, db=vuln_db.load([vuln_db.BUILTIN_DIR]), current={"routeros": "7.22.3"})
    known = [h.title.split(":")[0] for h in report.holes if h.device == "OLD" and h.area == sh.KNOWN]
    # No /ip service in that export: a fault that needs Winbox cannot be ruled out, so it is listed.
    assert known == ["CVE-2018-14847", "CVE-2023-30799", "CVE-2023-32154", "CVE-2019-3924"]
    assert _hole(report, "is older than 7.22.3", "OLD").severity == sh.MEDIUM
    assert _hole(report, "Runs RouterOS 6", "OLD").severity == sh.LOW
    assert not any("older than" in t for t in _titles(report, "SAFE"))  # it is on the current release
    assert not any("Nothing stops" in t for t in _titles(report, "OLD"))  # no firewall section: nothing claimed
    # No release entered as current: nothing is called old on that ground.
    assert not any("older than" in h.title for h in sh.collect(site, db=vuln_db.load([vuln_db.BUILTIN_DIR])).holes)


# --------------------------------------------------------------------------- #
# pfSense findings, hosts seen on the network, saved logins


def _pfsense(findings: list[Finding], version: str = "24.6") -> NS:
    return NS(source_type="pfsense", hostname="fw", version=version, findings=findings, summary={})


def test_pfsense_findings_become_holes(tmp_path) -> None:
    w = Severity.WARNING
    findings = [
        Finding(w, "Management", "WebGUI has no interface restriction. An empty list binds the GUI on every interface.",
                remediation="Bind it to the management interface."),
        Finding(w, "VPN", "EX-VPN is bound to 'GW_Group', which is not an interface in this config."),
        Finding(w, "VPN", "OpenVPN server 'office' uses the weak cipher BF-CBC."),
        Finding(w, "Segmentation", "LAN can reach every other inside subnet on any protocol (filter rule #9)."),
        Finding(w, "Segmentation", "Inside subnets are flat: subnets reach each other freely (score 14/100)."),
        Finding(w, "Interfaces", "OPT5 is enabled but has no address"),
        Finding(Severity.ERROR, "Firewall", "A WAN rule passes any source to the firewall itself."),
        Finding(Severity.INFO, "System", "Hostname is fw"),
    ]
    site = SiteTopology(name="t")
    site.devices.append(Device(name="fw", kind="pfsense", mgmt_ip="10.0.0.254"))
    report = sh.collect(site, load=lambda _dev: _pfsense(findings), db=vuln_db.load([vuln_db.BUILTIN_DIR]))
    assert sorted(_titles(report)) == [
        "A WAN rule passes any source to the firewall itself",
        "Inside subnets are flat: subnets reach each other freely (score 14/100)",
        "OpenVPN server 'office' uses the weak cipher BF-CBC",
        "WebGUI has no interface restriction",
    ]  # the tunnel that cannot start and the interface note are faults, not holes
    gui = _hole(report, "WebGUI")
    assert (gui.area, gui.severity, gui.fix) == (sh.PORTS, sh.MEDIUM, "Bind it to the management interface.")
    assert gui.detail == "An empty list binds the GUI on every interface."  # not the title said twice
    assert _hole(report, "A WAN rule").severity == sh.HIGH
    assert "• LAN can reach every other inside subnet" in _hole(report, "Inside subnets are flat").detail
    # The config only holds its format version: no guess is made about known vulnerabilities.
    assert report.versions[0].product == "" and "format version (24.6)" in report.versions[0].note
    assert any("software version not known" in n for n in report.notes)
    assert not [h for h in report.holes if h.area == sh.KNOWN]

    for software, product, hit in (("2.7.0-RELEASE", "pfsense-ce", True), ("2.7.2-RELEASE", "pfsense-ce", False),
                                   ("23.05.1-RELEASE", "pfsense-plus", True), ("24.03-RELEASE", "pfsense-plus", False)):
        site.devices[0].software_version = software
        again = sh.collect(site, load=lambda _dev: _pfsense([]), db=vuln_db.load([vuln_db.BUILTIN_DIR]))
        assert again.versions[0].product == product
        assert bool([h for h in again.holes if h.area == sh.KNOWN]) is hit, software


def test_hosts_seen_on_the_network(tmp_path) -> None:
    site = _site(tmp_path, safe=SAFE)  # 10.0.0.1, with a config
    seen = [
        SeenDevice(ip="10.0.0.1", role="switch", vendor="MikroTik", open_ports=(22, 23, 80, 8291),
                   ssh_banner="SSH-2.0-OpenSSH_9.3"),
        SeenDevice(ip="10.0.0.77", role="router", vendor="Acme", open_ports=(23, 80, 8291, 8728)),
        SeenDevice(ip="10.0.0.78", role="server", open_ports=(22, 80, 443), ssh_banner="SSH-2.0-OpenSSH_9.9p1 Debian"),
    ]
    report = sh.collect(site, seen=seen, db=vuln_db.load([vuln_db.BUILTIN_DIR]))
    acme = "10.0.0.77 (Acme router)"
    assert sorted(_titles(report, acme)) == [
        "Its web interface answers on plain HTTP only (port 80)",
        "Telnet is open (port 23)",
        "The MikroTik API without encryption is open (port 8728)",
        "Winbox is open (port 8291)",
    ]
    assert _hole(report, "Telnet is open", acme).severity == sh.HIGH
    assert all(h.source == sh.FROM_NETWORK for h in report.holes if h.device == acme)
    # A device with a config is judged by its config, not by what answered; its SSH greeting still counts.
    assert [t.split(":")[0] for t in _titles(report, "SAFE")] == ["CVE-2024-6387", "CVE-2023-48795"]
    assert "check the vendor's advisory" in _hole(report, "CVE-2024-6387").detail
    assert _titles(report, "10.0.0.78 (server)") == []  # HTTPS as well as HTTP, and a fixed OpenSSH
    assert not any("No network sweep" in n for n in report.notes)
    assert any("No network sweep" in n for n in sh.collect(site, db=vuln_db.load([vuln_db.BUILTIN_DIR])).notes)


def test_saved_logins_never_show_a_password_or_a_user_name(tmp_path) -> None:
    site = _site(tmp_path, a=SAFE.replace("name=SAFE", "name=A"), b=SAFE.replace("name=SAFE", "name=B"),
                 c=SAFE.replace("name=SAFE", "name=C"), d=SAFE.replace("name=SAFE", "name=D"))
    passwords = {"a": "Admin", "b": "S3cret-shared!", "c": "S3cret-shared!", "d": None}
    users = {"a": "admin", "b": "a-very-particular-login-name", "c": "root", "d": ""}
    db = vuln_db.load([vuln_db.BUILTIN_DIR])
    report = sh.collect(site, db=db, password_of=lambda dev: passwords[dev.name],
                        username_of=lambda dev: users[dev.name])
    default = _hole(report, "well-known default password")
    assert (default.device, default.severity, default.source) == ("A", sh.HIGH, sh.FROM_LOGINS)
    shared = _hole(report, "The same password is saved for 2 devices")
    assert shared.severity == sh.MEDIUM and shared.detail.startswith("B, C.")
    admins = _hole(report, "built-in admin account")
    assert admins.severity == sh.LOW and admins.detail.startswith("A, C.") and admins.title.startswith("2 device")
    everything = report.text() + " ".join(report.notes)
    assert "S3cret" not in everything and "a-very-particular-login-name" not in everything

    # Not asked for: nothing is said about passwords, and the notes say they were not compared.
    quiet = sh.collect(site, db=db, password_of=None, username_of=lambda dev: users[dev.name])
    assert not [h for h in quiet.holes if "password" in h.title] and any("not compared" in n for n in quiet.notes)


# --------------------------------------------------------------------------- #
# The page


def test_page_lists_filters_and_copies(tmp_path, monkeypatch) -> None:
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QGuiApplication
    from PySide6.QtWidgets import QApplication

    from pfsense_checker import security_holes_page as shp

    QApplication.instance() or QApplication([])
    site = _site(tmp_path, edge=EDGE, safe=SAFE)
    asked: list[str] = []

    def password_of(dev):  # noqa: ANN001, ANN202
        asked.append(dev.name)
        return "admin"

    seen = [SeenDevice(ip="10.0.0.77", role="router", vendor="Acme", open_ports=(23,))]
    page = shp.SecurityHolesPage(site=lambda: site, seen=lambda: seen, password_of=password_of,
                                 username_of=lambda _dev: "netops")
    page.check(wait=True)
    assert asked == []  # the box is not ticked: no saved password was read
    assert "2 device config(s) checked" in page.status.text() and "high" in page.status.text()
    areas = [page.tree.topLevelItem(i).text(0) for i in range(page.tree.topLevelItemCount())]
    assert areas[0].startswith("Known vulnerabilities (3)") and areas[1].startswith("Open ports and services")
    first = page.tree.currentItem().data(0, Qt.ItemDataRole.UserRole)
    assert first.title.startswith("CVE-2023-32154") and "CVE-2023-32154" in page.detail_title.text()
    assert page.fix.toPlainText() == "Update to 7.9.1 or later." and page.btn_copy_fix.isEnabled()
    assert "does not apply it" in page.source.text()

    # Filters: severity, device, words.
    total = len(page.shown_holes())
    page.f_severity.setCurrentIndex(page.f_severity.findData(sh.HIGH))
    assert 0 < len(page.shown_holes()) < total and all(h.severity == sh.HIGH for h in page.shown_holes())
    page.f_severity.setCurrentIndex(0)
    page.f_device.setCurrentIndex(page.f_device.findData("10.0.0.77 (Acme router)"))
    assert [h.title for h in page.shown_holes()] == ["Telnet is open (port 23)"]
    page.f_device.setCurrentIndex(0)
    page.f_text.setText("telnet")
    assert {h.device for h in page.shown_holes()} == {"EDGE", "10.0.0.77 (Acme router)"}
    page.copy_list()
    copied = QGuiApplication.clipboard().text()
    assert "[High] EDGE: Unencrypted management services" in copied and "UPnP" not in copied
    page.f_text.setText("nothing-matches-this")
    assert page.tree.topLevelItemCount() == 0 and page.detail_title.text() == "Select a weakness."
    page.f_text.clear()

    # Software versions, and the release typed in as current.
    assert [page.versions.item(r, 2).text() for r in range(page.versions.rowCount())] == ["7.5", "7.22.3"]
    assert page.versions.item(0, 3).text() == "3 that affect this version"
    assert page.versions.item(1, 3).text() == "none in NetCheck's list"
    page.current_edits["routeros"].setText("7.22.3")
    page.current_edits["routeros"].editingFinished.emit()
    assert sh.load_current() == {"routeros": "7.22.3"}  # saved (conftest points this at a temporary file)
    page.check(wait=True)
    assert any(h.title == "MikroTik RouterOS 7.5 is older than 7.22.3" for h in page.report.holes)
    assert shp.SecurityHolesPage(site=lambda: site).current_edits["routeros"].text() == "7.22.3"

    # Saved passwords are only read when the box is ticked.
    page.compare_passwords.setChecked(True)
    page.check(wait=True)
    assert asked == ["edge", "safe"]
    assert any("default password" in h.title for h in page.report.holes)
    assert "Not checked (" in page.tabs.tabText(1) and "not a live feed" in page.notes.toPlainText()


def test_home_opens_the_page_and_gives_it_the_sweep() -> None:
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from pfsense_checker.home_screen import HomeScreen
    from pfsense_checker.security_holes_page import SecurityHolesPage
    from pfsense_checker.session_screen import SessionScreen

    QApplication.instance() or QApplication([])
    home = HomeScreen()
    home._ensure_page("security_holes")  # noqa: SLF001
    assert isinstance(home.security_holes, SecurityHolesPage)
    assert home.security_holes._seen() == []  # noqa: SLF001 - Login to Routers not opened yet: nothing seen
    screen = SessionScreen()
    host = SeenDevice(ip="10.0.0.9", role="switch")
    screen._seen["10.0.0.0/24"] = [host]  # noqa: SLF001
    assert screen.seen_devices() == [host]
