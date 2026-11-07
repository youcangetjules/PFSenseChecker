"""Network-device discovery for the Login to Routers subnets panel."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pfsense_checker import net_discovery as nd  # noqa: E402
from pfsense_checker.lan_scan import LanHost  # noqa: E402

GW = {"222.10.50.1"}


def test_mikrotik_from_banner_ports_and_mac() -> None:
    d = nd.classify(
        "222.10.50.20",
        mac="18:fd:74:ca:86:ce",
        open_ports=(22, 23, 80, 8291, 8728),
        ssh_banner="SSH-2.0-ROSSSH",
        http_title="RouterOS",
        gateways=GW,
    )
    assert d is not None
    assert (d.role, d.vendor) == ("router", "MikroTik")
    assert any("ROSSSH" in e for e in d.evidence)
    assert "Telnet (23) open" in d.evidence


def test_pfsense_gateway_is_a_firewall() -> None:
    d = nd.classify(
        "222.10.50.1",
        mac="ec:0d:9a:d9:85:1b",
        open_ports=(22, 80),
        ssh_banner="SSH-2.0-OpenSSH_10.3",
        http_title="Netgate pfSense Plus - Login",
        gateways=GW,
    )
    assert d is not None
    assert (d.role, d.vendor) == ("firewall", "pfSense")
    assert "default gateway of this PC" in d.evidence


def test_unknown_gateway_is_still_seen() -> None:
    d = nd.classify("10.0.0.1", open_ports=(80,), gateways={"10.0.0.1"})
    assert d is not None and d.role == "gateway"


def test_switch_from_web_title() -> None:
    d = nd.classify("10.0.0.9", open_ports=(80,), http_title="MikroTik SwOS")
    assert d is not None and d.role == "switch"


def test_ordinary_host_is_not_seen() -> None:
    assert (
        nd.classify(
            "222.10.50.25",
            mac="aa:bb:cc:00:11:22",
            open_ports=(445,),
            ssh_banner="SSH-2.0-OpenSSH_for_Windows_9.5",
            gateways=GW,
        )
        is None
    )


def test_vendor_table_is_local() -> None:
    assert nd.vendor_from_mac("18-FD-74-CA-86-CE") == "MikroTik"
    assert nd.vendor_from_mac("2c:c8:1b:ad:26:01") == "MikroTik"
    assert nd.vendor_from_mac("aa:bb:cc:dd:ee:ff") == ""


def test_parse_default_gateways_windows_and_linux() -> None:
    win = (
        "          0.0.0.0          0.0.0.0      222.10.50.1     222.10.50.25    281\n"
        "      222.10.50.0    255.255.255.0         On-link      222.10.50.25    281\n"
    )
    assert nd.parse_default_gateways(win) == {"222.10.50.1"}
    assert nd.parse_default_gateways("default via 192.168.1.1 dev eth0\n") == {
        "192.168.1.1"
    }


def test_sweep_refuses_large_subnets() -> None:
    with pytest.raises(nd.SweepTooLarge):
        nd.discover("172.28.112.0/20", scan=lambda *a, **k: [], gateways=set())
    with pytest.raises(nd.SweepTooLarge):
        nd.discover("169.254.0.0/16", scan=lambda *a, **k: [], gateways=set())
    assert nd.sweep_size("10.0.0.0/22") == 1022


def test_discover_probes_only_management_ports() -> None:
    probed: list[tuple[str, int]] = []
    hosts = [
        LanHost(ip="222.10.50.20", mac="18:fd:74:ca:86:ce"),
        LanHost(ip="222.10.50.25", mac="aa:bb:cc:00:11:22"),
        LanHost(ip="10.9.9.9"),  # outside the subnet: ignored
    ]
    open_map = {"222.10.50.20": {22, 80, 8291}, "222.10.50.25": set()}

    def probe(ip, port, timeout):  # noqa: ANN001
        probed.append((ip, port))
        return port in open_map.get(ip, set())

    seen = nd.discover(
        "222.10.50.0/24",
        scan=lambda *a, **k: hosts,
        probe=probe,
        ssh=lambda ip: (ip == "222.10.50.20", "SSH-2.0-ROSSSH" if ip == "222.10.50.20" else ""),
        title=lambda ip, ports: "RouterOS",
        gateways=GW,
    )
    assert [d.ip for d in seen] == ["222.10.50.20"]
    assert {p for _ip, p in probed} <= set(nd.NETWORK_PORTS) - {22}  # 22: one ssh probe only
    assert all(ip != "10.9.9.9" for ip, _p in probed)


def test_http_title_follows_one_same_host_redirect(monkeypatch) -> None:
    calls: list[tuple[str, int, bool]] = []

    def fake_get(ip, port, tls, timeout):  # noqa: ANN001
        calls.append((ip, port, tls))
        if port == 80:
            return "HTTP/1.1 301 Moved", f"https://{ip}:8445/", b"<title>301</title>"
        return "HTTP/1.1 200 OK", "", b"<title>Netgate pfSense Plus - Login</title>"

    monkeypatch.setattr(nd, "_http_get", fake_get)
    assert nd.read_http_title("222.10.50.1", (80,)) == "Netgate pfSense Plus - Login"
    assert calls == [("222.10.50.1", 80, False), ("222.10.50.1", 8445, True)]


def test_http_title_ignores_redirect_to_another_host(monkeypatch) -> None:
    calls: list[str] = []

    def fake_get(ip, port, tls, timeout):  # noqa: ANN001
        calls.append(ip)
        return "HTTP/1.1 302 Found", "https://evil.example/", b"<title>moved</title>"

    monkeypatch.setattr(nd, "_http_get", fake_get)
    assert nd.read_http_title("10.0.0.1", (80,)) == "moved"
    assert calls == ["10.0.0.1"]


def test_panel_text() -> None:
    dev = nd.SeenDevice(ip="222.10.50.20", role="router", vendor="MikroTik")
    assert nd.seen_summary("done", [dev, dev])[0] == "2 seen"
    assert nd.seen_summary("done", [])[0] == "none seen"
    assert nd.seen_summary("scanning", [])[0] == "scanning…"
    assert nd.seen_summary("too_large", [], "too big")[0] == "too large"
    assert nd.connected_summary(["a"]) == ("1 connected", nd.CONNECTED_COLOR)
    assert nd.connected_summary([])[0] == "none connected"


def test_subnets_panel_shows_seen_and_connected_columns(monkeypatch) -> None:
    from PySide6.QtWidgets import QApplication, QLabel

    from pfsense_checker import session_screen
    from pfsense_checker.topology_site import SiteTopology

    app = QApplication.instance() or QApplication([])

    def fake_discover(cidr, **kwargs):  # noqa: ANN001
        if cidr == "172.28.112.0/20":
            raise nd.SweepTooLarge("too big")
        return [
            nd.SeenDevice(ip=f"222.10.50.{n}", role="router", vendor="MikroTik")
            for n in (5, 10, 20, 30)
        ] + [nd.SeenDevice(ip="222.10.50.1", role="firewall", vendor="pfSense")]

    monkeypatch.setattr(nd, "discover", fake_discover)
    monkeypatch.setattr(nd, "default_gateways", lambda: set())

    screen = session_screen.SessionScreen()
    screen.set_site(SiteTopology(subnets=["222.10.50.0/24", "172.28.112.0/20"]))
    worker = screen._discovery_worker
    assert worker is not None
    worker.wait(5000)
    for _ in range(20):
        app.processEvents()

    def cell(row: int, col: int) -> str:
        w = screen.subnet_table.cellWidget(row, col)
        assert isinstance(w, QLabel)
        return w.text()

    assert screen.subnet_table.columnCount() == 4
    assert cell(0, 1) == "5 seen"
    assert cell(0, 2) == "none connected"
    assert cell(1, 1) == "too large"
    assert screen.btn_rescan.isEnabled()


def test_kind_for_maps_vendors_to_login_kinds() -> None:
    assert nd.kind_for(nd.SeenDevice(ip="1", role="firewall", vendor="pfSense")) == "pfsense"
    assert nd.kind_for(nd.SeenDevice(ip="1", role="router", vendor="MikroTik")) == "mikrotik"
    assert nd.kind_for(nd.SeenDevice(ip="1", role="switch")) == "switch"
    assert nd.kind_for(nd.SeenDevice(ip="1", role="gateway")) == "router"


def test_seen_devices_fill_the_subnet_tab(monkeypatch) -> None:
    from PySide6.QtWidgets import QApplication

    from pfsense_checker import session_screen
    from pfsense_checker.topology_site import Device, SiteTopology

    app = QApplication.instance() or QApplication([])
    seen = [nd.SeenDevice(ip="222.10.50.1", role="firewall", vendor="pfSense",
                          mac="ec:0d:9a:d9:85:1b", evidence=("web GUI: pfSense",))]
    seen += [
        nd.SeenDevice(ip=f"222.10.50.{n}", role="router", vendor="MikroTik",
                      mac=f"18:fd:74:00:00:{n:02x}")
        for n in (5, 10, 20, 30)
    ]
    monkeypatch.setattr(nd, "discover", lambda cidr, **k: seen if cidr.startswith("222.") else [])
    monkeypatch.setattr(nd, "default_gateways", lambda: set())
    monkeypatch.setattr(
        session_screen.SessionScreen, "_hydrate_device_from_saved_credentials",
        lambda self, dev, host: None,
    )

    site = SiteTopology(subnets=["172.28.112.0/20", "222.10.50.0/24"])
    for n, kind in ((5, "juniper"), (10, "router")):  # one operator choice, one generic
        dev = Device(name=f"host-222-10-50-{n}", kind=kind, mgmt_ip=f"222.10.50.{n}")
        dev.ensure_ssh().host = f"222.10.50.{n}"
        site.add_or_update_device(dev)

    screen = session_screen.SessionScreen()
    screen.set_site(site)
    for _ in range(50):
        w = screen._discovery_worker
        if w is not None:
            w.wait(5000)
        app.processEvents()
        if screen._discovery_worker is None and not screen._discovery_queue:
            break

    hosts = sorted(d.mgmt_ip for d in screen._site.devices)
    assert hosts == [f"222.10.50.{n}" for n in (1, 10, 20, 30, 5)]  # no duplicates
    kinds = {d.mgmt_ip: d.kind for d in screen._site.devices}
    assert kinds["222.10.50.5"] == "juniper"  # operator's choice kept
    assert kinds["222.10.50.10"] == "mikrotik"  # generic upgraded
    assert kinds["222.10.50.1"] == "pfsense"

    # The panel opens on the populated tab, not the empty /20.
    tabs = screen.device_subnet_tabs
    assert tabs.tabText(tabs.currentIndex()) == "222.10.50.0/24 (5)"
    visible = [r for r in range(screen.table.rowCount()) if not screen.table.isRowHidden(r)]
    assert len(visible) == 5

    # Selecting a subnet row shows its tab.
    screen.subnet_table.selectRow(0)
    app.processEvents()
    assert tabs.tabText(tabs.currentIndex()).startswith("172.28.112.0/20")
    screen.subnet_table.selectRow(1)
    app.processEvents()
    assert tabs.tabText(tabs.currentIndex()) == "222.10.50.0/24 (5)"


def test_ssh_probe_identifies_itself_before_closing() -> None:
    """sshd must not log 'did not receive identification' (sshguard bait)."""
    import socket
    import threading

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    got: list[bytes] = []

    def serve() -> None:
        conn, _ = server.accept()
        conn.sendall(b"SSH-2.0-OpenSSH_10.3\r\n")
        conn.settimeout(3)
        try:
            got.append(conn.recv(100))
        finally:
            conn.close()

    th = threading.Thread(target=serve)
    th.start()
    is_open, line = nd.probe_ssh("127.0.0.1", port, timeout=3)
    th.join(5)
    server.close()
    assert (is_open, line) == (True, "SSH-2.0-OpenSSH_10.3")
    assert got and got[0].startswith(b"SSH-2.0-NetCheck")


def test_identification_is_cached_until_refresh() -> None:
    calls = {"ssh": 0, "probe": 0}

    def ssh(ip):  # noqa: ANN001
        calls["ssh"] += 1
        return True, "SSH-2.0-ROSSSH"

    def probe(ip, port, timeout):  # noqa: ANN001
        calls["probe"] += 1
        return False

    kw = dict(
        scan=lambda *a, **k: [LanHost(ip="10.1.1.1")],
        probe=probe,
        ssh=ssh,
        title=lambda ip, ports: "",
        gateways=set(),
    )
    assert [d.vendor for d in nd.discover("10.1.1.0/24", **kw)] == ["MikroTik"]
    nd.discover("10.1.1.0/24", **kw)  # automatic sweep: ping only
    assert calls["ssh"] == 1
    nd.discover("10.1.1.0/24", refresh=True, **kw)  # Scan this subnet
    assert calls["ssh"] == 2
