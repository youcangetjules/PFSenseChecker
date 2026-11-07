"""DNS Leakage: wire format, check verdicts, VLAN profiles and the package."""

from __future__ import annotations

import socket
import struct
import subprocess
import sys
import zipfile

import pytest

from pfsense_checker import dns_leak as d
from pfsense_checker import dns_leak_builder as b
from pfsense_checker.checker import check_file


def _response(txid: int, name: str, answers: list[tuple[int, bytes]], rcode: int = 0) -> bytes:
    _tx, q = d.build_query(name, d.T_A, txid)
    head = struct.pack(">HHHHHH", txid, 0x8180 | rcode, 1, len(answers), 0, 0)
    body = q[12:]
    for rtype, rdata in answers:
        body += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 60, len(rdata)) + rdata
    return head + body


def test_wire_roundtrip() -> None:
    raw = _response(0x1234, "example.com", [(d.T_A, socket.inet_aton("93.184.216.34")),
                                            (d.T_TXT, b"\x05hello\x05world")])
    ans = d.parse_response(raw, 0x1234)
    assert ans.rcode == 0
    assert ans.values(d.T_A) == ["93.184.216.34"]
    assert ans.values(d.T_TXT) == ["helloworld"]
    with pytest.raises(ValueError):
        d.parse_response(raw, 0x9999)
    nx = d.parse_response(_response(7, "nope.example", [], rcode=3), 7)
    assert nx.rcode_name == "NXDOMAIN"


def test_pick_profile_by_address() -> None:
    profiles = [{"label": "A", "subnet": "10.0.1.0/24"}, {"label": "B", "subnet": "10.0.2.0/24"}]
    assert d.pick_profile(profiles, ["172.16.0.5", "10.0.2.9"])["label"] == "B"
    assert d.pick_profile(profiles, ["192.168.1.2"]) == {}


def _fake_network(monkeypatch, *, direct: str) -> None:
    """direct = 'blocked' | 'redirected' | 'open' for plain DNS to public resolvers."""
    def udp(server, name, qtype=d.T_A, timeout=2.0):  # noqa: ANN001, ANN202
        local = server.startswith("10.")
        if not local and direct == "blocked":
            raise TimeoutError()
        if name == d.WHOAMI:
            egress = "203.0.113.1" if (local or direct == "redirected") else "198.51.100.9"
            return d.Answer(0, [(d.T_A, egress)])
        return d.Answer(0, [(d.T_A, "93.184.216.34")])

    def tcp(server, name, qtype=d.T_A, timeout=3.0):  # noqa: ANN001, ANN202
        if direct == "blocked":
            raise ConnectionRefusedError("refused")
        return d.Answer(0, [(d.T_A, "93.184.216.34")])

    def refuse(*_a, **_k):  # noqa: ANN002, ANN003, ANN202
        raise ConnectionRefusedError("refused")

    def no_canary(*_a, **_k):  # noqa: ANN002, ANN003, ANN202
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(d, "query_udp", udp)
    monkeypatch.setattr(d, "query_tcp", tcp)
    monkeypatch.setattr(d, "query_dot", refuse)
    monkeypatch.setattr(d, "query_doh", refuse)
    monkeypatch.setattr(d.socket, "getaddrinfo", no_canary)
    monkeypatch.setattr(d, "local_addresses", lambda: ["10.0.1.20"])


def _by_id(checks: list[d.Check]) -> dict[str, d.Check]:
    return {c.id: c for c in checks}


def test_plain_dns_blocked_redirected_or_leaking(monkeypatch) -> None:
    for mode, want in (("blocked", d.PASS), ("redirected", d.PASS), ("open", d.FAIL)):
        _fake_network(monkeypatch, direct=mode)
        checks = _by_id(d.run_checks(["10.0.1.1"], resolvers=["10.0.1.1"]))
        assert checks["direct-udp:8.8.8.8"].status == want, mode
        assert checks["system"].status == d.PASS
        assert checks["expected:10.0.1.1"].status == d.PASS
        assert checks["dot:1.1.1.1"].status == d.PASS and checks["canary"].status == d.PASS
        detail = checks["direct-udp:8.8.8.8"].detail
        assert {"blocked": "Blocked", "redirected": "redirected", "open": "directly"}[mode] in detail


def test_wrong_resolvers_ipv6_and_egress(monkeypatch) -> None:
    _fake_network(monkeypatch, direct="blocked")
    checks = _by_id(d.run_checks(["10.0.1.1"], resolvers=["10.0.1.1", "8.8.4.4", "2001:db8::53"],
                                 expected_egress=["192.0.2.50"]))
    assert checks["system"].status == d.FAIL and "8.8.4.4" in checks["system"].detail
    assert checks["system6"].status == d.FAIL
    assert checks["egress"].status == d.FAIL  # leaves from 203.0.113.1, not the VPN
    assert "fec0:0:0:ffff::1" in d.WINDOWS_PLACEHOLDERS


def test_profiles_from_pfsense_config(tmp_path) -> None:
    xml = tmp_path / "fw.xml"
    xml.write_text("""<?xml version="1.0"?><pfsense><version>24.6</version>
<system><hostname>fw</hostname><dnsserver>9.9.9.9</dnsserver></system>
<interfaces>
 <wan><if>igb0</if><enable/><ipaddr>dhcp</ipaddr></wan>
 <lan><if>igb1</if><descr>LAN</descr><enable/><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
 <opt1><if>igb2</if><descr>IOT</descr><enable/><ipaddr>192.168.2.1</ipaddr><subnet>24</subnet></opt1>
</interfaces>
<dhcpd><opt1><enable/><dnsserver>192.168.2.53</dnsserver><range><from>192.168.2.10</from><to>192.168.2.20</to></range></opt1></dhcpd>
<unbound><enable/></unbound>
</pfsense>""", encoding="utf-8")
    profiles = {p["subnet"]: p for p in b.profiles_from_config(check_file(xml))}
    assert set(profiles) == {"192.168.1.0/24", "192.168.2.0/24"}
    assert profiles["192.168.1.0/24"]["expected_resolvers"] == ["192.168.1.1"]
    assert profiles["192.168.2.0/24"]["expected_resolvers"] == ["192.168.2.53"]


def test_package_contents_and_report_loading(tmp_path) -> None:
    profiles = [{"label": "LAN", "subnet": "192.168.1.0/24", "expected_resolvers": ["192.168.1.1"]}]
    z = b.build_package(tmp_path, profiles, site="Home", expected_egress=["203.0.113.1", "junk"])
    names = set(zipfile.ZipFile(z).namelist())
    assert {f"{b.PACKAGE_DIR}/{n}" for n in ("dns_leak.py", "dnsleak.json", "run_dns_leak.cmd",
                                               "run_dns_leak.sh", "README.txt")} <= names
    zipfile.ZipFile(z).extractall(tmp_path / "x")
    pkg = tmp_path / "x" / b.PACKAGE_DIR
    import json

    cfg = json.loads((pkg / "dnsleak.json").read_text(encoding="utf-8"))
    assert cfg["expected_egress"] == ["203.0.113.1"]
    assert cfg["profiles"][0]["expected_resolvers"] == ["192.168.1.1"]
    # the packaged script stands alone (no pfsense_checker imports)
    out = subprocess.run([sys.executable, "-I", str(pkg / "dns_leak.py"), "--help"],
                         capture_output=True, text=True, timeout=30, check=False)
    assert out.returncode == 0 and "DNS leak" in out.stdout
    report = {"tool": d.TOOL, "checks": []}
    rp = tmp_path / "r.json"
    rp.write_text(json.dumps(report), encoding="utf-8")
    assert b.load_report(rp)["tool"] == d.TOOL
    rp.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError):
        b.load_report(rp)
