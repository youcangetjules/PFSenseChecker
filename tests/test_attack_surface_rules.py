"""Attack-surface assessment: exposed vs hardened pfSense configs, RouterOS, posture."""

from __future__ import annotations

from xml.etree import ElementTree as ET

from pfsense_checker import attack_surface as a
from pfsense_checker.checker import check_file
from pfsense_checker.models import CheckResult, PackageInfo, Severity

EXPOSED = """<pfsense>
 <system>
  <webgui><protocol>http</protocol><interfaces>wan,lan</interfaces></webgui>
  <enablesshd/>
  <ssh><port>2222</port></ssh>
 </system>
 <interfaces>
  <wan><if>igb0</if><enable/><descr>WAN</descr></wan>
  <lan><if>igb1</if><enable/></lan>
 </interfaces>
 <filter>
  <rule><type>pass</type><interface>wan</interface><source><any/></source><destination><any/></destination><descr>open wan</descr></rule>
  <rule><type>pass</type><interface>wan</interface><source><any/></source><destination><any/><port>443</port></destination><descr>web</descr><log/></rule>
  <rule><type>pass</type><interface>lan</interface><source><any/></source><destination><any/></destination><descr>lan any</descr></rule>
  <rule><type>pass</type><interface>wan</interface><source><any/></source><destination><any/></destination><descr>old</descr><disabled/></rule>
 </filter>
 <nat>
  <rule><interface>wan</interface><target>10.0.0.5</target><local-port>3389</local-port><destination><port>3389</port></destination><descr>rdp</descr></rule>
  <rule><interface>wan</interface><target>10.0.0.6</target><descr>whole host</descr></rule>
  <onetoone><interface>wan</interface><descr>dmz box</descr></onetoone>
 </nat>
 <openvpn>
  <openvpn-server><description>roadwarrior</description><cipher>BF-CBC</cipher><digest>SHA1</digest><compression>adaptive</compression></openvpn-server>
 </openvpn>
 <ipsec>
  <phase1><descr>branch</descr><iketype>ikev1</iketype>
   <encryption><item><encryption-algorithm><name>3des</name></encryption-algorithm><hash-algorithm>md5</hash-algorithm><dhgroup>2</dhgroup></item></encryption>
  </phase1>
 </ipsec>
 <unbound><enable/><active_interface>all</active_interface></unbound>
 <cert><descr>web</descr><prv>LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tU0VDUkVUS0VZTUFURVJJQUw=</prv></cert>
</pfsense>"""

HARDENED = """<pfsense>
 <system>
  <webgui><protocol>https</protocol><interfaces>lan</interfaces></webgui>
  <enablesshd/><ssh><sshdkeyonly/></ssh>
 </system>
 <interfaces>
  <wan><if>igb0</if><enable/><blockpriv/><blockbogons/></wan>
  <lan><if>igb1</if><enable/></lan>
 </interfaces>
 <filter>
  <rule><type>pass</type><interface>lan</interface><source><network>lan</network></source><destination><any/><port>443</port></destination><descr>lan web</descr></rule>
 </filter>
 <unbound><enable/><active_interface>lan</active_interface><dnssec/></unbound>
 <syslog><remoteserver>10.0.0.9:514</remoteserver></syslog>
</pfsense>"""


def _assess(xml: str, packages=()):  # noqa: ANN001, ANN202
    result = CheckResult(hostname="fw", root_tag="pfsense", version="24.6", valid_xml=True)
    result.packages = list(packages)
    text = a.assess_pfsense(ET.fromstring(xml), result)
    return result, text


def _by(result: CheckResult, category: str) -> list:
    return [f for f in result.findings if f.category == category]


def test_exposed_config_reports_each_control() -> None:
    result, text = _assess(EXPOSED)
    mgmt = {f.message for f in _by(result, "Management")}
    assert any("HTTP" in m for m in mgmt) and any("bound to WAN" in m for m in mgmt)
    assert any("password authentication" in m and "2222" in m for m in mgmt)
    assert any(f.severity is Severity.ERROR and "WAN" in f.message for f in _by(result, "Management"))
    fw = " ".join(f.message for f in _by(result, "Firewall"))
    assert "Block private networks is off on WAN" in fw and "bogon" in fw
    assert "open wan" in fw and "web port 443" in fw and "lan any" in fw
    assert "old" not in fw  # disabled rules are ignored
    nat = " ".join(f.message for f in _by(result, "NAT"))
    assert "rdp" in nat and "3389" in nat and "whole host" in nat and "dmz box" in nat
    vpn = " ".join(f.message for f in _by(result, "VPN"))
    for bit in ("bf-cbc", "digest sha1", "compression", "IKEv1", "3des", "md5", "DH group 2"):
        assert bit in vpn, bit
    dns = " ".join(f.message for f in _by(result, "DNS"))
    assert "WAN" in dns and "DNSSEC" in dns
    assert _by(result, "Logging") and _by(result, "Packages") and _by(result, "Secrets")
    assert result.summary["assessment"] == text and text.startswith("Attack surface — fw")


def test_private_key_material_never_copied() -> None:
    result, text = _assess(EXPOSED)
    blob = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tU0VDUkVUS0VZTUFURVJJQUw="
    assert blob not in text
    assert all(blob not in f.message and blob not in (f.remediation or "") for f in result.findings)
    assert "1 private key" in " ".join(f.message for f in _by(result, "Secrets"))


def test_hardened_config_raises_no_warnings() -> None:
    pkgs = [PackageInfo(name="pfBlockerNG", internal_name="pfblockerng", enabled=True)]
    result, text = _assess(HARDENED, pkgs)
    assert not [f for f in result.findings if f.severity in (Severity.ERROR, Severity.WARNING)]
    assert "key-only" in text and "remote syslog target is set" in text
    assert "IDS/blocklist present (pfblockerng)" in text


def test_disabled_ids_package_is_a_warning() -> None:
    pkgs = [PackageInfo(name="suricata", internal_name="suricata", enabled=False)]
    result, _ = _assess(HARDENED, pkgs)
    assert [f for f in _by(result, "Packages") if f.severity is Severity.WARNING]


def test_empty_config_says_nothing_found() -> None:
    result, text = _assess("<pfsense/>")
    assert "No management, firewall, NAT, VPN, or DNS exposure" not in text  # logging/packages still speak
    assert _by(result, "Logging")


def test_posture() -> None:
    r = CheckResult(valid_xml=False)
    assert a.apply_posture(r) == "INVALID"
    r = CheckResult(valid_xml=True)
    assert a.apply_posture(r) == "PASS"
    a._add(r, Severity.WARNING, "x", "w", "p", "fix")  # noqa: SLF001
    assert a.apply_posture(r) == "EXPOSED"
    a._add(r, Severity.ERROR, "x", "e", "p", "fix")  # noqa: SLF001
    assert a.apply_posture(r) == "FAIL" and r.summary["posture"] == "FAIL"


def test_helpers() -> None:
    assert a._ports("80, 443:8443 abc") == {80, 443, 8443}  # noqa: SLF001
    assert a._sample([str(i) for i in range(7)]) == "0; 1; 2; 3; 4; +2 more"  # noqa: SLF001
    assert a._label("", 2) == "rule 3" and a._label(" web ", 0) == "web"  # noqa: SLF001
    node = ET.fromstring("<x><Enable>no</Enable><on/></x>")
    assert not a._has_flag(node, "enable") and a._has_flag(node, "on")  # noqa: SLF001


def test_routeros_input_accepts_and_dstnat(tmp_path) -> None:
    rsc = tmp_path / "r.rsc"
    rsc.write_text("""# 2026-11-07 by RouterOS 7.22.3
/ip firewall filter
add action=accept chain=input comment=winbox-anywhere
add action=accept chain=input src-address=10.0.0.0/24 dst-port=8291 protocol=tcp comment=winbox-mgmt
add action=drop chain=input
/ip firewall nat
add action=dst-nat chain=dstnat dst-port=3389 protocol=tcp to-addresses=10.0.0.5
/system identity
set name=rt1
""", encoding="utf-8")
    result = check_file(rsc)
    text = result.summary.get("assessment") or a.assess_routeros(result)
    fw = " ".join(f.message for f in result.findings if f.category == "Firewall")
    assert "winbox-anywhere" in fw and "winbox-mgmt" not in fw
    assert "dst-nat" in text
