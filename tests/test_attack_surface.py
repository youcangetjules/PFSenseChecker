"""Attack-surface assessment of a pfSense config."""

from __future__ import annotations

from pathlib import Path

from pfsense_checker.checker import check_file

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"

_EXPOSED = """<?xml version="1.0"?>
<pfsense>
  <version>2.7.2</version>
  <system>
    <hostname>edge</hostname>
    <domain>lab.local</domain>
    <enablesshd>enabled</enablesshd>
    <webgui><protocol>http</protocol></webgui>
  </system>
  <interfaces>
    <wan><enable></enable><if>igb0</if><descr>WAN</descr><ipaddr>dhcp</ipaddr></wan>
  </interfaces>
  <filter>
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <descr>Wide open</descr>
      <source><any></any></source>
      <destination><any></any></destination>
    </rule>
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <descr>HTTPS from anywhere</descr>
      <source><any></any></source>
      <destination><any></any><port>443</port></destination>
    </rule>
  </filter>
  <nat>
    <rule>
      <interface>wan</interface>
      <descr>RDP</descr>
      <destination><port>3389</port></destination>
      <target>10.0.0.5</target>
      <local-port>3389</local-port>
    </rule>
  </nat>
  <openvpn>
    <openvpn-server>
      <description>legacy</description>
      <cipher>BF-CBC</cipher>
      <digest>SHA1</digest>
      <comp-lzo></comp-lzo>
    </openvpn-server>
  </openvpn>
  <ipsec>
    <phase1>
      <descr>peer</descr>
      <iketype>ikev1</iketype>
      <encryption>
        <item>
          <encryption-algorithm><name>3des</name></encryption-algorithm>
          <hash-algorithm>hmac_sha1</hash-algorithm>
          <dhgroup>2</dhgroup>
        </item>
      </encryption>
    </phase1>
  </ipsec>
  <unbound>
    <enable></enable>
    <active_interface>wan</active_interface>
  </unbound>
  <cert>
    <descr>web</descr>
    <prv>SECRETKEYDATA</prv>
  </cert>
</pfsense>
"""


def test_exposed_config_is_not_a_pass(tmp_path: Path) -> None:
    path = tmp_path / "exposed.xml"
    path.write_text(_EXPOSED, encoding="utf-8")
    result = check_file(path)
    assert result.summary["posture"] == "FAIL"
    text = result.summary["assessment"]
    assert "WebGUI is HTTP" in text
    assert "any source to any port" in text
    assert "3389" in text
    assert "bf-cbc" in text.lower()
    assert "dh group 2" in text.lower()
    assert "DNS: resolver is bound to WAN" in text
    assert "private key" in text.lower()
    blob = text + "\n".join(f.message for f in result.findings)
    assert "SECRETKEYDATA" not in blob
    assert any(f.severity.value == "error" and f.category == "Firewall" for f in result.findings)
    assert any(f.remediation for f in result.findings)


def test_sample_config_is_exposed_not_pass() -> None:
    result = check_file(SAMPLES / "sample_config.xml")
    assert result.summary["posture"] == "EXPOSED"
    text = result.summary["assessment"]
    assert "WebGUI has no interface restriction" in text
    assert "private-network blocking is off" in text
    assert "$2b$" not in text
    assert "$2b$" not in "\n".join(f.message for f in result.findings)
