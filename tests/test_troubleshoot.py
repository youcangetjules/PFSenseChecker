"""Problems / Troubleshooting: interface choices and the context sent to Ollama."""

from __future__ import annotations

import json
from pathlib import Path

from pfsense_checker import ai, troubleshoot as t
from pfsense_checker.checker import check_file

MIKROTIK = """\
# 2026-11-07 by RouterOS 7.22.3
# model = CRS109-8G-1S-2HnD
/interface bridge
add name=BR1 vlan-filtering=no
/interface vlan
add interface=BR1 name=V7-S2-VL662-JAP vlan-id=662
add interface=BR1 name=V2-S5-VL630-LAN vlan-id=630
/interface list
add name=LAN
/interface list member
add interface=V2-S5-VL630-LAN list=LAN
/interface wireless security-profiles
add name=prof1 wpa2-pre-shared-key=supersecretpsk1
/interface bridge port
add bridge=BR1 interface=ether7 pvid=662
add bridge=BR1 interface=ether3 pvid=630
/ip address
add address=222.10.70.10/24 interface=V7-S2-VL662-JAP
add address=222.10.50.10/24 interface=V2-S5-VL630-LAN
/ip route
add gateway=222.10.50.1
/system identity
set name=SW1
"""

PFSENSE = """\
<?xml version="1.0"?>
<pfsense>
  <version>24.6</version>
  <system><hostname>fw1</hostname><domain>lan</domain>
    <user><name>admin</name><bcrypt-hash>$2y$10$abcdefghijklmnopqrstuuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012</bcrypt-hash></user>
  </system>
  <interfaces>
    <wan><if>igb0</if><descr>0_S1_P0_1G_F_WAN</descr><enable/><ipaddr>dhcp</ipaddr></wan>
    <lan><if>igb1</if><descr>LAN</descr><enable/><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
    <opt1><if>igb2</if><descr>GUEST</descr><enable/><ipaddr>192.168.2.1</ipaddr><subnet>24</subnet></opt1>
  </interfaces>
  <dhcpd>
    <lan><enable/><denyunknown/><range><from>192.168.1.100</from><to>192.168.1.199</to></range>
      <ddnsdomainkey>c2VjcmV0a2V5c2VjcmV0a2V5</ddnsdomainkey>
      <staticmap><mac>aa:bb:cc:dd:ee:ff</mac><ipaddr>192.168.1.50</ipaddr></staticmap>
    </lan>
  </dhcpd>
  <filter>
    <rule><type>pass</type><interface>lan</interface><source><network>lan</network></source><destination><any/></destination><descr>LAN out</descr></rule>
    <rule><type>block</type><interface>opt1</interface><source><any/></source><destination><network>lan</network></destination><descr>guest no lan</descr></rule>
  </filter>
</pfsense>
"""


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_problem_keys_unique() -> None:
    keys = [p.key for p in t.PROBLEMS]
    assert len(keys) == len(set(keys))
    assert "other" in t.PROBLEM_BY_KEY


def test_mikrotik_choices_skip_lists_and_profiles(tmp_path) -> None:
    r = check_file(_write(tmp_path, "sw1.rsc", MIKROTIK))
    choices = t.interface_choices(r)
    keys = [c.key for c in choices]
    assert keys[0] == t.WHOLE_DEVICE
    assert "V7-S2-VL662-JAP" in keys and "ether7" in keys
    for not_iface in ("LAN", "all", "prof1"):
        assert not_iface not in keys
    label = next(c.label for c in choices if c.key == "V7-S2-VL662-JAP")
    assert "222.10.70.10/24" in label and "VLAN 662" in label


def test_mikrotik_context_focuses_on_interface_and_drops_secrets(tmp_path) -> None:
    r = check_file(_write(tmp_path, "sw1.rsc", MIKROTIK))
    ctx = t.build_context(r, "V7-S2-VL662-JAP", "wifi", "printer on 662 unreachable")
    assert "operator's notes" in ctx and "printer on 662 unreachable" in ctx
    assert "interface=ether7" in ctx  # the bridge port carrying VLAN 662
    assert "/ip address add address=222.10.70.10/24" in ctx
    assert "supersecretpsk1" not in ctx
    assert "Can't connect" in ctx or "Wi-Fi" in ctx


def test_pfsense_context_has_rules_dhcp_flags_not_secrets(tmp_path) -> None:
    r = check_file(_write(tmp_path, "fw1.xml", PFSENSE))
    keys = [c.key for c in t.interface_choices(r)]
    assert keys[:3] == ["", "wan", "lan"]
    ctx = t.build_context(r, "lan", "no_dhcp")
    assert "range/from=192.168.1.100" in ctx
    assert "denyunknown" in ctx and "static mappings: 1" in ctx
    assert "c2VjcmV0a2V5c2VjcmV0a2V5" not in ctx and "$2y$" not in ctx
    assert '"LAN out"' in ctx
    assert "guest no lan" not in ctx  # rule on another interface
    whole = t.build_context(r, "", "no_reach")
    assert "guest no lan" in whole


def test_secret_keys_precise() -> None:
    for secret in ("wpa2-pre-shared-key", "private-key", "ddnsdomainkey", "secret", "auth-key",
                   "bcrypt-hash", "community", "tls", "sae-password", "key"):
        assert t.is_secret_key(secret), secret
    for plain in ("broadcast-flood", "local-address", "multicast-router", "interface",
                  "vlan-filtering", "dhcp-snooping", "address", "keepalive-timeout"):
        assert not t.is_secret_key(plain), plain


def test_context_window_grows() -> None:
    assert t.context_window("x" * 100) == 8192
    assert t.context_window("x" * 60_000) >= 16384


class _FakeStream:
    def __init__(self, chunks: list[dict]) -> None:
        self._lines = [json.dumps(c).encode() + b"\n" for c in chunks]

    def __enter__(self):  # noqa: ANN204
        return iter(self._lines)

    def __exit__(self, *exc) -> None:  # noqa: ANN002
        return None


def _fake_urlopen(sent: dict, chunks: list[dict]):  # noqa: ANN202
    def urlopen(request, timeout=0):  # noqa: ANN001, ANN202
        sent.update(url=request.full_url, body=json.loads(request.data), timeout=timeout)
        return _FakeStream(chunks)

    return urlopen


def test_ask_streams_with_system_prompt_and_num_ctx(monkeypatch) -> None:
    sent: dict = {}
    chunks = [
        {"message": {"thinking": "hmm"}},
        {"message": {"content": "1. "}},
        {"message": {"content": "cause"}},
        {"done": True},
    ]
    monkeypatch.setattr(ai.urllib.request, "urlopen", _fake_urlopen(sent, chunks))
    seen: list[str] = []
    thought: list[int] = []
    reply = t.ask("ctx", "no_dhcp", "lan", model="m", base_url="http://127.0.0.1:11434",
                  on_text=seen.append, on_thinking=thought.append)
    assert reply == "1. cause"
    assert seen == ["1. ", "1. cause"] and thought == [1]
    assert sent["url"].endswith("/api/chat") and sent["body"]["stream"] is True
    assert sent["body"]["messages"][0]["content"] == t.SYSTEM_PROMPT
    assert sent["body"]["options"]["num_ctx"] == 8192
    assert "interface lan" in json.dumps(sent["body"]["messages"][1])
    assert "think" not in sent["body"]
    t.ask("ctx", "no_dhcp", "lan", model="m", base_url="http://127.0.0.1:11434", think=False)
    assert sent["body"]["think"] is False


def test_ask_can_be_stopped_and_reports_errors(monkeypatch) -> None:
    import pytest

    sent: dict = {}
    monkeypatch.setattr(ai.urllib.request, "urlopen",
                        _fake_urlopen(sent, [{"message": {"content": "x"}}, {"done": True}]))
    with pytest.raises(ai.OllamaStopped):
        t.ask("ctx", "other", "", model="m", base_url="http://127.0.0.1:11434", should_stop=lambda: True)
    monkeypatch.setattr(ai.urllib.request, "urlopen",
                        _fake_urlopen(sent, [{"error": "model 'm' not found"}]))
    with pytest.raises(RuntimeError, match="not found"):
        t.ask("ctx", "other", "", model="m", base_url="http://127.0.0.1:11434")
