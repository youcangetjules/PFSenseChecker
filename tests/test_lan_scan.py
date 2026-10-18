"""Tests for lan_scan address classification and ARP parsing."""

from __future__ import annotations

from pfsense_checker.lan_scan import (
    classify_address,
    normalize_mac,
    parse_arp_table,
    resolve_mac_to_ip,
)


def test_classify_ip_and_mac() -> None:
    assert classify_address("10.0.0.5").kind == "ip"
    assert classify_address("10.0.0.5").value == "10.0.0.5"
    assert classify_address("AA:BB:CC:DD:EE:FF").kind == "mac"
    assert classify_address("aa-bb-cc-dd-ee-ff").value == "aa:bb:cc:dd:ee:ff"
    assert classify_address("aabbccddeeff").kind == "mac"
    assert classify_address("").kind == "empty"
    assert classify_address("not-an-addr").kind == "invalid"


def test_normalize_mac() -> None:
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"


def test_parse_arp_windows() -> None:
    sample = """
Interface: 192.168.1.10 --- 0xb
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-01     dynamic
  192.168.1.50          11-22-33-44-55-66     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
"""
    hosts = parse_arp_table(sample)
    by_ip = {h.ip: h for h in hosts}
    assert "192.168.1.1" in by_ip
    assert by_ip["192.168.1.1"].mac == "aa:bb:cc:dd:ee:01"
    assert "192.168.1.255" not in by_ip  # broadcast filtered
    assert resolve_mac_to_ip("11:22:33:44:55:66", hosts) == "192.168.1.50"


def test_local_ipv4_addresses_excludes_loopback() -> None:
    from pfsense_checker.lan_scan import local_ipv4_addresses, local_ipv4_cidrs

    for ip in local_ipv4_addresses():
        assert not ip.startswith("127.")
    assert isinstance(local_ipv4_cidrs(), list)


def test_nic_kind_fiber_vs_hyperv() -> None:
    from pfsense_checker.lan_scan import nic_kind

    assert nic_kind("222.10.50.25", "V2_S4_1G_FIB_VL630_LAN_Main") == "lan"
    assert nic_kind("172.28.112.1", "vEthernet (Default Switch)") == "virtual"
    assert nic_kind("169.254.137.182", "WiFi") == "link-local"
    assert nic_kind("100.64.1.2", "Tailscale") == "vpn"
    assert nic_kind("100.48.62.40", "mgmt") == "lan"
