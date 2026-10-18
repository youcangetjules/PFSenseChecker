"""Subnet health helpers."""

from __future__ import annotations

from pfsense_checker import subnet_health
from pfsense_checker.monitor.beacon import run_cycle


def test_normalize_link_type() -> None:
    assert subnet_health.normalize_link_type("Wi-Fi") == "wlan"
    assert subnet_health.normalize_link_type("ethernet") == "wired"
    assert subnet_health.link_type_label("wlan") == "WLAN"


def test_normalize_duplex() -> None:
    assert subnet_health._normalize_duplex(True) == "full"
    assert subnet_health._normalize_duplex(False) == "half"
    assert subnet_health._normalize_duplex("FullDuplex") == "full"
    assert subnet_health._normalize_duplex(None) == ""


def test_describe_local_adapter_includes_nic_fields(monkeypatch) -> None:
    row = subnet_health.SubnetAccess(
        cidr="100.48.62.0/24",
        ip="100.48.62.10",
        interface="Ethernet",
        mac="aa:bb:cc:dd:ee:ff",
        link_type="wired",
        link_speed="10 Gbps",
        duplex="full",
        mtu=1500,
        source="local",
    )
    monkeypatch.setattr(subnet_health, "discover_local_subnets", lambda: [row])
    text = subnet_health.describe_local_adapter("100.48.62.0/24")
    assert "type Wired" in text
    assert "speed 10 Gbps" in text
    assert "duplex full" in text
    assert "MTU 1500" in text



def test_subnet_rows_from_beacon_meta() -> None:
    beacon = {
        "beacon_id": "b1",
        "hostname": "lab",
        "last_seen": "2026-01-01T00:00:00",
        "meta": {
            "interval_sec": 45,
            "accessible_subnets": [
                {
                    "cidr": "10.0.0.0/24",
                    "link_type": "wlan",
                    "gateway": "10.0.0.1",
                    "ping_status": "ok",
                    "ping_ms": 3.2,
                }
            ],
        },
    }
    rows = subnet_health.subnet_rows_from_beacon(beacon)
    assert len(rows) == 1
    assert rows[0].cidr == "10.0.0.0/24"
    assert rows[0].link_type == "wlan"
    assert rows[0].source == "beacon:b1"
    assert rows[0].ping_ms == 3.2


def test_beacon_cycle_includes_accessible_subnets() -> None:
    cfg = {
        "beacon_id": "test-1",
        "collector_url": "http://127.0.0.1:9",
        "interval_sec": 30,
        "link_type": "wired",
        "ping_targets": [],
        "dhcp_targets": [],
        "subnets": [
            {
                "cidr": "192.168.50.0/24",
                "gateway": "192.168.50.1",
                "interface": "lan",
                "link_type": "wired",
            }
        ],
    }
    report = run_cycle(cfg, cycle_index=0)
    assert report.meta["interval_sec"] == 30
    assert report.meta["accessible_subnets"][0]["cidr"] == "192.168.50.0/24"
    assert report.meta["accessible_subnets"][0]["link_type"] == "wired"
