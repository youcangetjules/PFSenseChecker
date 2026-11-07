"""Beacon Creator syntax check: every field red (with a reason) or green."""

from __future__ import annotations

from pfsense_checker.beacon_builder import check_config, default_config


def _by(checks):
    return {(c.field, c.row, c.key): c for c in checks}


def test_defaults_only_flag_the_placeholder_collector() -> None:
    checks = check_config(default_config("beacon-01"))
    bad = [(c.field, c.message) for c in checks if not c.ok]
    assert bad == [("collector_url", "Still the placeholder: put the collector's address in")]


def test_good_config_is_all_green() -> None:
    cfg = default_config("nas-01")
    cfg["collector_url"] = "http://222.10.50.25:8787"
    cfg["ping_targets"] = [{"host": "192.168.1.1", "subnet": "192.168.1.0/24", "interface": "Ethernet 2"},
                           {"host": "gw.example.lan", "subnet": "wan", "interface": ""},
                           {"host": "", "subnet": "", "interface": ""}]  # blank row ignored
    assert all(c.ok for c in check_config(cfg))


def test_bad_fields_are_red_with_reasons() -> None:
    cfg = default_config("bad id!")
    cfg.update(hostname="-nope-", collector_url="ftp://x", token="a b", interval_sec=5)
    cfg["ping_targets"] = [
        {"host": "192.168.1.300", "subnet": "192.168.1.0/24"},
        {"host": "10.0.0.1", "subnet": "192.168.1.0/24"},
        {"host": "10.0.0.1", "subnet": "10.0.0.0/33"},
        {"host": "", "subnet": "lan", "interface": "lan"},
    ]
    cfg["dhcp_targets"] = [
        {"subnet": "192.168.1.0/24", "interface": "lan", "bind_ip": "10.0.0.9", "enabled": "maybe"},
        {"subnet": "192.168.1.0/24", "interface": "lan", "bind_ip": "0.0.0.0", "enabled": "yes"},
    ]
    by = _by(check_config(cfg))
    for key in [("beacon_id", None, ""), ("hostname", None, ""), ("collector_url", None, ""),
                ("token", None, ""), ("interval_sec", None, ""),
                ("ping_targets", 0, "host"), ("ping_targets", 1, "subnet"), ("ping_targets", 2, "host"),
                ("ping_targets", 2, "subnet"), ("ping_targets", 3, "host"),
                ("dhcp_targets", 0, "bind_ip"), ("dhcp_targets", 0, "enabled")]:
        assert not by[key].ok, key
        assert by[key].message
    assert "row 2" in by[("ping_targets", 2, "host")].message
    assert by[("dhcp_targets", 1, "bind_ip")].ok and by[("dhcp_targets", 1, "enabled")].ok
    assert by[("ping_targets", 0, "subnet")].ok


def test_interval_shorter_than_a_ping_round() -> None:
    cfg = default_config("b")
    cfg.update(collector_url="https://collector.lan", interval_sec=10, ping_count=5, ping_timeout=3.0)
    by = _by(check_config(cfg))
    assert not by[("interval_sec", None, "")].ok
    assert "15 s" in by[("interval_sec", None, "")].message
