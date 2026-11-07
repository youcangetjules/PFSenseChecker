"""Subnet Health device scan: nmap XML, router tables, classification, problems."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

from pfsense_checker import device_scan as ds

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
 <host><status state="up"/>
  <address addr="10.0.0.1" addrtype="ipv4"/><address addr="AA:BB:CC:00:00:01" addrtype="mac" vendor="Routerboard.com"/>
  <hostnames><hostname name="gw.lan"/></hostnames>
  <ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="MikroTik RouterOS sshd"/></port>
         <port protocol="tcp" portid="23"><state state="closed"/></port></ports>
  <os><osmatch name="MikroTik RouterOS 7" accuracy="96"/></os>
 </host>
 <host><status state="up"/><address addr="10.0.0.50" addrtype="ipv4"/><address addr="02:42:0a:00:00:32" addrtype="mac"/></host>
 <host><status state="down"/><address addr="10.0.0.99" addrtype="ipv4"/></host>
</nmaprun>"""

MT_TABLES = """##ARP
 0 DC address=10.0.0.20 mac-address=AA:BB:CC:00:00:20 interface=bridge published=no status=reachable
 1 D  address=10.0.0.30 interface=bridge published=no status=failed
 2 DC address=10.0.0.40 mac-address=AA:BB:CC:00:00:40 interface=bridge status=stale
 3 DC address=10.0.0.41 mac-address=AA:BB:CC:00:00:41 interface=bridge status=stale
 4 DC address=192.168.5.7 mac-address=AA:BB:CC:00:05:07 interface=bridge status=stale
##LEASE
 0 D address=10.0.0.20 mac-address=AA:BB:CC:00:00:20 server=dhcp1 status=bound expires-after=9m host-name="Phone A"
 1   address=10.0.0.40 mac-address=AA:BB:CC:00:00:40 server=dhcp1 status=bound host-name=printer
##POOL
 0 name=dhcp_pool0 ranges=10.0.0.20-10.0.0.40
"""

PF_TABLES = """##ARP
? (10.0.0.1) at aa:bb:cc:00:00:01 on igb1 expires in 1185 seconds [ethernet]
? (10.0.0.77) at (incomplete) on igb1 expired [ethernet]
##LEASE
lease 10.0.0.60 {
  starts 4 2026/11/05 10:00:00;
  ends 4 2026/11/05 12:00:00;
  binding state active;
  hardware ethernet aa:bb:cc:00:00:60;
  client-hostname "laptop";
}
lease 10.0.0.61 {
  binding state free;
  hardware ethernet aa:bb:cc:00:00:61;
}
##KEA
"""


def test_mac_helpers() -> None:
    assert ds.norm_mac("AA-BB-CC-00-00-01") == "aa:bb:cc:00:00:01"
    assert ds.norm_mac("ff:ff:ff:ff:ff:ff") == ""
    assert ds.is_macvlan_mac("02:42:0a:00:00:32")
    assert ds.is_random_mac("da:a1:19:00:00:01")
    assert not ds.is_random_mac("02:42:0a:00:00:32")
    assert ds.is_locally_administered("aa:bb:cc:00:00:01")  # 0xaa has the local bit set
    assert not ds.is_locally_administered("00:1b:21:00:00:01")


def test_nmap_args_exclude_firewalls() -> None:
    args = ds.nmap_args("10.0.0.0/24", exclude=["10.0.0.254", "nonsense"])
    assert args[:2] == ["-oX", "-"] and "-sV" in args and "-O" in args
    assert args[args.index("--exclude") + 1] == "10.0.0.254"
    assert args[-1] == "10.0.0.0/24"
    assert "-sn" in ds.nmap_args("10.0.0.0/24", aggressive=False)


def test_parse_nmap_xml() -> None:
    rows = ds.parse_nmap_xml(NMAP_XML)
    assert [r.ip for r in rows] == ["10.0.0.1", "10.0.0.50"]
    gw = rows[0]
    assert gw.mac == "aa:bb:cc:00:00:01" and gw.vendor == "Routerboard.com" and gw.hostname == "gw.lan"
    assert gw.services == ["22/tcp ssh MikroTik RouterOS sshd"]
    assert gw.os_guess == "MikroTik RouterOS 7 (96%)"


def test_parse_mikrotik_tables() -> None:
    rows, pools = ds.parse_mikrotik_tables(MT_TABLES, "sw1")
    arp = {r.ip: r for r in rows if r.source == "router-arp:sw1"}
    assert arp["10.0.0.30"].incomplete and not arp["10.0.0.20"].incomplete
    leases = {r.ip: r for r in rows if r.source == "lease:sw1"}
    assert leases["10.0.0.20"].lease == "dynamic" and leases["10.0.0.20"].hostname == "Phone A"
    assert leases["10.0.0.40"].lease == "static"
    assert len(pools) == 1 and pools[0].size == 21


def test_parse_pfsense_tables() -> None:
    rows = ds.parse_pfsense_tables(PF_TABLES, "fw")
    by = {(r.source, r.ip): r for r in rows}
    assert by[("router-arp:fw", "10.0.0.77")].incomplete
    lease = by[("lease:fw", "10.0.0.60")]
    assert lease.mac == "aa:bb:cc:00:00:60" and lease.hostname == "laptop"
    assert ("lease:fw", "10.0.0.61") not in by  # free leases are ignored


def _result(now: datetime) -> tuple[ds.ScanResult, list[ds.Sighting], list[ds.Pool]]:
    mt_rows, pools = ds.parse_mikrotik_tables(MT_TABLES, "sw1")
    sightings = ds.parse_nmap_xml(NMAP_XML) + mt_rows + [
        ds.Sighting(ip="10.0.0.25", mac="00:1b:21:00:00:25", source="nmap"),  # static, inside pool
        ds.Sighting(ip="10.0.0.70", mac="00:1b:21:00:00:70", source="nmap", hostname="nas"),
        ds.Sighting(ip="10.0.0.70", mac="00:1b:21:00:00:71", source="nmap"),  # clash
        ds.Sighting(ip="10.0.0.80", mac="00:1b:21:00:00:80", source="nmap", hostname="NAS"),
        ds.Sighting(ip="10.0.0.90", mac="da:a1:19:00:00:90", source="nmap"),
    ]
    result = ds.ScanResult(cidr="10.0.0.0/24", gateway="10.0.0.1")
    result.devices = ds.merge(result.cidr, sightings)
    leases = [s for s in sightings if s.source.startswith("lease:")]
    beacons = [
        {"beacon_id": "b-nas", "hostname": "nas", "last_seen": (now - timedelta(minutes=30)).isoformat(),
         "meta": {"accessible_subnets": [{"cidr": "10.0.0.0/24", "ip": "10.0.0.80", "mac": "00:1b:21:00:00:80"}]}},
        {"beacon_id": "b-gone", "last_seen": now.isoformat(),
         "meta": {"accessible_subnets": [{"cidr": "10.0.0.0/24", "ip": "10.0.0.200"}]}},
    ]
    ds.classify(result.devices, gateways={"10.0.0.1"}, router_ips={"10.0.0.1": "gw"},
                statics=[ds.StaticMap("10.0.0.40", "aa:bb:cc:00:00:40", "sw1")], leases=leases, beacons=beacons)
    result.problems = ds.find_problems(result, sightings=sightings, pools=pools,
                                       statics=[ds.StaticMap("10.0.0.40", "aa:bb:cc:00:00:40", "sw1")],
                                       beacons=beacons, previous_gateway_mac="aa:bb:cc:99:99:99", now=now)
    return result, sightings, pools


def test_classification() -> None:
    now = datetime(2026, 11, 7, 12, tzinfo=timezone.utc)
    result, _s, _p = _result(now)
    kind = {(d.ip, d.mac): d.conn_type for d in result.devices}
    assert kind[("10.0.0.1", "aa:bb:cc:00:00:01")] == ds.CONN_ROUTER
    assert kind[("10.0.0.50", "02:42:0a:00:00:32")] == ds.CONN_MACVLAN
    assert kind[("10.0.0.20", "aa:bb:cc:00:00:20")] == ds.CONN_DHCP
    assert kind[("10.0.0.40", "aa:bb:cc:00:00:40")] == ds.CONN_STATIC_DHCP
    assert kind[("10.0.0.25", "00:1b:21:00:00:25")] == ds.CONN_STATIC
    nas = next(d for d in result.devices if d.ip == "10.0.0.80")
    assert nas.beacon_id == "b-nas"
    # The ARP entry without a MAC folds into an IP-only device; 192.168.5.7 is dropped.
    assert any(d.ip == "10.0.0.30" and not d.mac for d in result.devices)
    assert not any(d.ip.startswith("192.168.") for d in result.devices)


def test_problems() -> None:
    now = datetime(2026, 11, 7, 12, tzinfo=timezone.utc)
    result, _s, _p = _result(now)
    kinds = {(p.kind, p.subject) for p in result.problems}
    assert ("IP clash", "10.0.0.70") in kinds
    assert ("Gateway MAC changed", "10.0.0.1") in kinds
    assert ("Static IP in DHCP pool", "10.0.0.25") in kinds
    assert ("Incomplete ARP", "10.0.0.30") in kinds
    assert ("Duplicate hostname", "nas") in kinds
    assert ("Random MAC", "10.0.0.90") in kinds
    assert ("Wrong subnet", "192.168.5.7") in kinds
    assert ("Beacon offline", "10.0.0.80") in kinds
    assert ("Beacon not seen", "10.0.0.200") in kinds
    assert ("Reservation in pool", "10.0.0.40") in kinds
    assert not any(k == "Beacon not seen" and s == "10.0.0.80" for k, s in kinds)


def test_pool_nearly_full_and_stale_lease() -> None:
    now = datetime(2026, 11, 7, 12, tzinfo=timezone.utc)
    pool = ds.Pool(ipaddress.IPv4Address("10.0.0.10"), ipaddress.IPv4Address("10.0.0.11"), "sw1")
    sightings = [ds.Sighting(ip="10.0.0.10", mac="00:1b:21:00:00:10", source="lease:sw1", lease="dynamic"),
                 ds.Sighting(ip="10.0.0.11", mac="00:1b:21:00:00:11", source="lease:sw1", lease="dynamic")]
    result = ds.ScanResult(cidr="10.0.0.0/24")
    result.devices = ds.merge(result.cidr, sightings)
    result.devices[0].first_seen = now - timedelta(days=30)
    probs = ds.find_problems(result, sightings=sightings, pools=[pool], statics=[], beacons=[], now=now)
    kinds = [(p.kind, p.severity) for p in probs]
    assert ("Pool nearly full", ds.SEV_FAIL) in kinds
    assert [p.subject for p in probs if p.kind == "Stale lease"] == ["10.0.0.10"]


def test_scan_without_nmap_uses_ping_sweep(monkeypatch) -> None:
    monkeypatch.setattr(ds, "nmap_path", lambda: "")
    monkeypatch.setattr(ds, "local_sightings", lambda net: [])
    monkeypatch.setattr(ds, "ping_sweep", lambda cidr: [ds.Sighting(ip="10.0.0.5", mac="00:1b:21:00:00:05", source="ping")])
    res = ds.scan("10.0.0.0/24", gateway="10.0.0.1", options=ds.ScanOptions(use_db=False, router_tables=False))
    assert res.engine == "ping sweep" and any("nmap is not installed" in n for n in res.notes)
    assert [d.ip for d in res.devices] == ["10.0.0.5"]
    assert res.devices[0].conn_type == ds.CONN_STATIC


def test_age_text() -> None:
    now = datetime(2026, 11, 7, tzinfo=timezone.utc)
    assert ds.age_text(now - timedelta(minutes=5), now) == "new"
    assert ds.age_text(now - timedelta(hours=5), now) == "5 h"
    assert ds.age_text(now - timedelta(days=3), now) == "3 d"
    assert ds.age_text(now - timedelta(days=400), now) == "13 mo"


def test_pool_without_lease_table_is_inferred_dhcp() -> None:
    pool = ds.Pool(ipaddress.IPv4Address("10.0.0.100"), ipaddress.IPv4Address("10.0.0.199"), "fw")
    s = [ds.Sighting(ip="10.0.0.150", mac="00:1b:21:00:01:50", source="arp")]
    devs = ds.merge("10.0.0.0/24", s)
    ds.classify(devs, gateways=set(), router_ips={}, statics=[], leases=[], beacons=[], pools=[pool])
    assert devs[0].conn_type == ds.CONN_DHCP_INFERRED
    result = ds.ScanResult(cidr="10.0.0.0/24", devices=devs)
    assert not ds.find_problems(result, sightings=s, pools=[pool], statics=[], beacons=[])
    ds.classify(devs, gateways=set(), router_ips={}, statics=[], leases=[], beacons=[], pools=[pool],
                leases_read={"fw"})
    assert devs[0].conn_type == ds.CONN_STATIC
    assert [p.kind for p in ds.find_problems(result, sightings=s, pools=[pool], statics=[], beacons=[])] == [
        "Static IP in DHCP pool"]
