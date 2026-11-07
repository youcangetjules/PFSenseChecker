"""SSH inventory collection: RouterOS and FreeBSD, read-only commands."""

from __future__ import annotations

from pfsense_checker import ssh_inventory, ssh_session
from pfsense_checker.ssh_session import SshRunResult
from pfsense_checker.topology_site import Device

_ROS_INTERFACES = """Flags: R - RUNNING; S - SLAVE; X - DISABLED
 0  RS name=sfp-sfpplus1 default-name=sfp-sfpplus1 type=ether mtu=1500 mac-address=18:FD:74:E8:DA:C5
 1   S name=sfp19 default-name=sfp19 type=ether mtu=1500 mac-address=18:FD:74:E8:DA:D7
 2  X  name=sfp20 default-name=sfp20 type=ether mtu=1500 mac-address=18:FD:74:E8:DA:D8
 3  R  name=B1-Bridge type=bridge mtu=1500 mac-address=18:FD:74:E8:DA:C5
 4  R  name=V2-VL630 type=vlan mtu=1500 mac-address=18:FD:74:E8:DA:C5 comment="LAN"
"""
_ROS_ADDRESSES = """Flags: X - DISABLED; D - DYNAMIC
 0   address=222.10.50.5/24 network=222.10.50.0 interface=V2-VL630 actual-interface=V2-VL630
"""
_ROS_VLANS = " 0 R name=V2-VL630 mtu=1500 arp=enabled interface=B1-Bridge vlan-id=630\n"
_ROS_RESOURCE = """                   uptime: 3w2d4h
                  version: 7.22.3 (stable)
               board-name: CRS328-4C-20S-4S+
                      cpu: ARMv7
"""
_ROS_BOARD = """       routerboard: yes
             model: CRS328-4C-20S-4S+
     serial-number: HE00ABC123
  current-firmware: 7.22.3
"""
_ROS_MONITOR = """                      name: sfp-sfpplus1
                    status: link-ok
          auto-negotiation: disabled
                      rate: 10Gbps
               full-duplex: yes
        sfp-module-present: yes
           sfp-vendor-name: FS
    sfp-vendor-part-number: SFP-10GSR-85
"""

_IFCONFIG = """igb0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
\tether ec:0d:9a:d9:85:1a
\tinet 100.48.62.1 netmask 0xffffff00 broadcast 100.48.62.255
\tmedia: Ethernet autoselect (1000baseT <full-duplex>)
\tstatus: active
igb1: flags=8802<BROADCAST,SIMPLEX,MULTICAST> metric 0 mtu 1500
\tether ec:0d:9a:d9:85:1b
\tmedia: Ethernet autoselect
\tstatus: no carrier
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> metric 0 mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
mce1.630: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
\tether 00:02:c9:aa:bb:cc
\tinet 222.10.50.1 netmask 0xffffff00 broadcast 222.10.50.255
\tvlan: 630 vlanproto: 802.1q vlanpcp: 0 parent interface: mce1
\tstatus: active
"""
_PCICONF = """igb0@pci0:3:0:0:\tclass=0x020000 card=0x15218086 chip=0x15218086 rev=0x01 hdr=0x00
    vendor     = 'Intel Corporation'
    device     = 'I350 Gigabit Network Connection'
"""


def _ros_output() -> str:
    return "\n\n".join(
        f"$ {cmd}\n{body}"
        for cmd, body in (
            ("/system resource print", _ROS_RESOURCE),
            ("/system routerboard print", _ROS_BOARD),
            ("/system identity print", "  name: CRS328-MASTER"),
            ("/interface print terse without-paging", _ROS_INTERFACES),
            ("/ip address print terse without-paging", _ROS_ADDRESSES),
            ("/interface vlan print terse without-paging", _ROS_VLANS),
        )
    )


def test_collect_routeros_over_ssh(monkeypatch) -> None:
    sent: list[list[str]] = []

    def fake_run(device, commands, *, password=None, timeout=20.0):  # noqa: ANN001
        sent.append(list(commands))
        if commands[0].startswith("/system resource"):
            return SshRunResult(ok=True, output=_ros_output())
        return SshRunResult(ok=True, output=_ROS_MONITOR)

    monkeypatch.setattr(ssh_session, "run_ssh_commands", fake_run)
    dev = Device(name="host-222-10-50-5", kind="mikrotik", mgmt_ip="222.10.50.5")
    result = ssh_inventory.collect_interfaces(dev)
    assert result.ok and result.platform == "routeros"
    by = {i.name: i for i in result.interfaces}
    assert by["sfp-sfpplus1"].status == "link-ok" and by["sfp-sfpplus1"].speed_mbps == 10000
    assert by["sfp-sfpplus1"].pci_vendor == "FS SFP-10GSR-85"
    assert by["sfp19"].status == "down" and by["sfp20"].status == "disabled"
    assert by["V2-VL630"].addresses == ["222.10.50.5/24"] and by["V2-VL630"].vlan_id == "630"
    assert by["V2-VL630"].comment == "LAN"
    assert result.system["model"] == "CRS328-4C-20S-4S+"
    assert result.system["serial"] == "HE00ABC123"
    assert result.system["version"].startswith("7.22.3")
    assert result.system["hostname"] == "CRS328-MASTER"
    # One monitor, for the one running Ethernet port; read commands only.
    assert sent[1] == ['/interface ethernet monitor [find name="sfp-sfpplus1"] once']
    for batch in sent:
        for cmd in batch:
            assert cmd.startswith(("/system", "/interface", "/ip"))
            assert " set " not in cmd and " add " not in cmd and " remove " not in cmd

    n = ssh_inventory.apply_inventory_to_device(dev, result)
    assert n == 5 and dev.model == "CRS328-4C-20S-4S+"
    assert dev.inventory["platform"] == "routeros"
    again = Device.from_dict(dev.to_dict())  # saved with the site
    assert again.inventory["interfaces"][0]["name"] == "sfp-sfpplus1"


def test_collect_freebsd_with_unknown_kind(monkeypatch) -> None:
    bodies = {
        "uname -sr": "FreeBSD 15.0",
        "ifconfig -a": _IFCONFIG,
        "pciconf -lv": _PCICONF,
        "sysctl -n kern.hostname": "guardian",
    }

    def fake_run(device, commands, *, password=None, timeout=20.0):  # noqa: ANN001
        if commands == ["uname -s"]:
            return SshRunResult(ok=True, output="FreeBSD")
        return SshRunResult(ok=True, output="\n\n".join(f"$ {c}\n{bodies.get(c, '')}" for c in commands))

    monkeypatch.setattr(ssh_session, "run_ssh_commands", fake_run)
    result = ssh_inventory.collect_interfaces(Device(name="fw", kind="router"))
    assert result.platform == "freebsd" and result.system["hostname"] == "guardian"
    by = {i.name: i for i in result.interfaces}
    assert by["igb0"].speed_mbps == 1000 and by["igb0"].duplex == "full"
    assert by["igb0"].pci_vendor == "Intel Corporation I350 Gigabit Network Connection"
    assert by["igb1"].status == "no carrier"
    assert by["mce1.630"].vlan_id == "630" and by["mce1.630"].parent == "mce1"
    assert "lo0" not in by


def test_unknown_kind_detects_routeros(monkeypatch) -> None:
    def fake_run(device, commands, *, password=None, timeout=20.0):  # noqa: ANN001
        if commands == ["uname -s"]:
            return SshRunResult(ok=True, output="bad command name uname (line 1 column 1)")
        if commands[0].startswith("/system resource"):
            return SshRunResult(ok=True, output=_ros_output())
        return SshRunResult(ok=False, error="monitor skipped")

    monkeypatch.setattr(ssh_session, "run_ssh_commands", fake_run)
    result = ssh_inventory.collect_interfaces(Device(name="x", kind="router"))
    assert result.platform == "routeros" and result.ok


def test_media_speed() -> None:
    assert ssh_inventory.media_speed("1000baseT") == 1000
    assert ssh_inventory.media_speed("10Gbase-SR") == 10000
    assert ssh_inventory.media_speed("1Gbps") == 1000
    assert ssh_inventory.media_speed("100Mbps") == 100
    assert ssh_inventory.media_speed("autoselect") is None


def test_viewer_rows_from_inventory_and_fallback(monkeypatch) -> None:
    from pfsense_checker.session_screen import inventory_rows
    from pfsense_checker.topology_site import PortComponent

    def fake_run(device, commands, *, password=None, timeout=20.0):  # noqa: ANN001
        if commands[0].startswith("/system resource"):
            return SshRunResult(ok=True, output=_ros_output())
        return SshRunResult(ok=True, output=_ROS_MONITOR)

    monkeypatch.setattr(ssh_session, "run_ssh_commands", fake_run)
    dev = Device(name="sw", kind="mikrotik")
    ssh_inventory.apply_inventory_to_device(dev, ssh_inventory.collect_interfaces(dev))
    rows = {r["port"]: r for r in inventory_rows(dev)}
    assert rows["sfp-sfpplus1"]["speed"] == "10 Gbps" and rows["sfp-sfpplus1"]["up"]
    assert rows["sfp20"]["status"] == "disabled" and not rows["sfp20"]["up"]
    assert rows["V2-VL630"]["vlan"] == "VLAN 630 on B1-Bridge"
    assert rows["V2-VL630"]["address"] == "222.10.50.5/24"
    assert rows["sfp-sfpplus1"]["source"] == "SSH"

    plain = Device(name="cfg-only", components=[PortComponent(name="ether1", address="10.0.0.1/24")])
    fallback = inventory_rows(plain)
    assert fallback == [{"port": "ether1", "status": "", "speed": "", "mac": "", "address": "10.0.0.1/24",
                         "vlan": "", "hardware": "", "source": "Config", "up": False, "comment": ""}]
