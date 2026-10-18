"""Tests for SSH interface inventory parsers."""

from __future__ import annotations

from pfsense_checker import ssh_inventory
from pfsense_checker.topology_site import Device


_IFCONFIG_SAMPLE = """
igb0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
	options=4e507bb<RXCSUM,TXCSUM,VLAN_MTU,JUMBO_MTU>
	ether ec:0d:9a:d9:85:1a
	inet 100.48.62.1 netmask 0xffffff00 broadcast 100.48.62.255
	media: Ethernet autoselect (1000baseT <full-duplex>)
	status: active
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> metric 0 mtu 16384
	inet 127.0.0.1 netmask 0xff000000
igb1: flags=8802<BROADCAST,SIMPLEX,MULTICAST> metric 0 mtu 1500
	ether ec:0d:9a:d9:85:1b
	media: Ethernet autoselect
	status: no carrier
"""

_PCICONF_SAMPLE = """
igb0@pci0:3:0:0:	class=0x020000 card=0x15218086 chip=0x15218086 rev=0x01 hdr=0x00
    vendor     = 'Intel Corporation'
    device     = 'I350 Gigabit Network Connection'
    class      = network
    subclass   = ethernet
igb1@pci0:3:0:1:	class=0x020000 card=0x15218086 chip=0x15218086 rev=0x01 hdr=0x00
    vendor     = 'Intel Corporation'
    device     = 'I350 Gigabit Network Connection'
"""


def test_parse_ifconfig_addresses() -> None:
    ifaces = ssh_inventory.parse_ifconfig(_IFCONFIG_SAMPLE)
    by_name = {i.name: i for i in ifaces}
    assert "igb0" in by_name
    assert by_name["igb0"].primary_address.startswith("100.48.62.1")
    assert "1000baseT" in by_name["igb0"].media
    assert by_name["igb0"].status == "active"


def test_parse_pciconf_maps_interface() -> None:
    pci = ssh_inventory.parse_pciconf_lv(_PCICONF_SAMPLE)
    assert "igb0" in pci
    locator, vendor = pci["igb0"]
    assert "pci0:3:0:0" in locator
    assert "Intel" in vendor


def test_apply_inventory_sets_ports_and_kind() -> None:
    ifaces = ssh_inventory.parse_ifconfig(_IFCONFIG_SAMPLE)
    pci = ssh_inventory.parse_pciconf_lv(_PCICONF_SAMPLE)
    for iface in ifaces:
        if iface.name in pci:
            iface.pci, iface.pci_vendor = pci[iface.name]
    result = ssh_inventory.InventoryResult(
        ok=True, platform="freebsd", interfaces=ifaces
    )
    # Filter like collect would
    result.interfaces = [i for i in ifaces if ssh_inventory._include_interface(i)]
    dev = Device(name="fw1", kind="router")
    n = ssh_inventory.apply_inventory_to_device(dev, result)
    assert n >= 1
    assert any(c.name == "igb0" for c in dev.components)
    igb0 = next(c for c in dev.components if c.name == "igb0")
    assert igb0.address.startswith("100.48.62.1")
    assert "lo0" not in dev.ports
    assert dev.kind == "pfsense"
