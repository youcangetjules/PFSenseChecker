"""Beacon probes: ping RTT parsing and the DHCP DISCOVER / OFFER packets."""

from __future__ import annotations

import socket
import struct

from pfsense_checker.monitor import probes as p


def test_rtt_from_windows_linux_and_single_reply() -> None:
    win = "Packets: Sent = 2, Received = 2\n    Minimum = 1ms, Maximum = 3ms, Average = 2ms"
    assert p._parse_rtt_ms(win) == 2.0  # noqa: SLF001
    linux = "rtt min/avg/max/mdev = 0.412/1.250/2.010/0.300 ms"
    assert p._parse_rtt_ms(linux) == 1.25  # noqa: SLF001
    assert p._parse_rtt_ms("Reply from 10.0.0.1: bytes=32 time<1ms TTL=64") == 1.0  # noqa: SLF001
    assert p._parse_rtt_ms("Request timed out.") is None  # noqa: SLF001


def test_discover_packet_shape() -> None:
    mac = bytes.fromhex("02aabbccddee")
    pkt = p._build_dhcp_discover(0x12345678, mac)  # noqa: SLF001
    assert pkt[0] == 1 and pkt[1] == 1 and pkt[2] == 6
    assert struct.unpack_from("!I", pkt, 4)[0] == 0x12345678
    assert struct.unpack_from("!H", pkt, 10)[0] == 0x8000  # broadcast flag
    assert pkt[28:34] == mac and pkt[236:240] == b"\x63\x82\x53\x63"
    assert pkt[240:243] == bytes([53, 1, 1]) and pkt[-1] == 255


def _offer(xid: int, *, msg_type: int = 2, op: int = 2, cookie: bytes = b"\x63\x82\x53\x63") -> bytes:
    msg = bytearray(240)
    msg[0] = op
    struct.pack_into("!I", msg, 4, xid)
    msg[16:20] = socket.inet_aton("192.168.1.150")
    msg[236:240] = cookie
    opts = bytes([53, 1, msg_type, 0]) + bytes([54, 4]) + socket.inet_aton("192.168.1.1")
    opts += bytes([1, 4]) + socket.inet_aton("255.255.255.0")
    opts += bytes([3, 8]) + socket.inet_aton("192.168.1.1") + socket.inet_aton("192.168.1.2")
    return bytes(msg) + opts + bytes([255])


def test_offer_parsed() -> None:
    got = p._parse_dhcp_offer(_offer(7), 7)  # noqa: SLF001
    assert got == {"yiaddr": "192.168.1.150", "server_id": "192.168.1.1", "subnet_mask": "255.255.255.0",
                   "router": "192.168.1.1", "subnet": "192.168.1.150/255.255.255.0"}


def test_offer_rejected_when_wrong() -> None:
    parse = p._parse_dhcp_offer  # noqa: SLF001
    assert parse(_offer(7), 8) is None  # someone else's transaction
    assert parse(_offer(7, msg_type=5), 7) is None  # ACK, not OFFER
    assert parse(_offer(7, op=1), 7) is None  # a request, not a reply
    assert parse(_offer(7, cookie=b"\0\0\0\0"), 7) is None
    assert parse(b"\x02" * 100, 7) is None  # too short


def test_decline_names_the_address_and_server() -> None:
    pkt = p._build_dhcp_decline(9, bytes(6), "192.168.1.150", "192.168.1.1")  # noqa: SLF001
    opts = pkt[240:]
    assert opts[:3] == bytes([53, 1, 4])
    assert socket.inet_aton("192.168.1.150") in opts and socket.inet_aton("192.168.1.1") in opts
    assert p.utc_now().endswith(("Z", "+00:00"))
