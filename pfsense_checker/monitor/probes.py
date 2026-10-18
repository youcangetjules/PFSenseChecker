"""ICMP ping and DHCP DISCOVER probe helpers for beacon agents."""

from __future__ import annotations

import platform
import random
import socket
import struct
import subprocess
import time
from datetime import datetime, timezone

from pfsense_checker import winproc
from pfsense_checker.monitor.models import ProbeKind, ProbeResult, ProbeStatus


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ping_host(
    host: str,
    *,
    count: int = 2,
    timeout_sec: float = 2.0,
    subnet: str = "",
    interface: str = "",
) -> ProbeResult:
    """Ping a host using the OS ping utility (no root required on Windows)."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(int(timeout_sec * 1000)), host]
    else:
        # -c count, -W timeout (seconds, Linux); macOS uses -W in ms via -t style
        cmd = ["ping", "-c", str(count), "-W", str(int(timeout_sec)), host]

    started = time.perf_counter()
    try:
        completed = winproc.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec * count + 3,
            check=False,
        )
        latency = (time.perf_counter() - started) * 1000
        out = (completed.stdout or "") + (completed.stderr or "")
        # Windows often returns 0 even for "Destination net unreachable" ICMP errors.
        unreachable_markers = (
            "destination net unreachable",
            "destination host unreachable",
            "destination protocol unreachable",
            "general failure",
            "request timed out",
            "100% loss",
            "could not find host",
            "transmit failed",
        )
        out_l = out.lower()
        icmp_error = any(m in out_l for m in unreachable_markers)
        ok = completed.returncode == 0 and not icmp_error
        # Extract a more precise latency if present
        rtt = _parse_rtt_ms(out) if ok else None
        if rtt is None and ok:
            rtt = latency / max(count, 1)
        msg = "reachable"
        if not ok:
            if icmp_error:
                msg = "unreachable (ICMP error / timeout)"
            else:
                msg = "unreachable"
        return ProbeResult(
            kind=ProbeKind.PING.value,
            status=ProbeStatus.OK.value if ok else ProbeStatus.FAIL.value,
            target=host,
            subnet=subnet,
            interface=interface,
            message=msg,
            latency_ms=round(rtt, 2) if rtt is not None else None,
            detail={"raw_tail": out.strip()[-400:]},
            ts=utc_now(),
        )
    except subprocess.TimeoutExpired:
        return ProbeResult(
            kind=ProbeKind.PING.value,
            status=ProbeStatus.FAIL.value,
            target=host,
            subnet=subnet,
            interface=interface,
            message="ping timed out",
            ts=utc_now(),
        )
    except OSError as exc:
        return ProbeResult(
            kind=ProbeKind.PING.value,
            status=ProbeStatus.ERROR.value,
            target=host,
            subnet=subnet,
            interface=interface,
            message=f"ping failed to launch: {exc}",
            ts=utc_now(),
        )


def _parse_rtt_ms(output: str) -> float | None:
    # Windows: Average = 12ms / Average = 12ms
    # Linux: rtt min/avg/max/mdev = 0.123/1.2/2.3/0.4 ms
    import re

    m = re.search(r"Average\s*=\s*(\d+)\s*ms", output, re.I)
    if m:
        return float(m.group(1))
    m = re.search(r"=\s*[\d.]+/([\d.]+)/", output)
    if m:
        return float(m.group(1))
    m = re.search(r"time[=<]([\d.]+)\s*ms", output, re.I)
    if m:
        return float(m.group(1))
    return None


def dhcp_discover(
    *,
    bind_ip: str = "0.0.0.0",
    timeout_sec: float = 5.0,
    subnet: str = "",
    interface: str = "",
    release_offer: bool = True,
) -> ProbeResult:
    """Send a DHCPDISCOVER and wait for a DHCPOFFER.

    Requires permission to bind UDP port 68 (often admin/root). On failure due
    to permissions, returns status ``error`` with a clear message rather than
    crashing the beacon loop.
    """
    xid = random.randint(1, 0xFFFFFFFF)
    chaddr = bytes([random.randint(0, 255) for _ in range(6)])
    packet = _build_dhcp_discover(xid, chaddr)

    sock: socket.socket | None = None
    started = time.perf_counter()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError:
            pass
        sock.settimeout(timeout_sec)
        try:
            sock.bind((bind_ip, 68))
        except OSError as exc:
            return ProbeResult(
                kind=ProbeKind.DHCP.value,
                status=ProbeStatus.ERROR.value,
                target="255.255.255.255:67",
                subnet=subnet,
                interface=interface,
                message=(
                    f"Cannot bind UDP/68 ({exc}). Run beacon as admin/root, "
                    "or disable DHCP probes on this beacon."
                ),
                ts=utc_now(),
            )

        sock.sendto(packet, ("255.255.255.255", 67))
        # Collect responses until timeout for a matching xid OFFER
        deadline = time.perf_counter() + timeout_sec
        while time.perf_counter() < deadline:
            remaining = max(0.05, deadline - time.perf_counter())
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                break
            offer = _parse_dhcp_offer(data, xid)
            if offer is None:
                continue
            latency = (time.perf_counter() - started) * 1000
            yiaddr = offer["yiaddr"]
            server = offer.get("server_id") or addr[0]
            # Optionally decline/release so we don't consume a real lease long-term
            if release_offer and yiaddr and yiaddr != "0.0.0.0":
                try:
                    decline = _build_dhcp_decline(xid, chaddr, yiaddr, server)
                    sock.sendto(decline, ("255.255.255.255", 67))
                except OSError:
                    pass
            return ProbeResult(
                kind=ProbeKind.DHCP.value,
                status=ProbeStatus.OK.value,
                target=server,
                subnet=subnet or offer.get("subnet", ""),
                interface=interface,
                message=f"OFFER {yiaddr} from {server}",
                latency_ms=round(latency, 2),
                detail=offer,
                ts=utc_now(),
            )

        return ProbeResult(
            kind=ProbeKind.DHCP.value,
            status=ProbeStatus.FAIL.value,
            target="255.255.255.255:67",
            subnet=subnet,
            interface=interface,
            message=f"No DHCPOFFER within {timeout_sec:.0f}s",
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
            ts=utc_now(),
        )
    except OSError as exc:
        return ProbeResult(
            kind=ProbeKind.DHCP.value,
            status=ProbeStatus.ERROR.value,
            target="255.255.255.255:67",
            subnet=subnet,
            interface=interface,
            message=f"DHCP probe error: {exc}",
            ts=utc_now(),
        )
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# --- DHCP packet helpers (minimal RFC 2131) ---------------------------------


def _build_dhcp_discover(xid: int, chaddr: bytes) -> bytes:
    # BOOTREQUEST
    msg = bytearray(240)
    msg[0] = 1  # op
    msg[1] = 1  # htype ethernet
    msg[2] = 6  # hlen
    msg[3] = 0  # hops
    struct.pack_into("!I", msg, 4, xid)
    # secs, flags (broadcast)
    struct.pack_into("!HH", msg, 8, 0, 0x8000)
    # ciaddr, yiaddr, siaddr, giaddr = 0
    msg[28:34] = chaddr
    # magic cookie
    msg[236:240] = b"\x63\x82\x53\x63"
    # options: 53=DHCPDISCOVER, 55=param request, 255=end
    options = bytes(
        [
            53,
            1,
            1,  # DHCPDISCOVER
            55,
            4,
            1,
            3,
            6,
            15,  # request subnet, router, dns, domain
            255,
        ]
    )
    return bytes(msg) + options


def _build_dhcp_decline(xid: int, chaddr: bytes, yiaddr: str, server: str) -> bytes:
    msg = bytearray(240)
    msg[0] = 1
    msg[1] = 1
    msg[2] = 6
    struct.pack_into("!I", msg, 4, xid)
    struct.pack_into("!HH", msg, 8, 0, 0x8000)
    try:
        msg[16:20] = socket.inet_aton(yiaddr)  # yiaddr field unused in DECLINE; put in option
    except OSError:
        pass
    msg[28:34] = chaddr
    msg[236:240] = b"\x63\x82\x53\x63"
    opts = bytearray([53, 1, 4])  # DHCPDECLINE
    try:
        opts += bytes([50, 4]) + socket.inet_aton(yiaddr)  # requested IP
        opts += bytes([54, 4]) + socket.inet_aton(server)  # server id
    except OSError:
        pass
    opts.append(255)
    return bytes(msg) + bytes(opts)


def _parse_dhcp_offer(data: bytes, expected_xid: int) -> dict | None:
    if len(data) < 240:
        return None
    if data[0] != 2:  # BOOTREPLY
        return None
    xid = struct.unpack_from("!I", data, 4)[0]
    if xid != expected_xid:
        return None
    if data[236:240] != b"\x63\x82\x53\x63":
        return None
    yiaddr = socket.inet_ntoa(data[16:20])
    msg_type = None
    server_id = None
    subnet_mask = None
    router = None
    i = 240
    while i < len(data):
        code = data[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(data):
            break
        length = data[i + 1]
        val = data[i + 2 : i + 2 + length]
        if code == 53 and length == 1:
            msg_type = val[0]
        elif code == 54 and length == 4:
            server_id = socket.inet_ntoa(val)
        elif code == 1 and length == 4:
            subnet_mask = socket.inet_ntoa(val)
        elif code == 3 and length >= 4:
            router = socket.inet_ntoa(val[:4])
        i += 2 + length
    if msg_type != 2:  # DHCPOFFER
        return None
    return {
        "yiaddr": yiaddr,
        "server_id": server_id,
        "subnet_mask": subnet_mask,
        "router": router,
        "subnet": f"{yiaddr}/{subnet_mask}" if subnet_mask else yiaddr,
    }
