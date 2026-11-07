"""Build the DNS Leakage test package.

One zip runs anywhere on the site: it holds a profile per VLAN (subnet and the
resolver clients there should use, read from the loaded firewall / router
config), and ``dns_leak.py`` picks the profile from the address of the machine
it runs on. Standard-library Python 3.8+ is all it needs.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import re
import zipfile
from pathlib import Path

from pfsense_checker import dns_leak
from pfsense_checker.models import CheckResult

PACKAGE_DIR = "netcheck-dnsleak"


def _split(text: str) -> list[str]:
    return [x for x in re.split(r"[\s,;]+", text or "") if x]


def _ips(values) -> list[str]:  # noqa: ANN001
    out = []
    for v in values:
        try:
            ip = str(ipaddress.ip_address(str(v).strip()))
        except ValueError:
            continue
        if ip not in out:
            out.append(ip)
    return out


def profiles_from_config(result: CheckResult) -> list[dict]:
    """One profile per addressed, enabled interface: label, subnet, expected resolvers."""
    if result.source_type == "mikrotik":
        return _profiles_mikrotik(result)
    return _profiles_pfsense(result)


def _profiles_pfsense(result: CheckResult) -> list[dict]:
    dns = result.dns or {}
    local_resolver = bool(dns.get("resolver") or dns.get("unbound_enable") or dns.get("forwarder"))
    scopes = {s.get("interface", "").lower(): s for s in result.dhcp_scopes}
    out: list[dict] = []
    for iface in result.interfaces:
        if not iface.enabled or not iface.ipaddr or iface.ipaddr in ("dhcp", "pppoe", "dhcp6"):
            continue
        try:
            net = ipaddress.ip_interface(f"{iface.ipaddr}/{iface.subnet or 32}")
        except ValueError:
            continue
        if net.network.prefixlen >= 31:
            continue
        scope = scopes.get(iface.name.lower(), {})
        expected = _ips(_split(scope.get("dnsservers", "")))
        source = "DHCP DNS servers"
        if not expected:
            if local_resolver:
                expected, source = [str(net.ip)], "firewall's own resolver on this interface"
            else:
                expected, source = _ips(dns.get("servers") or []), "system DNS servers"
        out.append({
            "label": f"{iface.name} {iface.descr}".strip(),
            "subnet": str(net.network),
            "expected_resolvers": expected,
            "source": source,
        })
    return out


def _profiles_mikrotik(result: CheckResult) -> list[dict]:
    raw = result.summary.get("raw", {})
    nets = []
    for row in raw.get("ip dhcp-server network", []):
        try:
            nets.append((ipaddress.ip_network(row.get("address", ""), strict=False), row))
        except ValueError:
            continue
    out: list[dict] = []
    for addr in raw.get("ip address", []):
        if str(addr.get("disabled", "no")).lower() in ("yes", "true"):
            continue
        try:
            net = ipaddress.ip_interface(addr.get("address", ""))
        except ValueError:
            continue
        if net.network.prefixlen >= 31:
            continue
        row = next((r for n, r in nets if n == net.network), {})
        expected = _ips(_split(row.get("dns-server", "")))
        source = "DHCP network dns-server"
        if not expected and row.get("gateway"):
            expected, source = _ips([row["gateway"]]), "DHCP gateway"
        if not expected:
            source = "not set — fill in"
        out.append({
            "label": addr.get("interface", "") or str(net.network),
            "subnet": str(net.network),
            "expected_resolvers": expected,
            "source": source,
        })
    return out


_CMD = """@echo off
rem NetCheck DNS leak test - double-click to run.
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (py -3 dns_leak.py %*) else (python dns_leak.py %*)
echo.
pause
"""

_SH = """#!/bin/sh
# NetCheck DNS leak test
cd "$(dirname "$0")" || exit 1
if command -v python3 >/dev/null 2>&1; then exec python3 dns_leak.py "$@"; fi
exec python dns_leak.py "$@"
"""


def _readme(site: str, profiles: list[dict]) -> str:
    lines = [
        f"NetCheck DNS leak test {dns_leak.VERSION}" + (f" - {site}" if site else ""),
        "",
        "Run it on a computer in the VLAN you want to test:",
        "  Windows:       double-click run_dns_leak.cmd",
        "  macOS / Linux: sh run_dns_leak.sh",
        "Needs Python 3.8 or newer; nothing else is installed.",
        "",
        "It picks the VLAN from this computer's address, then checks which DNS servers",
        "the computer uses, whether plain DNS to public resolvers gets out, is blocked or",
        "is redirected to your resolver, and whether DNS-over-TLS / DNS-over-HTTPS work.",
        "It sends ordinary DNS lookups (example.com, whoami.akamai.net,",
        "use-application-dns.net) to 1.1.1.1, 8.8.8.8, 9.9.9.9 and their DoT/DoH",
        "services. Use --no-public to skip those.",
        "",
        "The report is saved in the results folder. Copy it back to NetCheck and open it",
        "on the DNS Leakage page.",
        "",
        "VLAN profiles in this package:",
    ]
    for p in profiles:
        lines.append(f"  {p['subnet']:<20} {p['label']}  -> expects {', '.join(p['expected_resolvers']) or '?'}")
    return "\n".join(lines) + "\n"


def build_package(
    out_dir: Path | str,
    profiles: list[dict],
    *,
    site: str = "",
    expected_egress: list[str] | None = None,
) -> Path:
    """Write the zip; return its path."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    config = {
        "site": site,
        "profiles": [
            {k: p[k] for k in ("label", "subnet", "expected_resolvers") if k in p} for p in profiles
        ],
        "expected_egress": _ips(expected_egress or []),
        "timeout": 2.0,
        "public": True,
        "ipv6": True,
    }
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M")
    safe_site = re.sub(r"[^A-Za-z0-9._-]+", "_", site).strip("_")
    zpath = out_dir / f"netcheck-dnsleak{'-' + safe_site if safe_site else ''}-{stamp}.zip"
    script = Path(dns_leak.__file__).read_text(encoding="utf-8")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{PACKAGE_DIR}/dns_leak.py", script)
        z.writestr(f"{PACKAGE_DIR}/dnsleak.json", json.dumps(config, indent=2))
        z.writestr(f"{PACKAGE_DIR}/run_dns_leak.cmd", _CMD.replace("\n", "\r\n"))
        info = zipfile.ZipInfo(f"{PACKAGE_DIR}/run_dns_leak.sh")
        info.external_attr = 0o755 << 16
        z.writestr(info, _SH)
        z.writestr(f"{PACKAGE_DIR}/README.txt", _readme(site, profiles))
    return zpath


def load_report(path: Path | str) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("tool") != dns_leak.TOOL:
        raise ValueError("Not a NetCheck DNS leak report")
    return data
