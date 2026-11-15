"""Dashboard tiles → "Show and explain": what each number counts, why it matters,
and exactly what is behind it, from the loaded config. Qt-free; returns HTML.
(added 2026-11-15)
"""

from __future__ import annotations

from html import escape

from pfsense_checker.models import CheckResult, Severity

TILES = ("verdict", "errors", "warnings", "interfaces", "virtual", "fw", "vpn", "packages")

_INTRO = {
    "verdict": (
        "Result",
        "The overall verdict for this config. <b>PASS</b>: no errors or warnings. <b>EXPOSED</b>: no "
        "errors, but warnings that leave something open or fragile. <b>FAIL</b>: at least one error — "
        "something that is broken or unsafe. <b>INVALID</b>: the file could not be read as a config.",
    ),
    "errors": (
        "Errors",
        "Findings that are broken or unsafe as configured: traffic that cannot work, management "
        "open to the Internet, rules that contradict each other. Fix these first.",
    ),
    "warnings": (
        "Warnings",
        "Findings that work today but are risky, wasteful or likely to break: weak crypto, "
        "unused objects, settings that differ from the rest of the network.",
    ),
    "interfaces": (
        "Interfaces",
        "Enabled / total interfaces in the config (ports, VLAN interfaces, bridges, tunnels). "
        "Disabled ones carry no traffic; check they are meant to be off.",
    ),
    "virtual": (
        "Bridges / VLANs / LAGGs",
        "Virtual interfaces built on the physical ports: bridges join ports into one network, "
        "VLANs split a port into tagged networks, LAGGs bundle ports for speed or failover.",
    ),
    "fw": (
        "Firewall rules",
        "Filter rules, in the order the firewall evaluates them. Disabled rules are listed but do "
        "nothing. A pass rule high in the list can hide every rule below it.",
    ),
    "vpn": (
        "VPN endpoints",
        "VPN servers, clients and tunnels (OpenVPN, IPsec, WireGuard). Each one is a way into or "
        "out of the network, so each should be known and wanted.",
    ),
    "packages": (
        "Packages",
        "Add-on packages installed on the firewall. Every package is more code that can have "
        "flaws; remove what is not used.",
    ),
}


def _table(headers: list[str], rows: list[list[str]], empty: str) -> str:
    if not rows:
        return f"<p><i>{escape(empty)}</i></p>"
    head = "".join(f"<th align='left' style='padding:2px 8px;'>{escape(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td style='padding:2px 8px;'>{escape(str(c))}</td>" for c in r) + "</tr>"
        for r in rows
    )
    return f"<table cellspacing='0' border='1' style='border-collapse:collapse;'><tr>{head}</tr>{body}</table>"


def _findings(result: CheckResult, severity: Severity) -> str:
    rows = [[f.category or "—", f.message, f.remediation or "—"]
            for f in result.findings if f.severity == severity]
    return _table(["Area", "Finding", "Fix"], rows, f"No {severity.value}s in this config.")


def explain(key: str, result: CheckResult | None) -> tuple[str, str]:
    """(title, HTML) for tile *key*."""
    title, intro = _INTRO.get(key, (key, ""))
    if result is None:
        return title, f"<p>{intro}</p><p><i>Load a config to see what is behind this tile.</i></p>"
    s = result.summary
    who = escape(result.hostname or (result.path.name if result.path else "this config"))
    parts = [f"<p>{intro}</p>", f"<p style='color:#607d8b;'>Config: <b>{who}</b></p>"]
    if key == "verdict":
        parts.append(f"<p>{result.error_count} error(s), {result.warning_count} warning(s).</p>")
        if s.get("assessment"):
            parts.append(f"<pre>{escape(str(s['assessment']))}</pre>")
        parts.append("<h4>Errors</h4>" + _findings(result, Severity.ERROR))
        parts.append("<h4>Warnings</h4>" + _findings(result, Severity.WARNING))
    elif key == "errors":
        parts.append(_findings(result, Severity.ERROR))
    elif key == "warnings":
        parts.append(_findings(result, Severity.WARNING))
    elif key == "interfaces":
        rows = [[i.name, i.descr, i.device, "yes" if i.enabled else "NO",
                 (f"{i.ipaddr}/{i.subnet}" if i.subnet and i.ipaddr not in ("dhcp", "pppoe") else i.ipaddr) or "—",
                 i.kind]
                for i in result.interfaces]
        parts.append(_table(["Name", "Description", "Device", "Enabled", "Address", "Kind"], rows,
                            "No interfaces found."))
    elif key == "virtual":
        parts.append("<h4>Bridges</h4>" + _table(
            ["Bridge", "Members", "Description", "STP"],
            [[b.bridgeif, ", ".join(b.members), b.descr, "on" if b.stp_enabled else "off"] for b in result.bridges],
            "No bridges."))
        parts.append("<h4>VLANs</h4>" + _table(
            ["Tag", "Parent", "Interface", "Description"],
            [[v.tag, v.if_parent, v.vlanif, v.descr] for v in result.vlans], "No VLANs."))
        parts.append("<h4>LAGGs</h4>" + _table(
            ["LAGG", "Members", "Protocol", "Description"],
            [[g.laggif, ", ".join(g.members), g.proto, g.descr] for g in result.laggs], "No LAGGs."))
    elif key == "fw":
        rows = [[r.index, r.type, r.interface, r.protocol or "any", r.source or "any",
                 r.destination or "any", r.dst_port or "", "off" if r.disabled else "", r.descr]
                for r in result.filter_rules]
        parts.append(_table(["#", "Action", "Interface", "Proto", "Source", "Destination", "Port", "Disabled",
                             "Description"], rows, "No filter rules."))
    elif key == "vpn":
        rows = [[v.kind, v.name, v.peer or "—", v.interface or "—", ", ".join(v.networks) or "—",
                 "off" if v.disabled else "on"] for v in result.vpn]
        parts.append(_table(["Kind", "Name", "Peer", "Interface", "Networks", "State"], rows, "No VPN endpoints."))
    elif key == "packages":
        rows = [[p.name, p.version, "off" if p.enabled is False else ("on" if p.enabled else "?"), p.descr]
                for p in result.packages]
        parts.append(_table(["Package", "Version", "Enabled", "Description"], rows, "No packages installed."))
    return title, "".join(parts)
