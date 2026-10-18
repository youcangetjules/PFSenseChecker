"""Auto-detection of device joins (links) from parsed configs.

MikroTik exports usually carry port comments naming the far end
(e.g. sfp7 = "CRS109-1 (Office)"), and uplink ports are commented
">> Uplink" / ">> Main uplink to PFSense". This module turns those hints,
plus hostname matching, into topology links so the user does not have to
wire the site by hand after a folder import.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from pfsense_checker.models import CheckResult
from pfsense_checker.topology_site import Device, Link, SiteTopology

_UPLINK_RE = re.compile(r"\buplink\b", re.I)


def _norm(s: str) -> str:
    return "".join(ch for ch in (s or "").lower() if ch.isalnum())


@dataclass
class LinkDiscoveryReport:
    links_added: list[Link] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if not self.links_added:
            return "no new links auto-detected"
        pairs = ", ".join(
            f"{l.a_device}:{l.a_port or '?'}↔{l.b_device}:{l.b_port or '?'}"
            for l in self.links_added
        )
        return f"auto-detected {len(self.links_added)} link(s): {pairs}"


def _iface_comments(result: CheckResult) -> list[tuple[str, str]]:
    """(port_name, comment) pairs with non-empty comments."""
    out = []
    for iface in result.interfaces:
        if iface.descr:
            out.append((iface.name, iface.descr))
    return out


def _tagged_vlans_for_port(result: CheckResult, port: str) -> list[str]:
    """VLAN ids tagged on a port according to /interface bridge vlan rows."""
    vlans: list[str] = []
    for row in result.summary.get("bridge_vlans", []) or []:
        tagged = {p.strip().lower() for p in str(row.get("tagged", "")).split(",")}
        if port.lower() in tagged:
            for vid in str(row.get("vlan_ids", "")).split(","):
                vid = vid.strip()
                if vid and vid not in vlans:
                    vlans.append(vid)
    return sorted(vlans, key=lambda v: (len(v), v))


def _far_port_on(
    far_result: CheckResult | None,
    near_device: Device,
) -> str:
    """Best-effort far-end port: reverse comment match, else lone uplink port."""
    if far_result is None:
        return ""
    near_norm = _norm(near_device.name)
    for port, comment in _iface_comments(far_result):
        c = _norm(comment)
        if near_norm and len(near_norm) >= 4 and near_norm in c:
            return port
        if near_device.kind in ("pfsense", "opnsense") and "pfsense" in c:
            return port
    uplinks = [
        port
        for port, comment in _iface_comments(far_result)
        if _UPLINK_RE.search(comment)
    ]
    if len(uplinks) == 1:
        return uplinks[0]
    return ""


def _existing_pair(site: SiteTopology, a: str, b: str) -> bool:
    for link in site.links:
        if {link.a_device, link.b_device} == {a, b}:
            return True
    return False


def infer_links(
    site: SiteTopology,
    results: dict[str, CheckResult],
) -> LinkDiscoveryReport:
    """Detect device joins from port comments and hostnames.

    results maps topology device name -> parsed CheckResult.
    Only adds links between devices that both exist in the site, and never
    duplicates a link the user already declared for a device pair.
    """
    report = LinkDiscoveryReport()
    devices = {d.name: d for d in site.devices}
    pfsense_devs = [
        d for d in site.devices if d.kind in ("pfsense", "opnsense")
    ]

    norm_names: list[tuple[str, str]] = [
        (name, _norm(name)) for name in devices if len(_norm(name)) >= 4
    ]

    for a_name, result in results.items():
        if a_name not in devices:
            continue
        for a_port, comment in _iface_comments(result):
            c = _norm(comment)
            target: Device | None = None
            # 1. Far-end device named in the port comment
            for b_name, b_norm in norm_names:
                if b_name == a_name:
                    continue
                if b_norm in c:
                    target = devices[b_name]
                    break
            # 2. Generic pfSense uplink hint (">> Main uplink to PFSense")
            if target is None and "pfsense" in c and len(pfsense_devs) == 1:
                if pfsense_devs[0].name != a_name:
                    target = pfsense_devs[0]
            if target is None:
                continue
            if _existing_pair(site, a_name, target.name):
                continue

            b_port = _far_port_on(results.get(target.name), devices[a_name])
            vlans = _tagged_vlans_for_port(result, a_port)
            if not vlans and target.name in results:
                vlans = _tagged_vlans_for_port(results[target.name], b_port)
            kind = "trunk" if vlans else ("sfp" if "sfp" in a_port.lower() else "copper")
            link = Link(
                a_device=a_name,
                a_port=a_port,
                b_device=target.name,
                b_port=b_port,
                kind=kind,
                vlans=vlans,
                descr=f"auto-detected ({comment.strip()[:60]})",
            )
            site.links.append(link)
            report.links_added.append(link)

    if not report.links_added:
        report.notes.append(
            "No joins auto-detected — add links manually in Links / Trunks"
        )
    return report


def infer_links_for_site(site: SiteTopology) -> LinkDiscoveryReport:
    """Convenience: parse each device's attached config, then infer links."""
    from pfsense_checker.checker import check_file

    results: dict[str, CheckResult] = {}
    for dev in site.devices:
        src = dev.ensure_config_source()
        path = src.analyzable_path() if src else ""
        if not path:
            continue
        try:
            results[dev.name] = check_file(path)
        except Exception:  # noqa: BLE001 — device simply excluded from inference
            continue
    return infer_links(site, results)


def joined_summary(site: SiteTopology) -> list[dict[str, Any]]:
    """Tabular 'how devices are joined' rows for display."""
    rows = []
    for link in site.links:
        rows.append(
            {
                "a": f"{link.a_device}:{link.a_port}" if link.a_port else link.a_device,
                "b": f"{link.b_device}:{link.b_port}" if link.b_port else link.b_device,
                "kind": link.kind,
                "vlans": ",".join(link.vlans),
                "descr": link.descr,
            }
        )
    return rows
