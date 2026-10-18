"""Import Excel 'Physical Layout' workbooks into a SiteTopology.

Tuned for the home-network physical-layout spreadsheet style:
device titles (Firewall N / SECPOL), nearby hardware names, CRS port strips,
and IF / NW / S-IP / DHCP attachment cards.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from pfsense_checker.topology_site import (
    Device,
    EgressPath,
    Link,
    SiteTopology,
    SiteVlan,
    VpnAgreement,
)

_SECPOL_RE = re.compile(
    r"Firewall\s+(\d+)\s+SEC(?:POL)?\s*:\s*(S\d+)", re.I
)
_SEC_SHORT_RE = re.compile(r"Firewall\s+(\d+)\s+SEC\s*:\s*(S\d+)", re.I)
_CRS328_RE = re.compile(r"Mikrotik\s+CRS328", re.I)
_CRS109_RE = re.compile(r"Mikrotik\s+CRS109[-\s]*(\d+)?\s*\(([^)]+)\)", re.I)
_PFSENSE_RE = re.compile(r"PFSense|pfSense", re.I)
_EDGEROUTER_RE = re.compile(r"Edgerouter", re.I)
_SRX_RE = re.compile(r"Juniper\s+SRX", re.I)
_HAP_RE = re.compile(r"Mikrotik\s+Ax-S\s+HAP|hAP", re.I)
_ISP_TALKTALK_RE = re.compile(r"TalkTalk", re.I)
_ISP_SWISH_RE = re.compile(r"Swish\s+Internet|Swish\s+Fiber", re.I)
_ISP_4G_RE = re.compile(r"DLink|ThreeUK|4G", re.I)
_SERVER_RE = re.compile(r"DELL\s+Server|Dell\s+Server|Dell\s+Optiplex", re.I)
_ONT_RE = re.compile(r"\bONT\b", re.I)
_MEDIA_RE = re.compile(r"Media\s+Converter", re.I)
_EERO_RE = re.compile(r"\bEero\b", re.I)
_WIFI_RE = re.compile(r"Google\s+WiFi|Wi-?Fi", re.I)
_VPN_RE = re.compile(r"ExpressVPN\w*", re.I)
_IF_LABEL_RE = re.compile(r"^IF$", re.I)
_NW_RE = re.compile(r"^NW$", re.I)
_SIP_RE = re.compile(r"^S-IP(?:/GW)?$", re.I)
_DHCP_RE = re.compile(r"^DHCP$", re.I)
_VLAN_FROM_IF = re.compile(r"VL(\d+)", re.I)


def _cell_str(v: Any) -> str:
    if v is None:
        return ""
    return str(v).strip()


def _slug(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", name.strip())
    return s.strip("-") or "device"


def _infer_role_kind(text: str) -> tuple[str, str]:
    t = text.lower()
    if "crs328" in t:
        return "core-switch", "switch"
    if "crs109" in t:
        return "access-switch", "switch"
    if "pfsense" in t:
        return "firewall", "pfsense"
    if "edgerouter" in t or "srx" in t:
        return "egress", "router"
    if "hap" in t or "ax-s" in t:
        return "access-point", "mikrotik"
    if "talktalk" in t or "swish" in t or "4g" in t or "dlink" in t:
        return "isp", "isp"
    if "server" in t or "optiplex" in t:
        return "server", "server"
    if "eero" in t or "wifi" in t:
        return "access-point", "access-point"
    if "ont" in t or "media converter" in t:
        return "other", "other"
    if "expressvpn" in t:
        return "remote-router", "other"
    return "other", "other"


def _next_nonempty_right(ws, row: int, col: int, max_span: int = 8) -> str:  # noqa: ANN001
    for c in range(col + 1, col + max_span + 1):
        v = _cell_str(ws.cell(row, c).value)
        if v:
            return v
    return ""


def _collect_grid(ws) -> list[tuple[int, int, str]]:  # noqa: ANN001
    cells: list[tuple[int, int, str]] = []
    for r in range(1, (ws.max_row or 1) + 1):
        for c in range(1, (ws.max_column or 1) + 1):
            v = _cell_str(ws.cell(r, c).value)
            if v:
                cells.append((r, c, v))
    return cells


def _parse_vlan_cards(
    cells: list[tuple[int, int, str]],
) -> list[dict[str, str]]:
    """Find IF/NW/S-IP/DHCP label clusters; value is the cell to the right."""
    by_pos = {(r, c): v for r, c, v in cells}
    cards: list[dict[str, str]] = []
    seen: set[tuple[int, int]] = set()

    for r, c, v in cells:
        if not _IF_LABEL_RE.match(v):
            continue
        if (r, c) in seen:
            continue
        # Value for IF is typically 1–2 columns right
        if_val = ""
        for dc in (1, 2, 3):
            if_val = by_pos.get((r, c + dc), "")
            if if_val and not _IF_LABEL_RE.match(if_val):
                break
        if not if_val:
            continue
        card = {"if_label": if_val, "row": str(r), "col": str(c)}
        # Look down a few rows in same label column for NW / S-IP / DHCP
        for dr in range(1, 5):
            lab = by_pos.get((r + dr, c), "")
            val = ""
            for dc in (1, 2, 3):
                cand = by_pos.get((r + dr, c + dc), "")
                if cand and cand not in ("IF", "NW", "S-IP", "S-IP/GW", "DHCP"):
                    val = cand
                    break
            if _NW_RE.match(lab) and val:
                card["subnet"] = val
            elif _SIP_RE.match(lab) and val:
                card["s_ip"] = val
            elif _DHCP_RE.match(lab) and val:
                card["dhcp_pool"] = val
        cards.append(card)
        seen.add((r, c))
    return cards


def _device_near(cells: list[tuple[int, int, str]], row: int, col: int, radius: int = 3) -> str:
    """Pick a descriptive hardware name near a firewall title cell."""
    candidates: list[tuple[int, str]] = []
    for r, c, v in cells:
        if abs(r - row) > radius or abs(c - col) > 12:
            continue
        if _SECPOL_RE.search(v) or _SEC_SHORT_RE.search(v):
            continue
        if v in ("IF", "NW", "S-IP", "S-IP/GW", "DHCP", "Phy", "H/W  Firewall"):
            continue
        if len(v) < 4:
            continue
        # Prefer longer descriptive names to the right of the title
        dist = abs(r - row) * 10 + max(0, c - col)
        candidates.append((dist, v))
    candidates.sort()
    return candidates[0][1] if candidates else ""


def import_physical_layout_xlsx(path: Path | str) -> SiteTopology:
    """Parse a Physical Layout Excel workbook into SiteTopology."""
    try:
        from openpyxl import load_workbook
    except ImportError as exc:
        raise RuntimeError(
            "openpyxl is required to import Excel layouts. "
            "Run: pip install openpyxl"
        ) from exc

    path = Path(path)
    wb = load_workbook(path, data_only=True)
    # Prefer a sheet whose title mentions Physical Layout
    ws = None
    for name in wb.sheetnames:
        if "physical" in name.lower() or "layout" in name.lower():
            ws = wb[name]
            break
    if ws is None:
        ws = wb.active

    cells = _collect_grid(ws)
    site = SiteTopology(name=f"Imported — {path.stem}")
    devices: dict[str, Device] = {}

    def add_dev(name: str, **kwargs: Any) -> Device:
        key = name
        if key in devices:
            # Merge ports / blank fields
            existing = devices[key]
            for p in kwargs.get("ports", []) or []:
                if p not in existing.ports:
                    existing.ports.append(p)
            for field in ("model", "role", "secpol", "priority", "hardware", "notes", "kind"):
                if kwargs.get(field) and not getattr(existing, field):
                    setattr(existing, field, kwargs[field])
            return existing
        role, kind = kwargs.pop("role", None), kwargs.pop("kind", None)
        if role is None or kind is None:
            ir, ik = _infer_role_kind(name + " " + str(kwargs.get("model", "")))
            role = role or ir
            kind = kind or ik
        dev = Device(name=name, role=role, kind=kind, **kwargs)
        devices[key] = dev
        return dev

    # --- Priority band labels (for ISP notes) ---
    priority_bands: list[tuple[int, int, str, str]] = []  # row, col, label, pri
    for r, c, v in cells:
        m = re.search(r"Priority\s+(\d+)", v, re.I)
        if m and ("Online" in v or "Offline" in v):
            priority_bands.append((r, c, v, m.group(1)))

    def priority_for(col: int, row: int) -> str:
        best = ""
        best_dist = 10**9
        for br, bc, _lab, pri in priority_bands:
            if abs(br - row) > 5:
                continue
            dist = abs(bc - col)
            if dist < best_dist:
                best_dist = dist
                best = pri
        return best

    # --- Named gear ---
    for r, c, v in cells:
        m = _SECPOL_RE.search(v) or _SEC_SHORT_RE.search(v)
        if m:
            fw_num, secpol = m.group(1), m.group(2).upper()
            near = _device_near(cells, r, c)
            if not near:
                near = f"Firewall-{fw_num}"
            # Short display name
            if _PFSENSE_RE.search(near):
                name = "pfSense-FW"
                role, kind = "firewall", "pfsense"
                model = "pfSense"
                hardware = near
            elif _EDGEROUTER_RE.search(near):
                name = "Edgerouter-Egress"
                role, kind = "egress", "router"
                model = near.split("(")[0].strip()
                hardware = near
            elif _SRX_RE.search(near):
                name = "Juniper-SRX300"
                role, kind = "egress", "router"
                model = near.split("(")[0].strip()
                hardware = near
            elif _HAP_RE.search(near) or "HAP" in near.upper():
                name = "MikroTik-hAP"
                role, kind = "access-point", "mikrotik"
                model = near.split("(")[0].strip()
                hardware = near
            elif _CRS328_RE.search(near):
                name = "CRS328-Core"
                role, kind = "core-switch", "switch"
                model = "CRS328"
                hardware = near
            else:
                name = _slug(near)[:40]
                role, kind = _infer_role_kind(near)
                model = near.split("(")[0].strip()[:60]
                hardware = near
            add_dev(
                name,
                role=role,
                kind=kind,
                model=model,
                secpol=secpol,
                hardware=hardware,
                notes=f"Firewall {fw_num}",
            )
            continue

        if _CRS328_RE.search(v):
            add_dev(
                "CRS328-Core",
                role="core-switch",
                kind="switch",
                model="CRS328",
                secpol="S5",
                hardware=v,
            )
            continue

        m109 = _CRS109_RE.search(v)
        if m109:
            num = m109.group(1) or ""
            place = (m109.group(2) or "").strip()
            name = f"CRS109-{place or num or 'Access'}"
            add_dev(
                name,
                role="access-switch",
                kind="switch",
                model="CRS109",
                hardware=v,
                notes=place,
            )
            continue

        if _ISP_TALKTALK_RE.search(v) and "WAN" in v.upper():
            add_dev(
                "TalkTalk-WAN2",
                role="isp",
                kind="isp",
                model=v,
                priority=priority_for(c, r) or "1",
                notes=v,
                ports=["wan"],
            )
            continue
        if _ISP_SWISH_RE.search(v):
            add_dev(
                "Swish-WAN1",
                role="isp",
                kind="isp",
                model=v,
                priority=priority_for(c, r) or "0",
                notes=v,
                ports=["wan"],
            )
            continue
        if _ISP_4G_RE.search(v) and ("4G" in v or "DLink" in v or "Three" in v):
            add_dev(
                "ThreeUK-4G",
                role="isp",
                kind="isp",
                model=v,
                priority=priority_for(c, r) or "2",
                notes=v,
                ports=["wan"],
            )
            continue

        if _MEDIA_RE.search(v):
            add_dev(
                "Media-Converter",
                role="other",
                kind="other",
                model=v,
                notes="NOSEC passthrough",
            )
            continue
        if _ONT_RE.search(v):
            add_dev(
                "Swish-ONT",
                role="other",
                kind="other",
                model=v,
            )
            continue
        if _EERO_RE.search(v):
            add_dev("Amazon-Eero", role="access-point", kind="access-point", model=v)
            continue
        if _WIFI_RE.search(v) and "IF" not in v:
            add_dev("Google-WiFi", role="access-point", kind="access-point", model=v)
            continue
        if _SERVER_RE.search(v) and len(v) > 10:
            if _PFSENSE_RE.search(v):
                # Hardware line for the firewall — fold into pfSense-FW
                add_dev(
                    "pfSense-FW",
                    role="firewall",
                    kind="pfsense",
                    model="pfSense",
                    hardware=v,
                    secpol="S5",
                )
                continue
            name = _slug(v.split("(")[0])[:48]
            add_dev(name, role="server", kind="server", model=v, hardware=v)
            continue

        vpn = _VPN_RE.search(v)
        if vpn and v == vpn.group(0):
            add_dev(
                vpn.group(0),
                role="remote-router",
                kind="other",
                model=v,
                notes="ExpressVPN endpoint",
            )

    # --- CRS328 port strip (numbered ports on the same row as / near CRS328 title) ---
    crs_row = None
    for r, c, v in cells:
        if _CRS328_RE.search(v):
            crs_row = r
            break
    if "CRS328-Core" in devices and crs_row is not None:
        strip: list[tuple[int, str]] = []
        for r, c, v in cells:
            if abs(r - crs_row) > 3:
                continue
            if v.isdigit() and 1 <= int(v) <= 48:
                strip.append((c, v))
            elif re.fullmatch(r"C\d+|S\d+", v):
                strip.append((c, v))
        strip.sort(key=lambda t: t[0])
        uniq: list[str] = []
        seen_p: set[str] = set()
        for _c, p in strip:
            if p not in seen_p:
                seen_p.add(p)
                uniq.append(p)
        if uniq:
            devices["CRS328-Core"].ports = uniq
            devices["CRS328-Core"].components.clear()
            devices["CRS328-Core"].ensure_components()

    # pfSense NIC names from the sheet
    if "pfSense-FW" in devices:
        nic_names = []
        for _r, _c, v in cells:
            if re.fullmatch(r"EM-?\d+|BXE-?\d+|IGB-?\d+", v, re.I):
                nic_names.append(v.replace(" ", ""))
        for n in nic_names:
            if n not in devices["pfSense-FW"].ports:
                devices["pfSense-FW"].ports.append(n)

    # --- VLAN cards ---
    cards = _parse_vlan_cards(cells)
    vlan_by_id: dict[str, SiteVlan] = {}
    for card in cards:
        if_label = card.get("if_label", "")
        m = _VLAN_FROM_IF.search(if_label)
        vid = m.group(1) if m else ""
        if not vid:
            # synthesise from subnet hash-ish: use last octet pattern or skip id
            vid = if_label[:12] if if_label else "0"
        if vid not in vlan_by_id:
            vlan_by_id[vid] = SiteVlan(
                id=vid,
                name=if_label,
                if_label=if_label,
                subnet=card.get("subnet", ""),
                s_ip=card.get("s_ip", ""),
                dhcp_pool=card.get("dhcp_pool", ""),
            )
        else:
            existing = vlan_by_id[vid]
            if not existing.if_label:
                existing.if_label = if_label
            if not existing.subnet and card.get("subnet"):
                existing.subnet = card["subnet"]
            if not existing.s_ip and card.get("s_ip"):
                existing.s_ip = card["s_ip"]
            if not existing.dhcp_pool and card.get("dhcp_pool"):
                existing.dhcp_pool = card["dhcp_pool"]

    # Attach VLANs to likely devices by IF label hints
    for vid, vlan in vlan_by_id.items():
        label = (vlan.if_label or "").upper()
        if "PFSENSE" in label or "PF" in label:
            for n in ("pfSense-FW", "Edgerouter-Egress", "Juniper-SRX300"):
                if n in devices and n not in vlan.devices:
                    vlan.devices.append(n)
            vlan.gateway = "pfSense-FW" if "pfSense-FW" in devices else vlan.gateway
        if "IDRAC" in label or "SFP" in label:
            if "CRS328-Core" in devices and "CRS328-Core" not in vlan.devices:
                vlan.devices.append("CRS328-Core")
            for n, d in devices.items():
                if d.role == "server" and n not in vlan.devices:
                    vlan.devices.append(n)

    # --- Heuristic links (tier wiring, Excel left→right) ---
    links: list[Link] = []

    def link(a: str, ap: str, b: str, bp: str, **kw: Any) -> None:
        if a in devices and b in devices:
            links.append(Link(a_device=a, a_port=ap, b_device=b, b_port=bp, **kw))

    if "Swish-WAN1" in devices and "Juniper-SRX300" in devices:
        link("Swish-WAN1", "wan", "Juniper-SRX300", "ge-0/0/0", kind="fiber", speed="1G", descr="WAN1 main")
    elif "Swish-WAN1" in devices and "Edgerouter-Egress" in devices:
        link("Swish-WAN1", "wan", "Edgerouter-Egress", "eth0", kind="fiber", speed="1G", descr="WAN1 main")

    if "TalkTalk-WAN2" in devices and "Edgerouter-Egress" in devices:
        link("TalkTalk-WAN2", "wan", "Edgerouter-Egress", "eth1", kind="fiber", speed="1G", descr="WAN2 reserve")
    if "ThreeUK-4G" in devices and "Edgerouter-Egress" in devices:
        link("ThreeUK-4G", "wan", "Edgerouter-Egress", "eth2", kind="copper", speed="1G", descr="WAN3 backup")

    if "Edgerouter-Egress" in devices and "pfSense-FW" in devices:
        link("Edgerouter-Egress", "eth2", "pfSense-FW", "EM-0", kind="copper", speed="1G", descr="egress -> firewall")
    if "Juniper-SRX300" in devices and "pfSense-FW" in devices:
        link("Juniper-SRX300", "ge-0/0/6.0", "pfSense-FW", "BXE-0", kind="fiber", speed="1G", descr="SRX -> pfSense")
    if "Media-Converter" in devices and "pfSense-FW" in devices:
        link("Media-Converter", "fiber", "pfSense-FW", "BXE-0", kind="fiber", speed="1G", descr="media converter")

    if "pfSense-FW" in devices and "CRS328-Core" in devices:
        vlans = [v for v in vlan_by_id if v.isdigit()]
        link(
            "pfSense-FW", "BXE-1", "CRS328-Core", "S1",
            kind="trunk", speed="1G",
            vlans=vlans[:8] or ["140"],
            descr="firewall trunk",
        )

    # CRS328 → each CRS109
    crs109s = [n for n, d in devices.items() if d.role == "access-switch"]
    for i, name in enumerate(sorted(crs109s), start=1):
        link(
            "CRS328-Core", str(i), name, "sfp1",
            kind="trunk", speed="1G",
            vlans=[v for v in vlan_by_id if v.isdigit()][:6] or ["10"],
            descr=f"to {name}",
        )

    # Attach access VLANs to CRS109s
    for name in crs109s:
        for vid, vlan in vlan_by_id.items():
            if vid.isdigit() and name not in vlan.devices:
                # LAN-ish VLANs
                if vlan.subnet or "LAN" in (vlan.if_label or "").upper() or vid in ("10", "20", "30"):
                    vlan.devices.append(name)

    # VPN agreements for ExpressVPN endpoints
    vpns = [n for n, d in devices.items() if "ExpressVPN" in n]
    for i, vpn_name in enumerate(vpns[:4], start=1):
        if "pfSense-FW" in devices:
            site_vpn_name = f"VPN{i}-{vpn_name}"
            # stored later

    site.devices = list(devices.values())
    for d in site.devices:
        d.ensure_components()
    site.links = links
    site.vlans = list(vlan_by_id.values())
    site.ensure_positions()

    # Egress path
    if "Juniper-SRX300" in devices and "Swish-WAN1" in devices:
        site.egress.append(
            EgressPath(
                name="Primary-WAN",
                device="Juniper-SRX300",
                uplink_port="ge-0/0/0",
                upstream="Swish-WAN1",
                wan_subnet="dhcp",
                default_for=["all"],
                notes="Priority 0 main (from Excel)",
            )
        )
    elif "Edgerouter-Egress" in devices:
        up = "Swish-WAN1" if "Swish-WAN1" in devices else (
            "TalkTalk-WAN2" if "TalkTalk-WAN2" in devices else ""
        )
        site.egress.append(
            EgressPath(
                name="Primary-WAN",
                device="Edgerouter-Egress",
                uplink_port="eth0",
                upstream=up,
                wan_subnet="dhcp",
                default_for=["all"],
                notes="from Excel import",
            )
        )

    for i, vpn_name in enumerate(vpns[:4], start=1):
        if "pfSense-FW" in devices:
            site.vpn.append(
                VpnAgreement(
                    name=f"VPN{i}-{vpn_name}",
                    kind="openvpn",
                    a_device="pfSense-FW",
                    b_device=vpn_name,
                    notes="ExpressVPN from Excel layout",
                )
            )

    return site


def import_physical_layout_summary(site: SiteTopology) -> str:
    return (
        f"{len(site.devices)} devices · {len(site.links)} links · "
        f"{len(site.vlans)} VLAN cards · {len(site.vpn)} VPN · "
        f"{len(site.egress)} egress"
    )
