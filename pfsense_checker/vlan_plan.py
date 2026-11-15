"""Planned VLANs on a port (Topology → right-click a port → Add VLAN to this port…).

A port's VLANs come from the device's own config. A *planned* VLAN is one the
operator wants to add: it is kept with the topology (``Device.planned_vlans``),
drawn on the port as a hatched stripe, and ``commands()`` writes out what to
enter on the device to make it real. NetCheck never changes the device itself.

RouterOS commands follow how that bridge really enforces VLANs
(vlan_enforcement): switch-chip tables on CRS1xx / 2xx with vlan-filtering=no,
or the bridge VLAN table with vlan-filtering=yes. Qt-free. (added 2026-11-15)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pfsense_checker.port_vlans import PortVlans, _list, _vid_key, _vids

MIN_VID, MAX_VID = 1, 4094


def plan_of(device) -> dict[str, dict[str, list[str]]]:  # noqa: ANN001
    """The device's plan: {port (lower): {"tagged": [...], "untagged": [...]}}."""
    plan = getattr(device, "planned_vlans", None)
    if plan is None:
        plan = {}
        device.planned_vlans = plan
    return plan


def valid_vid(text: str) -> str:
    """The VLAN id as a clean string, or "" when it is not 1–4094."""
    try:
        n = int(str(text).strip())
    except ValueError:
        return ""
    return str(n) if MIN_VID <= n <= MAX_VID else ""


def add(device, port: str, vid: str, tagged: bool, existing: PortVlans | None = None) -> str:  # noqa: ANN001
    """Plan VLAN *vid* on *port*. Returns "" or why it was not added."""
    vid = valid_vid(vid)
    if not vid:
        return f"A VLAN id is a number from {MIN_VID} to {MAX_VID}."
    if existing is not None and vid in existing.vlans:
        how = "untagged" if vid in existing.untagged else "tagged"
        return f"VLAN {vid} is already on {port} ({how}) in the device's config."
    entry = plan_of(device).setdefault(port.lower(), {"tagged": [], "untagged": []})
    if vid in entry["tagged"] or vid in entry["untagged"]:
        return f"VLAN {vid} is already planned on {port}."
    if not tagged and (entry["untagged"] or (existing is not None and existing.untagged)):
        have = ", ".join(entry["untagged"] or (existing.untagged if existing else []))
        return (f"{port} already has an untagged (access) VLAN ({have}); a port can only have one. "
                "Add this one as tagged, or change the access VLAN on the device.")
    entry["tagged" if tagged else "untagged"].append(vid)
    return ""


def remove(device, port: str, vid: str) -> bool:  # noqa: ANN001
    plan = plan_of(device)
    entry = plan.get(port.lower())
    if not entry:
        return False
    found = False
    for key in ("tagged", "untagged"):
        if vid in entry[key]:
            entry[key].remove(vid)
            found = True
    if not entry["tagged"] and not entry["untagged"]:
        plan.pop(port.lower(), None)
    return found


def planned_on(device, port: str) -> list[tuple[str, bool]]:  # noqa: ANN001
    """[(vid, tagged)] planned on *port*, in VLAN order."""
    entry = plan_of(device).get(port.lower()) or {}
    rows = [(v, True) for v in entry.get("tagged", [])] + [(v, False) for v in entry.get("untagged", [])]
    return sorted(rows, key=lambda r: _vid_key(r[0]))


def merged(existing: PortVlans | None, entry: dict[str, list[str]] | None) -> tuple[PortVlans | None, set[str]]:
    """(the port's VLANs with the plan added, the planned VLAN ids). A new object:
    the config's own PortVlans is shared and must not change."""
    if not entry or not (entry.get("tagged") or entry.get("untagged")):
        return existing, set()
    base = existing or PortVlans()
    out = PortVlans(untagged=list(base.untagged), tagged=list(base.tagged), notes=list(base.notes),
                    ssid=base.ssid, via=base.via)
    planned: set[str] = set()
    for key in ("tagged", "untagged"):
        target = getattr(out, key)
        for vid in entry.get(key, []):
            if vid not in out.vlans:
                target.append(vid)
                planned.add(vid)
    return out, planned


# --------------------------------------------------------------------------- #
# What to enter on the device


def _join(old: list[str], port: str) -> str:
    return ",".join([*old, port] if port not in old else old)


def _mikrotik_commands(raw: dict[str, list[dict[str, Any]]], model: str, port: str, vid: str,
                       tagged: bool) -> list[str]:
    from pfsense_checker import vlan_enforcement as ve

    bridge = next((bp.get("bridge", "") for bp in raw.get("interface bridge port", [])
                   if (bp.get("interface") or "").lower() == port.lower()), "")
    how = "tagged" if tagged else "untagged (access)"
    out = [f"# VLAN {vid} {how} on {port}" + (f" (bridge {bridge})" if bridge else "")]
    if not bridge:
        out.append(f"# {port} is not in a bridge: add it to the bridge that carries VLAN {vid} first.")
        return out
    enf = ve.bridge_enforcement(raw, bridge, model)
    if enf.mode == ve.MODE_SWITCH_CHIP:
        out.append("# This switch forwards VLANs in the switch chip (vlan-filtering=no by design).")
        row = next((r for r in raw.get("interface ethernet switch vlan", []) if vid in _vids(r.get("vlan-id"))), None)
        if row is not None:
            out.append(f"/interface ethernet switch vlan set [find vlan-id={vid}] ports={_join(_list(row.get('ports')), port)}")
        else:
            out.append(f"/interface ethernet switch vlan add vlan-id={vid} ports={port}")
            out.append(f"#   VLAN {vid} is new on this switch: add the uplink port to ports= too "
                       "(and switch1-cpu if the switch needs an address in it).")
        if tagged:
            tag = next((r for r in raw.get("interface ethernet switch egress-vlan-tag", [])
                        if vid in _vids(r.get("vlan-id"))), None)
            if tag is not None:
                out.append("/interface ethernet switch egress-vlan-tag set "
                           f"[find vlan-id={vid}] tagged-ports={_join(_list(tag.get('tagged-ports')), port)}")
            else:
                out.append(f"/interface ethernet switch egress-vlan-tag add vlan-id={vid} tagged-ports={port}")
        else:
            out.append("/interface ethernet switch ingress-vlan-translation add "
                       f"ports={port} customer-vid=0 new-customer-vid={vid}")
        return out
    if enf.mode == ve.MODE_NONE:
        out.append(f"# Bridge {bridge} does not enforce VLANs yet (vlan-filtering=no and no switch-chip rules). "
                   "The lines below add the VLAN to the bridge table; turn enforcement on for them to take effect.")
    row = next((r for r in raw.get("interface bridge vlan", [])
                if r.get("bridge") == bridge and _vids(r.get("vlan-ids")) == [vid]), None)
    key = "tagged" if tagged else "untagged"
    if row is not None:
        out.append(f"/interface bridge vlan set [find bridge={bridge} vlan-ids={vid}] "
                   f"{key}={_join(_list(row.get(key)), port)}")
    else:
        out.append(f"/interface bridge vlan add bridge={bridge} vlan-ids={vid} {key}={port}")
        out.append(f"#   VLAN {vid} is new on this bridge: add the uplink port (and {bridge} itself if the "
                   "device needs an address in it) to tagged=.")
    if not tagged:
        out.append(f"/interface bridge port set [find interface={port}] pvid={vid}")
    return out


def _pfsense_steps(result, port: str, vid: str, tagged: bool) -> list[str]:  # noqa: ANN001
    iface = next((i for i in result.interfaces if (i.name or "").lower() == port.lower()), None)
    nic = (iface.device if iface is not None else "") or port
    label = f"{port.upper()}" + (f" ({iface.descr})" if iface is not None and iface.descr else "")
    if not tagged:
        return [f"# VLAN {vid} untagged on {label}",
                f"# pfSense sends untagged traffic on {nic} as the interface itself. To make {vid} the untagged "
                "VLAN there, set it as the access / native VLAN on the switch port at the other end."]
    return [f"# VLAN {vid} tagged on {label} (NIC {nic}) — in the pfSense web interface:",
            f"1. Interfaces → Assignments → VLANs → Add: Parent interface {nic}, VLAN tag {vid}.",
            f"2. Interfaces → Assignments: add the new VLAN {vid} on {nic}, enable it and give it an address.",
            "3. Firewall → Rules: add rules on the new interface (it starts with none, so nothing passes)."]


def commands(device, result=None) -> list[str]:  # noqa: ANN001
    """Lines to enter on *device* for everything planned on it ("" lines separate ports).

    *result* is the device's parsed config (CheckResult); it is loaded from the
    device's attached config file when not given."""
    plan = plan_of(device)
    if not plan:
        return []
    if result is None:
        try:
            from pfsense_checker import device_identity
            from pfsense_checker.checker import check_file

            path = device_identity.config_path_for(device)
            result = check_file(path) if path and Path(path).is_file() else None
        except Exception:  # noqa: BLE001
            result = None
    out: list[str] = [f"# {device.name}: planned VLANs. Check each line before entering it; "
                      "NetCheck has not changed the device."]
    kind = (getattr(result, "source_type", "") or getattr(device, "kind", "") or "").lower()
    for port in sorted(plan):
        for vid, tagged in planned_on(device, port):
            out.append("")
            real = _real_port_name(result, port)
            if result is not None and kind == "mikrotik":
                out += _mikrotik_commands(result.summary.get("raw", {}), result.summary.get("model", ""),
                                          real, vid, tagged)
            elif result is not None:
                out += _pfsense_steps(result, real, vid, tagged)
            else:
                how = "tagged" if tagged else "untagged (access)"
                out.append(f"# VLAN {vid} {how} on {real}: no config is loaded for this device, so there are "
                           "no exact commands. Add it in the device's own interface.")
    return out


def _real_port_name(result, port: str) -> str:  # noqa: ANN001
    """The port's name with the config's own capitalisation."""
    if result is None:
        return port
    for i in result.interfaces:
        if (i.name or "").lower() == port.lower():
            return i.name
    for bp in result.summary.get("raw", {}).get("interface bridge port", []):
        if (bp.get("interface") or "").lower() == port.lower():
            return bp["interface"]
    return port
