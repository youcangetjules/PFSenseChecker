"""Do two devices' configs agree with each other?

Log Analysis can be pointed at two devices. Their logs are read together, and
this module compares their saved configs where the two have to match:

- the two ends of each cable drawn between them on the Topology map (which
  VLANs each port carries, tagged or untagged; MTU, speed, disabled ports),
- the VLANs each knows and what they are called,
- the addresses each has in a VLAN (same network, same mask, no duplicate),
- the wireless controller (MikroTik CAPsMAN) and the CAP that looks for it,
- general settings worth a look when they differ (RouterOS version, STP mode,
  DNS servers, default route).

Nothing is sent to a device. The findings use the Log Analysis ``Finding``
type so they sit in the same tree; ``Finding.notes`` carries the text shown
where a log finding shows its lines.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from pfsense_checker import log_analysis as la
from pfsense_checker import vlan_plan
from pfsense_checker.config_analysis import _Device, _ip, _split, _yes
from pfsense_checker.port_vlans import DeviceVlans, PortVlans, _vid_key, from_result

AREA = "Config match"
_SEVERITY_ORDER = {la.ERROR: 0, la.WARN: 1, la.INFO: 2}
TAGGED, UNTAGGED, ABSENT = "tagged", "untagged", "not carried"
COMPARED = (
    "the two ends of each cable drawn between them (VLANs, MTU, speed)",
    "the VLANs each one knows",
    "the addresses each one has in a VLAN",
    "the wireless controller and its CAP (MikroTik)",
    "RouterOS version, STP mode, DNS servers and default route (MikroTik)",
)


@dataclass
class Side:
    """One of the two devices, with its config read."""

    device: Any  # topology_site.Device
    result: Any  # checker.CheckResult
    vlans: DeviceVlans
    label: str
    view: _Device  # interfaces with their VLAN ids and addresses

    @property
    def raw(self) -> dict:
        summary = getattr(self.result, "summary", None)
        return summary.get("raw", {}) if isinstance(summary, dict) else {}

    @property
    def mikrotik(self) -> bool:
        return getattr(self.result, "source_type", "") == "mikrotik"


def label_of(device) -> str:  # noqa: ANN001
    """The name the device gives itself in its config, else its name on Login to Routers."""
    from pfsense_checker import port_vlans

    return port_vlans.for_device(device).identity or getattr(device, "name", "") or "device"


def load_side(device) -> Side | None:  # noqa: ANN001
    """Read the device's saved config. None when it has none, or it does not parse."""
    from pfsense_checker import device_identity
    from pfsense_checker.checker import check_file

    path = device_identity.config_path_for(device)
    if not path:
        return None
    try:
        result = check_file(path)
        if not getattr(result, "valid_xml", False):
            return None
        vlans = from_result(result)
        view = _Device(result)
    except Exception:  # noqa: BLE001 - a bad config is reported as "no config", not a crash
        return None
    return Side(device, result, vlans, vlans.identity or getattr(device, "name", "") or "device", view)


def compare(dev_a, dev_b, site=None) -> list[la.Finding]:  # noqa: ANN001
    """Findings for two topology devices (their saved configs and the cables between them)."""
    a, b = load_side(dev_a), load_side(dev_b)
    missing = [d for d, s in ((dev_a, a), (dev_b, b)) if s is None]
    if missing:
        names = [getattr(d, "name", "device") for d in missing]
        return [la.Finding(
            f"{AREA}: {getattr(dev_a, 'name', '?')} ↔ {getattr(dev_b, 'name', '?')}",
            "No config to compare for " + " and ".join(names), la.WARN, len(names),
            "The comparison needs a saved config from both devices. Use Load Config on Login to "
            "Routers (or Load All), then analyse again.",
            [(n, 1) for n in names],
            notes=[f"{n}: no saved config was found, or it could not be read." for n in names])]
    name_a, name_b = getattr(dev_a, "name", ""), getattr(dev_b, "name", "")
    links = [ln for ln in getattr(site, "links", None) or []
             if {ln.a_device, ln.b_device} == {name_a, name_b} and name_a != name_b]
    return compare_sides(a, b, links)


def compare_sides(a: Side, b: Side, links: list[Any] | None = None) -> list[la.Finding]:
    area = f"{AREA}: {a.label} ↔ {b.label}"
    out: list[la.Finding] = []
    out += _cables(area, a, b, links or [])
    out += _vlans(area, a, b)
    out += _addresses(area, a, b)
    out += _wireless(area, a, b)
    out += _settings(area, a, b)
    if not any(f.severity in (la.ERROR, la.WARN) for f in out):
        out.insert(0, la.Finding(area, "Nothing found that does not match", la.INFO, 0,
                                 "NetCheck compared what is listed here. Anything else is not checked.",
                                 [(c, 1) for c in COMPARED]))
    return sorted(out, key=lambda f: _SEVERITY_ORDER[f.severity])


# --------------------------------------------------------------------------- #
# Cables


def _port(side: Side, port: str) -> tuple[PortVlans | None, set[str]]:
    """(the port's VLANs with planned ones added, the planned VLAN ids)."""
    key = side.vlans.key(port)
    return vlan_plan.merged(side.vlans.port(port), vlan_plan.plan_of(side.device).get(key))


def _state(pv: PortVlans, vid: str) -> str:
    if vid in pv.tagged:
        return TAGGED
    return UNTAGGED if vid in pv.untagged else ABSENT


def _describe(side: Side, port: str, pv: PortVlans | None, planned: set[str]) -> str:
    text = (pv.describe() if pv is not None else "") or "no VLANs known"
    if planned:
        text += f" (planned, not on the device yet: {', '.join(sorted(planned, key=_vid_key))})"
    # A plan for a VLAN the port already carries the other way changes nothing until it is entered.
    pending = [f"{vid} {'tagged' if tagged else 'untagged'}"
               for vid, tagged in vlan_plan.planned_on(side.device, side.vlans.key(port)) if vid not in planned]
    if pending:
        text += f" (planned on the map but the device still has it as above: VLAN {', '.join(pending)})"
    given = side.vlans.comments.get(side.vlans.key(port), "")
    return f"{side.label} {port}{f' “{given}”' if given else ''}: {text}"


def _eth(side: Side, port: str) -> dict:
    low = port.lower()
    for row in side.raw.get("interface ethernet", []):
        if low in (str(row.get("name", "")).lower(), str(row.get("default-name", "")).lower()):
            return row
    return {}


def _cable_pairs(a: Side, links: list[Any]) -> dict[tuple[str, str], set[str]]:
    """(port on a, port on b) → the VLANs that per-VLAN cables were drawn for."""
    pairs: dict[tuple[str, str], set[str]] = {}
    for ln in links:
        if ln.a_device == getattr(a.device, "name", ""):
            pa, pb = ln.a_port, ln.b_port
        else:
            pa, pb = ln.b_port, ln.a_port
        if not pa or not pb:
            continue
        drawn = pairs.setdefault((pa, pb), set())
        if getattr(ln, "kind", "") == "vlan":
            drawn.update(str(v) for v in ln.vlans or [])
    return pairs


def _cables(area: str, a: Side, b: Side, links: list[Any]) -> list[la.Finding]:
    pairs = _cable_pairs(a, links)
    if not pairs:
        return [la.Finding(
            area, "No cable between them on the Topology map", la.INFO, 0,
            "Port VLANs are compared at the two ends of a cable. Draw the cable between these two "
            "devices on Topology and analyse again to have its ends checked.")]
    out: list[la.Finding] = []
    for (pa, pb), drawn in pairs.items():
        ends = f"{a.label} {pa} ↔ {b.label} {pb}"
        va, plan_a = _port(a, pa)
        vb, plan_b = _port(b, pb)
        notes = [_describe(a, pa, va, plan_a), _describe(b, pb, vb, plan_b)]
        if va is None or vb is None or not va.vlans or not vb.vlans:
            out.append(la.Finding(area, f"Cable {ends}: VLANs not known on one end", la.INFO, 0,
                                  "One of the two ports has no VLANs in its config, so the ends cannot "
                                  "be compared.", notes=notes))
        else:
            out += _cable_vlans(area, ends, a, pa, va, b, pb, vb, drawn, notes)
        out += _cable_physical(area, ends, a, pa, b, pb)
    return out


def _cable_vlans(area: str, ends: str, a: Side, pa: str, va: PortVlans, b: Side, pb: str,  # noqa: PLR0913
                 vb: PortVlans, drawn: set[str], notes: list[str]) -> list[la.Finding]:
    bad: list[str] = []
    good: list[str] = []
    why: list[str] = []
    for vid in sorted(set(va.vlans) | set(vb.vlans) | drawn, key=_vid_key):
        sa, sb = _state(va, vid), _state(vb, vid)
        if sa == sb and sa != ABSENT:
            good.append(f"VLAN {vid}: {sa} on both ends")
        elif sa == sb:
            bad.append(f"VLAN {vid}: a cable is drawn for it, but neither port carries it")
        elif ABSENT in (sa, sb):
            bad.append(f"VLAN {vid}: {sa} on {a.label} {pa}, {sb} on {b.label} {pb}")
            why.append(f"VLAN {vid} stops at this cable: only one end carries it.")
        else:
            bad.append(f"VLAN {vid}: {sa} on {a.label} {pa}, {sb} on {b.label} {pb}")
            why.append(f"VLAN {vid}: one end sends its frames with the VLAN tag and the other expects "
                       "them without it, so that VLAN does not pass.")
    out: list[la.Finding] = []
    if bad:
        out.append(la.Finding(
            area, f"VLANs that do not match on the cable {ends}", la.ERROR, len(bad),
            "Each VLAN has to be set the same way on both ends of a cable: tagged on both, or "
            "untagged on both.", [(row, 1) for row in bad], notes=[*notes, "", *why]))
    if good:
        out.append(la.Finding(area, f"VLANs that match on the cable {ends}", la.INFO, len(good),
                              "", [(row, 1) for row in good], notes=notes))
    return out


def _cable_physical(area: str, ends: str, a: Side, pa: str, b: Side, pb: str) -> list[la.Finding]:
    ea, eb = _eth(a, pa), _eth(b, pb)
    rows: list[str] = []
    severity = la.WARN
    for side, port, eth in ((a, pa, ea), (b, pb, eb)):
        if _yes(eth.get("disabled")):
            rows.append(f"{side.label} {port} is disabled")
            severity = la.ERROR
    if ea and eb:
        for key, word in (("mtu", "MTU"), ("speed", "speed"), ("auto-negotiation", "auto-negotiation")):
            x, y = str(ea.get(key, "")), str(eb.get(key, ""))
            if x and y and x != y:
                rows.append(f"{word}: {x} on {a.label} {pa}, {y} on {b.label} {pb}")
    if not rows:
        return []
    return [la.Finding(area, f"Port settings that differ on the cable {ends}", severity, len(rows),
                       "Both ends of a link should use the same MTU, speed and negotiation.",
                       [(row, 1) for row in rows])]


# --------------------------------------------------------------------------- #
# VLANs and addresses


def _vlan_ids(side: Side) -> set[str]:
    ids = set(side.vlans.names)
    for pv in side.vlans.ports.values():
        ids.update(pv.vlans)
    ids.update(i.vlan_id for i in side.view.ifaces.values() if i.vlan_id)
    return {v for v in ids if v}


def _vlans(area: str, a: Side, b: Side) -> list[la.Finding]:
    ids_a, ids_b = _vlan_ids(a), _vlan_ids(b)
    out: list[la.Finding] = []
    rows = [f"VLAN {v}: only on {a.label}" for v in sorted(ids_a - ids_b, key=_vid_key)]
    rows += [f"VLAN {v}: only on {b.label}" for v in sorted(ids_b - ids_a, key=_vid_key)]
    if rows:
        out.append(la.Finding(area, "VLANs only one of them has", la.INFO, len(rows),
                              "Not a fault by itself: a VLAN only has to exist where it is used.",
                              [(row, 1) for row in rows]))
    if a.mikrotik == b.mikrotik:  # a firewall and a switch name things their own way
        names = [f"VLAN {v}: “{a.vlans.names[v]}” on {a.label}, “{b.vlans.names[v]}” on {b.label}"
                 for v in sorted(ids_a & ids_b, key=_vid_key)
                 if a.vlans.names.get(v) and b.vlans.names.get(v) and a.vlans.names[v] != b.vlans.names[v]]
        if names:
            out.append(la.Finding(area, "VLAN names that differ", la.INFO, len(names),
                                  "The VLAN works by its number; a different name is only confusing.",
                                  [(row, 1) for row in names]))
    return out


def _nets_by_vlan(side: Side) -> dict[str, list[ipaddress.IPv4Interface]]:
    out: dict[str, list[ipaddress.IPv4Interface]] = {}
    for iface in side.view.ifaces.values():
        if iface.enabled and iface.vlan_id and iface.networks:
            out.setdefault(iface.vlan_id, []).extend(iface.networks)
    return out


def _addresses(area: str, a: Side, b: Side) -> list[la.Finding]:
    nets_a, nets_b = _nets_by_vlan(a), _nets_by_vlan(b)
    bad: list[tuple[str, str]] = []  # (severity, row)
    good: list[str] = []
    for vid in sorted(set(nets_a) & set(nets_b), key=_vid_key):
        for na in nets_a[vid]:
            for nb in nets_b[vid]:
                if na.ip == nb.ip:
                    continue  # reported once below, for every interface
                if na.network == nb.network:
                    good.append(f"VLAN {vid}: {na.ip} and {nb.ip} in {na.network}")
                elif na.network.overlaps(nb.network):
                    bad.append((la.WARN, f"VLAN {vid}: {na} on {a.label}, {nb} on {b.label} "
                                         "(same network, different mask)"))
                else:
                    bad.append((la.ERROR, f"VLAN {vid}: {na} on {a.label}, {nb} on {b.label} "
                                          "(different networks: they cannot reach each other there)"))
    all_a = {n.ip: i.label for i in a.view.ifaces.values() if i.enabled for n in i.networks}
    all_b = {n.ip: i.label for i in b.view.ifaces.values() if i.enabled for n in i.networks}
    for ip in sorted(set(all_a) & set(all_b)):
        bad.append((la.ERROR, f"{ip} is set on both: {a.label} ({all_a[ip]}) and {b.label} ({all_b[ip]})"))
    out: list[la.Finding] = []
    if bad:
        worst = la.ERROR if any(s == la.ERROR for s, _r in bad) else la.WARN
        out.append(la.Finding(area, "Addresses that do not line up", worst, len(bad),
                              "Two devices in the same VLAN need addresses in the same network, with the "
                              "same mask, and not the same address.", [(row, 1) for _s, row in bad]))
    if good:
        out.append(la.Finding(area, "Networks they share", la.INFO, len(good), "", [(row, 1) for row in good]))
    return out


# --------------------------------------------------------------------------- #
# Wireless controller (MikroTik CAPsMAN)


def _first(raw: dict, section: str) -> dict:
    return next(iter(raw.get(section, [])), {})


def _wireless(area: str, a: Side, b: Side) -> list[la.Finding]:
    if not (a.mikrotik and b.mikrotik):
        return []
    bad: list[tuple[str, str]] = []
    good: list[str] = []
    for cap, ctrl in ((a, b), (b, a)):
        legacy = _first(cap.raw, "interface wireless cap")
        legacy_on = _yes(legacy.get("enabled"))
        new_on = _yes(_first(cap.raw, "interface wifi cap").get("enabled"))
        manager_on = _yes(_first(ctrl.raw, "caps-man manager").get("enabled"))
        new_manager_on = _yes(_first(ctrl.raw, "interface wifi capsman").get("enabled"))
        if not (legacy_on or new_on):
            continue
        wanted = _split(legacy.get("caps-man-addresses")) if legacy_on else []
        owned = [(w, ctrl.view.owner_of(ip)) for w in wanted if (ip := _ip(w)) is not None]
        owned = [(w, iface) for w, iface in owned if iface is not None]
        related = manager_on or new_manager_on or bool(owned)
        if not related:
            continue  # the other device is not this CAP's controller: nothing to match
        if legacy_on and wanted and not owned:
            bad.append((la.ERROR, f"{cap.label} looks for its controller at {', '.join(wanted)}; "
                                  f"{ctrl.label} has none of those addresses"))
        elif legacy_on and owned and not manager_on:
            bad.append((la.ERROR, f"{cap.label} looks for its controller at {owned[0][0]} "
                                  f"({ctrl.label}), where CAPsMAN is switched off"))
        elif legacy_on and manager_on:
            where = f"at {owned[0][0]} ({ctrl.label}, {owned[0][1].label})" if owned else f"by discovery ({ctrl.label})"
            good.append(f"{cap.label} finds its controller {where}")
            if owned:
                target = _ip(owned[0][0])
                near = any(target in n.network for i in cap.view.ifaces.values() if i.enabled for n in i.networks)
                if not near:
                    bad.append((la.WARN, f"{cap.label} has no address in the network of {owned[0][0]}: "
                                         "it reaches its controller through a router"))
        if new_on and not new_manager_on:
            bad.append((la.WARN, f"{cap.label} also has the new-style CAP switched on (/interface wifi cap); "
                                 f"the new-style controller on {ctrl.label} (/interface wifi capsman) is off, "
                                 "so that CAP has no controller to join"))
        va, vb = str(getattr(cap.result, "version", "") or ""), str(getattr(ctrl.result, "version", "") or "")
        if va and vb and va != vb:
            bad.append((la.WARN, f"RouterOS {va} on {cap.label}, {vb} on {ctrl.label}: a controller and its "
                                 "CAPs are best kept on the same version"))
    out: list[la.Finding] = []
    if bad:
        worst = la.ERROR if any(s == la.ERROR for s, _r in bad) else la.WARN
        out.append(la.Finding(area, "Wireless controller (CAPsMAN) settings that do not match", worst, len(bad),
                              "A CAP has to point at an address its controller really has, with the "
                              "controller switched on, and with the same kind of CAPsMAN on both.",
                              [(row, 1) for _s, row in bad]))
    if good:
        out.append(la.Finding(area, "Wireless controller (CAPsMAN) settings that match", la.INFO, len(good), "",
                              [(row, 1) for row in good]))
    return out


# --------------------------------------------------------------------------- #
# General settings (MikroTik to MikroTik)


def _default_gateway(side: Side) -> str:
    for row in side.raw.get("ip route", []):
        if row.get("dst-address") == "0.0.0.0/0" and not _yes(row.get("disabled")):
            return str(row.get("gateway", ""))
    return ""


def _settings(area: str, a: Side, b: Side) -> list[la.Finding]:
    out: list[la.Finding] = []
    if a.mikrotik and b.mikrotik:
        stp_a = {str(r.get("protocol-mode", "")) for r in a.raw.get("interface bridge", [])} - {""}
        stp_b = {str(r.get("protocol-mode", "")) for r in b.raw.get("interface bridge", [])} - {""}
        if stp_a and stp_b and stp_a != stp_b:
            out.append(la.Finding(
                area, "Spanning tree mode differs", la.WARN, 1,
                "Bridges that are cabled together should run the same spanning tree protocol.",
                [(f"{'/'.join(sorted(stp_a))} on {a.label}, {'/'.join(sorted(stp_b))} on {b.label}", 1)]))
        rows: list[str] = []
        pairs = (
            ("RouterOS version", str(getattr(a.result, "version", "") or ""), str(getattr(b.result, "version", "") or "")),
            ("DNS servers", str(_first(a.raw, "ip dns").get("servers", "")), str(_first(b.raw, "ip dns").get("servers", ""))),
            ("Default route", _default_gateway(a), _default_gateway(b)),
        )
        for word, x, y in pairs:
            if x != y and (x or y):
                rows.append(f"{word}: {x or 'none'} on {a.label}, {y or 'none'} on {b.label}")
        if rows:
            out.append(la.Finding(area, "Other settings that differ", la.INFO, len(rows),
                                  "Worth a look. They may differ on purpose.", [(row, 1) for row in rows]))
    for side, other in ((a, b), (b, a)):
        gw = _ip(_default_gateway(side)) if side.mikrotik else None
        owner = other.view.owner_of(gw) if gw is not None else None
        if owner is not None:
            out.append(la.Finding(area, f"{side.label} routes through {other.label}", la.INFO, 0,
                                  f"Its default route is {gw}, which is {other.label} ({owner.label}).",
                                  [(f"default route {gw} = {other.label} {owner.label}", 1)]))
    return out
