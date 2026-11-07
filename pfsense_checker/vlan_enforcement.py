"""How a MikroTik bridge really enforces VLANs: bridge filtering, the
switch chip, or nothing.

``vlan-filtering=no`` is not a fault by itself. On CRS1xx / CRS2xx (and
other non-CRS3xx switch chips) turning bridge VLAN filtering on moves
switching to the CPU and loses hardware offload, so a common, correct design
keeps ``vlan-filtering=no`` and enforces VLANs in the switch chip instead:

* ``/interface ethernet switch vlan``  — which ports are members of each VLAN
* ``/interface ethernet switch egress-vlan-tag`` — where frames leave tagged
* ``/interface ethernet switch ingress-vlan-translation`` — access-port PVIDs
* ``/interface ethernet switch set drop-if-invalid-or-src-port-not-member-of-vlan-on-ports``
  — drop frames whose VLAN the ingress port is not a member of

The checks read that whole picture before saying anything about filtering.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

MODE_BRIDGE = "bridge"  # vlan-filtering=yes
MODE_SWITCH_CHIP = "switch-chip"  # vlan-filtering=no, VLANs in the switch chip
MODE_NONE = "none"  # vlan-filtering=no and no switch-chip VLAN rules

# Models whose switch chip offloads bridge vlan-filtering (hardware offload
# stays on with vlan-filtering=yes).
_HW_FILTERING_PREFIXES = ("CRS3", "CRS5", "CCR2116", "CCR2216", "RB5009", "NETPOWER", "NETFIBER")


def _yes(value: Any) -> bool:
    return str(value or "").strip().lower() in ("yes", "true")


def _split(text: Any) -> list[str]:
    return [x.strip() for x in str(text or "").split(",") if x.strip()]


def hw_vlan_filtering(model: str) -> bool:
    """True when bridge vlan-filtering keeps hardware offload on this model."""
    return (model or "").strip().upper().startswith(_HW_FILTERING_PREFIXES)


@dataclass
class Enforcement:
    bridge: str
    mode: str
    model: str = ""
    bridge_vlans: set[str] = field(default_factory=set)  # VLAN ids in /interface bridge vlan
    chip_vlans: set[str] = field(default_factory=set)  # VLAN ids in /interface ethernet switch vlan
    cpu_vlans: set[str] = field(default_factory=set)  # chip VLANs with the CPU port as a member
    hw_ports: list[str] = field(default_factory=list)  # bridge ports with hw=yes
    unchecked_ports: list[str] = field(default_factory=list)  # hw ports outside the drop-if-not-member list

    @property
    def hw_filtering(self) -> bool:
        return hw_vlan_filtering(self.model)

    @property
    def enforced(self) -> bool:
        return self.mode in (MODE_BRIDGE, MODE_SWITCH_CHIP)

    def carries(self, vlan_id: str) -> str:
        """For traffic from the CPU side (wireless, VLAN interfaces):
        'yes' | 'missing' (not in the enforcing table) | 'unenforced'."""
        if self.mode == MODE_BRIDGE:
            return "yes" if vlan_id in self.bridge_vlans else "missing"
        if self.mode == MODE_SWITCH_CHIP:
            return "yes" if vlan_id in self.cpu_vlans else "missing"
        return "unenforced"

    def describe(self) -> str:
        if self.mode == MODE_BRIDGE:
            offload = ("the switch chip offloads it" if self.hw_filtering
                       else "on this model the CPU switches the bridge (no hardware offload)")
            return f"bridge VLAN filtering ({offload})"
        if self.mode == MODE_SWITCH_CHIP:
            return ("the switch chip (switch VLAN table); vlan-filtering=no keeps hardware offload, "
                    "which is the right design on this model")
        return "nothing: vlan-filtering=no and no switch-chip VLAN rules"

    def remedy(self, peer: str = "") -> str:
        """What to do when VLANs are not enforced at all."""
        if self.hw_filtering:
            return (f"Set vlan-filtering=yes on {self.bridge}; on {self.model or 'this model'} "
                    "the switch chip offloads it, so hardware offload stays on.")
        like = f", as {peer} does" if peer else ""
        return (f"Keep hardware offload and enforce the VLANs in the switch chip{like}: "
                "/interface ethernet switch vlan (members incl. switch1-cpu), egress-vlan-tag, "
                "ingress-vlan-translation for access ports, and the ports in "
                "drop-if-invalid-or-src-port-not-member-of-vlan-on-ports. "
                f"(vlan-filtering=yes would also enforce them, but on {self.model or 'this model'} "
                "it turns hardware offload off.)")


def bridge_enforcement(raw: Mapping[str, list[dict]], bridge: str, model: str = "") -> Enforcement:
    bridges = {b.get("name", ""): b for b in raw.get("interface bridge", [])}
    br = bridges.get(bridge, {})
    bridge_vlans: set[str] = set()
    for entry in raw.get("interface bridge vlan", []):
        if entry.get("bridge") == bridge and not _yes(entry.get("disabled")):
            bridge_vlans.update(_split(entry.get("vlan-ids")))
    hw_ports = [p.get("interface", "") for p in raw.get("interface bridge port", [])
                if p.get("bridge") == bridge and _yes(p.get("hw", "yes")) and not _yes(p.get("disabled"))
                and p.get("interface")]
    enf = Enforcement(bridge=bridge, mode=MODE_NONE, model=model, bridge_vlans=bridge_vlans)
    if _yes(br.get("vlan-filtering")):
        enf.mode = MODE_BRIDGE
        return enf
    chip_vlans: set[str] = set()
    cpu_vlans: set[str] = set()
    for entry in raw.get("interface ethernet switch vlan", []):
        if _yes(entry.get("disabled")):
            continue
        ids = set(_split(entry.get("vlan-id")))
        chip_vlans |= ids
        if any(p.lower().endswith("-cpu") for p in _split(entry.get("ports"))):
            cpu_vlans |= ids
    if chip_vlans:
        enf.mode = MODE_SWITCH_CHIP
        enf.chip_vlans, enf.cpu_vlans = chip_vlans, cpu_vlans
        switch = next(iter(raw.get("interface ethernet switch", [])), {})
        checked = set(_split(switch.get("drop-if-invalid-or-src-port-not-member-of-vlan-on-ports")))
        enf.hw_ports = hw_ports
        enf.unchecked_ports = [p for p in hw_ports if p not in checked and not p.lower().startswith(("wlan", "cap"))]
    return enf


def device_bridges(raw: Mapping[str, list[dict]], model: str = "") -> list[Enforcement]:
    return [bridge_enforcement(raw, b.get("name", ""), model)
            for b in raw.get("interface bridge", []) if b.get("name") and not _yes(b.get("disabled"))]
