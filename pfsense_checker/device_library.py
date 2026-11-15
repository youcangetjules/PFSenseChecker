"""Hardware library: what each device model looks like.

Used by Topology → Add Device: pick Manufacturer and Model and the device is
created with the right ports (names as the device's own OS or its case shows
them, and media: copper / SFP / SFP+ / Wi-Fi / serial / video).

It covers network gear (firewalls, routers, switches, access points) and what
hangs off it: servers, workstations, desktop and mini PCs, laptops, NAS,
monitors and TVs, AV receivers, set-top and streaming boxes, game consoles,
smart home devices, RS485 / serial converters, printers and cameras. Add
Device groups the models by category (:func:`category_of`).

Libraries are JSON files, one per vendor:

* built in: ``pfsense_checker/device_library/*.json``
* yours:    ``data/device_library/*.json`` — same format; a model with the same
  vendor and name replaces the built-in one, new ones are added.

Format::

    {
      "vendor": "MikroTik",          # shown as Manufacturer
      "kind": "mikrotik",            # NetCheck device kind (logo, colour, parsers)
      "models": [
        {
          "model": "CRS109-8G-1S-2HnD-IN",
          "type": "Switch + Wi-Fi",  # free text, shown in the dialog
          "role": "access-switch",   # access-switch / core-switch / firewall / router / access-point / egress …
          "kind": "mikrotik",        # optional: overrides the file's kind for this model
          "category": "Switches",    # optional: where Add Device lists it (else worked out from role / kind)
          "ports": [
            {"name": "ether{n}", "count": 8, "start": 1, "media": "1G · copper"},
            {"name": "sfp1", "media": "1G · sfp"},
            {"name": "wlan1", "media": "wlan · 2.4 GHz"}
          ],
          "notes": "optional"
        }
      ]
    }

``{n}`` in a port name is replaced by start, start+1, … for ``count`` ports.
(added 2026-11-07)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from pfsense_checker.paths import PROJECT_ROOT
from pfsense_checker.topology_site import Device, PortComponent

BUILTIN_DIR = Path(__file__).resolve().parent / "device_library"
USER_DIR = PROJECT_ROOT / "data" / "device_library"


# Add Device lists models under these, in this order.
CATEGORIES = (
    "Firewalls & routers",
    "Switches",
    "Wi-Fi",
    "Servers",
    "Workstations",
    "Desktops & mini PCs",
    "Laptops, phones & tablets",
    "Storage (NAS)",
    "Monitors & TVs",
    "Audio & AV receivers",
    "Set-top & streaming boxes",
    "Game consoles",
    "Smart home & IoT",
    "Serial / RS485 converters",
    "Printers",
    "Cameras",
    "Other",
)
OTHER = CATEGORIES[-1]
_ROUTERS, _SWITCHES, _WIFI = CATEGORIES[0], CATEGORIES[1], CATEGORIES[2]
_BY_ROLE_OR_KIND = {
    "firewall": _ROUTERS, "egress": _ROUTERS, "router": _ROUTERS, "remote-router": _ROUTERS,
    "isp": _ROUTERS, "upstream": _ROUTERS, "pfsense": _ROUTERS, "opnsense": _ROUTERS,
    "access-switch": _SWITCHES, "core-switch": _SWITCHES, "switch": _SWITCHES,
    "netgear-managed": _SWITCHES, "netgear-unmanaged": _SWITCHES,
    "access-point": _WIFI,
    "server": "Servers",
    "workstation": "Workstations",
    "desktop": "Desktops & mini PCs", "sff": "Desktops & mini PCs", "host": "Desktops & mini PCs",
    "laptop": "Laptops, phones & tablets",
    "nas": "Storage (NAS)",
    "monitor": "Monitors & TVs", "tv": "Monitors & TVs",
    "av-receiver": "Audio & AV receivers",
    "video-box": "Set-top & streaming boxes",
    "game-console": "Game consoles",
    "iot": "Smart home & IoT",
    "serial-converter": "Serial / RS485 converters",
    "printer": "Printers",
    "camera": "Cameras",
}


def category_of(kind: str, role: str = "", type_: str = "", explicit: str = "") -> str:
    """Where Add Device lists a model: the file's own "category", else from its
    role, its kind, and last the words in its type."""
    if explicit.strip():
        return explicit.strip()
    low = (type_ or "").lower()
    if "phone / tablet" in low:
        return "Laptops, phones & tablets"
    for key in ((role or "").lower(), (kind or "").lower()):
        if key in _BY_ROLE_OR_KIND:
            return _BY_ROLE_OR_KIND[key]
    for word, cat in (("firewall", _ROUTERS), ("router", _ROUTERS), ("switch", _SWITCHES),
                      ("access point", _WIFI), ("wi-fi", _WIFI)):
        if word in low:
            return cat
    return OTHER


@dataclass(frozen=True)
class PortSpec:
    name: str
    media: str = ""


@dataclass
class ModelSpec:
    vendor: str
    kind: str
    model: str
    type: str = ""
    role: str = ""
    ports: list[PortSpec] = field(default_factory=list)
    notes: str = ""
    source: str = ""  # library file it came from
    category: str = ""  # one of CATEGORIES (or the file's own word)

    def matches(self, category: str = "", search: str = "") -> bool:
        """In *category* ("" = any), with every word of *search* in its maker, model or type."""
        if category and self.category != category:
            return False
        text = f"{self.vendor} {self.model} {self.type}".lower()
        return all(word in text for word in search.lower().split())

    def summary(self) -> str:
        groups: dict[str, int] = {}
        for p in self.ports:
            key = p.media or "port"
            groups[key] = groups.get(key, 0) + 1
        return " · ".join(f"{n}× {m}" for m, n in groups.items())


@dataclass
class Library:
    models: dict[str, dict[str, ModelSpec]] = field(default_factory=dict)  # vendor → model → spec
    errors: list[str] = field(default_factory=list)
    files: list[Path] = field(default_factory=list)

    def vendors(self, category: str = "", search: str = "") -> list[str]:
        """Manufacturers (with at least one model in *category* that matches *search*)."""
        return sorted((v for v, specs in self.models.items()
                       if any(s.matches(category, search) for s in specs.values())), key=str.lower)

    def models_of(self, vendor: str, category: str = "", search: str = "") -> list[ModelSpec]:
        return sorted((s for s in self.models.get(vendor, {}).values() if s.matches(category, search)),
                      key=lambda m: _natural(m.model))

    def categories(self) -> list[str]:
        """Categories that have models, in the CATEGORIES order (a file's own words last)."""
        have = {s.category for specs in self.models.values() for s in specs.values()}
        return [c for c in CATEGORIES if c in have] + sorted(have - set(CATEGORIES))

    def count(self) -> int:
        return sum(len(specs) for specs in self.models.values())

    def get(self, vendor: str, model: str) -> ModelSpec | None:
        return self.models.get(vendor, {}).get(model)


def _natural(text: str) -> list:
    """Sort key: R230 before R1000, G2 before G10."""
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", text.lower())]


def expand_ports(raw: list[dict]) -> list[PortSpec]:
    out: list[PortSpec] = []
    for p in raw:
        name = str(p.get("name", "")).strip()
        if not name:
            raise ValueError("a port has no name")
        media = str(p.get("media", ""))
        count = int(p.get("count", 1))
        start = int(p.get("start", 1))
        if "{n}" in name:
            out += [PortSpec(name.replace("{n}", str(i)), media) for i in range(start, start + count)]
        else:
            out.append(PortSpec(name, media))
    names = [p.name for p in out]
    dup = {n for n in names if names.count(n) > 1}
    if dup:
        raise ValueError(f"duplicate port names: {', '.join(sorted(dup))}")
    return out


def _load_file(path: Path, lib: Library) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        vendor = str(data["vendor"]).strip()
        kind = str(data.get("kind", "other")).strip() or "other"
        for m in data.get("models", []):
            model = str(m["model"]).strip()
            model_kind = str(m.get("kind", kind))
            spec = ModelSpec(
                vendor=vendor,
                kind=model_kind,
                model=model,
                type=str(m.get("type", "")),
                role=str(m.get("role", "")),
                ports=expand_ports(m.get("ports", [])),
                notes=str(m.get("notes", "")),
                source=str(path),
                category=category_of(model_kind, str(m.get("role", "")), str(m.get("type", "")),
                                     str(m.get("category", data.get("category", "")))),
            )
            lib.models.setdefault(vendor, {})[model] = spec
        lib.files.append(path)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        lib.errors.append(f"{path.name}: {exc}")


def load_library(dirs: list[Path] | None = None) -> Library:
    """Built-in libraries, then the user's (which override by vendor + model)."""
    lib = Library()
    for folder in dirs if dirs is not None else [BUILTIN_DIR, USER_DIR]:
        if folder.is_dir():
            for path in sorted(folder.glob("*.json")):
                _load_file(path, lib)
    return lib


def unique_name(existing: set[str], base: str) -> str:
    base = base.strip() or "device"
    if base not in existing:
        return base
    n = 2
    while f"{base}-{n}" in existing:
        n += 1
    return f"{base}-{n}"


def make_device(spec: ModelSpec, name: str, *, mgmt_ip: str = "") -> Device:
    """A topology device for *spec*: kind, model, role and every port."""
    comps = [PortComponent(name=p.name, media=p.media) for p in spec.ports]
    dev = Device(
        name=name,
        kind=spec.kind,
        model=spec.model,
        role=spec.role,
        hardware=f"{spec.vendor} {spec.model}",
        ports=[p.name for p in spec.ports],
        components=comps,
        mgmt_ip=mgmt_ip.strip(),
        notes=f"Added from the device library ({Path(spec.source).name})." if spec.source else "",
    )
    if mgmt_ip.strip():
        dev.ensure_ssh()
    return dev
