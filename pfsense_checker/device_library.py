"""Hardware library: what each router / switch / firewall model looks like.

Used by Topology → Add Device: pick Manufacturer and Model and the device is
created with the right ports (names as the device's own OS shows them, and
media: copper / SFP / SFP+ / Wi-Fi).

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
          "role": "access-switch",   # access-switch / core-switch / firewall / router / access-point / egress
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
from dataclasses import dataclass, field
from pathlib import Path

from pfsense_checker.paths import PROJECT_ROOT
from pfsense_checker.topology_site import Device, PortComponent

BUILTIN_DIR = Path(__file__).resolve().parent / "device_library"
USER_DIR = PROJECT_ROOT / "data" / "device_library"


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

    def vendors(self) -> list[str]:
        return sorted(self.models, key=str.lower)

    def models_of(self, vendor: str) -> list[ModelSpec]:
        return sorted(self.models.get(vendor, {}).values(), key=lambda m: m.model.lower())

    def get(self, vendor: str, model: str) -> ModelSpec | None:
        return self.models.get(vendor, {}).get(model)


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
            spec = ModelSpec(
                vendor=vendor,
                kind=str(m.get("kind", kind)),
                model=model,
                type=str(m.get("type", "")),
                role=str(m.get("role", "")),
                ports=expand_ports(m.get("ports", [])),
                notes=str(m.get("notes", "")),
                source=str(path),
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
