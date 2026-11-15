"""Known vulnerabilities by product and version (used by Security Holes).

A small list that NetCheck carries with it: each entry names a published
fault, the versions it affects and the version that fixed it. It is not a
live feed. It holds faults that are well documented and that matter on the
kind of devices NetCheck looks at.

Lists are JSON files, one per product:

* built in: ``pfsense_checker/vuln_db/*.json``
* yours:    ``data/vuln_db/*.json`` — same format; an entry with the same
  product and id replaces the built-in one, new ones are added.

Format::

    {
      "product": "routeros",            # routeros / openssh / pfsense-ce / pfsense-plus / your own
      "name": "MikroTik RouterOS",      # shown on the page
      "caveat": "optional: said with every match of this product",
      "entries": [
        {
          "id": "CVE-2023-41570",
          "title": "The REST API ignores its access restrictions",
          "severity": "medium",         # high / medium / low
          "affected": [{"ge": "7.1", "lt": "7.12"}],   # any one range; "ge" and "lt" are both optional
          "fixed": "7.12",
          "needs": "www",               # optional: a service that has to be on (skipped when known off)
          "detail": "What it lets an attacker do."
        }
      ]
    }
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from pfsense_checker.paths import PROJECT_ROOT

BUILTIN_DIR = Path(__file__).resolve().parent / "vuln_db"
USER_DIR = PROJECT_ROOT / "data" / "vuln_db"
SEVERITIES = ("high", "medium", "low")
_WIDTH = 4  # version parts compared: 7.9 and 7.9.0.0 are the same


def parse_version(text: object) -> tuple[int, ...]:
    """The first dotted number in *text* ("7.22.3 (stable)" → (7, 22, 3, 0)). () when there is none."""
    m = re.search(r"\d+(?:\.\d+)*", str(text or ""))
    if not m:
        return ()
    parts = [int(x) for x in m.group(0).split(".")][:_WIDTH]
    return tuple(parts + [0] * (_WIDTH - len(parts)))


@dataclass(frozen=True)
class Vuln:
    product: str
    product_name: str
    id: str
    title: str
    severity: str
    affected: tuple[tuple[tuple[int, ...], tuple[int, ...]], ...]  # (ge, lt); () = no bound
    fixed: str = ""
    needs: str = ""
    detail: str = ""
    caveat: str = ""

    def affects(self, version: object) -> bool:
        v = parse_version(version)
        if not v:
            return False
        return any((not ge or v >= ge) and (not lt or v < lt) for ge, lt in self.affected)


@dataclass
class VulnDb:
    entries: dict[str, dict[str, Vuln]] = field(default_factory=dict)  # product → id → entry
    names: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    files: list[Path] = field(default_factory=list)

    def matches(self, product: str, version: object) -> list[Vuln]:
        """Entries for *product* that affect *version*, worst first."""
        found = [v for v in self.entries.get(product, {}).values() if v.affects(version)]
        return sorted(found, key=lambda v: (SEVERITIES.index(v.severity), v.id))

    def name(self, product: str) -> str:
        return self.names.get(product, product)

    def count(self) -> int:
        return sum(len(v) for v in self.entries.values())


def _load_file(path: Path, db: VulnDb) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        product = str(data["product"]).strip().lower()
        name = str(data.get("name", product))
        caveat = str(data.get("caveat", ""))
        loaded: list[Vuln] = []
        for e in data.get("entries", []):
            severity = str(e.get("severity", "medium")).lower()
            if severity not in SEVERITIES:
                raise ValueError(f"{e.get('id', '?')}: severity must be high, medium or low")
            ranges = tuple((parse_version(r.get("ge")), parse_version(r.get("lt"))) for r in e.get("affected", []))
            if not ranges or any(not ge and not lt for ge, lt in ranges):
                raise ValueError(f"{e.get('id', '?')}: every affected range needs a ge or an lt version")
            loaded.append(Vuln(product, name, str(e["id"]).strip(), str(e["title"]).strip(), severity, ranges,
                               str(e.get("fixed", "")), str(e.get("needs", "")).lower(), str(e.get("detail", "")),
                               str(e.get("caveat", caveat))))
        for vuln in loaded:
            db.entries.setdefault(product, {})[vuln.id] = vuln
        db.names[product] = name
        db.files.append(path)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        db.errors.append(f"{path.name}: {exc}")


def load(dirs: list[Path] | None = None) -> VulnDb:
    """The built-in lists, then the operator's (which add entries or replace them by id)."""
    db = VulnDb()
    for folder in dirs if dirs is not None else [BUILTIN_DIR, USER_DIR]:
        if folder.is_dir():
            for path in sorted(folder.glob("*.json")):
                _load_file(path, db)
    return db
