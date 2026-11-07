"""Decode coded interface / port names into readable parts.

Example scheme (settable on Config Check → Name Parser)::

    0_S3_P0_1G_F_LB_5820_direct
    │ │  │  │  │ └ free text (label)
    │ │  │  │  └── F = Fiber (E = Ethernet)
    │ │  │  └───── 1G = 1 Gbps link
    │ │  └──────── P0 = Port 0
    │ └─────────── S3 = Slot 3
    └───────────── 0 = physical port (type code, first part only)

The scheme lives in ``data/name_parser.json``: the separator, the type codes
for the first part, and token rules (a regular expression for the whole
part, and a meaning template where {1}, {2} … are the expression's groups).
Parts no rule matches are kept, in order, as the label.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from pfsense_checker.paths import PROJECT_ROOT

SCHEME_PATH = PROJECT_ROOT / "data" / "name_parser.json"


@dataclass
class TokenRule:
    pattern: str  # regular expression matched against one whole part (case-insensitive)
    meaning: str  # template, {1} {2} … are the groups
    kind: str = ""  # Slot, Port, Speed, Media, VLAN, … (column / grouping)
    anywhere: bool = True  # False: only in the coded head (before the first label part)


@dataclass
class NameScheme:
    separator: str = "_"
    type_codes: dict[str, str] = field(default_factory=dict)
    rules: list[TokenRule] = field(default_factory=list)


@dataclass(frozen=True)
class Part:
    token: str
    kind: str  # Type | Slot | Port | … | Label
    meaning: str


def default_scheme() -> NameScheme:
    return NameScheme(
        separator="_",
        type_codes={
            "0": "Physical port",
            "1": "VLAN interface",
            "2": "Bridge",
            "3": "VPN / tunnel",
        },
        rules=[
            TokenRule(r"S(\d+)", "Slot {1}", "Slot"),
            TokenRule(r"SLOT(\d+)", "Slot {1}", "Slot"),
            TokenRule(r"P(\d+)", "Port {1}", "Port"),
            TokenRule(r"PORT(\d+)", "Port {1}", "Port"),
            TokenRule(r"(\d+(?:\.\d+)?)G", "{1} Gbps", "Speed"),
            TokenRule(r"(\d+)MB?", "{1} Mbps", "Speed"),
            TokenRule(r"F|FIB", "Fiber", "Media", anywhere=False),
            TokenRule(r"E", "Ethernet", "Media", anywhere=False),
            TokenRule(r"VL(\d+)", "VLAN {1}", "VLAN"),
            TokenRule(r"BR(\d+)", "Bridge {1}", "Bridge"),
        ],
    )


def load_scheme(path: Path | None = None) -> NameScheme:
    p = path or SCHEME_PATH
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default_scheme()
    if not isinstance(data, dict):
        return default_scheme()
    rules = [TokenRule(str(r.get("pattern", "")), str(r.get("meaning", "")), str(r.get("kind", "")),
                       bool(r.get("anywhere", True)))
             for r in data.get("rules", []) if isinstance(r, dict) and r.get("pattern")]
    return NameScheme(
        separator=str(data.get("separator") or "_"),
        type_codes={str(k): str(v) for k, v in (data.get("type_codes") or {}).items()},
        rules=rules,
    )


def save_scheme(scheme: NameScheme, path: Path | None = None) -> None:
    p = path or SCHEME_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "separator": scheme.separator,
        "type_codes": scheme.type_codes,
        "rules": [{"pattern": r.pattern, "meaning": r.meaning, "kind": r.kind, "anywhere": r.anywhere}
                  for r in scheme.rules],
    }
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")


def rule_error(rule: TokenRule) -> str:
    """'' when the rule is usable, else why not (for the editor)."""
    try:
        rx = re.compile(rule.pattern)
    except re.error as exc:
        return f"Pattern does not compile: {exc}"
    for n in (int(g) for g in re.findall(r"\{(\d+)\}", rule.meaning)):
        if n > rx.groups:
            return f"Meaning uses {{{n}}} but the pattern has {rx.groups} group(s)"
    return ""


def _match(rule: TokenRule, token: str) -> str | None:
    try:
        m = re.fullmatch(rule.pattern, token, re.IGNORECASE)
    except re.error:
        return None
    if m is None:
        return None
    out = rule.meaning
    for i, g in enumerate(m.groups(), start=1):
        out = out.replace(f"{{{i}}}", g or "")
    return out


def parse(name: str, scheme: NameScheme | None = None) -> list[Part]:
    """Parts of a coded name, or [] when the name does not follow the scheme."""
    scheme = scheme or load_scheme()
    sep = scheme.separator or "_"
    tokens = [t for t in (name or "").strip().split(sep) if t != ""]
    if len(tokens) < 2:
        return []
    parts: list[Part] = []
    matched = 0
    start = 0
    if tokens[0] in scheme.type_codes:
        parts.append(Part(tokens[0], "Type", scheme.type_codes[tokens[0]]))
        matched += 1
        start = 1
    label: list[str] = []
    in_head = True

    def flush() -> None:
        if label:
            parts.append(Part(sep.join(label), "Label", " ".join(label)))
            label.clear()

    for tok in tokens[start:]:
        hit = None
        for rule in scheme.rules:
            if not (in_head or rule.anywhere):
                continue
            meaning = _match(rule, tok)
            if meaning is not None:
                hit = Part(tok, rule.kind or "Code", meaning)
                break
        if hit is None:
            label.append(tok)
            in_head = False
            continue
        flush()
        parts.append(hit)
        matched += 1
    flush()
    if matched < 2 and not (matched == 1 and parts and parts[0].kind == "Type"):
        return []
    return parts


def readable(name: str, scheme: NameScheme | None = None) -> str:
    """'Physical port · Slot 3 · Port 0 · 1 Gbps · Fiber · LB 5820 direct' (or '')."""
    return " · ".join(p.meaning for p in parse(name, scheme))


_CANDIDATE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.\-]*(?:_[A-Za-z0-9.\-]+)+")


def readable_in(text: str, scheme: NameScheme | None = None) -> str:
    """Decode the first coded name found inside *text* (e.g. a check subject
    'opt6 (0_S3_P0_1G_F_LB_5820_direct) 100.48.62.0/24')."""
    scheme = scheme or load_scheme()
    if scheme.separator != "_":
        candidates = [w.strip("()[],") for w in (text or "").split()]
    else:
        candidates = _CANDIDATE.findall(text or "")
    for cand in candidates:
        out = readable(cand, scheme)
        if out:
            return out
    return ""


def interface_kind(text: str, scheme: NameScheme | None = None) -> str:
    """'vlan' | 'bridge' | '' for a check subject (row shading in Will it work?)."""
    scheme = scheme or load_scheme()
    cands = _CANDIDATE.findall(text or "") if scheme.separator == "_" else (text or "").split()
    for cand in cands:
        parts = parse(cand, scheme)
        if not parts:
            continue
        head = parts[0].meaning.lower() if parts[0].kind == "Type" else ""
        kinds = {p.kind.lower() for p in parts}
        if "vlan" in head or ("vlan" in kinds and "bridge" not in head):
            return "vlan"
        if "bridge" in head or "bridge" in kinds:
            return "bridge"
    low = (text or "").lower()
    if re.search(r"\bvlan\b|\bvl\d+|vlan\d+", low):
        return "vlan"
    if "bridge" in low or re.search(r"\bbr\d+\b", low):
        return "bridge"
    return ""
