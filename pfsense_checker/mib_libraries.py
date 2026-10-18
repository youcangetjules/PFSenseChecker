"""MIB library paths and discovery for SNMP (pysnmp / pysmi).

Local MIB files live under ``data/mibs/`` by default. Extra search directories
are recorded in ``data/mib_libraries.json``. Vendor MIBs (TP-Link, Netgear,
Dell iDRAC, etc.) can be dropped into any configured folder.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pfsense_checker.paths import PROJECT_ROOT, ensure_data_dir

SETTINGS_PATH = PROJECT_ROOT / "data" / "mib_libraries.json"
DEFAULT_MIB_DIR = PROJECT_ROOT / "data" / "mibs"

_MIB_SUFFIXES = {".mib", ".txt", ".my", ".smi"}


@dataclass
class MibLibrarySettings:
    """Configured MIB search paths (first path is the default drop folder)."""

    search_paths: list[str] = field(default_factory=list)

    def normalised(self) -> MibLibrarySettings:
        paths: list[str] = []
        seen: set[str] = set()
        for raw in self.search_paths or []:
            text = str(raw or "").strip()
            if not text:
                continue
            key = str(Path(text).resolve()) if Path(text).exists() else text
            if key in seen:
                continue
            seen.add(key)
            paths.append(text)
        if not paths:
            paths = [str(DEFAULT_MIB_DIR)]
        return MibLibrarySettings(search_paths=paths)


@dataclass(frozen=True)
class MibFileInfo:
    name: str
    path: str
    size_bytes: int
    folder: str


def ensure_default_mib_dir() -> Path:
    """Create ``data/mibs`` and a short README if missing."""
    ensure_data_dir()
    DEFAULT_MIB_DIR.mkdir(parents=True, exist_ok=True)
    readme = DEFAULT_MIB_DIR / "README.txt"
    if not readme.is_file():
        readme.write_text(
            "Drop SNMP MIB files here (.mib / .txt / .my).\n"
            "Useful baselines: SNMPv2-MIB, IF-MIB, BRIDGE-MIB, Q-BRIDGE-MIB,\n"
            "LLDP-MIB, ENTITY-MIB, plus vendor MIBs for TP-Link, Netgear, Dell.\n"
            "Manage search paths under Setup → MIB Libraries.\n",
            encoding="utf-8",
        )
    return DEFAULT_MIB_DIR


def load_settings() -> MibLibrarySettings:
    ensure_default_mib_dir()
    if not SETTINGS_PATH.is_file():
        return MibLibrarySettings(search_paths=[str(DEFAULT_MIB_DIR)]).normalised()
    try:
        data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return MibLibrarySettings(search_paths=[str(DEFAULT_MIB_DIR)]).normalised()
    if not isinstance(data, dict):
        return MibLibrarySettings(search_paths=[str(DEFAULT_MIB_DIR)]).normalised()
    paths = data.get("search_paths") or data.get("paths") or []
    if not isinstance(paths, list):
        paths = []
    return MibLibrarySettings(search_paths=[str(p) for p in paths]).normalised()


def save_settings(settings: MibLibrarySettings) -> None:
    ensure_data_dir()
    cfg = settings.normalised()
    ensure_default_mib_dir()
    payload: dict[str, Any] = {"search_paths": list(cfg.search_paths)}
    SETTINGS_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def add_search_path(path: str | Path) -> MibLibrarySettings:
    cfg = load_settings()
    text = str(path).strip()
    if not text:
        raise ValueError("Empty MIB path")
    p = Path(text)
    if not p.is_dir():
        raise ValueError(f"Not a directory: {text}")
    resolved = str(p.resolve())
    paths = list(cfg.search_paths)
    if resolved not in {str(Path(x).resolve()) if Path(x).exists() else x for x in paths}:
        paths.append(resolved)
    cfg = MibLibrarySettings(search_paths=paths).normalised()
    save_settings(cfg)
    return cfg


def remove_search_path(path: str | Path) -> MibLibrarySettings:
    cfg = load_settings()
    target = str(Path(str(path)).resolve()) if Path(str(path)).exists() else str(path).strip()
    paths = []
    for raw in cfg.search_paths:
        key = str(Path(raw).resolve()) if Path(raw).exists() else raw
        if key == target or raw == str(path).strip():
            # Keep the default data/mibs folder even if "removed".
            if Path(raw).resolve() == DEFAULT_MIB_DIR.resolve() or Path(
                key
            ).resolve() == DEFAULT_MIB_DIR.resolve():
                paths.append(str(DEFAULT_MIB_DIR))
            continue
        paths.append(raw)
    if not paths:
        paths = [str(DEFAULT_MIB_DIR)]
    cfg = MibLibrarySettings(search_paths=paths).normalised()
    save_settings(cfg)
    return cfg


def list_mib_files(settings: MibLibrarySettings | None = None) -> list[MibFileInfo]:
    """Scan configured directories for MIB-like files (non-recursive one level + shallow)."""
    cfg = (settings or load_settings()).normalised()
    out: list[MibFileInfo] = []
    seen: set[str] = set()
    for folder in cfg.search_paths:
        root = Path(folder)
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() not in _MIB_SUFFIXES:
                continue
            if path.name.upper() == "README.TXT":
                continue
            key = str(path.resolve())
            if key in seen:
                continue
            seen.add(key)
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            out.append(
                MibFileInfo(
                    name=path.name,
                    path=str(path),
                    size_bytes=size,
                    folder=str(root),
                )
            )
    return out


def pysnmp_available() -> bool:
    try:
        import pysnmp  # noqa: F401
    except ImportError:
        return False
    return True


def pysmi_available() -> bool:
    try:
        import pysmi  # noqa: F401
    except ImportError:
        return False
    return True


def stack_status_text() -> str:
    """One-line status for the Setup UI."""
    bits = []
    snmp_ok = pysnmp_available()
    smi_ok = pysmi_available()
    bits.append("pysnmp " + ("installed" if snmp_ok else "MISSING"))
    bits.append("pysmi " + ("installed" if smi_ok else "MISSING"))
    if not snmp_ok or not smi_ok:
        bits.append("load via Home → Python Modules")
    cfg = load_settings()
    files = list_mib_files(cfg)
    bits.append(f"{len(cfg.search_paths)} search path(s)")
    bits.append(f"{len(files)} MIB file(s)")
    return " · ".join(bits)
