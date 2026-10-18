"""Inspect requirements.txt vs installed / loaded packages."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from pfsense_checker.paths import PROJECT_ROOT

REQUIREMENTS_PATH = PROJECT_ROOT / "requirements.txt"

# Distribution name -> preferred top-level import module (when they differ).
_IMPORT_NAMES: dict[str, str] = {
    "fastapi-poe": "fastapi_poe",
    "PySide6": "PySide6",
    "psycopg": "psycopg",
    "timescaledb": "timescaledb",
    "openpyxl": "openpyxl",
    "keyring": "keyring",
    "paramiko": "paramiko",
    "truststore": "truststore",
    "librouteros": "librouteros",
    # PyPI name junos-eznc; import path is jnpr.junos (Junos PyEZ).
    "junos-eznc": "jnpr.junos",
    "pysnmp": "pysnmp",
    "pysmi": "pysmi",
    "httpx": "httpx",
    "requests": "requests",
    "redfish": "redfish",
    "netmiko": "netmiko",
    "napalm": "napalm",
    "ncclient": "ncclient",
    "scapy": "scapy",
    "networkx": "networkx",
    "matplotlib": "matplotlib",
    "plotly": "plotly",
    "pyvis": "pyvis",
    "graphviz": "graphviz",
    "pygraphviz": "pygraphviz",
    "grandalf": "grandalf",
    "igraph": "igraph",
}

_REQ_RE = re.compile(
    r"""^\s*
    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)
    (?:\[(?P<extras>[^\]]*)\])?
    (?P<spec>\s*(?:[=<>!~]=?|===)\s*[^;#\s]+(?:\s*,\s*(?:[=<>!~]=?|===)\s*[^;#\s]+)*)?
    """,
    re.VERBOSE,
)


@dataclass(frozen=True)
class RequirementEntry:
    """One package line from requirements.txt."""

    name: str
    extras: str
    specifier: str
    raw: str
    optional_note: str = ""


@dataclass(frozen=True)
class ModuleStatus:
    """Installed / importable / loaded status for one requirement."""

    name: str
    extras: str
    specifier: str
    installed_version: str  # "" if missing
    importable: bool
    loaded: bool
    import_name: str
    raw: str
    optional_note: str = ""

    @property
    def status(self) -> str:
        if not self.installed_version:
            return "missing"
        return "installed"


def requirements_path() -> Path:
    return REQUIREMENTS_PATH


def parse_requirements(path: Path | None = None) -> list[RequirementEntry]:
    """Parse a pip-style requirements file (name, extras, version specs)."""
    req_path = path or REQUIREMENTS_PATH
    if not req_path.is_file():
        return []
    try:
        text = req_path.read_text(encoding="utf-8")
    except OSError:
        return []

    entries: list[RequirementEntry] = []
    pending_note = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            pending_note = ""
            continue
        if line.startswith("#"):
            note = line.lstrip("#").strip()
            if note:
                pending_note = note if not pending_note else f"{pending_note} {note}"
            continue
        # Strip inline comments and environment markers.
        code = line.split("#", 1)[0].strip()
        code = code.split(";", 1)[0].strip()
        if not code:
            continue
        match = _REQ_RE.match(code)
        if not match:
            continue
        name = match.group("name")
        extras = (match.group("extras") or "").strip()
        spec = (match.group("spec") or "").strip()
        entries.append(
            RequirementEntry(
                name=name,
                extras=extras,
                specifier=spec,
                raw=code,
                optional_note=pending_note,
            )
        )
        pending_note = ""
    return entries


def import_name_for(dist_name: str) -> str:
    """Best-effort top-level import name for a distribution."""
    if dist_name in _IMPORT_NAMES:
        return _IMPORT_NAMES[dist_name]
    return dist_name.replace("-", "_")


def installed_version(dist_name: str) -> str:
    """Return installed version string, or empty if not installed."""
    try:
        return importlib.metadata.version(dist_name)
    except importlib.metadata.PackageNotFoundError:
        pass
    # Normalize: PyPI names are case-insensitive; try canonical dash form.
    try:
        return importlib.metadata.version(dist_name.replace("_", "-"))
    except importlib.metadata.PackageNotFoundError:
        return ""


def is_importable(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def is_loaded(module_name: str) -> bool:
    if module_name in sys.modules:
        return True
    prefix = module_name + "."
    return any(name == module_name or name.startswith(prefix) for name in sys.modules)


def inspect_requirements(path: Path | None = None) -> list[ModuleStatus]:
    """Build status rows for each requirements.txt entry."""
    out: list[ModuleStatus] = []
    for entry in parse_requirements(path):
        mod = import_name_for(entry.name)
        version = installed_version(entry.name)
        out.append(
            ModuleStatus(
                name=entry.name,
                extras=entry.extras,
                specifier=entry.specifier,
                installed_version=version,
                importable=is_importable(mod),
                loaded=is_loaded(mod),
                import_name=mod,
                raw=entry.raw,
                optional_note=entry.optional_note,
            )
        )
    return out


def runtime_summary() -> dict[str, str]:
    """Interpreter facts for the Modules section header."""
    return {
        "python": sys.version.split()[0],
        "executable": sys.executable,
        "platform": sys.platform,
        "requirements": str(REQUIREMENTS_PATH),
    }


def pip_install(requirement_spec: str) -> None:
    """Install a requirement into the active interpreter via pip."""
    from pfsense_checker import winproc

    spec = (requirement_spec or "").strip()
    if not spec:
        raise ValueError("Empty requirement")
    cmd = [sys.executable, "-m", "pip", "install", spec]
    proc = winproc.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
        raise RuntimeError(err)


def import_now(module_name: str) -> None:
    """Import a module into this process (marks it Loaded)."""
    import importlib

    name = (module_name or "").strip()
    if not name:
        raise ValueError("Empty module name")
    importlib.import_module(name)
