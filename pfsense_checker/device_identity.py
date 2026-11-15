"""What a topology device is: vendor, model, OS version and device type.

Read from the device's config (the loaded config, or the latest export in
``data/mikrotik_exports`` named after the device), so the topology can show
"Switch · MikroTik CRS328-4C-20S-4S+ · RouterOS 7.22.3" without a live login.

Logos: drop the vendor's official logo as ``assets/logos/<vendor>.svg`` (or
``.png``) — for example ``mikrotik.svg``, ``pfsense.svg``. When no file is
there the chassis shows a coloured wordmark badge instead. NetCheck does not
ship vendor logos.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pfsense_checker.paths import PROJECT_ROOT

LOGO_DIR = PROJECT_ROOT / "assets" / "logos"
EXPORT_DIR = PROJECT_ROOT / "data" / "mikrotik_exports"

TYPE_FIREWALL = "Firewall"
TYPE_ROUTER = "Router"
TYPE_SWITCH = "Switch"
TYPE_SWITCH_WIFI = "Switch + Wi-Fi"
TYPE_AP = "Access point"
TYPE_DEVICE = "Device"
# What an endpoint is called on its box, by device kind (network gear is worked out below).
KIND_TYPES = {
    "server": "Server",
    "workstation": "Workstation",
    "desktop": "Desktop PC",
    "sff": "Mini PC",
    "laptop": "Laptop",
    "nas": "NAS",
    "kvm": "KVM",
    "tv": "TV",
    "monitor": "Monitor",
    "av-receiver": "AV receiver",
    "video-box": "Set-top box",
    "game-console": "Game console",
    "iot": "Smart device",
    "serial-converter": "Serial converter",
    "printer": "Printer",
    "camera": "Camera",
}

_VENDOR_NAMES = {
    "mikrotik": "MikroTik",
    "pfsense": "pfSense",
    "opnsense": "OPNsense",
    "juniper": "Juniper",
    "ubiquiti": "Ubiquiti",
    "fortinet": "Fortinet",
    "cisco": "Cisco",
    "netgear": "Netgear",
    "linksys": "Linksys",
}

# Device kind → vendor whose logo it wears.
_KIND_VENDOR = {"netgear-managed": "netgear", "netgear-unmanaged": "netgear"}

# Logo file names tried for each vendor, in order (assets/logos/<name>.<ext>,
# any case). HPE owns Juniper, so an hpe file serves Juniper / Aruba kit too.
LOGO_ALIASES: dict[str, tuple[str, ...]] = {
    "mikrotik": ("mikrotik", "routeros"),
    "pfsense": ("pfsense", "netgate"),
    "opnsense": ("opnsense", "deciso"),
    "juniper": ("juniper", "hpe", "juniper-networks"),
    "fortinet": ("fortinet", "fortigate"),
    "ubiquiti": ("ubiquiti", "unifi", "ui"),
    "cisco": ("cisco",),
    "netgear": ("netgear",),
    "linksys": ("linksys",),
}
LOGO_EXTS = (".svg", ".png", ".webp", ".jpg", ".jpeg")


@dataclass(frozen=True)
class Identity:
    vendor: str = ""  # mikrotik | pfsense | opnsense | …
    model: str = ""  # hardware model, e.g. CRS328-4C-20S-4S+
    os_version: str = ""  # e.g. "RouterOS 7.22.3", "config v24.6"
    hostname: str = ""
    source: str = ""  # config file it came from

    @property
    def vendor_name(self) -> str:
        return _VENDOR_NAMES.get(self.vendor, self.vendor.title())


_cache: dict[tuple[str, float], Identity] = {}


def identity_from_config(path: str | Path) -> Identity:
    p = Path(path)
    try:
        key = (str(p), p.stat().st_mtime)
    except OSError:
        return Identity()
    if key in _cache:
        return _cache[key]
    try:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(2_000_000)  # verbose exports put /system identity near the end
    except OSError:
        return Identity()
    ident = Identity(source=str(p))
    if "<pfsense" in head or "<opnsense" in head:
        vendor = "opnsense" if "<opnsense" in head else "pfsense"
        ver = re.search(r"<version>([^<]+)</version>", head)
        host = re.search(r"<hostname>([^<]+)</hostname>", head)
        ident = Identity(vendor, "", f"config v{ver.group(1).strip()}" if ver else "",
                         host.group(1).strip() if host else "", str(p))
    elif "by RouterOS" in head or "# software id" in head or re.search(r"^/interface", head, re.M):
        model = re.search(r"^#\s*model\s*=\s*(\S+)", head, re.M)
        ros = re.search(r"by RouterOS\s+(\S+)", head)
        ident = Identity("mikrotik", model.group(1) if model else "",
                         f"RouterOS {ros.group(1)}" if ros else "", "", str(p))
        ident_name = re.search(r"^/system identity\s*\n\s*set name=(\"[^\"]*\"|\S+)", head, re.M)
        if ident_name:
            ident = Identity(ident.vendor, ident.model, ident.os_version, ident_name.group(1).strip('"'), str(p))
    _cache[key] = ident
    return ident


def config_path_for(device: Any) -> str:
    """The loaded config, else the newest export named after the device."""
    src = device.ensure_config_source() if hasattr(device, "ensure_config_source") else None
    path = (src.analyzable_path() if src is not None else "") or getattr(device, "config_file", "") or ""
    if path and Path(path).is_file():
        return path
    name = (getattr(device, "name", "") or "").strip()
    if name and EXPORT_DIR.is_dir():
        matches = sorted(EXPORT_DIR.glob(f"{glob_escape(name)}_*"), key=lambda q: q.stat().st_mtime, reverse=True)
        if matches:
            return str(matches[0])
    return ""


def glob_escape(text: str) -> str:
    return re.sub(r"([\[\]*?])", r"[\1]", text)


def identity_for(device: Any) -> Identity:
    path = config_path_for(device)
    ident = identity_from_config(path) if path else Identity()
    if not ident.vendor:
        kind = (getattr(device, "kind", "") or "").lower()
        kind = _KIND_VENDOR.get(kind, kind)
        ident = Identity(kind if kind in _VENDOR_NAMES else "", getattr(device, "model", "") or "")
    return ident


def device_type(device: Any, ident: Identity | None = None) -> str:
    role = (getattr(device, "role", "") or "").lower()
    if role in ("firewall", "egress"):
        return TYPE_FIREWALL
    if role == "router":
        return TYPE_ROUTER
    if role.endswith("switch"):
        return TYPE_SWITCH
    if role in ("access-point", "ap"):
        return TYPE_AP
    ident = ident or identity_for(device)
    kind = (getattr(device, "kind", "") or "").lower()
    model = (ident.model or getattr(device, "model", "") or "").upper()
    if kind in ("pfsense", "opnsense", "firewall") or ident.vendor in ("pfsense", "opnsense") or "SRX" in model:
        return TYPE_FIREWALL
    if model.startswith(("CRS", "CSS")) or kind in ("switch", "netgear-managed", "netgear-unmanaged"):
        # MikroTik wireless suffixes: -2HnD, -5HacD, -2HaxD …
        return TYPE_SWITCH_WIFI if re.search(r"-\d*H(N|AC|AX)", model) else TYPE_SWITCH
    if model.startswith(("CCR", "RB5009", "RB4011", "RB750", "RB760", "L009", "HEX")):
        return TYPE_ROUTER
    if model.startswith(("RBCAP", "CAP", "RBWAP", "WAP", "HAP", "RBD", "AUDIENCE")):
        return TYPE_AP
    if kind == "router":
        return TYPE_ROUTER
    return KIND_TYPES.get(kind, TYPE_DEVICE)


def type_line(device: Any) -> str:
    """'Switch · MikroTik CRS328-4C-20S-4S+ · RouterOS 7.22.3'."""
    ident = identity_for(device)
    product = " ".join(x for x in (ident.vendor_name, ident.model) if x)
    own = ident.hostname if ident.hostname and ident.hostname != getattr(device, "name", "") else ""
    return " · ".join(x for x in (device_type(device, ident), product, ident.os_version,
                                   f"identity {own}" if own else "") if x)


def logo_files(folder: Path | None = None) -> dict[str, Path]:
    """Lower-case file stem → logo file in *folder* (SVG preferred over PNG, …)."""
    folder = folder or LOGO_DIR
    out: dict[str, Path] = {}
    try:
        stamp = (str(folder), folder.stat().st_mtime)
    except OSError:
        return out
    cached = _logo_dir_cache.get(stamp[0])
    if cached is not None and cached[0] == stamp[1]:
        return cached[1]
    rank = {ext: i for i, ext in enumerate(LOGO_EXTS)}
    for f in folder.iterdir():
        ext = f.suffix.lower()
        if ext not in rank or not f.is_file():
            continue
        stem = f.stem.lower()
        if stem not in out or rank[ext] < rank[out[stem].suffix.lower()]:
            out[stem] = f
    _logo_dir_cache[stamp[0]] = (stamp[1], out)
    return out


# folder → (folder mtime, files): re-read when a logo is added or removed.
_logo_dir_cache: dict[str, tuple[float, dict[str, Path]]] = {}


def logo_path(vendor: str, folder: Path | None = None) -> Path | None:
    """Logo for a vendor (or device kind), from assets/logos, or None."""
    if not vendor:
        return None
    key = _KIND_VENDOR.get(vendor.lower(), vendor.lower())
    files = logo_files(folder)
    for name in LOGO_ALIASES.get(key, (key,)):
        if name in files:
            return files[name]
    return None
