"""Security Holes: one list of weaknesses across the devices on Login to Routers.

What it looks at, and where each fact comes from:

- **Open ports and services** — the services each MikroTik runs (``/ip service``:
  Telnet, FTP, plain HTTP, the API), MAC-level access, SNMP, proxies; what
  pfSense exposes (its attack-surface findings); and the management ports the
  Login to Routers sweep saw open on hosts NetCheck holds no config for.
- **Firewall rules** — a device whose own firewall lets every network reach it,
  any-to-any rules, flat segmentation, port forwards.
- **Known vulnerabilities** — the device's software version against the list in
  ``vuln_db``; the OpenSSH version a host announces.
- **Software versions** — older than the release the operator entered as
  current, devices of one kind on different versions, an old release line.
- **Logins and passwords** — a saved password that is a factory default, the
  same password saved for several devices, logins as the built-in admin. Only
  when asked for: the passwords are compared on this PC and never shown, stored
  or logged. No user name is ever shown except the built-in ``admin`` / ``root``.

Nothing here contacts a device. It reads saved configs, what the sweep already
saw, and (when asked) the saved logins.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from pfsense_checker import vuln_db
from pfsense_checker.models import Severity
from pfsense_checker.paths import PROJECT_ROOT

# The release the operator says is current, per product: {"current": {"routeros": "7.22.3"}}.
# NetCheck does not look it up; it is what the vendor's site shows, typed on the page.
SETTINGS_PATH = PROJECT_ROOT / "data" / "security_holes.json"


def load_current(path: Path | None = None) -> dict[str, str]:
    try:
        data = json.loads((path or SETTINGS_PATH).read_text(encoding="utf-8"))
        current = data.get("current", {}) if isinstance(data, dict) else {}
        return {str(k): str(v) for k, v in current.items() if str(v).strip()} if isinstance(current, dict) else {}
    except (OSError, ValueError):
        return {}


def save_current(current: dict[str, str], path: Path | None = None) -> None:
    target = path or SETTINGS_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    kept = {k: v.strip() for k, v in current.items() if v.strip()}
    target.write_text(json.dumps({"current": kept}, indent=2) + "\n", encoding="utf-8")


HIGH, MEDIUM, LOW = "high", "medium", "low"
SEVERITIES = (HIGH, MEDIUM, LOW)
SEVERITY_WORD = {HIGH: "High", MEDIUM: "Medium", LOW: "Low"}

KNOWN = "Known vulnerabilities"
PORTS = "Open ports and services"
FIREWALL = "Firewall rules"
VPN = "VPN and encryption"
LOGINS = "Logins and passwords"
SOFTWARE = "Software versions"
OTHER = "Other"
AREAS = (KNOWN, PORTS, FIREWALL, VPN, LOGINS, SOFTWARE, OTHER)

SEVERAL = "Several devices"
FROM_CONFIG = "saved config"
FROM_NETWORK = "seen on the network (Login to Routers sweep)"
FROM_LOGINS = "saved logins"

# RouterOS services that carry the login in clear text.
CLEAR_TEXT = {
    "telnet": "Telnet",
    "ftp": "FTP",
    "www": "web interface over plain HTTP",
    "api": "API without encryption",
}
# Encrypted management services: fine to run, better limited to a management network.
SECURE_SERVICES = ("ssh", "winbox", "www-ssl", "api-ssl")
BUILT_IN_ADMINS = ("admin", "root")
# Factory defaults and the passwords tried first by every scanner.
DEFAULT_PASSWORDS = frozenset({
    "admin", "password", "pfsense", "opnsense", "mikrotik", "ubnt", "root", "toor", "cisco", "changeme",
    "default", "1234", "12345", "123456", "12345678", "123456789", "qwerty", "letmein", "admin123",
    "password1", "netgear", "juniper123",
})
# pfSense finding categories that are about security, and where they are listed.
_PFSENSE_AREAS = {
    "Management": PORTS, "DNS": PORTS, "Firewall": FIREWALL, "NAT": FIREWALL, "Segmentation": FIREWALL,
    "VPN": VPN, "Secrets": LOGINS, "Logging": OTHER,
}
_CRYPTO_WORDS = re.compile(r"cipher|digest|hash|\bDH\b|diffie|encrypt|weak|compress|\bTLS\b|\bMD5\b|\bSHA1\b|"
                           r"pre-shared|certificate|aggressive", re.I)
_CE_VERSION = re.compile(r"^\s*2\.\d+(\.\d+)?")
_PLUS_VERSION = re.compile(r"^\s*\d{2}\.(01|02|03|05|09|11)(\.\d+)?(\b|-)")


@dataclass
class Hole:
    severity: str
    area: str
    device: str
    title: str
    detail: str = ""
    fix: str = ""
    source: str = FROM_CONFIG

    def text(self) -> str:
        """One hole as plain text (for Copy)."""
        lines = [f"[{SEVERITY_WORD[self.severity]}] {self.device}: {self.title}"]
        if self.detail:
            lines.append(f"  {self.detail}")
        if self.fix:
            lines.append("  Fix: " + self.fix.replace("\n", "\n       "))
        return "\n".join(lines)


@dataclass
class VersionRow:
    device: str
    product: str  # product key in vuln_db ("" when not known)
    product_name: str
    version: str
    known: int = 0  # known vulnerabilities that affect it
    note: str = ""


@dataclass
class Report:
    holes: list[Hole] = field(default_factory=list)
    versions: list[VersionRow] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)  # devices whose config was read
    notes: list[str] = field(default_factory=list)  # what was not checked, and why

    def count(self, severity: str) -> int:
        return sum(1 for h in self.holes if h.severity == severity)

    def by_area(self) -> dict[str, list[Hole]]:
        out: dict[str, list[Hole]] = {}
        for area in AREAS:
            found = [h for h in self.holes if h.area == area]
            if found:
                out[area] = found
        return out

    def devices(self) -> list[str]:
        return sorted({h.device for h in self.holes}, key=str.lower)

    def summary(self) -> str:
        if not self.checked and not self.holes:
            return "Nothing to check yet: load a config on Login to Routers (Load Config or Load All)."
        counts = ", ".join(f"{self.count(s)} {s}" for s in SEVERITIES)
        return f"{len(self.checked)} device config(s) checked. {len(self.holes)} weakness(es): {counts}."

    def text(self) -> str:
        lines = [self.summary(), ""]
        for area, holes in self.by_area().items():
            lines.append(area)
            lines += [h.text() for h in holes]
            lines.append("")
        if self.notes:
            lines.append("Not checked")
            lines += [f"  {n}" for n in self.notes]
        return "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# Small helpers


def _yes(value: object) -> bool:
    return str(value or "").strip().lower() in ("yes", "true")


def _first(raw: dict, section: str) -> dict:
    return next(iter(raw.get(section, [])), {})


def _first_sentence(text: str, limit: int = 120) -> str:
    cut = re.split(r"(?<=[a-z0-9\)])\.\s", text.strip(), maxsplit=1)[0].rstrip(".")
    return cut if len(cut) <= limit else cut[: limit - 1].rstrip() + "…"


def _rest(text: str) -> str:
    """What follows the first sentence ("" when the title already says it all)."""
    title = _first_sentence(text, limit=10_000)
    return text.strip()[len(title):].lstrip(". ").strip()


def _host_of(device: Any) -> str:
    ssh = getattr(device, "ssh", None)
    return ((ssh.host if ssh else "") or getattr(device, "mgmt_ip", "") or "").strip()


# --------------------------------------------------------------------------- #
# MikroTik: what the config says the device offers


def routeros_services(result: Any) -> dict[str, dict]:
    """Enabled ``/ip service`` rows by name. {} when the export does not list them."""
    raw = result.summary.get("raw", {}) if isinstance(getattr(result, "summary", None), dict) else {}
    return {str(r["_name"]): r for r in raw.get("ip service", []) if r.get("_name") and not _yes(r.get("disabled"))}


def input_is_filtered(raw: dict) -> tuple[bool, list[str]]:
    """(does the input chain drop anything by default?, comments of drop rules that are switched off)."""
    live, off = False, []
    for row in raw.get("ip firewall filter", []):
        if str(row.get("chain", "")).lower() != "input" or str(row.get("action", "")).lower() not in ("drop", "reject"):
            continue
        if _yes(row.get("disabled")):
            off.append(str(row.get("comment") or "no comment"))
        elif not str(row.get("connection-state") or "").strip():  # "drop invalid" alone protects nothing
            live = True
    return live, off


def _routeros_holes(label: str, result: Any) -> list[Hole]:  # noqa: C901, PLR0912
    raw = result.summary.get("raw", {}) if isinstance(getattr(result, "summary", None), dict) else {}
    out: list[Hole] = []
    services = routeros_services(result)
    filtered, drops_off = input_is_filtered(raw)

    clear = [n for n in CLEAR_TEXT if n in services]
    if clear:
        ports = ", ".join(f"{CLEAR_TEXT[n]} (port {services[n].get('port', '?')})" for n in clear)
        out.append(Hole(
            HIGH if {"telnet", "ftp"} & set(clear) else MEDIUM, PORTS, label,
            "Unencrypted management services are on: " + ", ".join(clear),
            f"{ports}. A login to any of these crosses the network in clear text: anyone who can see the "
            "traffic can read the user name and password.",
            f"/ip service disable {','.join(clear)}\nUse SSH, Winbox, or the encrypted www-ssl / api-ssl instead."))
    anywhere = [n for n in SECURE_SERVICES if n in services and not str(services[n].get("address") or "").strip()]
    if anywhere:
        out.append(Hole(
            LOW if filtered else MEDIUM, PORTS, label,
            "Management services accept connections from any address: " + ", ".join(anywhere),
            "No address limit is set on these services" + ("." if filtered else ", and the device's own firewall "
            "does not limit them either (see Firewall rules)."),
            f"/ip service set {','.join(anywhere)} address=<your management network, for example 222.10.1.0/24>"))

    if raw.get("ip firewall filter") is not None and not filtered:
        nets = sorted({str(a.get("network") or a.get("address") or "") for a in raw.get("ip address", [])
                       if not _yes(a.get("disabled"))} - {""})
        detail = ("Its input chain has no enabled rule that drops traffic, so every service it runs can be reached "
                  "from every network it has an address in" + (f" ({', '.join(nets)})" if nets else "") + ".")
        if drops_off:
            detail += " Drop rules that exist but are switched off: " + "; ".join(drops_off[:6]) + "."
        out.append(Hole(MEDIUM, FIREWALL, label, "Nothing stops other networks reaching the device itself", detail,
                        "Accept your management network on the input chain, then enable a final drop rule."))

    mac = [word for section, word in (("tool mac-server", "MAC Telnet"), ("tool mac-server mac-winbox", "MAC Winbox"))
           if str(_first(raw, section).get("allowed-interface-list", "")).lower() == "all"]
    if mac:
        out.append(Hole(LOW, PORTS, label,
                        f"{' and '.join(mac)} {'are' if len(mac) > 1 else 'is'} allowed on every interface",
                        "MAC-level access works without an IP address, from any port in the same layer-2 network, "
                        "and is not stopped by the IP firewall.",
                        "/tool mac-server set allowed-interface-list=<a list of management interfaces>\n"
                        "/tool mac-server mac-winbox set allowed-interface-list=<the same list>"))
    if str(_first(raw, "ip ssh").get("strong-crypto", "")).lower() == "no":
        out.append(Hole(LOW, VPN, label, "SSH accepts older, weaker encryption",
                        "strong-crypto is off, so the SSH server still offers old ciphers and key exchanges.",
                        "/ip ssh set strong-crypto=yes"))
    if _yes(_first(raw, "snmp").get("enabled")) and result.summary.get("snmp_public_community"):
        out.append(Hole(MEDIUM, PORTS, label, "SNMP is on with the default community name “public”",
                        "Anything that can reach the device can read its interfaces, addresses and neighbours "
                        "with the community name every scanner tries first.",
                        "Use SNMPv3 with a user and password, or rename the community and limit its addresses."))
    for section, word in (("ip socks", "SOCKS proxy"), ("ip proxy", "web proxy")):
        if _yes(_first(raw, section).get("enabled")):
            out.append(Hole(HIGH, PORTS, label, f"The {word} is switched on",
                            f"A {word} on a router lets others send traffic through it. Unless you set it up "
                            "yourself, it is a common sign that the router has been taken over.",
                            f"/{section} set enabled=no (if you did not set it up, also check users, scripts and "
                            "the scheduler)"))
    if _yes(_first(raw, "ip upnp").get("enabled")):
        out.append(Hole(MEDIUM, PORTS, label, "UPnP is switched on",
                        "Any device inside can open ports to itself from the Internet without asking.",
                        "/ip upnp set enabled=no"))
    if _yes(_first(raw, "ip dns").get("allow-remote-requests")) and not filtered and raw.get("ip firewall filter") is not None:
        out.append(Hole(LOW, PORTS, label, "Answers DNS requests from any network",
                        "allow-remote-requests is on and the input chain does not limit who may ask.",
                        "Limit port 53 on the input chain to your own networks, or switch allow-remote-requests off."))
    for f in getattr(result, "findings", []):
        if f.category == "NAT" and "dst-nat" in f.message:
            out.append(Hole(LOW, FIREWALL, label, _first_sentence(f.message), f.message, f.remediation))
    return out


# --------------------------------------------------------------------------- #
# pfSense: the attack-surface findings the config check already makes


def _pfsense_holes(label: str, result: Any) -> list[Hole]:
    out: list[Hole] = []
    segmentation: list[Any] = []
    for f in getattr(result, "findings", []):
        area = _PFSENSE_AREAS.get(f.category)
        if area is None or f.severity == Severity.INFO and f.category not in ("NAT", "Management"):
            continue
        if f.category == "VPN" and not _CRYPTO_WORDS.search(f.message):
            continue  # a tunnel that cannot start is a fault, not a hole
        if f.category == "Segmentation":
            segmentation.append(f)
            continue
        severity = {Severity.ERROR: HIGH, Severity.WARNING: MEDIUM}.get(f.severity, LOW)
        out.append(Hole(severity, area, label, _first_sentence(f.message), _rest(f.message), f.remediation))
    if segmentation:
        head = next((f for f in segmentation if "flat" in f.message.lower()), segmentation[0])
        rest = [f.message for f in segmentation if f is not head]
        detail = "\n".join(x for x in (_rest(head.message), *(f"• {m}" for m in rest)) if x)
        out.append(Hole(MEDIUM, FIREWALL, label, _first_sentence(head.message), detail,
                        head.remediation or "Replace any-to-any rules between inside networks with rules for the "
                                            "services each network really needs."))
    return out


# --------------------------------------------------------------------------- #
# Versions and known vulnerabilities


def product_of(device: Any, result: Any) -> tuple[str, str]:
    """(vuln_db product, version text). ("", …) when the software version is not known."""
    if getattr(result, "source_type", "") == "mikrotik":
        version = str(getattr(result, "version", "") or getattr(device, "software_version", "") or "")
        return ("routeros" if vuln_db.parse_version(version) else ""), version
    text = str(getattr(device, "software_version", "") or "")
    if _CE_VERSION.match(text):
        return "pfsense-ce", text
    if _PLUS_VERSION.match(text):
        return "pfsense-plus", text
    return "", str(getattr(result, "version", "") or text)


def _service_is_off(needs: str, result: Any) -> bool:
    """True when the service a vulnerability needs is known to be switched off."""
    if not needs or getattr(result, "source_type", "") != "mikrotik":
        return False
    raw = result.summary.get("raw", {})
    if needs == "snmp":
        return "snmp" in raw and not _yes(_first(raw, "snmp").get("enabled"))
    if "ip service" not in raw:
        return False
    on = routeros_services(result)
    return not ({"www", "www-ssl"} & set(on)) if needs == "www" else needs not in on


def _vuln_hole(label: str, vuln: vuln_db.Vuln, version: str, source: str = FROM_CONFIG) -> Hole:
    detail = f"{vuln.detail} This device runs {vuln.product_name} {version}; it was fixed in {vuln.fixed}."
    if vuln.caveat:
        detail += " " + vuln.caveat
    return Hole(vuln.severity, KNOWN, label, f"{vuln.id}: {vuln.title}", detail,
                f"Update to {vuln.fixed.split(' (')[0]} or later.", source)


def _version_holes(label: str, device: Any, result: Any, db: vuln_db.VulnDb, current: dict[str, str],
                   report: Report) -> None:
    product, version = product_of(device, result)
    if not product:
        kind = "MikroTik" if getattr(result, "source_type", "") == "mikrotik" else "pfSense"
        note = (f"The config holds its format version ({version}), not the software version."
                if version else "No version in the config.")
        report.versions.append(VersionRow(label, "", kind, version or "not known", note=note))
        report.notes.append(f"{label}: software version not known, so it was not checked against known "
                            "vulnerabilities. See System → Update on the device.")
        return
    name = db.name(product)
    found = [v for v in db.matches(product, version) if not _service_is_off(v.needs, result)]
    report.holes += [_vuln_hole(label, v, version) for v in found]
    report.versions.append(VersionRow(label, product, name, version, known=len(found)))
    newest = current.get(product, "").strip()
    if vuln_db.parse_version(newest) and vuln_db.parse_version(version) < vuln_db.parse_version(newest):
        report.holes.append(Hole(MEDIUM, SOFTWARE, label, f"{name} {version} is older than {newest}",
                                 f"{newest} is the release entered as current on this page. Older releases miss "
                                 "its security fixes.", f"Update to {newest}."))
    if product == "routeros" and vuln_db.parse_version(version)[0] == 6:
        report.holes.append(Hole(LOW, SOFTWARE, label, "Runs RouterOS 6, the old release line",
                                 "MikroTik develops RouterOS 7. Version 6 only receives long-term fixes.",
                                 "Plan a move to RouterOS 7 (check the hardware supports it)."))


def _mixed_versions(report: Report) -> None:
    by_product: dict[str, dict[str, list[str]]] = {}
    for row in report.versions:
        if row.product:
            by_product.setdefault(row.product_name, {}).setdefault(row.version, []).append(row.device)
    for name, versions in by_product.items():
        if len(versions) > 1:
            parts = "; ".join(f"{v} on {', '.join(devs)}" for v, devs in sorted(versions.items()))
            report.holes.append(Hole(LOW, SOFTWARE, SEVERAL, f"{name} versions differ between devices",
                                     f"{parts}. The older ones miss fixes the newer ones have.",
                                     "Bring them to the same release."))


# --------------------------------------------------------------------------- #
# Hosts the sweep saw


def _seen_holes(seen: list[Any], known_hosts: dict[str, str], with_config: set[str], db: vuln_db.VulnDb) -> list[Hole]:
    out: list[Hole] = []
    for host in seen:
        ip = str(getattr(host, "ip", ""))
        what = " ".join(x for x in (getattr(host, "vendor", ""), getattr(host, "role", "")) if x)
        label = known_hosts.get(ip) or (f"{ip} ({what})" if what else ip)
        ports = set(getattr(host, "open_ports", ()) or ())
        if ip not in with_config:  # a config says more, and more exactly, than an open port
            if 23 in ports:
                out.append(Hole(HIGH, PORTS, label, "Telnet is open (port 23)",
                                "A Telnet login crosses the network in clear text.",
                                "Switch Telnet off on the device and use SSH.", FROM_NETWORK))
            if 80 in ports and 443 not in ports:
                out.append(Hole(MEDIUM, PORTS, label, "Its web interface answers on plain HTTP only (port 80)",
                                "A login to it crosses the network in clear text.",
                                "Turn on HTTPS for the web interface and switch HTTP off.", FROM_NETWORK))
            if 8728 in ports:
                out.append(Hole(MEDIUM, PORTS, label, "The MikroTik API without encryption is open (port 8728)",
                                "API logins on this port are not encrypted.",
                                "/ip service disable api (use api-ssl)", FROM_NETWORK))
            if 8291 in ports:
                out.append(Hole(LOW, PORTS, label, "Winbox is open (port 8291)",
                                "Winbox is reachable from the network this PC is on.",
                                "Limit Winbox to your management network: /ip service set winbox address=…",
                                FROM_NETWORK))
        m = re.search(r"OpenSSH[_ ](\d+\.\d+)", str(getattr(host, "ssh_banner", "") or ""))
        if m:
            out += [_vuln_hole(label, v, m.group(1), FROM_NETWORK) for v in db.matches("openssh", m.group(1))]
    return out


# --------------------------------------------------------------------------- #
# Saved logins


def _login_holes(devices: list[tuple[str, Any]], password_of: Callable[[Any], str | None] | None,
                 username_of: Callable[[Any], str] | None) -> list[Hole]:
    out: list[Hole] = []
    if username_of is not None:
        admins = [label for label, dev in devices if (username_of(dev) or "").strip().lower() in BUILT_IN_ADMINS]
        if admins:
            out.append(Hole(LOW, LOGINS, SEVERAL if len(admins) > 1 else admins[0],
                            f"{len(admins)} device(s) are logged into as the built-in admin account",
                            f"{', '.join(admins)}. The built-in account is the one every attack tries, and it "
                            "cannot be told apart from other people's use of it in the logs.",
                            "Create a named account with the rights NetCheck needs and use that.", FROM_LOGINS))
    if password_of is None:
        return out
    groups: dict[str, list[str]] = {}
    for label, dev in devices:
        password = password_of(dev)
        if not password:
            continue
        if password.strip().lower() in DEFAULT_PASSWORDS:
            out.append(Hole(HIGH, LOGINS, label, "The saved login uses a well-known default password",
                            "The password saved for this device is on the list of factory defaults and the "
                            "passwords every scanner tries first. It was compared on this PC and is not shown.",
                            "Change the password on the device, then save the new one on Login to Routers.",
                            FROM_LOGINS))
        groups.setdefault(hashlib.sha256(password.encode("utf-8")).hexdigest(), []).append(label)
    for labels in groups.values():
        if len(labels) > 1:
            out.append(Hole(MEDIUM, LOGINS, SEVERAL, f"The same password is saved for {len(labels)} devices",
                            f"{', '.join(labels)}. Whoever learns it on one device has all of them.",
                            "Give each device its own password (or use SSH keys).", FROM_LOGINS))
    return out


# --------------------------------------------------------------------------- #


def collect(site: Any, *, seen: list[Any] | None = None,  # noqa: PLR0913
            password_of: Callable[[Any], str | None] | None = None,
            username_of: Callable[[Any], str] | None = None,
            current: dict[str, str] | None = None, db: vuln_db.VulnDb | None = None,
            load: Callable[[Any], Any] | None = None) -> Report:
    """Every weakness NetCheck can see for the devices of *site*.

    *seen*: hosts from the Login to Routers sweep (None: no sweep in this run).
    *password_of* / *username_of*: the saved login of a device (None: not looked at).
    *current*: product → the release the operator says is current.
    *load*: device → its parsed config, or None (default: the saved config file).
    """
    from pfsense_checker import config_match

    db = db or vuln_db.load()
    report = Report()
    if db.errors:
        report.notes.append("Vulnerability list file(s) not loaded: " + "; ".join(db.errors))
    load = load or (lambda dev: getattr(config_match.load_side(dev), "result", None))
    devices: list[tuple[str, Any]] = []
    known_hosts: dict[str, str] = {}
    with_config: set[str] = set()
    for dev in getattr(site, "devices", None) or []:
        if getattr(dev, "ignored", False):
            continue
        result = load(dev)
        label = (getattr(result, "hostname", "") or "") or getattr(dev, "name", "device")
        devices.append((label, dev))
        host = _host_of(dev)
        if host:
            known_hosts[host] = label
        if result is None:
            report.notes.append(f"{label}: no saved config, so only its saved login and what the sweep saw "
                                "were looked at. Use Load Config on Login to Routers.")
            continue
        report.checked.append(label)
        if host:
            with_config.add(host)
        report.holes += (_routeros_holes if getattr(result, "source_type", "") == "mikrotik"
                         else _pfsense_holes)(label, result)
        _version_holes(label, dev, result, db, current or {}, report)
    _mixed_versions(report)
    if seen:
        report.holes += _seen_holes(seen, known_hosts, with_config, db)
    else:
        report.notes.append("No network sweep in this run: open ports on other hosts were not looked at. "
                            "Use Show live subnets on Login to Routers, then check again.")
    report.holes += _login_holes(devices, password_of, username_of)
    if password_of is None:
        report.notes.append("Saved passwords were not compared. Tick “Compare saved passwords” to look for "
                            "factory defaults and one password used on several devices.")
    order = {s: i for i, s in enumerate(SEVERITIES)}
    report.holes.sort(key=lambda h: (AREAS.index(h.area), order[h.severity], h.device.lower(), h.title))
    return report
