"""Cross-platform beacon bundle generator.

Produces a self-contained, stdlib-only beacon deployment for Windows, macOS,
Linux (Kubuntu/Debian) and BSD (FreeBSD). Each bundle contains the beacon
source, a ``config.json`` and platform launcher + service/daemon definitions.
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

VALID_TARGETS = ("windows", "macos", "linux", "bsd")

_PKG_ROOT = Path(__file__).resolve().parent
_REPO_ROOT = _PKG_ROOT.parent

# stdlib-only source files needed to run a beacon (no PySide6 / sqlite).
_SOURCE_FILES: list[tuple[Path, str]] = [
    (_PKG_ROOT / "__init__.py", "pfsense_checker/__init__.py"),
    (_PKG_ROOT / "paths.py", "pfsense_checker/paths.py"),
    # pfsense_checker/__init__ imports version (which reads the repo-root
    # versions.py); lan_scan and subnet_health import winproc. Without these a
    # built beacon could not start.
    (_PKG_ROOT / "version.py", "pfsense_checker/version.py"),
    (_REPO_ROOT / "versions.py", "versions.py"),
    (_PKG_ROOT / "winproc.py", "pfsense_checker/winproc.py"),
    (_PKG_ROOT / "subnet_health.py", "pfsense_checker/subnet_health.py"),
    (_PKG_ROOT / "lan_scan.py", "pfsense_checker/lan_scan.py"),
    (_PKG_ROOT / "monitor" / "__init__.py", "pfsense_checker/monitor/__init__.py"),
    (_PKG_ROOT / "monitor" / "models.py", "pfsense_checker/monitor/models.py"),
    (_PKG_ROOT / "monitor" / "probes.py", "pfsense_checker/monitor/probes.py"),
    (_PKG_ROOT / "monitor" / "beacon.py", "pfsense_checker/monitor/beacon.py"),
    (_REPO_ROOT / "run_beacon.py", "run_beacon.py"),
]


@dataclass(frozen=True)
class FieldCheck:
    """One field (or table cell) of a beacon config, checked.

    *field* is the config key ("beacon_id", "collector_url", …). Table cells
    use the list name ("ping_targets" / "dhcp_targets") with *row* and *key*.
    """

    field: str
    ok: bool
    message: str = ""
    row: int | None = None
    key: str = ""


_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_HOST_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
_YES_NO = {"yes", "no", "true", "false", "1", "0", "y", "n"}


def _is_hostname(text: str) -> bool:
    text = text.rstrip(".")
    return 0 < len(text) <= 253 and all(_HOST_LABEL.match(p) for p in text.split("."))


def _looks_like_ip(text: str) -> bool:
    return bool(re.fullmatch(r"[\d.]+", text))


def _check_ipv4(text: str) -> str:
    import ipaddress

    try:
        ipaddress.IPv4Address(text)
    except ValueError:
        return f"{text!r} is not a valid IPv4 address"
    return ""


def _check_subnet_label(text: str) -> tuple[str, object]:
    """Labels are free text, but anything shaped like an address must be valid."""
    import ipaddress

    if not text:
        return "", None
    if "/" in text or _looks_like_ip(text):
        try:
            return "", ipaddress.IPv4Network(text, strict=False)
        except ValueError:
            return f"{text!r} is not a valid subnet (expected e.g. 192.168.1.0/24)", None
    if any(c.isspace() for c in text):
        return "Labels cannot contain spaces", None
    return "", None


def _check_collector_url(text: str) -> str:
    from urllib.parse import urlsplit

    if not text:
        return "Required: the beacon reports here (e.g. http://10.0.0.5:8787)"
    if "COLLECTOR_HOST" in text:
        return "Still the placeholder: put the collector's address in"
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https"):
        return "Must start with http:// or https://"
    host = parts.hostname or ""
    if not host:
        return "No host in the URL"
    if _looks_like_ip(host):
        err = _check_ipv4(host)
        if err:
            return err
    elif not _is_hostname(host):
        return f"{host!r} is not a valid host name"
    try:
        port = parts.port
    except ValueError:
        return "Port must be a number from 1 to 65535"
    if port is not None and not 1 <= port <= 65535:
        return "Port must be a number from 1 to 65535"
    if parts.query or parts.fragment:
        return "No ?query or #fragment: the beacon adds its own paths"
    return ""


def check_config(cfg: dict) -> list[FieldCheck]:
    """Check every field the Beacon Creator lets the operator set.

    Table rows are checked as given (strings from the table, empty rows
    included) so a row index matches the table row. A row that is entirely
    blank is skipped.
    """
    out: list[FieldCheck] = []

    def put(field_name: str, err: str, row: int | None = None, key: str = "", ok_msg: str = "OK") -> None:
        out.append(FieldCheck(field_name, not err, err or ok_msg, row, key))

    bid = str(cfg.get("beacon_id") or "").strip()
    put("beacon_id", "" if _ID_RE.match(bid) else (
        "Required" if not bid else "Letters, digits, - and _ only (1–64 characters)"))
    host = str(cfg.get("hostname") or "").strip()
    put("hostname", "" if not host or _is_hostname(host) else
        "Letters, digits, - and . only; each part up to 63 characters", ok_msg="OK (blank = the host's own name)" if not host else "OK")
    site = str(cfg.get("site") or "")
    put("site", "" if len(site) <= 64 and site.isprintable() else "Up to 64 printable characters")
    put("collector_url", _check_collector_url(str(cfg.get("collector_url") or "").strip()))
    token = str(cfg.get("token") or "")
    put("token", "Spaces or line breaks in a token never match the collector" if token != token.strip() or any(
        c.isspace() for c in token) else "", ok_msg="OK" if token else "OK (no token: the collector must not require one)")

    def num(name: str, lo: float, hi: float) -> None:
        try:
            value = float(cfg.get(name))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            put(name, "Must be a number")
            return
        put(name, "" if lo <= value <= hi else f"Must be {lo:g}–{hi:g}")

    num("interval_sec", 10, 3600)
    num("ping_count", 1, 10)
    num("ping_timeout", 0.5, 30)
    num("dhcp_timeout", 1, 60)
    try:
        targets = [t for t in cfg.get("ping_targets") or [] if (t.get("host") if isinstance(t, dict) else t)]
        worst = float(cfg.get("ping_timeout", 0)) * int(cfg.get("ping_count", 0)) * max(1, len(targets))
        idx = next(i for i, c in enumerate(out) if c.field == "interval_sec")
        if out[idx].ok and worst > float(cfg.get("interval_sec", 60)):
            out[idx] = FieldCheck("interval_sec", False, f"A round of pings can take {worst:g} s "
                                  "(count × timeout × targets); make the interval longer")
    except (TypeError, ValueError, StopIteration):
        pass

    seen_hosts: dict[str, int] = {}
    for r, t in enumerate(cfg.get("ping_targets") or []):
        if isinstance(t, str):
            t = {"host": t}
        hostv = str(t.get("host") or "").strip()
        label = str(t.get("subnet") or "").strip()
        iface = str(t.get("interface") or "").strip()
        if not (hostv or label or iface):
            continue
        if not hostv:
            err = "Required: the address or name to ping"
        elif _looks_like_ip(hostv):
            err = _check_ipv4(hostv)
        else:
            err = "" if _is_hostname(hostv) else f"{hostv!r} is not a valid address or host name"
        if not err and hostv.lower() in seen_hosts:
            err = f"Same host as row {seen_hosts[hostv.lower()] + 1}"
        seen_hosts.setdefault(hostv.lower(), r)
        label_err, net = _check_subnet_label(label)
        if not err and net is not None and _looks_like_ip(hostv):
            import ipaddress

            if ipaddress.IPv4Address(hostv) not in net:  # type: ignore[operator]
                label_err = f"{hostv} is not inside {net}"
        put("ping_targets", err, r, "host")
        put("ping_targets", label_err, r, "subnet")
        put("ping_targets", "" if iface.isprintable() else "Unprintable characters", r, "interface")

    for r, t in enumerate(cfg.get("dhcp_targets") or []):
        if isinstance(t, str):
            t = {"subnet": t}
        label = str(t.get("subnet") or "").strip()
        iface = str(t.get("interface") or "").strip()
        bind = str(t.get("bind_ip") or "").strip()
        enabled = t.get("enabled", True)
        if not (label or iface or bind):
            continue
        label_err, net = _check_subnet_label(label)
        if not label and not iface:
            label_err = "Give a subnet label or an interface"
        put("dhcp_targets", label_err, r, "subnet")
        put("dhcp_targets", "" if iface.isprintable() else "Unprintable characters", r, "interface")
        bind_err = _check_ipv4(bind) if bind else ""
        if not bind_err and bind and bind != "0.0.0.0" and net is not None:
            import ipaddress

            if ipaddress.IPv4Address(bind) not in net:  # type: ignore[operator]
                bind_err = f"{bind} is not inside {net}; use an address of this beacon on it, or 0.0.0.0"
        put("dhcp_targets", bind_err, r, "bind_ip", ok_msg="OK" if bind else "OK (blank = 0.0.0.0)")
        en_err = "" if isinstance(enabled, bool) or str(enabled).strip().lower() in _YES_NO else "yes or no"
        put("dhcp_targets", en_err, r, "enabled")
    return out


@dataclass
class BuildResult:
    bundle_dir: Path
    zip_path: Path | None = None
    files: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def sanitize_id(beacon_id: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", beacon_id.strip()).strip("-")
    return slug or "beacon"


def default_config(beacon_id: str = "beacon-01") -> dict:
    return {
        "beacon_id": beacon_id,
        "hostname": "",
        "site": "",
        "version": "1.2.0",
        "collector_url": "http://COLLECTOR_HOST:8787",
        "token": "",
        "interval_sec": 60,
        "link_type": "",  # wired | wlan | auto-detect
        "ping_count": 2,
        "ping_timeout": 2.0,
        "dhcp_timeout": 5.0,
        "dhcp_release_offer": True,
        "speed_url": "",
        "speed_every_n_cycles": 5,
        "ping_targets": [
            {
                "host": "192.168.1.1",
                "subnet": "192.168.1.0/24",
                "interface": "lan",
                "link_type": "wired",
            }
        ],
        "dhcp_targets": [
            {
                "subnet": "192.168.1.0/24",
                "interface": "lan",
                "bind_ip": "0.0.0.0",
                "enabled": True,
                "link_type": "wired",
            }
        ],
        "subnets": [
            {
                "cidr": "192.168.1.0/24",
                "gateway": "192.168.1.1",
                "interface": "lan",
                "link_type": "wired",
            }
        ],
    }


def build_bundle(
    config: dict,
    targets: list[str],
    out_dir: Path | str,
    *,
    make_zip: bool = True,
    overwrite: bool = True,
) -> BuildResult:
    beacon_id = sanitize_id(str(config.get("beacon_id") or "beacon"))
    out_dir = Path(out_dir)
    bundle_dir = out_dir / f"beacon_{beacon_id}"
    result = BuildResult(bundle_dir=bundle_dir)

    unknown = [t for t in targets if t not in VALID_TARGETS]
    if unknown:
        result.warnings.append(f"Ignoring unknown targets: {', '.join(unknown)}")
    targets = [t for t in targets if t in VALID_TARGETS]
    if not targets:
        raise ValueError("No valid target OS selected")

    if bundle_dir.exists():
        if not overwrite:
            raise FileExistsError(f"{bundle_dir} already exists")
        shutil.rmtree(bundle_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)

    # 1. Copy stdlib-only source
    for src, rel in _SOURCE_FILES:
        dst = bundle_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_file():
            shutil.copyfile(src, dst)
            result.files.append(rel)
        else:
            result.warnings.append(f"Missing source file: {src}")

    # 2. Write config.json
    cfg_path = bundle_dir / "config.json"
    cfg_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    result.files.append("config.json")

    # 3. Per-OS launchers + services
    if "windows" in targets:
        _write_windows(bundle_dir, beacon_id, result)
    if "macos" in targets:
        _write_macos(bundle_dir, beacon_id, result)
    if "linux" in targets:
        _write_linux(bundle_dir, beacon_id, result)
    if "bsd" in targets:
        _write_bsd(bundle_dir, beacon_id, result)

    # 4. README
    (bundle_dir / "README.txt").write_text(
        _readme(beacon_id, targets), encoding="utf-8"
    )
    result.files.append("README.txt")

    # 5. Zip
    if make_zip:
        zip_base = out_dir / f"beacon_{beacon_id}"
        archive = shutil.make_archive(str(zip_base), "zip", root_dir=bundle_dir)
        result.zip_path = Path(archive)

    return result


def _write(path: Path, content: str, result: BuildResult, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Normalize line endings: LF for shell/unix files, CRLF for .bat/.ps1
    if path.suffix in {".sh", ".plist", ".service"} or path.name.startswith("pfsense_beacon"):
        content = content.replace("\r\n", "\n")
    path.write_text(content, encoding="utf-8", newline="")
    if executable:
        try:
            path.chmod(0o755)
        except OSError:
            pass
    result.files.append(f"{path.parent.name}/{path.name}")


# --------------------------------------------------------------------------- #
# Windows
# --------------------------------------------------------------------------- #

def _write_windows(bundle: Path, beacon_id: str, result: BuildResult) -> None:
    d = bundle / "windows"
    run_bat = (
        "@echo off\r\n"
        "setlocal\r\n"
        'cd /d "%~dp0.."\r\n'
        "where py >nul 2>nul && (set PY=py -3) || (set PY=python)\r\n"
        "%PY% run_beacon.py --config config.json %*\r\n"
    )
    _write(d / "run.bat", run_bat, result)

    ps1 = f"""# Register the beacon as a Windows scheduled task that runs at startup.
# Run this from an elevated PowerShell.  DHCP probes require admin (UDP/68).
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$bundle = Split-Path -Parent $here
$runbat = Join-Path $here "run.bat"
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$runbat`"" -WorkingDirectory $bundle
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "pfsense-beacon-{beacon_id}" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
Write-Host "Installed scheduled task: pfsense-beacon-{beacon_id}"
Write-Host "Start now with: schtasks /run /tn pfsense-beacon-{beacon_id}"
"""
    _write(d / "install_task.ps1", ps1, result)

    uninstall = (
        f'schtasks /delete /tn "pfsense-beacon-{beacon_id}" /f\r\n'
    )
    _write(d / "uninstall_task.bat", "@echo off\r\n" + uninstall, result)


# --------------------------------------------------------------------------- #
# macOS
# --------------------------------------------------------------------------- #

def _write_macos(bundle: Path, beacon_id: str, result: BuildResult) -> None:
    d = bundle / "macos"
    run_sh = (
        "#!/bin/sh\n"
        'cd "$(dirname "$0")/.." || exit 1\n'
        'exec python3 run_beacon.py --config config.json "$@"\n'
    )
    _write(d / "run.sh", run_sh, result, executable=True)

    label = f"com.pfsense.beacon.{beacon_id}"
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>run_beacon.py</string>
        <string>--config</string>
        <string>config.json</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/opt/pfsense-beacon-{beacon_id}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/pfsense-beacon-{beacon_id}.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/pfsense-beacon-{beacon_id}.err</string>
</dict>
</plist>
"""
    _write(d / f"{label}.plist", plist, result)

    install = f"""#!/bin/sh
# Install the beacon under /opt and load the launchd agent (run with sudo).
set -e
DEST="/opt/pfsense-beacon-{beacon_id}"
sudo mkdir -p "$DEST"
sudo cp -R "$(dirname "$0")/.."/* "$DEST"/
sudo cp "$(dirname "$0")/{label}.plist" /Library/LaunchDaemons/{label}.plist
sudo launchctl load -w /Library/LaunchDaemons/{label}.plist
echo "Loaded {label}. DHCP probes require running as root (LaunchDaemon does)."
"""
    _write(d / "install.sh", install, result, executable=True)


# --------------------------------------------------------------------------- #
# Linux (Kubuntu / Debian, systemd)
# --------------------------------------------------------------------------- #

def _write_linux(bundle: Path, beacon_id: str, result: BuildResult) -> None:
    d = bundle / "linux"
    dest = f"/opt/pfsense-beacon-{beacon_id}"
    run_sh = (
        "#!/bin/sh\n"
        'cd "$(dirname "$0")/.." || exit 1\n'
        'exec python3 run_beacon.py --config config.json "$@"\n'
    )
    _write(d / "run.sh", run_sh, result, executable=True)

    unit = f"""[Unit]
Description=pfSense subnet beacon {beacon_id}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={dest}
ExecStart=/usr/bin/python3 {dest}/run_beacon.py --config {dest}/config.json
Restart=always
RestartSec=10
# DHCP DISCOVER binds UDP/68; grant the capability instead of running as root:
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""
    _write(d / f"pfsense-beacon-{beacon_id}.service", unit, result)

    install = f"""#!/bin/sh
# Install the beacon under /opt and enable the systemd service (run with sudo).
set -e
DEST="{dest}"
sudo mkdir -p "$DEST"
sudo cp -R "$(dirname "$0")/.."/* "$DEST"/
sudo cp "$(dirname "$0")/pfsense-beacon-{beacon_id}.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pfsense-beacon-{beacon_id}.service
echo "Started pfsense-beacon-{beacon_id}. Check: systemctl status pfsense-beacon-{beacon_id}"
"""
    _write(d / "install.sh", install, result, executable=True)


# --------------------------------------------------------------------------- #
# BSD (FreeBSD rc.d)
# --------------------------------------------------------------------------- #

def _write_bsd(bundle: Path, beacon_id: str, result: BuildResult) -> None:
    d = bundle / "bsd"
    svc = beacon_id.replace("-", "_")
    dest = f"/usr/local/pfsense-beacon-{beacon_id}"
    run_sh = (
        "#!/bin/sh\n"
        'cd "$(dirname "$0")/.." || exit 1\n'
        'exec python3 run_beacon.py --config config.json "$@"\n'
    )
    _write(d / "run.sh", run_sh, result, executable=True)

    rc = f"""#!/bin/sh
#
# PROVIDE: pfsense_beacon_{svc}
# REQUIRE: NETWORKING
# KEYWORD: shutdown
#
# Add the following line to /etc/rc.conf to enable:
# pfsense_beacon_{svc}_enable="YES"

. /etc/rc.subr

name="pfsense_beacon_{svc}"
rcvar="pfsense_beacon_{svc}_enable"
pidfile="/var/run/${{name}}.pid"
pfsense_beacon_{svc}_chdir="{dest}"
command="/usr/sbin/daemon"
command_args="-P ${{pidfile}} -r -f /usr/local/bin/python3 {dest}/run_beacon.py --config {dest}/config.json"

load_rc_config $name
: ${{pfsense_beacon_{svc}_enable:=no}}

run_rc_command "$1"
"""
    _write(d / f"pfsense_beacon_{svc}", rc, result, executable=True)

    install = f"""#!/bin/sh
# Install the beacon and rc.d service on FreeBSD (run as root).
set -e
DEST="{dest}"
mkdir -p "$DEST"
cp -R "$(dirname "$0")/.."/* "$DEST"/
cp "$(dirname "$0")/pfsense_beacon_{svc}" /usr/local/etc/rc.d/pfsense_beacon_{svc}
chmod 755 /usr/local/etc/rc.d/pfsense_beacon_{svc}
sysrc pfsense_beacon_{svc}_enable=YES
service pfsense_beacon_{svc} start
echo "Started pfsense_beacon_{svc}. DHCP probes require root (rc.d runs as root)."
"""
    _write(d / "install.sh", install, result, executable=True)


# --------------------------------------------------------------------------- #
# README
# --------------------------------------------------------------------------- #

def _readme(beacon_id: str, targets: list[str]) -> str:
    lines = [
        f"pfSense beacon bundle: {beacon_id}",
        "=" * 50,
        "",
        "This is a self-contained, stdlib-only beacon. It needs only Python 3.8+",
        "(no pip packages). It pings targets and sends DHCP DISCOVER probes on its",
        "local subnet(s), then reports results to the collector in config.json.",
        "",
        "Edit config.json first:",
        "  - collector_url : where the collector is reachable",
        "  - token         : must match the collector's --token (if any)",
        "  - ping_targets  : gateways/hosts to ping on this subnet",
        "  - dhcp_targets  : subnets to run DHCP DISCOVER on (needs admin/root)",
        "",
        "Quick manual test (any OS):",
        "  python run_beacon.py --config config.json --once",
        "",
    ]
    if "windows" in targets:
        lines += [
            "Windows:",
            "  windows\\run.bat                 (run in foreground)",
            "  Elevated PowerShell: windows\\install_task.ps1   (startup task)",
            "  DHCP probes require Administrator.",
            "",
        ]
    if "macos" in targets:
        lines += [
            "macOS:",
            "  sudo macos/install.sh           (installs to /opt + LaunchDaemon)",
            "",
        ]
    if "linux" in targets:
        lines += [
            "Linux (Kubuntu/Debian):",
            "  sudo linux/install.sh           (installs to /opt + systemd unit)",
            "  Uses CAP_NET_BIND_SERVICE so DHCP works without full root.",
            "",
        ]
    if "bsd" in targets:
        lines += [
            "BSD (FreeBSD):",
            "  sudo bsd/install.sh             (installs to /usr/local + rc.d)",
            "",
        ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Generate a cross-platform beacon bundle")
    parser.add_argument("--config", help="Existing beacon JSON config to bundle")
    parser.add_argument("--beacon-id", default="beacon-01", help="Used when --config omitted")
    parser.add_argument("--collector", default="", help="Collector URL (when --config omitted)")
    parser.add_argument(
        "--targets",
        default="windows,macos,linux,bsd",
        help="Comma-separated: windows,macos,linux,bsd",
    )
    parser.add_argument("--out", default="beacons", help="Output folder")
    parser.add_argument("--no-zip", action="store_true", help="Do not create a .zip")
    args = parser.parse_args(argv)

    if args.config:
        cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    else:
        cfg = default_config(args.beacon_id)
        if args.collector:
            cfg["collector_url"] = args.collector

    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    res = build_bundle(cfg, targets, Path(args.out), make_zip=not args.no_zip)
    print(f"Bundle: {res.bundle_dir}")
    if res.zip_path:
        print(f"Zip:    {res.zip_path}")
    for w in res.warnings:
        print(f"WARN: {w}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
