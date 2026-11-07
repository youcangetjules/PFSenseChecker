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
