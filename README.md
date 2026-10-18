# pfSense / MikroTik Config Checker

Qt6 GUI tool that validates **pfSense/OPNsense `config.xml`** backups **and
MikroTik RouterOS `.rsc` exports** with **rich visualizations** (dashboard KPIs,
charts, per-device topology), lets you **map how your devices are physically
connected** (Topology Builder), runs **continuous subnet monitoring** (ping + DHCP)
via per-subnet beacon agents, includes a cross-platform **Beacon Creator**, and
an optional **AI Advisor** (redacted findings only).

## Supported inputs

| Source | Format | Detection |
| --- | --- | --- |
| pfSense / OPNsense | `config.xml` | XML root `<pfsense>` / `<opnsense>` |
| MikroTik RouterOS | `.rsc` / `.routeros` export (`/export`) | text sections like `/interface`, `/ip …` |
| MikroTik binary backup | `.backup` | **Restore evidence only** — not parsed; pair with RouterOS 7 REST export |

Format is auto-detected on open; the summary bar shows a `[pfSense/OPNsense]` or
`[MikroTik RouterOS]` badge. RouterOS parsing covers ethernet ports, bridges +
bridge ports, VLANs, bonding (LAGG), WireGuard/OVPN/tunnels, `/ip address`,
DHCP client/server, firewall filter/NAT, DNS, identity (hostname), routes and users.

### MikroTik `.backup` vs live export

RouterOS **binary `.backup` files are proprietary clones**. This tool does **not**
decode them. Attach a `.backup` in **Topology Builder** as restore evidence, then
**Configure REST** on that device so the app can collect a sanitized text export
(`/export` via RouterOS 7 HTTPS REST). Analysis always reflects the **live
export**, not a guarantee that the historical `.backup` matches the router.

## Quick start (Windows) — single launcher

Everything runs through one batch file (`pfsense.bat`). Double-click / bare run
opens the **login GUI with no console** (splash only). Prefer `launch.vbs` /
`NetCheck.vbs` for a fully silent start (no `.bat` flash). Headless tools skip
app login:

```bat
pfsense.bat                              REM login GUI (detaches; console closes)
pfsense.bat menu                         REM tools menu (console — no app login needed)
launch.vbs                               REM silent GUI — splash only, no console
```

Or call a component directly:

```bat
pfsense.bat setup                        REM create venv + install deps
pfsense.bat gui [config.xml]             REM same as bare run (login GUI)
pfsense.bat collector [port] [token]     REM monitoring collector (no login)
pfsense.bat beacon <config.json>         REM beacon loop (no login)
pfsense.bat beacon-once <config.json>    REM single beacon cycle (no login)
pfsense.bat build-beacon [options]       REM beacon bundle (no login)
pfsense.bat check <config.xml>           REM headless text report (no login)
```

## Setup (manual / non-Windows)

```powershell
cd "c:\Python Scripts\PFSenseChecker"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Config checker (GUI)

```powershell
pythonw main.pyw            # or: pfsense.bat
```

Open a config file, or drag-and-drop `config.xml` onto the window. Optional:

```powershell
pythonw main.pyw path\to\config.xml
```

### Visualizations

- **Dashboard** — KPI cards (pass/fail, errors, interfaces, VPN, packages) plus
  charts: findings by severity (donut), findings by category (bar), interface
  status (donut) and interfaces by kind (bar).
- **Topology** — layered diagram: physical NICs → aggregation (bridge / VLAN /
  LAGG) → logical interfaces → edge. **Editable**: drag nodes vertically; edges
  are orthogonal and re-route. **Auto-layout** uses a barycentre heuristic so
  links cross as little as possible; **Lock nodes** freezes the arrangement.
- **Live Monitor** — live KPI cards, a ping-latency time-series chart per target,
  and a probe-status donut.
- **Topology Builder** — flexible **grid-locked** physical map: drag chassis
  freely (snap-to-grid); **NICs/ports are components of their device** (not
  floating). Ctrl+wheel zoom, Arrange by tier, Import Excel / Enrich from config.
  Attach pfSense XML / MikroTik `.rsc` / `.backup`, collect REST exports, then
  **Analyze resiliency**.
- **Resiliency** — site-wide findings that combine physical links with every
  attached device config (VLAN continuity, addressing/DHCP, routes, firewall/NAT
  hints, VPN peer checks, single points of failure). Select a finding to
  highlight the affected chassis on the map.
- **AI Advisor** — asks a **local Ollama model** or Poe bot to prioritise and
  explain findings. Only a **redacted** findings summary is sent (no raw config,
  secrets, keys or hashes), and only when you click *Ask Advisor*. The exact
  payload is shown before sending. After a site analysis, the redacted
  resiliency summary is included as well.

### Local Ollama advisor

1. Start Ollama and install a model, for example:

   ```powershell
   ollama serve
   ollama pull llama3.2
   ```

2. In **AI Advisor**, select **Ollama (local)**.
3. Leave the URL as `http://127.0.0.1:11434` (or enter your Ollama server).
4. Click **Refresh models**, select a model, then **Ask Advisor**.

Ollama needs no API key for a typical local install. If your instance or
Ollama Cloud requires one, set `OLLAMA_API_KEY` or save it under AI Advisor
(stored only in gitignored `secrets.local.json`). URL/model may also use
`OLLAMA_HOST` and `OLLAMA_MODEL`. For Poe, select **Poe** and use `POE_API_KEY`
or the saved key in `secrets.local.json`.

### Headless check (CI-friendly)

```powershell
python -m pfsense_checker.cli config.xml --fail-on error       # exit 1 on errors
python -m pfsense_checker.cli config.xml --json                # machine-readable
python -m pfsense_checker.cli router.rsc                        # MikroTik export
```

## Continuous monitoring (beacons)

For continuous ping + DHCP “will it offer an address?” checks you **do need a beacon able to see each broadcast domain**. That can be:

- **One physical/VM agent per subnet**, or
- **One trunked host** with a beacon config (or multiple processes) per VLAN interface

Architecture:

```
[beacon VLAN/subnet A] --\
[beacon VLAN/subnet B] ----> collector (HTTP + SQLite) <--- GUI Live Monitor tab
[beacon VLAN/subnet C] --/
```

### 1. Start the collector (central box)

```powershell
python run_collector.py --host 0.0.0.0 --port 8787
# optional: --token secret --db data\monitor.db
```

### 2. Deploy a beacon on each subnet (or VLAN interface)

Edit `samples/beacon_lan.json` (and copy for other VLANs):

- `ping_targets` — gateway IPs / critical hosts on that subnet  
- `dhcp_targets` — run DHCPDISCOVER on that L2 domain (`bind_ip` can be `0.0.0.0`)

```powershell
# Prefer elevated shell on Windows if DHCP probes are enabled (UDP/68 bind)
python run_beacon.py --config samples\beacon_lan.json
```

Single test cycle without looping:

```powershell
python run_beacon.py --config samples\beacon_lan.json --once
```

DHCP probes send DISCOVER, wait for OFFER, then send DECLINE so the lease is not held. Beacons report every `interval_sec` (default 60).

### 3. Watch in the GUI

Open **Live Monitor**, point it at `http://127.0.0.1:8787`, enable **Auto-refresh**. Offline beacons (no heartbeat within ~3 minutes) show as `NO`.

## Beacon Creator (cross-platform)

The **Beacon Creator** tab (or `pfsense.bat build-beacon`) generates a
self-contained, **stdlib-only** beacon bundle — no pip packages needed on the
target host, only Python 3.8+. It produces launchers and service definitions for:

| OS | Launcher | Service / autostart |
| --- | --- | --- |
| **Windows** | `windows\run.bat` | `windows\install_task.ps1` (scheduled task, SYSTEM, at startup) |
| **macOS** | `macos/run.sh` | `macos/install.sh` → LaunchDaemon |
| **Linux** (Kubuntu/Debian) | `linux/run.sh` | `linux/install.sh` → systemd unit (with `CAP_NET_BIND_SERVICE`) |
| **BSD** (FreeBSD) | `bsd/run.sh` | `bsd/install.sh` → rc.d service |

Each bundle contains the beacon source, a `config.json`, a `README.txt`, and an
optional `.zip`. In the GUI you can:

- Fill in identity/collector/timing and edit ping & DHCP target tables
- **Prefill from checked config** — auto-populate targets from the loaded pfSense config
- Pick target OSes and output folder, then **Generate bundle(s)**

CLI equivalent:

```powershell
python -m pfsense_checker.beacon_builder --beacon-id lan-01 ^
    --collector http://10.0.0.5:8787 --targets windows,macos,linux,bsd --out beacons
```

DHCP probes bind UDP/68 and therefore require admin (Windows), root
(macOS/BSD) or `CAP_NET_BIND_SERVICE` (the Linux unit sets this).

## What the config checker covers

Structural integrity

- Well-formed XML / encoding / BOM / null-byte issues
- Duplicate unique tags (`sshdata`, `rrddata`, etc.) that break pfSense restores
- Expected top-level sections (`system`, `interfaces`, …)

Full interface inventory

- Every logical interface (`wan`, `lan`, `opt1…N`) with enabled/disabled state, device, IPv4/IPv6
- Virtual interfaces classified: **bridges**, **VLANs**, **LAGGs**, OpenVPN, IPsec, GIF, GRE, PPP
- Bridge membership resolved and cross-linked (member ports are not falsely flagged for having no IP)
- Bridge/LAGG member and assignment consistency

Services & packages

- All installed packages with version and **best-effort enabled/disabled detection** per package config block
- Registered package services and their run state

Firewall / NAT / VPN / routing

- Filter rules (type, interface, source/dest, disabled count)
- NAT: port forwards, 1:1, outbound (mode), NPt
- VPN: OpenVPN servers/clients, IPsec phase1/phase2 (with disabled state)
- Gateways, static routes, virtual IPs (CARP), aliases

System & security

- Hostname/domain/timezone, SSH daemon, WebGUI HTTP vs HTTPS
- DNS servers plus resolver (unbound) / forwarder (dnsmasq) conflict detection
- Users and admin password-hash presence
- Certificates (CA / cert / CRL counts), DHCP scopes and static mappings

GUI tabs: **Dashboard**, **Topology**, **Topology Builder**, **Resiliency**,
Findings, Interfaces, Bridges/VLANs/LAGG, Firewall/NAT, VPN, Routing/DHCP,
Packages/Services, **Live Monitor**, **Beacon Creator**, **AI Advisor**, Report.

## MikroTik notes

- Export a config on the router with `/export` (optionally `/export file=backup`)
  and open the resulting `.rsc` text. `/export hide-sensitive` is recommended.
- Interfaces with no IP that are bridge ports / bond members are not falsely
  flagged; the checker cross-links bridge/bond/VLAN membership like it does for pfSense.
- Use the **Topology Builder** tab to record uplinks between the MikroTik and your
  pfSense box, switches and APs so the whole L2/L3 path is documented in one place.

### RouterOS 7 REST collection (recommended for live MikroTik)

Prerequisites on the router:

1. RouterOS **v7** with **www-ssl** (HTTPS) enabled and a certificate assigned
   (`/ip/service`).
2. A least-privilege account that can run `/export` and read/remove the temporary
   `.rsc` under `/file` (prefer a dedicated automation user, not full admin if
   your group model allows).
3. Network reachability from the PC running PFSenseChecker to the router mgmt IP.

In the GUI (**Topology Builder**):

1. Select the device as **Enrich target**.
2. **Attach .backup…** (optional restore evidence) or **Configure REST…**.
3. Enter host, HTTPS port, username, password. Passwords are stored in
   **Windows Credential Manager** via the `keyring` package — **never** in the
   site JSON.
4. Prefer **Verify TLS**. Only enable **Allow insecure TLS** for lab self-signed
   certs (shows a warning). Optionally set a CA path.
5. **Test connection**, then **Collect export** (or **Collect all configs**).
6. Click **Analyze resiliency** to correlate MikroTik + pfSense configs with the
   physical map.

Cached sanitized exports are written under `data/mikrotik_exports/`.

## Site resiliency workflow

1. Build or load a site in **Topology Builder** (devices, links/trunks, VLANs, VPN, egress).
2. Attach a config to each firewall/router (local XML/`.rsc`, or REST for MikroTik).
3. **Analyze resiliency** → review the **Resiliency** tab (and map highlight).
4. Optionally send the redacted site summary to **AI Advisor**.

## Tests

```powershell
pip install -r requirements.txt pytest
python -m pytest tests -q
```
