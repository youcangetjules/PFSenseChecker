# Work log

Daily record of work done on NetCheck. Newest day first. Append a day; do not rewrite a past day except to correct a factual error.

## 2026-11-07

- Login panel: Help / Options / Forgot Credentials equal width, yellow / dark grey / blue with electric 1px borders; Login gets an electric-blue border, Cancel white with an 80% grey border (1.3.80).
- Python Modules: Available column (system-set, green/red with reason), Loaded choices persist across logins (data/python_modules.json, requirements.txt allowlist), a note for every package. 15 listed packages are not imported anywhere (1.3.79).
- Loaded configs list under the section menu (click to open in Config Check). Database page shows logged-in user@db and real SSL state (TLSv1.3 on localhost) next to Save login (1.3.78).
- Ignore device on the Login to Routers device list (saved, greyed, never probed). Discovery made sshguard-safe after it got this PC blocked from 222.10.50.1 SSH/GUI (1.3.77, BUG-040).
- Section menu: back arrow above the submenu title returns to the full section list (1.3.76).
- Seen devices are added to their subnet's Devices tab (kind from discovery, no duplicates); the tab follows the selected subnet (1.3.75, BUG-039).
- Subnets right-click: Scan / Alter (address + prefix) / Remove. Show live subnets fixed: `subnet_health.py` and `ssh_inventory.py` were committed empty; rebuilt the adapter-discovery part of `subnet_health` (1.3.74, BUG-024, BUG-037, BUG-038).
- Sliding section menu (`section_menu.py`): Config Check and Setup open a submenu, main list slides to a greyed 20 % strip. Config Check workspace now lives under Home with its tabs as the submenu (1.3.73).
- Login to Routers → Subnets: Seen and Connected columns, background discovery of routers / switches / gateways / firewalls (`net_discovery.py`). 222.10.50.0/24: pfSense Plus at .1 (gateway) and MikroTiks at .5, .10, .20, .30 (1.3.72, BUG-035, BUG-036).
- Discovery finding: all four MikroTiks answer on Telnet 23, HTTP 80 (no 443), Winbox 8291 and API 8728.
- Committed 1.3.58–1.3.70 (adc99c1). Logged BUG-028 (topology width test) and BUG-029 (Log Pipeline open on 0.0.0.0:59000).
- Login (BUG-015): pepper, key file and the `julian` row all check out. Today's log shows 11 rejected passwords, then a 1Password fill that never delivered, then a typed sign-in. Added non-secret rejection reasons and a per-user back-off (1.3.71, BUG-031).
- 1Password: fill now stops when the dialog closes, and an elevated NetCheck refuses to start 1Password (1.3.71, BUG-032).
- Logging went to the old `C:\Python Scripts\PFSenseChecker\data\logs` since the move to E:. Fixed (1.3.71, BUG-030).
- Tests: the auth test deletes its account; tests no longer write the operator's log (BUG-033, BUG-034). Deleted the 14 leftover `testuser_*` accounts from `netcheck`; only `julian` remains (BUG-033).
- Main window raises AttributeError every 15 s after sign-in (`subnet_health.load_settings` missing): added to BUG-024.

## 2026-10-18

- WAN3 (0_S2_P3_E_1G_last_line on igb3) moved left of its NIC: igb3 → WAN port card → Internet (1.3.70, BUG-027).
- Segmentation analysis (`segmentation.py`): subnet-to-subnet reach from the filter rules, reach badges on the topology cards, a matrix under the topology, and Segmentation findings. guardian scores 8/100: 12 of 13 inside subnets pass any to any (1.3.69).
- Topology is narrower (columns sized to their labels), the physical NICs are framed as the firewall chassis, and bridges have their own column right of the VLANs (1.3.68).
- Topology: em0 and mce0 go through FailoverGW to Internet and to the 3_EVL tunnels; igb3 goes straight to Internet. Internet and external VLANs share one column (1.3.67).
- Topology: Internet and the external VLANs (3_EVL tunnels) are on the left of the physical NICs. em0 + mce0 feed the FailoverGW card, which feeds the three tunnels. No links cross on the guardian config (1.3.66).
- Config Check warns when a tunnel is bound to a missing interface or gateway group (1.3.66).
- Topology draws its links again. Columns are Physical NIC → Port name → VLANs / tunnels → Edge. Both WAN ports reach Internet and carry the tunnels. Each NIC's cards share a row band, and links use separate lanes (1.3.65).
- Topology links no longer run across the cards. Columns spread to the window width (1.3.64).
- Status bar: yellow Help between AI Help and Close (1.3.63).
- Topology draws one physical NIC to every VLAN on that port. The port name is the label; OPT15 stays on the second line (1.3.62).
- Findings right-click: Explain Issue, Explain Severity, Suggest Fix, and What Breaks if Removed, each with a write-up from the loaded config. The window has Save Analysis (1.3.61).
- Config-check sidebar is labeled OPNsense/pfSense Config Checker above “Choose a section” (1.3.60).
- Config Check writes an attack-surface assessment onto the dashboard (management plane, WAN exposure, any-to-any passes, published admin ports, VPN crypto, DNS, logging). Result stays EXPOSED while warnings remain (1.3.58).
- Signing in no longer crashes when background work is still marked busy (1.3.58).
- Home → Log Pipeline streams logs in from pfSense. The listen port is selectable and defaults to 59000 (1.3.59).
- Config Check: the dashed area is a real drop target for `config.xml` and RouterOS `.rsc`, including when NetCheck is elevated (1.3.52).
- Setup → OpenObserve: ingest and read-only search. App logs and accepted syslog can be forwarded. The password stays in the OS keyring (1.3.53).
- Login panel: Help, Options, Forgot Credentials, Login, and Cancel share one row. Login turns light blue on hover (1.3.54).
- Release identity is `versions.py`: SemVer plus a commit sequence that increases by 1 on every commit. `worklog.md` and `buglog.md` are now the daily record and the bug tracker (1.3.55).
- Enter in the password field activates Login. The 1Password button is not the dialog default. Fill waits off the UI thread, and a CLI failure is reported instead of “no login found” (1.3.56).
- A companion Console window opens with NetCheck and shows the live log. Home → Console → Pop out raises that same window (1.3.57).
- Agent notes: queued commands run in order; a new request is appended. Only a direct STOP or WAIT plus an urgent directive interrupts the queue.

## 2026-09-25

- 1Password CLI fill, generate, and save on the change-password dialog. Secrets go through stdin, not the command line (1.3.48).
- If the CLI cannot attach, start the desktop app and retry. Unlock waits up to 90s instead of aborting on the first “account is not signed in” (1.3.49, 1.3.50).
- Analysis workspace: left section sidebar in place of the top tab bar (1.3.51).

## 2026-08-26

- Login → Devices grouped by subnet; device details under the topology map (1.3.43).
- Chassis model from RouterOS board-name; SSH inventory and config pull fill software and ports (1.3.42, 1.3.44, 1.3.47).
- pfSense config pull: sudo/PTY hang fixed, password prompt when login or sudo fails, pull runs off the UI thread (1.3.45, 1.3.46).
- Startup: adapter discovery, SSH credential load, splash, and login DB probe no longer block the first paint (1.3.39–1.3.41).

## 2026-08-25

- Login → Routers: device search, local NIC line, connect/save credentials (password in Credential Manager, hash only in PostgreSQL), Kind dropdown, SSH inventory into the topology (1.3.10–1.3.21).
- Python modules, MIB paths, and optional vendor libraries (1.3.22–1.3.24).
- Load and pull pfSense/OPNsense `config.xml` over SSH, including sudo (1.3.25–1.3.29).
- Syslog listener, bind address, and NIC picker (1.3.28–1.3.32, 1.3.35).
- Restored core modules that had been emptied and were exiting the GUI on startup (1.3.33).
- Topology chassis menu: Pull Config, OS/hardware, alerts (1.3.34).
- Logo and splash wordmark fixes (1.3.36–1.3.38).
- Status bar theme, beacons, busy cursor, and the maximized-window clip (1.3.2–1.3.9).
- Login gate no longer crashes on a missing status-bar import (1.3.1).
- Patch log is one Change per version; Setup → Version shows it (1.3.12).

## 2026-07-26

- 1.2.0: login gate with peppered password hashes, users admin, File / Folder Ops, PostgreSQL `netcheck` schema, connectivity save, module Save/Commit, in-app tests, silent Windows subprocesses, Console pop-out, MikroTik export over SSH.

## 2026-07-25

- 1.1.0: home hub (Login, Beaconing, Subnet Health, Config, Speed, Topology), Ollama, OUI lookup, logging, SNMP v3, database admin, lazy page load.

## 2026-06-01

- 1.0.0: initial pfSense / MikroTik config checker. Findings, dashboard, topology, resiliency, live monitor, SSH session, MikroTik REST, advisor hooks.
