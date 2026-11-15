# Work log

Daily record of work done on NetCheck. Newest day first. Append a day; do not rewrite a past day except to correct a factual error.

## 2026-11-15

- Security Holes built (1.10.0). On the saved site (5 configs; no sweep, no passwords read): 34 weaknesses, 4 high, 18 medium, 12 low. High: all four MikroTiks have Telnet, FTP, plain HTTP and the API switched on. Medium: their input chains drop nothing (CRS328 has three drop rules, all switched off), so every service is reachable from every VLAN; ssh / winbox / api-ssl have no address limit; CRS328 has SNMP on with the community name public; guardian: web GUI on every interface, SSH password login allowed, 5 any-to-any rules, flat segmentation, no remote syslog configured. No known vulnerability matches RouterOS 7.22.3 in NetCheck's list. guardian's software version is not known (its config holds format version 24.6), so it was not checked against the list. The vulnerability list is ten entries written from memory of the published advisories (affected and fixed versions), not checked against the advisories today. Checked by tests and an offscreen render; not tried in the running app; the password comparison was exercised with made-up passwords only.
- MikroTik commands: optional rule for Wi-Fi client events on a CAPsMAN controller, `topics=caps,debug` (1.9.1). Chosen over `topics=caps` so that caps,info lines, which the info rule already sends, are not sent twice. Not entered on a switch; that both rules firing would send a line twice is how RouterOS logging rules are understood to work, not something tested here.
- MikroTik logs not arriving in Syslog: diagnosed, no code change. NetCheck was listening on 59000 (UDP and TCP; the one-time port move had run) and receiving pfSense lines from 222.10.50.1 (2,216 since 20:00); nothing had come from any MikroTik. Read-only SSH (print commands only) on the four switches: CRS328-MASTER's `remote` action is right (222.10.50.25:59000, UDP, syslog format), but its two rules to it are `wireless,debug`, and its log has no `wireless` lines at all: of 1,000 lines 990 are `caps` (976 `caps,debug`: client connected / disconnected; 13 `caps,info`). The three CRS109s have no remote logging set up. The rule to add on CRS328 is `topics=caps` → `remote`; left for the operator to enter. Seen in passing in guardian's filter log: 222.20.20.254 opening connections to many hosts and ports in 222.20.20.0/24 from one source port.
- Device library for Add Device grown from 31 models (9 makers) to 733 (58 makers), with Category and Search in the dialog and seven new device kinds (1.9.0). Port layouts are written from memory of each model's hardware, not checked against data sheets today: brand-specific entries were kept to models whose ports are well known, and the rest are generic entries (for example "Smart TV (Ethernet + Wi-Fi)"). Ethernet speed is left as plain "copper" where it is not known (Sky, Arlo, Unblock Tech). Wi-Fi cards that are optional (OptiPlex Micro, HP Mini, ThinkCentre Tiny) are not listed as ports. The nine existing library files keep their models unchanged and are now written one model per line. Checked by tests (every model: has ports, a known kind, role, colour and category) and an offscreen render of the dialog; not tried in the running app.
- Topology: bridge name pill moved above the bridge outline (1.8.3, BUG-056). Rendered from the saved site for CRS109-1 and CRS328: pill at 52–66 px, outline at 68 px, ports below.
- Log Pipeline merged into Syslog (1.8.2). `log_pipeline_screen.py` is gone; the MikroTik block is `mikrotik_log_box.py`. On this PC the saved Syslog port is 5514 (last used 26 Aug, 2,976 lines from 222.10.50.1) and Log Pipeline was on 59000 (its settings were saved today): the first time Syslog is opened in the app, its UDP and TCP ports become 59000. That has not happened yet: data/syslog.json and data/log_pipeline.json are untouched. Syslog still accepts only attached routers and 222.10.50.0/24, where Log Pipeline accepted any source. Checked by tests and an offscreen render against copies of the settings; not tried in the running app. Tests can no longer reach the real data/syslog.json or data/log_pipeline.json (conftest).
- Sections: Console, Syslog and Log Pipeline moved under Logs (1.8.1). The section list goes from 23 entries to 20; Logs has six pages. Setup → Logging and Setup → OpenObserve stay under Setup (they are settings). Syslog and Log Pipeline are still two separate receivers that do nearly the same job; not merged.
- Log Analysis: device picker and two-device config comparison (1.8.0). Run on the saved configs: CRS328-MASTER sfp7 ↔ CRS109-1 sfp1 has VLAN 662 tagged on the CRS328 end and untagged on the CRS109-1 end (the map has a planned tagged 662 there that is not on the device); CRS109-1 has the new-style CAP (/interface wifi cap) switched on while CRS328's /interface wifi capsman is off (its legacy CAP does point at 222.10.1.5, which CRS328 has, with CAPsMAN on); guardian has VLAN 662 as 222.10.80.1/24 while the switches use 222.10.70.x/24; CRS109-3 has 222.10.70.30/32 on VLAN 662 where the others use /24. Only the CRS328–CRS109-1 cable is drawn, so other pairs get no port comparison. Whether these explain the 19,711 "no suitable CAPsMAN" lines is not established. Checked by tests and an offscreen render; not tried in the running app.
- Removed a leftover `crs109` "paused" entry from data/device_logs/state.json: written at 19:22 by an earlier version of the Load All test, before that test was pointed at a temporary state file (BUG-055). No device on Login to Routers has that name. guardian's pause entry is untouched.
- Log Pipeline: MikroTik remote-logging commands with Copy and undo (1.7.1). On this PC the page lists 172.27.224.1 (Hyper-V), 222.10.50.25 and 100.48.62.65 and starts on 222.10.50.25. Checked by tests and an offscreen render only: the commands have not been entered on a MikroTik, so no MikroTik line has been seen arriving on port 59000 yet.
- Log Analysis page (1.7.0). On the downloaded MikroTik logs (28 files, 41,745 lines, 18 Oct – 15 Nov): CRS109-3 rebooted once without a proper shutdown; CRS109-1 logged "no suitable CAPsMAN" 19,711 times; CRS109-2 ether2 went down 118 times, "Fujitsu PC (VL630)" 60, ether6 56; client C8:FF:77:A3:65:27 reassociated 2,107 times on CRS109-W-3-1; CRS109-3 refused 99 WinBox connections from 222.10.50.25 (this PC). pfSense log parsing is tested on sample lines only: no guardian logs have been downloaded (its logins fail, BUG-054).
- guardian SSH and web GUI (443) stopped answering this PC at about 19:10 (ping and port 80 still answer): pfSense Login Protection (sshguard) block. Cause: the automatic log downloads added on 9 Nov failed to log in to guardian every 6 hours (19 failures), then Load All failed at 19:08, then manual Load Config tries. guardian accepts keys only; the saved login is a password from August and no key file; none of the three default keys in ~/.ssh is accepted; ssh-agent is stopped. Fixed going forward in 1.6.3 (BUG-054): a refused login pauses all automatic logins to that device. guardian is paused in data/device_logs/state.json now. Still needed from the operator: the block to clear on guardian, and the right private key file set for guardian on Login to Routers.
- VLAN cable onto a port that lacks the VLAN now asks first (1.6.4). Dropping on the right stripe was checked and works (CRS328 sfp-sfpplus1 VLAN 630 → guardian OPT5).
- Port names in switch pills (from RouterOS comments) and Rename port on the map (1.6.2). CRS109-1 shows Mavenir E72 (VL630), Phillips Hue (VL710), Growatt LAN, Netgear LL Wireless (VL710), >> Uplink.
- Rainbow connector: blended colours, clear of device edges, faint behind boxes; any cable's long bar can be dragged (1.6.1).
- Topology: planned VLANs on ports, with the commands to apply them (1.6.0). Tried on the saved site: VLAN 662 tagged on CRS109-1 sfp1 gives switch-chip commands (switch vlan + egress-vlan-tag), noting the uplink / CPU port must be added for a VLAN new to the switch. Nothing entered on any device.
- Login to Routers: Load All (1.5.9). Faked-SSH test only; not run against the real devices.
- guardian's bridge0 drawing corrected: only VLAN 710 on igb0 and mce1 is bridged (1.5.8, BUG-053).
- MikroTik parser no longer registers interface lists / profiles / the switch chip as interfaces (BUG-051); CRS109-1 goes from 28 "interfaces" to 15. Logical map rebuilt on that, with port VLAN notes and right-click (1.5.7).
- Will it work? right-click: Check Controller, Use Controller Data (repair steps to copy, nothing applied), Show which port(s); Reachability wording for switch-chip designs (1.5.6). CRS109-1: VLAN 662 still warned — it has an interface there and is not in the switch chip.
- Dashboard tiles: Show and explain; white text on the selected Will it work? row (1.5.5, BUG-052).
- VLAN stripe hover; same-size-per-model checkbox on Login to Routers (1.5.4).
- 25 px rainbow connector for all-VLAN port pairs; per-VLAN cable delete fixed (1.5.3, BUG-050).
- Re-arrange cable / Re-arrange all cables on the cable menu; chosen lane saved as Link.lane in the topology JSON (1.5.2).
- Cable hops at crossings on all topology canvases (1.5.1).
- Topology Auto-arrange with ELK (1.5.0). elkjs 0.12.1 fetched with npm pack (operator approved the download); tarball sha512 matched the npm registry; only elk.bundled.js + LICENSE kept, in pfsense_checker/vendor/elk. Runs in QJSEngine with a setTimeout shim and the console extension; no Node at run time. Tried on the saved site with sample cables (none are saved yet): guardian on top, CRS328 below, the CRS109s at the bottom.
- Python Modules: nmap row next to Graphviz in a Programs panel (1.4.2). This PC: nmap not installed; Npcap driver running (Subnet Health scans use the ping sweep + ARP fallback until nmap is installed).

## 2026-11-09

- Topology: per-VLAN cables from the stripes in the port pills (1.4.1). Saved as links of kind "vlan" with one VLAN.
- Automatic router log downloads over SSH (1.4.0): schedule (6 h default) + after Connect / Load Config, files in data/device_logs, index table device_log_downloads, Logs → Device Logs page. Live: CRS328 gave its 1000-line memory log, then 3 new lines on the next run. Not tried against guardian (sshguard); pfSense path covered by tests only.
- Live check first failed with "Authentication failed" because it ran under C:\Python312, which has no keyring; the app's .venv has it. Background downloads also apply the saved login from ssh_host_credentials, as Connect does.

## 2026-11-08

- Easter eggs drawn better: shaded figures with hands, shoes, eyes and ground shadows, shadowed bubbles, gradient captions, vignette (1.3.127).
- Easter eggs: Black Knight, coconuts, Shirley, Nothing to see here, Zoolander, Brave Sir Robin (1.3.126). 15 scenes. Minstrels sing new lines, not the film's song. Login status bar: SSL on the second row; green #69f0ae → #00e676.
- Status bar shows the database in full (1.3.125). Live: PostgreSQL 18.1 on localhost:5432 (::1), database netcheck, SSL in use (TLSv1.3, TLS_AES_256_GCM_SHA384), sslmode prefer, server ssl on. No PostGIS or TimescaleDB extension installed yet.
- requirements.txt checked: every third-party import is listed; `packaging` is optional (guarded) and ships with pip.
- Easter eggs: Mrs. Doubtfire dropped (operator); The Shining door, A Few Good Men courtroom, Jack Sparrow's sinking arrival (1.3.124). 9 scenes. Biggus Dickus got the "little titter" line.
- Easter eggs: Good Morning Vietnam, Fawlty Towers (the Germans), Biggus Dickus (1.3.123). Cancel/Quit narrowed to 130px.
- Login screen: status bar twice as high with Cancel/Quit in it; Login button on the right (1.3.122).
- Login Tools: Easter Egg me (three original cartoon homages, drawn with QPainter, no film material); Tools buttons equal width across the panel; copyright line 3pt larger (1.3.121).
- Login Tools: Get in Touch opens an Outlook email to administrator@aliniant.com, subject "Tell me about netcheck" (mailto fallback) (1.3.120). Outlook found at Office16 on this PC; not clicked here (it would open a draft).
- Login screen description 2pt larger, with the Aliniant UK Ltd sign-off after "Enjoy" (1.3.119).
- Login screen: the operator's description of NetCheck added between the Login and Tools panels (1.3.118).
- Login screen: the copyright line moved from the banner to between the Tools panel and the status bar (1.3.117).
- Login screen: Login and Tools panel contents moved 10px further down from their title pills (1.3.116).
- Port right-click → Uplink: any port can be moved into the title bar for northbound cables; saved per device (1.3.115).
- The two empty "Pfsense · host" boxes were guardian again: a network scan found its web GUI at 100.48.64.1 (LAN, igb1) and 222.10.50.1 (VLAN 630 gateway, also this PC's default gateway) and added each as a device with no config. They are no longer drawn; host-222-10-50-1 was also marked ignored and was drawn anyway (1.3.115).
- CRS109-2 (Lounge): ether1 is named "Fujitsu PC (VL630)"; the RouterOS inventory cut it to "Fujitsu", so it showed outside its bridge (1.3.115, BUG-049). Reconnecting the CRS109 stores the full name.
- CRS328: front panel now sfp1-20, combo1-4, sfp-sfpplus1-4; its six CAPsMAN interfaces are no longer drawn as ports (1.3.114).
- guardian's bridge0 joins VLAN 710 on igb0 and mce1: now drawn as a chip with lines to the 710 stripe on each port (1.3.113).
- Uplinks in the chassis title bar (1.3.112). guardian: WAN, OPT1 (WAN2), OPT2 (WAN1_main) and the three EVL OpenVPN clients.
- Suite: 418 passed. `test_log_pipeline::test_pipeline_page_port_defaults_to_59000` failed once in the full suite and passed on rerun (child-process timing).

## 2026-11-07

- Topology Add Device with a device library (9 built-in vendor files + data/device_library) (1.3.111). Port lists in the starter library are from known models; worth checking against real units.
- SSH pulls share one login with Connect (keys / agent, key-only retry); fixes Load Config on guardian asking for a password (1.3.110, BUG-048). Not run live against guardian (sshguard).
- Right-drag pans the topology canvases; room to pan round the devices; redraws keep the view (1.3.109).
- Map pick switches the Devices subnet tab; subnet tabs repainted with their colours and a highlighted selected tab (1.3.108, BUG-047).
- Linksys support and logo background clearing (1.3.106); linksys.jpg moved into assets/logos.
- WLANs coloured by SSID VLAN via CAPsMAN on CRS328 (630 LAN / 710 IOT) and placed in each CRS109's bridge; right-click no longer rubber-bands; ports below the title bar with room for the bridge name (1.3.107).
- Map selection follows the Devices list both ways; selected chassis border 1px thicker and pulsing; Python Modules unticks apply at next login; 30 new tests for modules that had none (attack_surface rules, vlan_enforcement, monitor probes, cli, wireshark_bridge, excel_layout) plus selection / unload tests. Suite: 382 passed (1.3.105).
- Topology ports coloured by VLAN, trunks striped, VLAN legend, bridges drawn around their ports, VLAN interfaces / bridges no longer port cells, IP addresses 2pt larger (1.3.104).
- Config findings shown on hover: CRS109-3 ether4 / ether5 have PVID 630 but are untagged members of 662 / 710; CRS328 combo1-4 and sfp1 are untagged in more than one VLAN; CRS109-3 ether3's bridge port is disabled.
- Zoom slider on the Login to Routers, Topology and Topology Builder canvases (1.3.103).
- Login screen rainbow backdrop, very subtle and slowly undulating, different each opening (1.3.102).
- Fixed device boxes jumping while dragged on Login to Routers / Topology (1.3.101, BUG-046).
- Logos fill the chassis title bar, aspect kept, margins trimmed; operator's mikrotik.png, pfsense.png and juniper.jpg in assets/logos (1.3.100).
- Panel title pills restyled to the Lumen glass chip (motifs.md section 3), app-wide (1.3.99).
- DNS Leakage test package and page (1.3.98). First run on this PC (VLAN 630, 222.10.50.25): uses 222.10.50.1 as it should, but plain DNS to 1.1.1.1 / 8.8.8.8 / 9.9.9.9 (UDP and TCP 53) goes straight out, DoT (853) and DoH reach Cloudflare / Google / Quad9, and use-application-dns.net resolves. DNS egress 172.70.161.26 (Cloudflare: guardian forwards). Windows' fec0:0:0:ffff::1-3 placeholder IPv6 DNS servers are ignored.
- Topology port layouts (one row / flat / rectangular, right-click the title), cells fill the box width (1.3.97).
- Vendor logos: lookup widened (aliases, any case, more formats, Fortinet / Cisco / Netgear); waiting on the operator to drop official logo files into assets/logos (1.3.97).
- gemma4:26b without thinking: 99 s on the same VLAN 662 prompt, same main causes. Think first is now off by default.
- Troubleshooter live run: gemma4:26b on CRS109-1 VLAN 662 named the missing switch-chip VLAN, the 222.10.70.0/24 vs 222.10.80.0/24 mismatch with guardian, and no access port for 662. It took 9.5 minutes (52 s reading the prompt, about 8 minutes thinking); the first, non-streamed attempt timed out at 600 s. Now streamed, with Think first optional.
- Problems / Troubleshooting rebuilt (`troubleshoot.py`): device / interface / problem / further info → Ollama against the config, with a preview of exactly what is sent (1.3.96, BUG-044).
- Name Parser (`name_parser.py`, Config Check tab), Parsed name column and VLAN / bridge row shading in Will it work?; topology type / model / OS / identity line and logo lookup (`device_identity.py`); Graphviz panel (`graphviz_status.py`) (1.3.95).
- Graphviz 16.1.0 is installed at C:\Program Files\Graphviz\bin and renders, but is not on PATH; the Python graphviz package is not installed.
- librouteros: all four MikroTiks (RouterOS 7.22.3) have api (8728, plain text) and api-ssl (8729) enabled, but api-ssl has no certificate. librouteros and keyring are not installed in C:\Python312. Operator decision: not yet — no API work until asked.
- guardian's long SSH username is deliberate (operator decision); leave it in topology.json and ssh_host_credentials and do not flag it.
- Beacon Creator syntax check, green / red per field and cell (1.3.94).
- Config Check VLAN awareness (`vlan_enforcement.py`): bridge filtering vs switch-chip VLANs vs none; the CAP vlan-filtering ERROR is gone where the switch chip enforces VLANs (1.3.94, BUG-043).
- Live config findings: CRS109-1 and CRS109-2 enforce VLANs in the switch chip (pass). CRS109-3 has a bridge VLAN table (600/630/662/710) but nothing enforces it. CRS109-1 has VLAN 662 in its bridge table but not in the switch chip, so its own 222.10.70.10 address on VL662 is unreachable. CRS328-MASTER filters on the bridge (offloaded on CRS3xx).
- Subnet Health device scan (`device_scan.py`): nmap first (ping sweep + ARP fallback; nmap not installed yet), router ARP / DHCP tables, loaded-config pools and static maps, beacons; connection types; problem list; device age in PostgreSQL `subnet_devices`. Old ping / speed checks kept on an Access & speed tab; settings rebuilt with the collector token in the keyring. Beacon bundles fixed (1.3.93, BUG-024, BUG-042).
- First live scan of 222.10.50.0/24: 11 devices (guardian, four MikroTiks, a pfSense static mapping at .11, this PC, .64–.67 in guardian's DHCP pool), no problems. MikroTik tables were not read from the command line (no SSH password in that process); guardian was skipped (sshguard).
- Topology chassis: one row, typed / shaded ports, pfSense ports by name, port-exact cables in lanes; drag a loaded config onto Config Check (1.3.92).
- Logs → Login History (login_sessions table, heartbeat, failed attempts with unknown names withheld) (1.3.91).
- Topology page unlocked: port-to-port cables by drag, Delete cable on right-click, Lock layout, edits shared with Login to Routers (1.3.90).
- Python Modules: loaded but not required modules shaded light blue (1.3.89).
- Inventory viewer step 1: `ssh_inventory` rebuilt for pfSense/FreeBSD and RouterOS over SSH (read-only), Ports / interfaces is now a table saved with the device (1.3.88, BUG-024). Not yet run against live devices: Connect in the app to collect. Next: RouterOS API (api-ssl), SNMP v3, feed into Will it work?.
- Will it work? → Reachability for pfSense and MikroTik, cross-device default gateway; DHCP uses the same dead-VLAN-interface check (1.3.87).
- Reachability findings: guardian opt3 (100.48.56.0/24, LB_MCN) and opt12 (VLAN 662) have no pass rule out (pfSense default block). CRS328-MASTER's bridge filters VLANs but is not tagged in VLAN 710, so its own VL710 address (222.20.20.5) and DHCP relay REL5 are dead. VLAN 662 subnet mismatch confirmed from both sides. Internal networks use public address space (100.48.x, 144.80.37.x, 213.26.72.x, 222.10.x, 222.20.20.x).
- Will it work? → Bandwidth (estimate), cross-device per VLAN to the Internet; details pane for long results (1.3.86).
- Bandwidth findings: Internet ≈ 1 Gbps via WAN1 (FailoverGW tier 1), failover 150 Mbps via WAN2; WAN3 not in the group. Five VLANs share guardian mce1 (1 Gbps per its description) behind a 10G switch uplink, so mce1 is the bottleneck. CRS109-1 ether5 negotiates 10 Mbps only. VLAN 662 has no working gateway (subnet mismatch). CAPsMAN 2.4 GHz 20 MHz n ≈ 72 Mbps realistic per radio.
- Will it work? → Wireless (local radios, CAP, CAPsMAN manager, cross-device CAP/manager dependencies). Python Modules rows shaded green / red for needed modules (1.3.85).
- Wireless findings on the live network: CAPsMAN on CRS328-MASTER uses WPA2-PSK/AES (no WPA3, no PMF); channels 2412/2432/2442 overlap (use 1/6/11); CAP CRS109-1 bridge has vlan-filtering=no, so SSID VLANs 630/710 pass but VLAN hopping is possible; CRS109-1 has both legacy and wifi CAP enabled.
- Config Check → Will it work? (`config_analysis.py`): DHCP area for pfSense and MikroTik, cross-device relay resolution, degraded state and coverage when upstream configs are missing (1.3.84).
- DHCP findings on the live network (CRS328-MASTER + guardian): VL600 relays to 222.10.1.1 but guardian opt19 has DHCP disabled; VL662 is 222.10.70.0/24 on the MikroTik but 222.10.80.0/24 on guardian (relay target 222.10.70.1 owned by nothing loaded); relays on VL600/630/638/710 sit on the server's own subnet (duplicate answers); guardian opt4 scope enabled on a disabled interface and overlapping opt3; 8-address pools on opt6/opt7.
- guardian config.xml was unreadable (sudo text after </pfsense>); fixed (BUG-041).
- Main menu: Security Holes, Pentesting, DNS Leakage sections with landing pages; no tests run yet. Operator has a remote pentesting server (details needed before wiring it in) (1.3.83).
- Python Modules: Persist Changes button (load ticked modules now and after each sign-in); Save/Commit applies to this session only (1.3.82).
- Load config dialog: load from device first and default; status connected is green and semi-bold; Config button green when loaded, blue while loading; login Tools buttons red / green / hazard-striped Check Config; Cancel renamed Cancel/Quit App (1.3.81).
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
