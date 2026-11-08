"""NetCheck application version and change log.

SemVer and the commit sequence live in the repo-root ``versions.py``:

  * ``SEMVER`` — major.minor.patch. Every shipped patch bumps it.
  * ``SEQUENCE`` — increases by 1 on every git commit (``hooks/pre-commit``).

This module's ``__version__`` is that SemVer and must equal ``CHANGELOG[0]``.
``full_version()`` is ``<semver>+<sequence>``. Every shipped patch must:

  1. Bump ``SEMVER`` in ``versions.py`` (``__version__`` follows it).
  2. Prepend a matching :class:`Change` to ``CHANGELOG`` (newest first).
  3. Put concrete user-visible detail in ``notes`` (not vague "misc fixes").

Do not hand-edit ``SEQUENCE``; the commit hook adds 1. Setup → Version and
About read this module. Do not document a patch elsewhere without also
recording it here.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


def _read_versions_file() -> tuple[str, int]:
    """Load ``SEMVER`` and ``SEQUENCE`` from the repo-root ``versions.py``."""
    import importlib.util

    path = Path(__file__).resolve().parents[1] / "versions.py"
    spec = importlib.util.spec_from_file_location("_netcheck_versions_file", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"missing {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    semver = str(getattr(mod, "SEMVER", "")).strip()
    try:
        sequence = int(getattr(mod, "SEQUENCE"))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("versions.py SEQUENCE must be an integer") from exc
    if not semver:
        raise RuntimeError("versions.py SEMVER is empty")
    if sequence < 1:
        raise RuntimeError("versions.py SEQUENCE must be >= 1")
    return semver, sequence


# SemVer. Always equal to CHANGELOG[0].version. Sequence is separate.
__version__, SEQUENCE = _read_versions_file()
VERSION = __version__
APP_NAME = "NetCheck"


def full_version() -> str:
    """SemVer plus commit sequence, for example ``1.3.57+1``."""
    return f"{__version__}+{SEQUENCE}"


@dataclass(frozen=True)
class Change:
    """One shipped version/patch and what it changed.

    Prefer one focused patch per ``Change``. A minor/major release may group
    several related notes under the same version when they ship together.
    """

    version: str
    date: str  # YYYY-MM-DD
    notes: tuple[str, ...]


# Newest first. Each patch since 1.2.0 is its own version entry.
CHANGELOG: tuple[Change, ...] = (
    Change(
        version="1.3.115",
        date="2026-11-08",
        notes=(
            "Right-click a port → Uplink: the port moves into the title bar and its "
            "cables leave northwards; untick it to put it back. Automatic uplinks can be "
            "turned off the same way. Saved with the topology.",
            "Empty boxes found by a network scan at another device's interface address "
            "(guardian's LAN and VLAN 630 gateway) are no longer drawn as extra devices; "
            "devices marked ignored are left off the canvas.",
            "RouterOS inventory keeps interface names with spaces whole (\"Fujitsu PC "
            "(VL630)\" was cut to \"Fujitsu\" and fell out of its bridge); names saved by "
            "the old inventory are matched to the config's full name (BUG-049).",
        ),
    ),
    Change(
        version="1.3.114",
        date="2026-11-08",
        notes=(
            "Front-panel order: copper, then SFP, then combo, then SFP+ (then SFP28 / "
            "QSFP), each group set apart.",
            "CAPsMAN interfaces on the controller are not drawn as ports: the radios "
            "belong to the CAPs.",
        ),
    ),
    Change(
        version="1.3.113",
        date="2026-11-08",
        notes=(
            "A pfSense bridge of VLAN interfaces is drawn as a bridge chip with a line "
            "to the VLAN stripe it joins on each port, and that stripe outlined, instead "
            "of a box round the whole ports.",
        ),
    ),
    Change(
        version="1.3.112",
        date="2026-11-08",
        notes=(
            "Uplinks sit in the middle of the chassis title bar, between the name and "
            "the logo, and their cables leave from the top. pfSense uplinks: the WAN "
            "interface, interfaces with a gateway or a DHCP / PPPoE address, OpenVPN "
            "clients (ovpncN) and interfaces described as WAN or EVL. Ports named wan, "
            "wan1… count on any vendor. The box widens to fit name, uplinks and logo.",
        ),
    ),
    Change(
        version="1.3.111",
        date="2026-11-07",
        notes=(
            "Topology → Add Device…: pick Manufacturer and Model from the device library "
            "and the device is created with its ports (names as its OS shows them, and "
            "copper / SFP / SFP+ / Wi-Fi), placed in view and selected. Optional name and "
            "management IP.",
            "Device library (`device_library.py`): built-in JSON per vendor — MikroTik, "
            "Netgate (pfSense), Juniper, Ubiquiti, Netgear, Fortinet, Linksys, Cisco and "
            "Generic — plus your own files in data/device_library (same format; they add "
            "models or replace built-in ones).",
            "Canvas: ports tagged sfp / sfp+ in their media count as SFP; igc1-igc3 are no "
            "longer mistaken for SFP cages; pfSense ports from the library keep their own "
            "names as labels.",
        ),
    ),
    Change(
        version="1.3.110",
        date="2026-11-07",
        notes=(
            "Load Config / Pull Config / SSH commands log in the way Connect does: "
            "with no password they use the key file, the SSH agent and ~/.ssh keys, and "
            "when a key-only server rejects a password they retry with the keys. Before, "
            "they turned keys off, so a key-only firewall (guardian) always asked for a "
            "password it could never accept (BUG-048).",
        ),
    ),
    Change(
        version="1.3.109",
        date="2026-11-07",
        notes=(
            "Topology canvases: right-drag pans the view (grab-hand cursor); a plain "
            "right-click still opens the menu. 800px of canvas is kept round the devices "
            "so there is always room to pan, and redraws keep the view where it was.",
        ),
    ),
    Change(
        version="1.3.108",
        date="2026-11-07",
        notes=(
            "Login to Routers: picking a device on the map switches the Devices list to "
            "that device's subnet tab and selects and shows its row.",
            "Subnet tabs are drawn by NetCheck (SubnetTabBar): green when the subnet has "
            "devices, grey when empty — the per-tab colours never showed before because "
            "Qt style sheets have no :nth-child (BUG-047). The selected tab is a shade "
            "darker with a 2px border on its left, right and top.",
        ),
    ),
    Change(
        version="1.3.107",
        date="2026-11-07",
        notes=(
            "WLANs are tied to VLANs: wireless ports are coloured by their SSID's VLAN, "
            "from the CAPsMAN controller (matched to each CAP by radio name; a CAP's "
            "second interface is the virtual AP for the slave configuration) or from a "
            "standalone radio's vlan-mode=use-tag. Hover shows the SSID, VLAN and who set "
            "it. CAP radios and their virtual APs sit inside the bridge the CAP adds them "
            "to (dynamic bridge ports that never appear in an export).",
            "Right-click on empty canvas no longer drags a selection box; the right "
            "button only opens the menu.",
            "Port rows sit lower, clear of the title bar; a box with a bridge gets a "
            "strip for the bridge name, in a larger font.",
        ),
    ),
    Change(
        version="1.3.106",
        date="2026-11-07",
        notes=(
            "Linksys devices recognised (Velop, EA, MR, MX, LGS, WRT models) with their "
            "logo, badge and colour; LGS switches drawn as a front panel.",
            "Logos without real transparency (JPGs, flattened PNGs) have their flat "
            "background cleared from the edges in — including a fake transparency "
            "checkerboard — so they sit cleanly on the title bar.",
        ),
    ),
    Change(
        version="1.3.105",
        date="2026-11-07",
        notes=(
            "Login to Routers: selecting a device on the map selects it in the Devices "
            "list, and selecting a row selects it on the map. The selected device's "
            "border is 1px thicker and pulses gently.",
            "Python Modules: unticking Loaded on a loaded module and choosing Save/Commit "
            "now takes it off the sign-in list; the dialog says the change will be "
            "updated at your next login (it stays loaded until then).",
            "More automated tests: attack-surface rules, VLAN enforcement, beacon "
            "ping / DHCP packet parsing, the headless CLI, the Wireshark bridge stub, "
            "the Excel layout import, map selection and the pulse.",
        ),
    ),
    Change(
        version="1.3.104",
        date="2026-11-07",
        notes=(
            "Topology / Login to Routers canvas: VLANs and bridges are no longer drawn as "
            "ports. Ports are coloured by the VLAN they carry (read from each device's "
            "config: switch-chip tables, bridge VLAN table and PVIDs, pfSense VLAN "
            "parents); trunks are striped in the colours of every VLAN they carry; labels "
            "sit on a white chip so they always read. Hover shows access / trunk, each "
            "VLAN named, the bridge, and config faults (PVID vs untagged mismatch, untagged "
            "in several VLANs). A VLAN legend runs across the top. Each bridge is drawn "
            "as a dashed outline around its member ports (`port_vlans.py`).",
            "IP addresses on port tiles are 2pt larger.",
        ),
    ),
    Change(
        version="1.3.103",
        date="2026-11-07",
        notes=(
            "Zoom slider on every site canvas (Login to Routers, Topology, Topology "
            "Builder): bottom-right bar with -, slider (10%-400%, logarithmic), +, the "
            "zoom percentage (click for 100%) and Fit. Ctrl+wheel still zooms, within "
            "the same limits, and moves the slider.",
        ),
    ),
    Change(
        version="1.3.102",
        date="2026-11-07",
        notes=(
            "Login screen: a very subtle, slowly undulating rainbow behind it (about 10% "
            "over the usual grey, waves on 40-90 s cycles), starting from a different "
            "colour, direction and wave pattern each time it opens. Animates only while "
            "visible (`rainbow_backdrop.py`).",
        ),
    ),
    Change(
        version="1.3.101",
        date="2026-11-07",
        notes=(
            "Dragging or resizing a device box no longer makes it jump: the canvas "
            "announces the change once, when the mouse is let go, instead of on every "
            "step, which made Login to Routers rebuild every box mid-drag (BUG-046).",
        ),
    ),
    Change(
        version="1.3.100",
        date="2026-11-07",
        notes=(
            "Topology: the vendor logo fills the chassis title bar (4px inset), aspect "
            "ratio kept, at most 40% of the box wide; empty transparent / white margins "
            "in the image are trimmed first, rendered at 2x for zoom. The type line stops "
            "short of the logo.",
        ),
    ),
    Change(
        version="1.3.99",
        date="2026-11-07",
        notes=(
            "Panel titles (every group box, including the login screen) are the Lumen "
            "glass-chip pill from motifs.md: translucent 3-stop gradient, soft edge, 5px "
            "corners, #22303c semi-bold text (`panel_motif.py`). Nothing else restyled.",
        ),
    ),
    Change(
        version="1.3.98",
        date="2026-11-07",
        notes=(
            "DNS Leakage works: build a test package (one zip, a profile per VLAN with "
            "its expected resolver, read from a loaded pfSense / MikroTik config), run it "
            "on a computer in each VLAN, open the reports here, or Run on this PC. It "
            "checks the resolvers the computer uses (IPv4 / IPv6), the expected resolver, "
            "plain DNS UDP / TCP 53 to Cloudflare, Google and Quad9 (blocked, redirected "
            "to your resolver, or leaking), DNS-over-TLS, DNS-over-HTTPS, the Firefox DoH "
            "canary and the DNS egress address (optionally against a VPN exit). "
            "Standard-library Python only (`dns_leak.py`, `dns_leak_builder.py`).",
            "Config parser: Unbound ACL detection no longer relies on deprecated XML "
            "element truthiness.",
        ),
    ),
    Change(
        version="1.3.97",
        date="2026-11-07",
        notes=(
            "Topology: chassis ports stretch to fill the box width, with full port "
            "names when there is room. Right-click a chassis title to pick the port "
            "layout: one row, flat (two rows, switch style) or rectangular (rows to "
            "fit the box). Saved per device.",
            "Removed an unused layout menu whose actions called missing methods.",
            "Vendor logos: assets/logos takes MikroTik, pfSense, OPNsense, Juniper / HPE, "
            "Fortinet, Ubiquiti, Cisco and Netgear files (SVG / PNG / WebP / JPG, any "
            "case, aliases such as fortigate or hpe; see assets/logos/README.md). New "
            "device kinds fortinet and cisco, detected from the model.",
        ),
    ),
    Change(
        version="1.3.96",
        date="2026-11-07",
        notes=(
            "Problems / Troubleshooting works: describe the problem (device, interface, "
            "problem type, further info) and Ask Ollama. NetCheck sends the parts of that "
            "device's config that matter for the interface and problem (VLAN / bridge, "
            "DHCP incl. config.xml settings, routes, gateways, firewall and NAT rules, "
            "DNS, VPN, RouterOS sections) plus its own Will it work? checks and findings, "
            "with other loaded configs as peers. Secrets are dropped first. 'Show what "
            "will be sent' previews it; Ollama's context window is sized to fit. The "
            "answer streams in as it is written, with a live timer, a thinking indicator "
            "and Stop; the timeout only fires if Ollama goes silent for 5 minutes. "
            "'Think first' (off by default) lets a thinking model reason first: gemma4:26b "
            "took 9.5 min with it and 1.5 min without, finding the same main causes.",
            "Secret filter: DHCP dynamic-DNS keys, passphrases and SNMP communities are "
            "now redacted before anything goes to an AI model (BUG-044).",
        ),
    ),
    Change(
        version="1.3.95",
        date="2026-11-07",
        notes=(
            "Config Check → Name Parser: decode coded port names (e.g. "
            "0_S3_P0_1G_F_… = Physical port · Slot 3 · Port 0 · 1 Gbps · Fiber). "
            "Separator, type codes and part rules are editable, checked (bad "
            "patterns red), tried live, and saved to data/name_parser.json.",
            "Will it work? has a Parsed name column between Check and Result; "
            "VLAN rows are shaded blue and bridge rows light amber, still banded.",
            "Topology: each box shows its type, vendor, model, OS version and "
            "identity (from its config), e.g. Switch + Wi-Fi · MikroTik "
            "CRS109-8G-1S-2HnD · RouterOS 7.22.3. Empty models are filled from "
            "the config. Logos come from assets/logos/<vendor>.svg|png when "
            "present, else the wordmark badge.",
            "Python Modules: a separate Graphviz panel (installed, version, on "
            "PATH, test render, Python package).",
        ),
    ),
    Change(
        version="1.3.94",
        date="2026-11-07",
        notes=(
            "Beacon Creator: Check syntax shades every field and table cell green "
            "(good to go) or red (hover for the reason); after the first check it "
            "re-checks as you type. Generate refuses red fields (the placeholder "
            "collector URL still asks). Same check in the sign-in Beacon Creation "
            "dialog.",
            "Config Check reads how each MikroTik bridge really enforces VLANs: "
            "bridge filtering, the switch chip (CRS1xx/2xx with vlan-filtering=no "
            "keep hardware offload — now a pass, not an error), or nothing. Fixes "
            "offer switch-chip rules first where vlan-filtering would cost "
            "hardware offload.",
            "New VLAN findings: VLANs in the bridge table but missing from the "
            "switch chip, ports outside drop-if-not-member, and VLAN interfaces "
            "the switch chip does not carry to the CPU.",
        ),
    ),
    Change(
        version="1.3.93",
        date="2026-11-07",
        notes=(
            "Subnet Health: scan a subnet for devices. nmap is the main source "
            "(aggressive -sV -O by default; a ping sweep + ARP when nmap is not "
            "installed); router ARP / DHCP tables (saved logins) and loaded configs "
            "fill the gaps. Firewalls are not probed unless ticked (sshguard).",
            "Each device shows its connection type (Router / gateway, DHCP, Static "
            "DHCP, Static, MACVLAN, or DHCP inferred when a pool's leases were not "
            "read), vendor, beacon, and its age: first and last seen are kept in "
            "PostgreSQL (subnet_devices).",
            "Problems tab: IP clashes, gateway MAC changes, static addresses inside "
            "a DHCP pool, one MAC on many IPs, wrong subnet, incomplete ARP, stale "
            "leases, nearly full pools, duplicate hostnames, random MACs, beacons "
            "offline or not found by the scan.",
            "Subnet Health settings, gateway ping and speed sample, and collector "
            "polling are back (lost in BUG-024); the collector token is kept in "
            "the Windows credential store.",
            "Beacons report their MAC, so Subnet Health can mark the device they "
            "run on. Built beacon bundles start again (BUG-042).",
        ),
    ),
    Change(
        version="1.3.92",
        date="2026-11-07",
        notes=(
            "Topology: routers and firewalls are one horizontal row of narrower "
            "(72 px) ports, grouped physical → bridge → VLAN → wireless → "
            "tunnels. VLANs are amber, bridges teal, tunnels / CAP violet, "
            "wireless green; disabled ports are faded and dashed.",
            "pfSense / OPNsense ports show their own interface names; the second "
            "line is the address, or OPTn · NIC.",
            "Cables leave from the exact port (bottom, or top toward a device "
            "above), run in their own lane in the gap between devices, and no "
            "longer cross other chassis.",
            "Drag an entry from Loaded configs onto Config Check to check it.",
        ),
    ),
    Change(
        version="1.3.91",
        date="2026-11-07",
        notes=(
            "Main menu: Logs, first entry Login History — who signed in, from "
            "which IP address and computer, when, for how long and how the "
            "session ended (signed out, or no heartbeat after a crash). Refused "
            "sign-ins are listed in red; the name is kept only for real "
            "accounts. Stored in PostgreSQL (login_sessions); no passwords.",
        ),
    ),
    Change(
        version="1.3.90",
        date="2026-11-07",
        notes=(
            "Topology page is fully interactive (it was a locked preview): drag "
            "chassis, drag from a port to a port on another device to draw a "
            "cable, right-click a cable → Delete cable. Cables highlight on "
            "hover and are easy to hit. Lock layout freezes the map. Edits reach "
            "Login to Routers' map and the rest of the app; Save Topology keeps "
            "them.",
        ),
    ),
    Change(
        version="1.3.89",
        date="2026-11-07",
        notes=(
            "Python Modules: a module that is loaded but not required by "
            "NetCheck is shaded light blue.",
        ),
    ),
    Change(
        version="1.3.88",
        date="2026-11-07",
        notes=(
            "Interface inventory over SSH works again (ssh_inventory.py had been "
            "committed empty): after Connect, pfSense / FreeBSD reports ifconfig "
            "(link, negotiated speed, duplex, MAC, addresses, VLAN parent), "
            "pciconf (NIC vendor / model), version and CPU; MikroTik reports "
            "interfaces, addresses, VLANs, model, serial, firmware, uptime and "
            "each running port's negotiated rate and SFP module. Read commands "
            "only, using the saved SSH login. A device of unknown kind is "
            "identified first (uname).",
            "Ports / interfaces is a table: port, status (green when up), speed, "
            "MAC, address, VLAN / parent, hardware, source, with when and how it "
            "was collected. The inventory is saved with the device.",
        ),
    ),
    Change(
        version="1.3.87",
        date="2026-11-07",
        notes=(
            "Will it work? → Reachability. pfSense: default gateway / group "
            "usable, outbound NAT mode covers each internal network, the first "
            "deciding firewall rule per network (pass, or block / reject before "
            "any pass, or none — pfSense blocks by default), DNS resolver, "
            "overlapping subnets. MikroTik: default route on-link and its "
            "gateway in a loaded config (a dependency), VLAN interfaces on a "
            "VLAN-filtering bridge that is not a tagged member (the device's "
            "own address there is dead), the same VLAN on a different subnet "
            "on the router, overlapping subnets.",
            "Internal networks in public (Internet-routable) address space are "
            "flagged.",
            "DHCP: a relay or server on such a dead VLAN interface is reported "
            "as never seeing a request.",
        ),
    ),
    Change(
        version="1.3.86",
        date="2026-11-07",
        notes=(
            "Will it work? → Bandwidth (estimate). pfSense: Internet capacity "
            "from the default gateway / group (load-balanced tier, failover "
            "tier) and per-network LAN speed and sharing; speeds come from "
            "interface descriptions (e.g. '1G', '150m'), media or NIC type. "
            "MikroTik: port speeds from speed= / advertise= or port type, ports "
            "that only negotiate 10 / 100 Mbps, per-VLAN access ports, trunks "
            "and assumed uplink, Wi-Fi (PHY and ≈ realistic), then onward "
            "through the loaded router that serves the VLAN to the Internet.",
            "Without the router's config a VLAN's path is degraded past the "
            "uplink. A VLAN whose tag reaches the router on a different subnet "
            "is flagged: those clients have no working gateway.",
            "Will it work? shows the full result and fix of the selected check "
            "under the list.",
        ),
    ),
    Change(
        version="1.3.85",
        date="2026-11-07",
        notes=(
            "Will it work? → Wireless. Local MikroTik radios: SSID, security "
            "(open / WEP fail, WPA1 / TKIP warn), protected management frames, "
            "country, WPS, bridged or addressed. CAP: manager found by address "
            "or discovery (a dependency), CAPsMAN enabled there, and each "
            "locally forwarded SSID VLAN carried on the CAP bridge. CAPsMAN "
            "manager: SSID, security profile, channel, country, datapath bridge, "
            "provisioning, overlapping 2.4 GHz channels, and the CAPs as a "
            "dependency. A bridge with VLAN filtering off is reported: tags pass "
            "but nothing stops VLAN hopping.",
            "Python Modules: rows NetCheck needs are light green when loaded and "
            "available, light red when not; packages it does not use are not "
            "shaded.",
        ),
    ),
    Change(
        version="1.3.84",
        date="2026-11-07",
        notes=(
            "Config Check → Will it work?: a deep functional analysis with a "
            "verdict per area (Works / Works with warnings / Will not work / "
            "Degraded). DHCP is the first area: pfSense scopes (interface up and "
            "addressed, range inside the subnet and off the interface address, "
            "pool size, overlaps, static maps, gateway and DNS options, resolver "
            "listening), MikroTik servers (bridge-port binding, pool, network "
            "entry, gateway / DNS) and relays (interface address, firewall input "
            "chain for UDP 67).",
            "Cross-device: relays are followed to the loaded config that owns "
            "the server address (scope enabled? serves the relayed subnet? same "
            "VLAN id with a different subnet? relay on the server's own subnet?). "
            "When a needed upstream config is not loaded, the analysis says it "
            "is degraded, gives the coverage and names each config to add.",
            "Failures and warnings also appear in Findings (category DHCP).",
            "Config Check reads pfSense configs pulled with sudo again: the "
            "sudo lecture / prompt that was saved after </pfsense> made the "
            "whole file unreadable. Pulls now drop it, and existing files load "
            "with a warning.",
        ),
    ),
    Change(
        version="1.3.83",
        date="2026-11-07",
        notes=(
            "Main menu: Security Holes, Pentesting and DNS Leakage sections "
            "after Config Check. Each has a landing page with its purpose and "
            "scope; none runs tests yet.",
        ),
    ),
    Change(
        version="1.3.82",
        date="2026-11-07",
        notes=(
            "Python Modules: Persist Changes next to Save/Commit. It loads any "
            "ticked module that is not loaded yet and saves the Loaded column, "
            "so those modules load again after each sign-in. Purple when the "
            "ticks differ from what is saved; a module that fails to load is "
            "not saved. Save/Commit now only applies changes to this session.",
        ),
    ),
    Change(
        version="1.3.81",
        date="2026-11-07",
        notes=(
            "Load config: Load directly from device is on top and selected by "
            "default; Browse for a local file is below. A kind that cannot be "
            "pulled from (not pfSense / OPNsense / MikroTik) still defaults to "
            "the local file.",
            "Device status 'connected' is green and semi-bold.",
            "Config button: green 'Config Loaded' when a config is attached, "
            "blue 'Loading…' while it is pulled or parsed (back to its previous "
            "state if the load fails).",
            "Login screen Tools: Beacon Creation red, Start Collector green, "
            "Check Config yellow / black diagonal stripes like an ejection-seat "
            "handle (label on a black plate); all three the same size.",
            "Login screen: Cancel is labelled Cancel/Quit App.",
        ),
    ),
    Change(
        version="1.3.80",
        date="2026-11-07",
        notes=(
            "Login panel: Help (yellow), Options (dark grey, white text) and "
            "Forgot Credentials (blue) are the same width as Forgot Credentials, "
            "each with a 1px border in an electric version of its colour.",
            "Login to main tool keeps its size and gets an electric-blue 1px "
            "border; Cancel is white with a 1px 80% grey (#333333) border.",
        ),
    ),
    Change(
        version="1.3.79",
        date="2026-11-07",
        notes=(
            "Python Modules: an Available column right of Loaded, set by "
            "NetCheck — green when the package is installed, meets Required, "
            "and is loaded in this process without an import error; red with "
            "the reason in the tooltip otherwise. You only change Installed and "
            "Loaded.",
            "Loaded choices survive log-out / log-in: Save/Commit stores them in "
            "data/python_modules.json and they are imported again after each "
            "sign-in. Only modules listed in requirements.txt are honoured.",
            "Every package in requirements.txt has its own note (what it is, "
            "what NetCheck uses it for), shown in the Notes column. 15 packages "
            "are marked 'Not used by NetCheck yet'.",
        ),
    ),
    Change(
        version="1.3.78",
        date="2026-11-07",
        notes=(
            "Loaded configs: under the section menu, every Login to Routers "
            "device with a config file attached (name, kind, IP). Click one to "
            "open it in Config Check. Ignored devices are listed greyed.",
            "Database: next to Save login, the live connection's state — "
            "logged in as user@database, and whether SSL is really in use "
            "(read from pg_stat_ssl, with protocol), or a red SSL OFF warning. "
            "The tooltip notes that prefer/allow can fall back to plain text "
            "and that require does not verify the server certificate.",
        ),
    ),
    Change(
        version="1.3.77",
        date="2026-11-07",
        notes=(
            "Right-click a device → Ignore device: the row is greyed out, its "
            "Use box is unticked and locked, it is never tested or connected "
            "and does not count as connected. For a box also listed through "
            "another VLAN. Saved with the site; sweeps leave it alone. "
            "Stop ignoring device undoes it.",
            "Discovery no longer trips pfSense sshguard: one SSH connection per "
            "host that sends NetCheck's own version line before closing (a bare "
            "connect made sshd log a missing identification string), and each "
            "host is identified once per run. Automatic sweeps only ping known "
            "hosts; Scan this subnet / Rescan subnets look again.",
        ),
    ),
    Change(
        version="1.3.76",
        date="2026-11-07",
        notes=(
            "A back arrow (curving up and back) sits above the submenu title. "
            "It slides the menu back to the full section list and leaves the "
            "current page open; picking the section again reopens its "
            "submenu where you were.",
        ),
    ),
    Change(
        version="1.3.75",
        date="2026-11-07",
        notes=(
            "Every device a subnet sweep sees is added to the Devices panel "
            "under that subnet's tab, with its kind from discovery (pfsense, "
            "mikrotik, …). A device already listed by IP or MAC is not added "
            "again; a kind you chose is kept, a generic one is upgraded.",
            "Selecting a subnet row (or its Devices button) shows that "
            "subnet's tab. Until you pick a tab, the panel opens on the first "
            "tab with devices instead of an empty one.",
        ),
    ),
    Change(
        version="1.3.74",
        date="2026-11-07",
        notes=(
            "Right-click a subnet on Login to Routers: Scan this subnet (look "
            "for network devices now), Alter this subnet (network address and "
            "prefix / pool size, normalised as you type, duplicates refused), "
            "Remove this subnet.",
            "Show live subnets works again, and Local adapter shows this PC's "
            "NIC (type, speed, duplex, MTU) or 'reached by routing'. "
            "subnet_health.py had been committed empty; adapter discovery, the "
            "adapter description and beacon subnet rows are rebuilt.",
            "Hyper-V vEthernet adapters are classed as virtual, not wired.",
        ),
    ),
    Change(
        version="1.3.73",
        date="2026-11-07",
        notes=(
            "One section menu, 300 px wide. Picking Config Check or Setup "
            "slides the main list into a greyed strip on the left (20 %) and "
            "shows that section's submenu in the rest; picking any other "
            "section slides it back. The strip stays clickable.",
            "Config Check is a child of the main menu: Open / Pull config, then "
            "Dashboard, Topology, Findings and every other workspace tab. The "
            "workspace no longer has its own menu or a separate Home… page.",
        ),
    ),
    Change(
        version="1.3.72",
        date="2026-11-07",
        notes=(
            "Login to Routers → Subnets has two columns: Seen (routers, "
            "switches, gateways and firewalls found on that subnet) and "
            "Connected (session devices with SSH up). Hover Seen for each "
            "device and why it was identified.",
            "Listed subnets are swept in the background when the site loads "
            "or a subnet is added; Rescan subnets repeats it. Ping + ARP, then "
            "TCP connects to 22, 23, 80, 443, 830, 8291 and 8728 only, the SSH "
            "banner and the web GUI title. No logins. Subnets larger than /22 "
            "show 'too large' instead of being swept.",
            "Identification: RouterOS (ROSSSH banner, Winbox/API ports, "
            "RouterOS title), pfSense / OPNsense (GUI title, one same-host "
            "redirect followed), switches (SwOS / switch titles), this PC's "
            "default gateway, and a local MAC vendor table. MACs are not sent "
            "to the OUI web service for this.",
            "Found devices: the Vendor column shows what discovery identified.",
            "Subnet Devices buttons are disabled while a scan runs (they never were).",
        ),
    ),
    Change(
        version="1.3.71",
        date="2026-11-07",
        notes=(
            "Sign-in backs off after five failed attempts per username "
            "(2 s, doubling, up to 5 min). A success clears it. The window "
            "is per process: restarting NetCheck resets it.",
            "A rejected sign-in logs why (unknown or inactive user, unreadable "
            "stored hash, or wrong password), whether the password was typed or "
            "filled from 1Password, and whether it had leading or trailing "
            "spaces. The password and its length are never logged; an unknown "
            "username is not logged either.",
            "1Password fill stops waiting as soon as the sign-in dialog closes. "
            "An elevated NetCheck no longer starts 1Password (it would run "
            "elevated, as a copy you have not unlocked); it says to run "
            "NetCheck unelevated instead.",
            "Logs go to this install's data/logs again. A logging.json saved "
            "by an older copy (C:\\Python Scripts\\…) sent them to that folder.",
            "The startup line and each 1Password fill log whether NetCheck is elevated.",
        ),
    ),
    Change(
        version="1.3.70",
        date="2026-10-18",
        notes=(
            "A WAN in no gateway group (WAN3 on igb3) has its port card left of the NIC, "
            "beside the gateway groups, and links NIC → WAN port → Internet.",
        ),
    ),
    Change(
        version="1.3.69",
        date="2026-10-18",
        notes=(
            "Segmentation check: the filter rules are evaluated in pfSense order for every "
            "pair of inside subnets (any protocol, some services, or blocked), with a "
            "0–100 score and a finding per subnet that can reach every other.",
            "Each subnet card on the topology has a reach badge (red open, amber limited, "
            "green isolated); hover lists what it reaches. A subnet-to-subnet matrix sits "
            "under the topology.",
            "Bridges are reported as layer 2 joins, with which rules actually filter them.",
        ),
    ),
    Change(
        version="1.3.68",
        date="2026-10-18",
        notes=(
            "Topology is narrower: each column is as wide as its longest label "
            "(120–270 px) with a fixed gap, instead of stretching to the window.",
            "The physical NICs sit inside one frame labelled with the firewall and "
            "its hostname: the box itself.",
            "Bridges have their own column on the right of the VLANs.",
        ),
    ),
    Change(
        version="1.3.67",
        date="2026-10-18",
        notes=(
            "Topology: Internet and the external VLANs share the left column. A WAN NIC "
            "in a gateway group reaches Internet only through the group's card; the group "
            "feeds both Internet and the tunnels bound to it. A WAN NIC in no group goes "
            "straight to Internet. Every gateway group with a member NIC is drawn.",
        ),
    ),
    Change(
        version="1.3.66",
        date="2026-10-18",
        notes=(
            "Topology reads left to right as Internet | External VLANs | Gateway groups | "
            "Physical NICs | Port name | VLANs. Internet is one tall card on the far left, "
            "and every WAN NIC runs straight into it. Tunnels and EVL-named VLANs are "
            "external VLANs: each hangs off the WAN it is bound to, or off its gateway "
            "group's card, which sits between that group's NICs. Rows are placed so no "
            "two links cross; bridge links run on the outer right.",
            "Gateway groups and OpenVPN/IPsec ids are parsed. A tunnel bound to a name "
            "that is not an interface or gateway group is a VPN warning.",
        ),
    ),
    Change(
        version="1.3.65",
        date="2026-10-18",
        notes=(
            "Topology links are drawn again after the window resizes. Columns are "
            "Physical NIC → Port name → VLANs / tunnels → Edge. A NIC with its own "
            "port name feeds its VLANs through that name; a NIC without one feeds "
            "its VLANs directly. Every WAN port (gateway, DHCP/PPPoE, or WAN in the "
            "name) reaches Internet and carries the tunnel interfaces. Each NIC's "
            "cards share a row band, and links from different cards use separate lanes.",
        ),
    ),
    Change(
        version="1.3.64",
        date="2026-10-18",
        notes=(
            "Topology links stay in the gaps between cards. A link that skips "
            "a column crosses in a gap, or below the cards when they are packed. "
            "The four columns spread across the window.",
        ),
    ),
    Change(
        version="1.3.63",
        date="2026-10-18",
        notes=(
            "A yellow Help button sits between AI Help and Close on the status bar. "
            "It explains Home versus the config checker, findings, topology, and Log Pipeline.",
        ),
    ),
    Change(
        version="1.3.62",
        date="2026-10-18",
        notes=(
            "Topology: one physical NIC fans out to every VLAN on that port. "
            "The port name is the label. OPT15 and the other assignment ids "
            "are on the second line, and they are not drawn as NICs.",
        ),
    ),
    Change(
        version="1.3.61",
        date="2026-10-18",
        notes=(
            "Right-click a finding for Explain Issue, Explain Severity, Suggest Fix, "
            "or What Breaks if Removed. Each write-up uses the rule or interface "
            "from the file. Save Analysis writes that window to a text file.",
        ),
    ),
    Change(
        version="1.3.60",
        date="2026-10-18",
        notes=(
            "The config-check sidebar is labeled OPNsense/pfSense Config Checker "
            "above Choose a section, so it is not mistaken for the main NetCheck menu.",
        ),
    ),
    Change(
        version="1.3.59",
        date="2026-10-18",
        notes=(
            "Home → Log Pipeline streams logs in from pfSense. The incoming "
            "port is selectable and defaults to 59000 (UDP syslog and a TCP "
            "line stream on that same port).",
        ),
    ),
    Change(
        version="1.3.58",
        date="2026-10-18",
        notes=(
            "Dragging a config in writes an attack-surface assessment "
            "(management plane, WAN exposure, any-to-any passes, published "
            "admin ports, VPN crypto, DNS, logging) on the dashboard. "
            "The result stays EXPOSED while warnings remain; it is not PASS. "
            "Signing in no longer crashes when background work is still marked busy.",
        ),
    ),
    Change(
        version="1.3.57",
        date="2026-10-18",
        notes=(
            "A companion Console window opens with NetCheck and lists every "
            "log line. Home → Console → Pop out raises that same window.",
        ),
    ),
    Change(
        version="1.3.56",
        date="2026-10-18",
        notes=(
            "Login: Enter in the password field activates Login, not the "
            "1Password button. 1Password fill waits in the background so the "
            "window stays usable while you unlock the app, and a CLI failure "
            "is shown instead of a missing-item message.",
        ),
    ),
    Change(
        version="1.3.55",
        date="2026-10-18",
        notes=(
            "Release identity is versions.py: SemVer plus a commit sequence "
            "that increases by 1 on every commit (shown as <semver>+<sequence>). "
            "worklog.md is the daily record. buglog.md is the bug tracker.",
        ),
    ),
    Change(
        version="1.3.54",
        date="2026-10-18",
        notes=(
            "Login panel: Help, Options, Forgot Credentials, Login, and Cancel "
            "sit on one row. Login turns light blue when the pointer is over it.",
        ),
    ),
    Change(
        version="1.3.53",
        date="2026-10-18",
        notes=(
            "Setup → OpenObserve: ingest and search API (health, JSON ingest, "
            "read-only SQL search). Optional forward of NetCheck app logs and "
            "accepted router syslog. The password stays in the OS keyring, "
            "not in the settings file or PostgreSQL.",
        ),
    ),
    Change(
        version="1.3.52",
        date="2026-10-18",
        notes=(
            "Config Check: the dashed area is a real drop target for "
            "config.xml and RouterOS .rsc. Explorer drags are accepted "
            "(including when NetCheck is running elevated).",
        ),
    ),
    Change(
        version="1.3.51",
        date="2026-09-25",
        notes=(
            "Analysis workspace: replace the top tab bar with a left section "
            "sidebar matching Home (logo, Choose a section, 200px tree, Home…).",
        ),
    ),
    Change(
        version="1.3.50",
        date="2026-09-25",
        notes=(
            "1Password: after launching the desktop app, wait for unlock "
            "instead of aborting on 'account is not signed in'. Poll op whoami "
            "until the vault is unlocked or 90s elapses; bring 1Password to "
            "the foreground so Windows Hello / master-password can complete.",
        ),
    ),
    Change(
        version="1.3.49",
        date="2026-09-25",
        notes=(
            "1Password: if the CLI cannot attach, start the installed desktop "
            "app (Store or classic), wait for the IPC pipe, and retry. Replace "
            "raw op timestamps with a short unlock / Developer-integration hint "
            "(including elevated vs unelevated integrity mismatch).",
        ),
    ),
    Change(
        version="1.3.48",
        date="2026-09-25",
        notes=(
            "Change password / login: 1Password CLI integration — fill current "
            "password, generate a new one, and save the NetCheck login item "
            "(tagged NetCheck) after a successful change. Secrets go through "
            "stdin JSON, never the command line. Options holds vault and title prefix.",
        ),
    ),
    Change(
        version="1.3.47",
        date="2026-08-26",
        notes=(
            "Topology map: pfSense/OPNsense chassis ports populate from pulled or "
            "loaded config.xml (WAN/LAN/OPT interfaces with IPs); existing configs "
            "refresh on load topology.",
        ),
    ),
    Change(
        version="1.3.46",
        date="2026-08-26",
        notes=(
            "pfSense config pull: dialog to enter SSH password when login fails, "
            "or sudo password when automatic elevation fails (Load Config and "
            "chassis Pull Config).",
        ),
    ),
    Change(
        version="1.3.45",
        date="2026-08-26",
        notes=(
            "pfSense config pull: fix sudo hang (no PTY on OpenSSH 10); blank "
            "password field falls back to keyring; sudo prompt when SSH password "
            "differs; pull on background thread with status-bar progress; Console "
            "DEBUG includes paramiko transport trace.",
        ),
    ),
    Change(
        version="1.3.44",
        date="2026-08-26",
        notes=(
            "Device details: two columns (device summary left, ports right); "
            "Model and Software lines always shown; SSH inventory captures "
            "RouterOS board-name + version and pfSense freebsd-version; "
            "config pull fills software from config.xml.",
        ),
    ),
    Change(
        version="1.3.43",
        date="2026-08-26",
        notes=(
            "Login→Devices: one tab per subnet (devices grouped by SSH host "
            "IP); device details panel restored below the link topology map.",
        ),
    ),
    Change(
        version="1.3.42",
        date="2026-08-26",
        notes=(
            "Topology chassis: board-name from MikroTik SSH inventory is "
            "stored as the device model and shown in the title bar; hostname "
            "and role move to the subtitle line.",
        ),
    ),
    Change(
        version="1.3.41",
        date="2026-08-26",
        notes=(
            "Fix splash not showing: restore the pre-login animation wait so "
            "the bar slide runs on a live event loop before the login dialog.",
        ),
    ),
    Change(
        version="1.3.40",
        date="2026-08-26",
        notes=(
            "More startup and UI responsiveness: splash no longer blocks ~2.6s "
            "before login; schema migration runs once per process; login DB "
            "probe is threaded; login logo rasterizes at display size; map "
            "drag debounces topology preview refresh.",
        ),
    ),
    Change(
        version="1.3.39",
        date="2026-08-26",
        notes=(
            "Startup speed: local adapter discovery no longer blocks the UI "
            "(background thread + 45s cache); Login page builds after the hub "
            "paints; SSH credentials load in one DB query per site refresh; "
            "splash logo layers reuse the prepared SVG cache.",
        ),
    ),
    Change(
        version="1.3.38",
        date="2026-08-25",
        notes=(
            "Logo: dimension arrows match the Inkscape original — slim "
            "concave heads, single-ended stubs converging on the A's legs, "
            "double-ended vertical gauges. The © 2026 Aliniant Laboratories "
            "line is baked to an outline and the page grown so it shows.",
        ),
    ),
    Change(
        version="1.3.37",
        date="2026-08-25",
        notes=(
            "Splash/logo: re-wired for the tidied A-Netcheck.svg. The 1px "
            "light-grey frame is injected at render time (survives Inkscape "
            "re-saves) and drawn above the sliding bars; off-page scaffolding "
            "working copies are hidden so no ticks leak below the logo; new "
            "construction lines and swoosh pointers render with Qt-safe "
            "arrows.",
        ),
    ),
    Change(
        version="1.3.36",
        date="2026-08-25",
        notes=(
            "Logo: 1px light-grey outer frame; remove leftover construction "
            "ticks that peeked under the wordmark at the bottom centre.",
        ),
    ),
    Change(
        version="1.3.35",
        date="2026-08-25",
        notes=(
            "Syslog: Listen on dropdown lists named NICs (fiber LAN first, "
            "Hyper-V/APIPA tagged virtual) so the copy-into-pfSense address is "
            "this PC’s 222.10.50.x, not vEthernet 172.x. Start listener turns "
            "green and reads Listener Active while bound.",
        ),
    ),
    Change(
        version="1.3.34",
        date="2026-08-25",
        notes=(
            "Topology chassis right-click: Pull Config, Show more OS / hardware / "
            "uptime (SSH), and Show more alerts (SNMPv3). Right-click no longer "
            "starts a drag.",
        ),
    ),
    Change(
        version="1.3.33",
        date="2026-08-25",
        notes=(
            "Restore emptied core modules (models, discovery, viz, samples) "
            "that caused the GUI to exit immediately on startup.",
        ),
    ),
    Change(
        version="1.3.32",
        date="2026-08-25",
        notes=(
            "Syslog bind: a CIDR such as 222.10.50.0/24 is moved to Also "
            "accept from and the listener binds 0.0.0.0 (fixes getaddrinfo 11001).",
        ),
    ),
    Change(
        version="1.3.31",
        date="2026-08-25",
        notes=(
            "Syslog: Also accept from CIDRs (default hint 222.10.50.0/24) so "
            "fiber-sourced logs are kept when SSH mgmt is on another IP; "
            "listen hint lists that subnet first.",
        ),
    ),
    Change(
        version="1.3.30",
        date="2026-08-25",
        notes=(
            "Syslog: show this PC’s IPv4:port to paste into OPNsense remote "
            "logging; explain syslogd “Host is down” vs attached-router sources.",
        ),
    ),
    Change(
        version="1.3.29",
        date="2026-08-25",
        notes=(
            "pfSense/OPNsense Pull Config: after sudo -n fails, run sudo -S cat "
            "with the SSH password (then a sudo prompt). Same session as "
            "`sudo id` — SCP cannot read root-only config.xml.",
        ),
    ),
    Change(
        version="1.3.28",
        date="2026-08-25",
        notes=(
            "Home → Syslog: UDP/TCP listener for remote logs from attached "
            "routers (allowlist by mgmt/SSH IP), bind/port settings, live table.",
        ),
    ),
    Change(
        version="1.3.27",
        date="2026-08-25",
        notes=(
            "Status bar: 25px busy progress bar to the right of User / module / "
            "Status while background work shows the wait-cursor spinner.",
        ),
    ),
    Change(
        version="1.3.26",
        date="2026-08-25",
        notes=(
            "pfSense/OPNsense Pull Config: fix broken remote cat (shell "
            "redirection), retry via sudo -n and SFTP, and show a clear "
            "message when the SSH user lacks permission to read config.xml.",
        ),
    ),
    Change(
        version="1.3.25",
        date="2026-08-25",
        notes=(
            "Load Config: pull live config.xml from pfSense/OPNsense over SSH "
            "(/cf/conf/config.xml, then /conf/config.xml) when Kind is "
            "pfsense or opnsense — same chooser as MikroTik /export verbose.",
        ),
    ),
    Change(
        version="1.3.24",
        date="2026-08-25",
        notes=(
            "When an action needs an optional package that is missing or not "
            "loaded, remind you to install/load it under Home → Python Modules "
            "(Open Modules / Load now). Wired for SSH Connect, MIB Libraries, "
            "Postgres, Excel import, and Poe AI.",
        ),
    ),
    Change(
        version="1.3.23",
        date="2026-08-25",
        notes=(
            "Python Modules: optional topology viz stack (networkx, "
            "matplotlib, plotly, pyvis, graphviz, pygraphviz, grandalf, "
            "igraph). Setup → MIB Libraries for SNMP MIB search paths; "
            "requirements include pysnmp + pysmi.",
        ),
    ),
    Change(
        version="1.3.22",
        date="2026-08-25",
        notes=(
            "Python Modules / requirements: optional pysnmp, httpx, requests, "
            "redfish, netmiko, napalm, ncclient, scapy for TP-Link/Netgear "
            "switches and Dell iDRAC (toggle off locally via Save/Commit).",
        ),
    ),
    Change(
        version="1.3.21",
        date="2026-08-25",
        notes=(
            "Subnets list: next to Devices, show how many session devices "
            "from that subnet are SSH-connected (none / N connected).",
        ),
    ),
    Change(
        version="1.3.20",
        date="2026-08-25",
        notes=(
            "Login topology map: drag chassis; drag port→port on another "
            "device to create links; Save Topology persists devices + links.",
        ),
    ),
    Change(
        version="1.3.19",
        date="2026-08-25",
        notes=(
            "Login→Routers Kind column is a dropdown (editable best-guess); "
            "Save credentials reloads login fields; hydrate username from DB "
            "when building the device table.",
        ),
    ),
    Change(
        version="1.3.18",
        date="2026-08-25",
        notes=(
            "After Connect: SSH inventory (ifconfig+pciconf / ip+lspci / "
            "RouterOS) fills the right-hand topology with ports and assigned IPs.",
        ),
    ),
    Change(
        version="1.3.17",
        date="2026-08-25",
        notes=(
            "Login→Routers: selecting a device/IP loads saved username "
            "(and keyring password) into the Login panel from "
            "ssh_host_credentials.",
        ),
    ),
    Change(
        version="1.3.16",
        date="2026-08-25",
        notes=(
            "Save credentials: DB stores salted PBKDF2 password_hash only "
            "(never plaintext); live SSH secret remains in Windows "
            "Credential Manager.",
        ),
    ),
    Change(
        version="1.3.15",
        date="2026-08-25",
        notes=(
            "Login→Routers Save credentials: upsert username/IP/keyring ref "
            "into netcheck.ssh_host_credentials and confirm for that IP "
            "(password stays in Windows Credential Manager, never in DB).",
        ),
    ),
    Change(
        version="1.3.14",
        date="2026-08-25",
        notes=(
            "Login→Routers: Connect button is blue; Connected is green.",
        ),
    ),
    Change(
        version="1.3.13",
        date="2026-08-25",
        notes=(
            "Login→Routers Devices: click found IP (blue link) adds/selects "
            "that device in the session table; Connect enabled when a target "
            "is selected (uses typed or stored credentials); local NIC line "
            "shows type, speed, duplex, and MTU.",
        ),
    ),
    Change(
        version="1.3.12",
        date="2026-08-25",
        notes=(
            "version.py: record every patch as its own Change entry; "
            "__version__ must match CHANGELOG[0]; Setup -> Version is the UI.",
        ),
    ),
    Change(
        version="1.3.11",
        date="2026-08-25",
        notes=(
            "Devices: show local adapter under found hosts (name, IP, MAC, "
            "Wired/WLAN, NIC link speed via Get-NetAdapter LinkSpeed).",
        ),
    ),
    Change(
        version="1.3.10",
        date="2026-08-25",
        notes=(
            "Search for devices: dialog default subnet is taken from the "
            "IP/MAC box (CIDR or IP->/24), then written back after OK.",
        ),
    ),
    Change(
        version="1.3.9",
        date="2026-08-25",
        notes=(
            "Main window: fix status bar clipped when maximized — stop "
            "setGeometry(availableGeometry); use maximize + frame clamp and "
            "reserve status bar min height 28px.",
        ),
    ),
    Change(
        version="1.3.8",
        date="2026-08-25",
        notes=(
            "Home nav: About section placeholder (aliniant labs / NetCheck).",
        ),
    ),
    Change(
        version="1.3.7",
        date="2026-08-25",
        notes=(
            "Home nav: Wireshark section + pfsense_checker/wireshark_bridge.py "
            "Lua API scaffold (WSDG Ch. 13 modules, stub plugin text). "
            "Docs: https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html",
        ),
    ),
    Change(
        version="1.3.6",
        date="2026-08-25",
        notes=(
            "Device search found-table: TCP probe columns HTTP :80 and "
            "HTTPS :443 alongside SSH :22 (open / closed / no reply).",
        ),
    ),
    Change(
        version="1.3.5",
        date="2026-08-25",
        notes=(
            "Subnets panel: 'Show live subnets' adds this PC's adapter CIDRs "
            "to the site subnet list.",
        ),
    ),
    Change(
        version="1.3.4",
        date="2026-08-25",
        notes=(
            "Busy wait cursor (pfsense_checker/busy.py) while config check, "
            "AI ask, LAN scan, SSH probe/test, resiliency, and folder import run.",
        ),
    ),
    Change(
        version="1.3.3",
        date="2026-08-25",
        notes=(
            "Status bar beacons: 'None Seen' (red) or 'N Seen' (green); "
            "removed 'Beacons: unreachable' wording.",
        ),
    ),
    Change(
        version="1.3.2",
        date="2026-08-25",
        notes=(
            "Status bar theme (login + main): very dark navy #061830, "
            "semi-bold 9pt text, white/green/red chips via branding helpers.",
        ),
    ),
    Change(
        version="1.3.1",
        date="2026-08-25",
        notes=(
            "Login gate: fix NameError (STATUS_BAR_TEXT not imported) so the "
            "login page appears after splash instead of crashing silently.",
        ),
    ),
    Change(
        version="1.3.0",
        date="2026-08-25",
        notes=(
            "Login/splash logo: bake outlined grey 'netcheck' path into prepared "
            "SVG so the wordmark always renders (Qt cannot fill live SVG <text>).",
        ),
    ),
    Change(
        version="1.2.0",
        date="2026-07-26",
        notes=(
            "Login gate with public-key peppered password hashes; users table + users_login_v.",
            "Super-admin account julian; must_change_password on first login.",
            "Users home section - add / reset / roles / enable-disable.",
            "File / Folder Ops section (moved toolbar actions); window min/max/close.",
            "Status bar: DB connectivity, beacons count, left context (user | module - capabilities).",
            "PostgreSQL netcheck DB schema: topology, config, connectivity, users.",
            "Save Connectivity to DB from Login to Routers.",
            "Python Modules: Installed/Loaded checkboxes + Save/Commit (grey->green).",
            "Tests section - run pytest from the UI.",
            "File / Folder Ops placed second in the nav (under Login to Routers).",
            "version.py changelog module + Setup -> Version view.",
            "Optional vendor SDKs in requirements / Modules: librouteros, junos-eznc.",
            "Launcher login: Login to main tool + Beacon/Collector/Check tools + DB status bar.",
            "Silent Windows subprocesses (no ping/arp console cascade); Console panel Pop out.",
            "Load Config chooser: local file or MikroTik /export verbose over SSH.",
        ),
    ),
    Change(
        version="1.1.0",
        date="2026-07-25",
        notes=(
            "Home hub sections: Login, Beaconing, Subnet Health, Config, Speed, Topology.",
            "Ollama advisor settings; OUI/MAC RapidAPI; Logging; SNMP v3.",
            "Database admin (PostgreSQL); lazy page/tab load for faster startup.",
            "Subnet health local + beacon reporting; Console live logs.",
            "Problems/Troubleshooting section linking findings / resiliency / monitor.",
        ),
    ),
    Change(
        version="1.0.0",
        date="2026-06-01",
        notes=(
            "Initial pfSense / MikroTik config checker GUI.",
            "Findings, dashboard KPIs, topology builder, resiliency, live monitor.",
            "SSH session screen; MikroTik REST collect; AI advisor hooks.",
        ),
    ),
)


def current_version() -> str:
    return __version__


def latest_change() -> Change | None:
    return CHANGELOG[0] if CHANGELOG else None


def all_patches() -> tuple[Change, ...]:
    """Full changelog (newest first) — alias for UI / export."""
    return CHANGELOG


def format_changelog(*, max_releases: int | None = None) -> str:
    """Human-readable changelog text (newest first)."""
    lines = [f"{APP_NAME} {full_version()}", ""]
    entries = CHANGELOG if max_releases is None else CHANGELOG[: max(0, max_releases)]
    for entry in entries:
        kind = "patch" if len(entry.notes) == 1 else "release"
        lines.append(f"## {entry.version}  ({entry.date})  [{kind}]")
        for note in entry.notes:
            lines.append(f"  • {note}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def format_version_line() -> str:
    """One-line summary for status / about."""
    latest = latest_change()
    if latest is None:
        return f"{APP_NAME} {full_version()}"
    first = latest.notes[0] if latest.notes else ""
    if first:
        return f"{APP_NAME} {full_version()} — {first}"
    return f"{APP_NAME} {full_version()}"


def _validate_version_module() -> None:
    """Fail fast if __version__ drifts from the changelog head."""
    if not CHANGELOG:
        raise RuntimeError("CHANGELOG is empty")
    if CHANGELOG[0].version != __version__:
        raise RuntimeError(
            f"__version__={__version__!r} must equal "
            f"CHANGELOG[0].version={CHANGELOG[0].version!r}"
        )
    seen: set[str] = set()
    for entry in CHANGELOG:
        if entry.version in seen:
            raise RuntimeError(f"duplicate changelog version: {entry.version}")
        seen.add(entry.version)
        if not entry.notes:
            raise RuntimeError(f"{entry.version} has no notes")


_validate_version_module()
