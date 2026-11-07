"""Explain one config finding in enough detail to act on it.

The four write-ups are local. They use the finding text and the inventory
already parsed from the file. They do not call a model, and they do not
treat a warning as a clean result.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from pfsense_checker.models import CheckResult, Finding, InterfaceInfo, RuleInfo, Severity

_KIND = {
    "issue": "Explain Issue",
    "severity": "Explain Severity",
    "fix": "Suggest Fix",
    "removal": "What Breaks if Removed",
}


def analyse(finding: Finding, result: CheckResult | None, kind: str) -> str:
    """Return the write-up for *kind*: issue, severity, fix, or removal."""
    if kind not in _KIND:
        raise ValueError(f"unknown analysis kind {kind}")
    loaded = result or CheckResult()
    topic = classify(finding)
    body = _BODIES[topic](kind, finding, loaded)
    return _header(finding, loaded, kind) + "\n\n" + body.strip() + "\n"


def suggested_filename(finding: Finding, kind: str, result: CheckResult | None) -> str:
    """File name for Save Analysis. No path, no secrets."""
    host = (result.hostname if result is not None else "") or "firewall"
    category = finding.category or "finding"
    label = {"issue": "issue", "severity": "severity", "fix": "fix", "removal": "removal"}.get(
        kind, "analysis"
    )
    raw = f"{host}-{category}-{label}-analysis.txt"
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip("-")
    return safe or "finding-analysis.txt"


def classify(finding: Finding) -> str:
    blob = f"{finding.category} {finding.path} {finding.message}".lower()
    checks: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("wan_open", ("any destination and port", "any source to any port", "to any port")),
        ("wan_port", ("published port", "publish a port")),
        ("any_any", ("any-to-any", "any source, any destination")),
        ("blockpriv", ("private-network", "block private", "private networks")),
        ("bogon", ("bogon",)),
        ("webgui_wan", ("webgui is bound to wan",)),
        ("webgui_http", ("webgui is http", "protocol is http", "webgui protocol is http")),
        ("webgui_open", ("no interface restriction", "webgui has no")),
        ("ssh_password", ("password authentication",)),
        ("ssh_off", ("ssh daemon not enabled", "ssh is not enabled")),
        ("nat_1to1", ("1:1",)),
        ("nat_admin", ("admin or data-plane", "admin ports", "publish an admin")),
        ("nat_noport", ("no port", "name a target but no port")),
        ("vpn_compress", ("compression", "voracle")),
        ("vpn_dh", ("dh group",)),
        ("vpn_ike", ("ikev1", "aggressive mode")),
        ("vpn_cipher", ("broken cipher", "broken encryption", "bf-cbc", "3des")),
        ("vpn_digest", ("digest", "weak hash")),
        ("dns_wan", ("resolver is enabled on wan", "bound to wan", "open resolver")),
        ("dnssec", ("dnssec",)),
        ("syslog", ("remote syslog", "no remote syslog")),
        ("secrets", ("private key",)),
        ("pkg_off", ("appear disabled", "installed but disabled", "disabled ids")),
        ("ids", ("no suricata", "no ids", "not inspecting")),
        ("iface_nodevice", ("no <if>", "no device assignment")),
        ("iface_noaddr", ("no ipv4/ipv6", "without an ip")),
        ("iface_disabled", ("present but disabled",)),
        ("iface_dhcp", ("uses dhcp", "uses pppoe")),
        ("inventory", ("config version",)),
    )
    for topic, needles in checks:
        if any(needle in blob for needle in needles):
            return topic
    return "generic"


def _header(finding: Finding, result: CheckResult, kind: str) -> str:
    host = result.hostname or "(no hostname)"
    if result.domain:
        host = f"{host}.{result.domain}"
    version = result.version or "?"
    path = str(result.path) if result.path else "(no file)"
    line = str(finding.line) if finding.line is not None else "—"
    remediation = (finding.remediation or "").strip() or "(none stored on this finding)"
    return "\n".join(
        [
            f"OPNsense/pfSense finding — {_KIND[kind]}",
            f"Host: {host} · version {version}",
            f"File: {path}",
            f"Severity: {finding.severity.value.upper()} · Category: {finding.category or '—'} · Path: {finding.path or '—'}",
            f"Line: {line}",
            "",
            "Finding",
            finding.message.strip() or "(empty message)",
            "",
            "Stored remediation",
            remediation,
        ]
    )


def _rules_cited(finding: Finding, result: CheckResult) -> list[RuleInfo]:
    text = finding.message.lower()
    found: list[RuleInfo] = []
    seen: set[tuple[str, int]] = set()
    pool = list(result.filter_rules) + list(result.nat_rules)
    for rule in pool:
        descr = (rule.descr or "").strip().lower()
        if descr and descr in text:
            key = (rule.kind, rule.index)
            if key not in seen:
                seen.add(key)
                found.append(rule)
    for match in re.finditer(r"\brule\s+(\d+)\b", finding.message, flags=re.IGNORECASE):
        index = int(match.group(1)) - 1
        if 0 <= index < len(result.filter_rules):
            rule = result.filter_rules[index]
            key = (rule.kind, rule.index)
            if key not in seen:
                seen.add(key)
                found.append(rule)
    return found


def _format_rules(rules: list[RuleInfo]) -> str:
    if not rules:
        return ""
    lines = ["Rules named by this finding:"]
    shown = rules[:8]
    for rule in shown:
        port = rule.dst_port or "(any)"
        lines.append(
            f"  #{rule.index + 1} {rule.type or rule.kind} iface={rule.interface or '—'} "
            f"proto={rule.protocol or '—'} src={rule.source or 'any'} "
            f"dst={rule.destination or 'any'} dst-port={port} "
            f"dir={rule.direction or '—'} disabled={'yes' if rule.disabled else 'no'} "
            f"descr={rule.descr or '—'}"
        )
    extra = len(rules) - len(shown)
    if extra:
        lines.append(f"  +{extra} more named rules not listed here.")
    return "\n".join(lines)


def _iface_for(finding: Finding, result: CheckResult) -> InterfaceInfo | None:
    path = (finding.path or "").lower()
    name = ""
    if path.startswith("interfaces/"):
        name = path.split("/", 1)[1].strip()
    if not name:
        match = re.match(r"([A-Za-z][A-Za-z0-9]*)", finding.message.strip())
        if match:
            name = match.group(1)
    want = name.lower()
    for iface in result.interfaces:
        if iface.name.lower() == want:
            return iface
    return None


def _format_iface(iface: InterfaceInfo | None) -> str:
    if iface is None:
        return ""
    addr = iface.ipaddr or "(none)"
    if iface.subnet and iface.ipaddr and iface.ipaddr.lower() not in {"dhcp", "pppoe"}:
        addr = f"{iface.ipaddr}/{iface.subnet}"
    return (
        "Interface row:\n"
        f"  {iface.name.upper()} enabled={'yes' if iface.enabled else 'no'} "
        f"if={iface.device or '—'} kind={iface.kind} ip={addr} "
        f"bridge-member={'yes' if iface.bridge_member else 'no'} "
        f"descr={iface.descr or '—'}"
    )


def _evidence(finding: Finding, result: CheckResult) -> str:
    parts = [part for part in (_format_rules(_rules_cited(finding, result)), _format_iface(_iface_for(finding, result))) if part]
    if not parts:
        return (
            "The inventory has no rule or interface row whose name appears in this finding. "
            "The text above is the evidence."
        )
    return "\n\n".join(parts)


def _rubric(finding: Finding) -> str:
    level = finding.severity
    if level is Severity.ERROR:
        return (
            "ERROR means a reviewer should treat the box as exposed, or the config as "
            "broken, until this object changes. It is not a style nit. A later firewall "
            "rule or an upstream ACL can still drop the packet; this finding does not "
            "check that upstream filter. It says the config here permits the condition."
        )
    if level is Severity.WARNING:
        return (
            "WARNING means the hardening review fails on this point. It is not INFO, "
            "and it is not a PASS. The exposure can depend on another control "
            "(a missing WAN pass in front of an open GUI, a specific published port, "
            "weak crypto that is not 'none'). Do not close it because the rest of the "
            "file parsed."
        )
    return (
        "INFO is inventory or a choice that is not, by itself, an exposure. "
        "It does not mean the host is fine. ERROR and WARNING rows are the ones "
        "that fail the review."
    )


_Body = Callable[[str, Finding, CheckResult], str]


def _join(*parts: str) -> str:
    return "\n\n".join(part.strip() for part in parts if part and part.strip())


def _wan_open(kind: str, finding: Finding, result: CheckResult) -> str:
    evidence = _evidence(finding, result)
    if kind == "issue":
        return _join(
            "This is an inbound permit on WAN (or a floating rule that includes WAN) "
            "with source any and no destination port. On pfSense/OPNsense that rule "
            "matches new connections to every address and port the firewall will "
            "forward or terminate, limited only by whatever more-specific block sits "
            "above it. pfSense is stateful: this rule is not what allows replies to "
            "LAN-initiated sessions. Those replies match state. This rule is for "
            "sessions that start on the outside.",
            evidence,
            "A description such as an auto-generated policy-routing or whitelist rule "
            "does not make the match narrow. If the source is any and the destination "
            "port is empty, the match is any.",
        )
    if kind == "severity":
        return _join(
            _rubric(finding),
            "This is an ERROR rather than a WARNING because the rule does not name a "
            "port. A WAN pass to 443 is a published service. A WAN pass with no port "
            "is a hole. It would be a WARNING only if the destination port were set "
            "and the remaining question was whether that one service should be public.",
        )
    if kind == "fix":
        return _join(
            "1. Open Firewall → Rules → WAN and find the rule names in the finding.",
            "2. For each one, write down the flows that are supposed to be public. "
            "If the answer is none, delete the rule.",
            "3. If a service must be reachable, replace the rule with a pass that sets "
            "interface WAN, source (not any, if you can), destination host, and one "
            "destination port. Turn logging on.",
            "4. Do not 'fix' this by adding a block under it. First-match means the "
            "wide pass already won.",
            evidence,
        )
    return _join(
        "Removing the finding from this list changes nothing on the firewall.",
        "Deleting these WAN pass rules stops new inbound sessions that had no "
        "narrower pass. Outbound internet from LAN keeps working: return packets "
        "match state created by the LAN rules. What does break is any service that "
        "was reachable only because of this wide rule — a forgotten port-forward, "
        "a VPN that was matching 'any' instead of udp/1194 or udp/51820, or a "
        "management path you did not mean to publish.",
        "Before you delete: on the WAN tab, note every other enabled pass and every "
        "NAT forward. After you delete, confirm those specific passes still exist. "
        "Then generate an inbound session that should fail, and one that should "
        "still work.",
        evidence,
    )


def _any_any(kind: str, finding: Finding, result: CheckResult) -> str:
    evidence = _evidence(finding, result)
    if kind == "issue":
        return _join(
            "An enabled pass with source any, destination any, and no destination "
            "port matches every new session on that interface. On LAN this is the "
            "usual default 'allow LAN to any'. It is still an any-to-any: any host "
            "on that interface can open any protocol to any address. On WAN it is "
            "the ERROR case handled separately when the finding says WAN.",
            evidence,
        )
    if kind == "severity":
        return _join(
            _rubric(finding),
            "Any-to-any on an inside interface is a WARNING, not an ERROR, because "
            "the source is already on a network you accept. It is still a failed "
            "hardening check: lateral movement and unrestricted egress ride this "
            "rule. It becomes an ERROR when the interface is WAN or the source is "
            "the internet.",
        )
    if kind == "fix":
        return _join(
            "Replace each named rule with passes that name the destination and port "
            "(DNS, HTTP/HTTPS, NTP, and the specific internal ranges). Keep a final "
            "reject if you want a logged deny instead of silent default.",
            "If this is the default LAN rule and you are not ready to split it, "
            "leave it and record that the LAN is a flat trust zone. Do not mark the "
            "finding resolved.",
            evidence,
        )
    return _join(
        "Deleting an inside any-to-any pass stops clients on that interface from "
        "opening new sessions, except sessions matched by an earlier pass. Existing "
        "states die when they expire. WAN inbound is a different rule. DHCP and "
        "the firewall's own management address are not 'LAN to any' — clients can "
        "lose DNS, updates, and VPN in one change if this was their only egress pass.",
        "Do this on a maintenance window. Have a console or LAN IP session that "
        "does not depend on the rule you are deleting.",
        evidence,
    )


def _wan_port(kind: str, finding: Finding, result: CheckResult) -> str:
    evidence = _evidence(finding, result)
    if kind == "issue":
        return _join(
            "These WAN passes accept any source, but they name a destination port. "
            "That port is published. The internet can complete a handshake to it "
            "unless a more-specific block is above this rule.",
            evidence,
        )
    if kind == "severity":
        return _join(
            _rubric(finding),
            "A named port is a WARNING. It is a deliberate publish, not an any-port "
            "hole. It is still an exposure of whatever answers on that port.",
        )
    if kind == "fix":
        return _join(
            "Keep the pass only for the service that must be public. Set the "
            "destination to that host, not any. Restrict source if the clients are "
            "known. Enable logging. Prefer VPN for admin ports (22, 443 on the "
            "firewall itself, 3389, Winbox).",
            evidence,
        )
    return _join(
        "Deleting the pass stops new connections to that port from the WAN side. "
        "The daemon on the inside host keeps running; it just stops receiving "
        "internet handshakes. Clients on LAN are unaffected if they do not use "
        "this WAN rule.",
        evidence,
    )


def _blockpriv(kind: str, finding: Finding, result: CheckResult) -> str:
    evidence = _evidence(finding, result)
    if kind == "issue":
        return _join(
            "Block private networks on WAN drops RFC1918, loopback, and link-local "
            "sources before the rule list. With it off, a packet sourced from "
            "10/8, 172.16/12, or 192.168/16 is allowed to hit your WAN passes. "
            "That is normal on a private interconnect or a misconfigured upstream. "
            "It is also how spoofed internal sources arrive if the provider does "
            "not filter them.",
            evidence,
        )
    if kind == "severity":
        return _join(_rubric(finding), "WARNING, not ERROR: the damage depends on whether any WAN pass would accept that source. Combined with an any-source WAN pass, treat it as urgent.")
    if kind == "fix":
        return _join(
            "Interfaces → WAN → enable 'Block private networks and loopback addresses'. "
            "Do that only if the WAN subnet is a public address or a provider link "
            "that should never carry your RFC1918. If WAN is an MPLS or a cross-connect "
            "in RFC1918, leave the box off and write a rule that blocks bogons you "
            "do not use, instead of the blanket option.",
        )
    return _join(
        "Turning the option on is not a deletion. It adds an automatic block. "
        "What breaks: BGP peers, IPsec peers, monitoring, and failover links that "
        "use private addresses on that WAN. What does not break: public internet "
        "clients, and LAN egress.",
    )


def _bogon(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return _join(
            "Block bogon networks drops sources from unallocated space, using the "
            "firewall's bogon list. Off means those sources are eligible for WAN rules.",
            _evidence(finding, result),
        )
    if kind == "severity":
        return _join(_rubric(finding), "WARNING. The list is only as good as its updates, and it is not a substitute for a WAN rule set.")
    if kind == "fix":
        return "Enable bogon blocking on each public WAN and confirm the bogon update job is running. Do not enable it on an interface whose legitimate peers sit in space the list calls bogon."
    return "Enabling it drops sources the list marks unallocated. A new allocation that you actually peer with will blackhole until you exempt it. LAN traffic is untouched."


def _webgui_open(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return _join(
            "system/webgui/interfaces is empty. On pfSense and OPNsense an empty "
            "list does not mean 'LAN only'. The GUI listens on every assigned "
            "interface that is up, including WAN. Whether the internet can log in "
            "then depends on the WAN filter. The listen socket is still there.",
            _evidence(finding, result),
        )
    if kind == "severity":
        return _join(
            _rubric(finding),
            "WARNING while the bind list is empty, because a WAN pass or a missing "
            "block is a separate row. It is an ERROR if WAN is explicitly in the "
            "listen list. Do not downgrade this because you 'usually' block WAN to "
            "the firewall: check that rule.",
        )
    if kind == "fix":
        return _join(
            "System → Advanced → Admin Access → set the WebGUI listen interfaces "
            "to the management interface only (LAN, or a dedicated MGMT VLAN). "
            "Leave protocol HTTPS. Confirm you still have a session on that "
            "interface before you apply. Anti-lockout on LAN is what keeps that "
            "session alive; do not remove it in the same change.",
        )
    return _join(
        "Restricting the listen list stops the GUI on every interface you remove, "
        "including WAN. It does not delete users, certificates, or the LAN "
        "listener you kept. What breaks: bookmarks and NAT that reached the GUI "
        "on the WAN address, and any monitoring that scraped the GUI on that IP. "
        "SSH, if it is a different bind, is unchanged. If you remove the GUI "
        "entirely, you are on the console until you put a listen interface back.",
    )


def _webgui_http(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return "The GUI is set to HTTP. The login and the session cookie cross the network in clear text. Anyone on the path can take the session."
    if kind == "severity":
        return _join(_rubric(finding), "WARNING. It becomes a much worse finding if that HTTP listener is also reachable from WAN.")
    if kind == "fix":
        return "Set the protocol to HTTPS, keep a certificate you control, and only then disable HTTP. Apply from a host that can still reach the GUI if the certificate name does not match."
    return "Switching to HTTPS does not remove the GUI. Old http:// bookmarks stop. Clients that cannot validate the certificate will warn. The password in flight stops being readable."


def _webgui_wan(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return "The GUI listen list includes WAN. The management plane is bound to the outside interface. A WAN filter that does not explicitly block it will present the login to the internet."
    if kind == "severity":
        return _join(_rubric(finding), "ERROR. The bind itself is the exposure. It does not wait on a second misconfiguration to be worth a failure.")
    if kind == "fix":
        return "Remove WAN from the listen interfaces. Keep one inside interface. Apply only while you have a session on that inside interface."
    return "The GUI stops answering on the WAN address. Inside management stays if you left an inside interface in the list. Inbound NAT to the GUI port on WAN dies with it."


def _ssh_password(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return _join(
            "sshd is on, and password authentication is not disabled. A guessable "
            "or reused admin password is a shell on the firewall. The finding does "
            "not say the port is open on WAN; check the filter for tcp/22 (or the "
            "configured port) on WAN separately.",
            _evidence(finding, result),
        )
    if kind == "severity":
        return _join(_rubric(finding), "WARNING. Key-only SSH on LAN is a normal admin path. Password SSH is not. It is an ERROR if a WAN pass publishes that port.")
    if kind == "fix":
        return "Install an admin key, set password authentication to disabled (or sshdkeyonly), and confirm a second session still logs in with the key before you close the password session. Do not leave the port on WAN."
    return "Disabling password auth does not stop SSH. Key logins keep working. Password logins stop, including scripts and monitoring that used a password. Disabling sshd entirely drops every remote shell; the console remains."


def _ssh_off(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return "The SSH daemon is not enabled. This row is telling you the remote shell is absent. It is not telling you the host is hardened, and it is not a vulnerability."
    if kind == "severity":
        return _join(_rubric(finding), "INFO because an off service is not an exposure. Do not spend review time here while ERROR and WARNING rows are open.")
    if kind == "fix":
        return "No change is required to 'clear' this. If you need a shell, enable SSH on the management interface only, with keys, and a WAN block for that port."
    return "There is no SSH service to remove. Turning the finding off changes nothing. Enabling SSH would add a service; that is the opposite of removal."


def _nat_admin(kind: str, finding: Finding, result: CheckResult) -> str:
    evidence = _evidence(finding, result)
    if kind == "issue":
        return _join(
            "A WAN port-forward publishes an inside host on an admin or data port "
            "(SSH, RDP, Winbox, databases, the GUI, Docker, and the like). The "
            "internet handshake lands on the target address and local port. The "
            "associated filter pass, if pfSense created one, is what lets it through.",
            evidence,
        )
    if kind == "severity":
        return _join(_rubric(finding), "WARNING per published port. Several of these together are how a firewall becomes a jump host. The finding lists the ports it could parse; an alias instead of a number is not expanded.")
    if kind == "fix":
        return _join(
            "Delete forwards that are unused. For the rest, set the source to the "
            "clients that must connect, or move the service behind VPN and delete "
            "the forward. Do not leave 22, 3389, 8291, or database ports on any-source.",
            evidence,
        )
    return _join(
        "Deleting the forward stops internet clients from reaching that inside "
        "port. The inside service keeps running for LAN clients. The firewall's "
        "own management is unchanged unless the target was the firewall itself. "
        "An associated filter rule can remain after the NAT rule is gone — delete "
        "that pass too, or the port is still open to the WAN address.",
        evidence,
    )


def _nat_noport(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return _join(
            "The NAT rule names an inside target and no external or local port. "
            "That is not a finished port-forward. Depending on how it was saved, "
            "it can fail closed or publish more than the one service you remember.",
            _evidence(finding, result),
        )
    if kind == "severity":
        return _join(_rubric(finding), "WARNING because the object is incomplete, not because a specific port was confirmed public.")
    if kind == "fix":
        return "Set the protocol, the external port, and the local port. If you cannot name them, delete the rule."
    return "Deleting it removes that translation. Inside hosts keep their LAN addresses. Anything that was accidentally published by the half-written rule stops being published."


def _nat_1to1(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return "1:1 NAT maps a public address onto an inside host for every protocol, not one port. The filter then decides which of those ports answer. A wide WAN pass in front of a 1:1 publishes the host."
    if kind == "severity":
        return _join(_rubric(finding), "WARNING. It is the mapping that is broad. The open ports are whatever the filter passes to that address.")
    if kind == "fix":
        return "Replace 1:1 with port-forwards for the services that must be public, and a filter pass per port. Keep 1:1 only when the host is a screened public server and the filter is tight."
    return "Removing the 1:1 drops every inbound session to that public address. Outbound from the host falls back to the normal WAN address. LAN access to the host's private IP is unchanged."


def _vpn_cipher(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return _join(
            "The tunnel proposes a cipher that is broken (BF-CBC, DES, 3DES, CAST, "
            "or none). A peer that negotiates it does not give you confidentiality. "
            "Blowfish-CBC is the old OpenVPN default and it is still in exported configs.",
            _evidence(finding, result),
        )
    if kind == "severity":
        return _join(_rubric(finding), "ERROR. A tunnel that can come up with a broken cipher is a failed VPN, not a tuning item.")
    if kind == "fix":
        return "Set data-ciphers to AES-256-GCM or CHACHA20-POLY1305 only, on both ends, in the same change window. Remove the weak name from the list. A leftover BF-CBC in the colon-separated list is enough for a downgrade."
    return "Removing the weak cipher does not delete the tunnel. Peers that can only do BF-CBC or 3DES will fail to negotiate until they are upgraded. Traffic that should have been inside the tunnel does not fall back to clear text by itself; it fails closed unless a separate route sends it out WAN."


def _vpn_digest(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return "The HMAC or hash is SHA1 or MD5. That is not acceptable for a new tunnel. GCM suites authenticate with the AEAD and should not be carrying a legacy digest beside a broken cipher."
    if kind == "severity":
        return _join(_rubric(finding), "WARNING. SHA1-HMAC is weaker than a broken cipher, and it is still a failed crypto review.")
    if kind == "fix":
        return "Set SHA256 or SHA384 on both ends together. On AEAD ciphers, do not add a second legacy digest."
    return "Changing the digest forces a rekey. Old peers that only offer SHA1 drop until they match. Sessions inside the tunnel reconnect."


def _vpn_compress(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return "Compression is enabled on OpenVPN. Compressing before encryption is the VORACLE exposure: an attacker who can observe the tunnel can learn about the plaintext from the compressed size. It also buys little on an already-compressed payload."
    if kind == "severity":
        return _join(_rubric(finding), "WARNING. The tunnel can still be using a strong cipher. The compression switch is the defect.")
    if kind == "fix":
        return "Disable compression on both ends in the same change. Leave it off. Do not set adaptive."
    return "Turning compression off does not delete the tunnel. During the mismatch (one side still compressing) the tunnel fails to pass traffic. After both sides match, throughput is whatever the link is, without the compression oracle."


def _vpn_ike(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return "IKEv1, and aggressive mode in particular, exposes identity and uses an exchange that does not belong on a current tunnel. Aggressive mode is how weak pre-shared keys are attacked offline."
    if kind == "severity":
        return _join(_rubric(finding), "WARNING. Aggressive mode with a short PSK is routinely broken. The finding is the mode, not a proof that the PSK was captured.")
    if kind == "fix":
        return "Move both peers to IKEv2. Drop aggressive mode. Use a long PSK or certificates."
    return "The current SA drops when you change the mode. Traffic fails over only if you already have a second path. There is no half-up IKEv1/IKEv2 mix on one proposal."


def _vpn_dh(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return "DH groups 1, 2, and 5 are small enough to be broken. The IKE exchange that used them does not give you the secrecy you think the tunnel has, even if the data cipher is AES."
    if kind == "severity":
        return _join(_rubric(finding), "WARNING. Group 14 or a 256-bit ECP group is the floor. Group 2 in a leftover proposal is enough to negotiate down.")
    if kind == "fix":
        return "Remove groups 1, 2, and 5 from every proposal on both peers. Use 14 or higher, or ECP-256/384."
    return "Peers that only offer group 2 will not rekey. The tunnel stays down until both sides share a modern group. Existing child SAs drop at rekey, not necessarily at the instant you edit the proposal."


def _dns_wan(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return _join(
            "Unbound is enabled and its active interface includes WAN (or all). "
            "The resolver will answer queries that reach port 53 on that address. "
            "If the WAN filter also passes 53, this is an open resolver: cache "
            "poisoning and amplification against third parties.",
            _evidence(finding, result),
        )
    if kind == "severity":
        return _join(_rubric(finding), "WARNING on the bind. It is an incident if udp/53 and tcp/53 are passed on WAN. Check those rules before you call this theoretical.")
    if kind == "fix":
        return "Set Unbound's active interfaces to LAN (and localhost). Add an explicit WAN block for tcp/53 and udp/53 to the firewall itself. Do not 'fix' an open resolver by only hiding version.bind."
    return "Stopping the WAN bind stops outside queries to the firewall's resolver. LAN clients keep resolving if LAN is still an active interface. DHCP that hands out the firewall as DNS keeps working from the inside. Monitoring that queried the WAN address for DNS stops."


def _dnssec(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return "The resolver is on and DNSSEC validation is not. Answers are accepted without a signature check. A poisoned or hijacked upstream is then believed."
    if kind == "severity":
        return _join(_rubric(finding), "WARNING. It is not the same defect as listening on WAN. Both can be true.")
    if kind == "fix":
        return "Enable DNSSEC validation on Unbound. Expect a few broken unsigned zones to fail; those failures are the control working. Do not disable it to 'fix' a single broken name — make an exception for that name."
    return "Turning validation on does not stop DNS. Names that fail validation stop resolving. That will look like an outage for those names only. Turning the resolver off entirely is a different change and breaks every client that uses this firewall for DNS."


def _syslog(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return _join(
            "No remote syslog target is set. Filter, auth, and VPN logs stay on "
            "the firewall disk. A full disk, a crash, or an attacker who gets a "
            "shell and truncates /var/log removes the record. There is no copy.",
            _evidence(finding, result),
        )
    if kind == "severity":
        return _join(_rubric(finding), "WARNING. Logging is not optional on an edge that already has WAN passes. INFO would be wrong: the gap is operational, and it hides the other findings.")
    if kind == "fix":
        return "Point remote logging at a collector that is not this firewall. Use the Log Pipeline listen port if that collector is NetCheck (default 59000), or your existing syslog host. Log the WAN pass rules. Confirm one live line arrives before you close the change."
    return "Adding a remote target does not stop local logs. Removing the only remote target, if you add one and then delete it, returns you to disk-only. Turning local logging off to 'reduce disk' is how you lose the record. Do not do that as the fix."


def _secrets(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return _join(
            "The backup contains private keys (certificate <prv> material). "
            "The count is in the finding. The key bytes are not, and they must "
            "not be pasted into a ticket, a chat, or this analysis. Anyone with "
            "the XML can impersonate the certificate: GUI, OpenVPN, or IPsec, "
            "depending on which cert it is.",
            "This says nothing about whether the live daemon is vulnerable. It "
            "says the file you just opened is a credential store.",
        )
    if kind == "severity":
        return _join(_rubric(finding), "WARNING on the file handling, not a statement that the key algorithm is weak. A single copy in Downloads is enough.")
    if kind == "fix":
        return "Store the XML where you store other private keys. Delete extra copies. If this file has already been mailed or dropped in a shared folder, treat those certificates as compromised and reissue them. Do not print the key to confirm."
    return "Deleting <prv> from a copy of the XML makes that copy unable to restore the service that needs the key. The live firewall keeps the key until you replace the certificate there. Removing the certificate on the live box breaks every service that presents it (GUI, VPN). Reissue first, switch the service, then retire the old cert. Do not 'remove' the key by posting it."


def _ids(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return "No Suricata, Snort, or pfBlocker package is installed. The firewall is doing stateful filtering only. It is not inspecting payloads and it is not sinkholing on a DNS blocklist. That may be a deliberate design if inspection happens on another box."
    if kind == "severity":
        return _join(_rubric(finding), "INFO when the package is absent. It is a WARNING if the package is installed and turned off — that is a control you think you have.")
    if kind == "fix":
        return "If this edge is supposed to inspect, add the package and enable it on the WAN or the transit interface, then confirm alerts leave the box. If inspection is upstream, record that and leave the INFO. Do not install an IDS and leave it disabled."
    return "There is no IDS process to remove. Installing one and then deleting it returns you to filter-only. Enabling a disabled IDS changes traffic only if you put it inline; a span/alert-only setup does not drop packets."


def _pkg_off(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return _join(
            "A package is installed and its enable flag is off. The config still "
            "holds that package's settings (peers, rules, keys). The process is "
            "not providing the control. For WireGuard or OpenVPN that means the "
            "tunnel is down. For Suricata it means no inspection.",
            _evidence(finding, result),
        )
    if kind == "severity":
        return _join(_rubric(finding), "INFO when the checker only knows the package is disabled and the package is not an inspection control. WARNING when an IDS or blocklist is the thing that is off.")
    if kind == "fix":
        return "Either enable it and confirm the process is up, or uninstall it so the next reviewer does not think the control exists. Read the peers and the interface bind before you enable a VPN package — enabling it brings those tunnels up."
    return "Uninstalling removes the package's config as well as the service. A disabled WireGuard tunnel that you delete will drop any site that still pointed a route at it, which is already blackholed if the service is off. Export the settings first if you might rebuild them. Leaving it disabled changes nothing that is currently passing traffic."


def _iface_noaddr(kind: str, finding: Finding, result: CheckResult) -> str:
    iface = _iface_for(finding, result)
    evidence = _format_iface(iface)
    member = ""
    if iface is not None and not iface.bridge_member and iface.kind not in {"lagg", "bridge"}:
        member = (
            "The checker did not mark this port as a bridge or LAGG member. "
            "If it is in fact a switch port or a transit member, the missing "
            "address is normal and the row is noise. If it is supposed to route, "
            "it is up at layer 1 with no layer 3 address, so nothing is routed there."
        )
    if kind == "issue":
        return _join(
            "The interface is enabled and has neither an IPv4 nor an IPv6 address. "
            "Enabled does not mean it forwards. It means the NIC is in the config "
            "and not administratively down.",
            evidence,
            member,
        )
    if kind == "severity":
        return _join(_rubric(finding), "WARNING so a transit port is visible, not because an address-less switch port is an incident. Confirm the role before you treat it as a defect.")
    if kind == "fix":
        return "If it is a member port, attach it to the bridge or LAGG and leave the address empty. If it is a routed network, assign the address and prefix. If it is unused, disable it so it stops looking like a live path."
    return _join(
        "Disabling the interface drops every VLAN, bridge membership, and filter "
        "rule that names it. Hosts on that wire lose the firewall as a gateway "
        "immediately. Assigning an address does not 'remove' the port; it starts "
        "routing there, which can create a new path you did not intend. Do not "
        "disable a port that is the parent of VLANs you still use.",
        evidence,
    )


def _iface_disabled(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return _join("The interface exists in the config and is administratively down. It is not passing traffic.", _format_iface(_iface_for(finding, result)))
    if kind == "severity":
        return _join(_rubric(finding), "INFO. A disabled spare port is normal. Check that no production VLAN still names it as a parent.")
    if kind == "fix":
        return "No change, unless you expected it to be up. If you expected it up, enable it and give it an address or a bridge membership."
    return "It is already disabled. Deleting the interface assignment removes the name from the firewall. Rules and gateways that still point at that name become stale. Physical cabling on a deleted OPT does not move itself."


def _iface_dhcp(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return _join(
            "The address is learned (DHCP or PPPoE), not pinned. The firewall does "
            "not own a stable address on that interface. Published DNS, VPN peers, "
            "and inbound NAT follow whatever the provider hands out.",
            _format_iface(_iface_for(finding, result)),
        )
    if kind == "severity":
        return _join(_rubric(finding), "INFO. Dynamic WAN is normal on many circuits. It is not a vulnerability. It is a constraint on anything you publish.")
    if kind == "fix":
        return "Leave DHCP if the circuit is dynamic. Use dynamic DNS or stop publishing services on the WAN address. Set a static address only when the provider routed you one."
    return "Replacing DHCP with a static address that the provider did not route blackholes the WAN. Removing the interface is a different and larger outage. Keeping DHCP changes nothing tonight."


def _iface_nodevice(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return _join("The logical interface is enabled but has no physical or virtual device in <if>. The name exists. There is no NIC behind it, so it cannot pass packets.", _format_iface(_iface_for(finding, result)))
    if kind == "severity":
        return _join(_rubric(finding), "ERROR because the object is inconsistent: enabled, and bound to nothing. Rules that reference it do not do what they say.")
    if kind == "fix":
        return "Assign the NIC, VLAN, bridge, or LAGG this name is supposed to be, or disable the logical interface until you can."
    return "Disabling it removes a non-functional name from the active set. Rules pointing at it already match nothing. Deleting it breaks the config references (gateways, DHCP, rules) that still use the name."


def _inventory(kind: str, finding: Finding, result: CheckResult) -> str:
    if kind == "issue":
        return _join(
            "This row is the inventory line the checker inserts so the review "
            "starts from the version and the counts. It is not a defect.",
            f"Counts in the summary: {result.summary.get('interfaces_total', len(result.interfaces))} interfaces, "
            f"{result.summary.get('filter_rules', len(result.filter_rules))} filter rules, "
            f"{result.summary.get('nat_rules', len(result.nat_rules))} NAT, "
            f"{result.summary.get('vpn', len(result.vpn))} VPN, "
            f"{result.summary.get('packages', len(result.packages))} packages.",
        )
    if kind == "severity":
        return _join(_rubric(finding), "INFO on purpose. Do not use this row to decide the review. Use the ERROR and WARNING rows.")
    if kind == "fix":
        return "Nothing to change. Read the version against the release you think is installed. A config version that does not match the running firmware is a restore risk, not something this row edits."
    return "There is no object to remove. Deleting the version element in the XML makes the next restore less identifiable. It does not change the running firewall until you restore."


def _generic(kind: str, finding: Finding, result: CheckResult) -> str:
    evidence = _evidence(finding, result)
    if kind == "issue":
        return _join(
            "This row is a specific object in the file, not a general opinion of "
            "the firewall. Read the path as the XML location and the message as "
            "the condition the checker matched. It does not claim an exploit "
            "beyond that condition.",
            evidence,
            "Confirm it on the live box before you change anything: the backup "
            "can be older than the running config.",
        )
    if kind == "severity":
        return _join(
            _rubric(finding),
            "The checker chose this severity from the condition in the message. "
            "Raise it if the same object is reachable from WAN. Lower it only "
            "when you can show the condition is expected and the path is not exposed.",
        )
    if kind == "fix":
        stored = (finding.remediation or "").strip()
        if stored:
            return _join(
                "Do this, then re-check the file:",
                stored,
                "One change at a time. Keep a session that does not depend on the object you are editing.",
                evidence,
            )
        return _join(
            "This finding does not carry a stored remediation. Change only the "
            "object at the path, and only after you can say what still has to work. "
            "Re-import the config and confirm this row is gone for the reason you "
            "intended, not because the section was deleted by accident.",
            evidence,
        )
    return _join(
        "Clearing the row in this tool does not change the firewall.",
        "Removing the object at the path stops whatever that object was doing. "
        "Interfaces take their rules, DHCP, and gateways with them. A pass rule "
        "takes the sessions that matched only that rule. A package takes its "
        "tunnels or inspection. The rest of the config stays.",
        "Before removal, export a copy of the section. After removal, test the "
        "service you think was independent of it.",
        evidence,
    )


_BODIES: dict[str, _Body] = {
    "wan_open": _wan_open,
    "any_any": _any_any,
    "wan_port": _wan_port,
    "blockpriv": _blockpriv,
    "bogon": _bogon,
    "webgui_open": _webgui_open,
    "webgui_http": _webgui_http,
    "webgui_wan": _webgui_wan,
    "ssh_password": _ssh_password,
    "ssh_off": _ssh_off,
    "nat_admin": _nat_admin,
    "nat_noport": _nat_noport,
    "nat_1to1": _nat_1to1,
    "vpn_cipher": _vpn_cipher,
    "vpn_digest": _vpn_digest,
    "vpn_compress": _vpn_compress,
    "vpn_ike": _vpn_ike,
    "vpn_dh": _vpn_dh,
    "dns_wan": _dns_wan,
    "dnssec": _dnssec,
    "syslog": _syslog,
    "secrets": _secrets,
    "ids": _ids,
    "pkg_off": _pkg_off,
    "iface_noaddr": _iface_noaddr,
    "iface_disabled": _iface_disabled,
    "iface_dhcp": _iface_dhcp,
    "iface_nodevice": _iface_nodevice,
    "inventory": _inventory,
    "generic": _generic,
}
