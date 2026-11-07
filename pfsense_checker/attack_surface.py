"""Attack-surface assessment for a loaded firewall config.

Structural checks answer "will this XML restore". This module answers
"what is exposed". Findings name the control, the evidence, and what to change.
Private key material is never copied into a finding.
"""

from __future__ import annotations

import re
from xml.etree import ElementTree as ET

from pfsense_checker.models import CheckResult, Finding, Severity

# Published services that are common initial-access targets.
_ADMIN_PORTS = frozenset(
    {
        21,
        22,
        23,
        80,
        161,
        162,
        443,
        500,
        623,
        1194,
        2375,
        2376,
        3306,
        3389,
        4500,
        5432,
        5900,
        5985,
        5986,
        6379,
        6443,
        8080,
        8291,
        8443,
        8728,
        8729,
        9443,
        10443,
        27017,
        51820,
    }
)

_WEAK_OVPN_CIPHERS = frozenset(
    {
        "none",
        "bf-cbc",
        "des-cbc",
        "des-ede3-cbc",
        "cast5-cbc",
        "rc2-cbc",
        "rc2-40-cbc",
        "rc2-64-cbc",
        "seed-cbc",
    }
)
_WEAK_DIGESTS = frozenset({"sha1", "md5", "md4", "none"})
_WEAK_DH = frozenset({"1", "2", "5"})
_WEAK_IPSEC_ENC = frozenset({"des", "3des", "blowfish", "cast128", "null"})
_IDS_PACKAGES = frozenset({"suricata", "snort", "pfblockerng", "pfblockerng-devel"})


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _text(el: ET.Element | None) -> str:
    if el is None or el.text is None:
        return ""
    return el.text.strip()


def _find(parent: ET.Element | None, name: str) -> ET.Element | None:
    if parent is None:
        return None
    want = name.lower()
    for child in parent:
        if _local(child.tag).lower() == want:
            return child
    return None


def _find_text(parent: ET.Element | None, name: str) -> str:
    return _text(_find(parent, name))


def _find_all(parent: ET.Element | None, name: str) -> list[ET.Element]:
    if parent is None:
        return []
    want = name.lower()
    return [child for child in parent if _local(child.tag).lower() == want]


def _has_flag(parent: ET.Element | None, name: str) -> bool:
    el = _find(parent, name)
    if el is None:
        return False
    return _text(el).lower() not in {"false", "off", "0", "no", "disabled"}


def _ports(text: str) -> set[int]:
    found: set[int] = set()
    for part in re.split(r"[,:\s]+", text or ""):
        if part.isdigit():
            found.add(int(part))
    return found


def _iface_names(text: str) -> list[str]:
    return [part.strip().lower() for part in (text or "").split(",") if part.strip()]


def _endpoint_is_any(el: ET.Element | None) -> bool:
    if el is None:
        return True
    if _find(el, "any") is not None:
        return True
    address = _find_text(el, "address").lower()
    network = _find_text(el, "network").lower()
    if address in {"any", "0.0.0.0", "0.0.0.0/0", "::/0"}:
        return True
    return not address and not network


def _label(descr: str, index: int) -> str:
    text = (descr or "").strip()
    return text if text else f"rule {index + 1}"


def _add(result: CheckResult, severity: Severity, category: str, message: str, path: str, remediation: str) -> None:
    result.findings.append(
        Finding(
            severity=severity,
            category=category,
            message=message,
            path=path,
            remediation=remediation,
        )
    )


def assess_pfsense(root: ET.Element, result: CheckResult) -> str:
    """Append attack-surface findings and return the dashboard narrative."""
    lines: list[str] = []
    host = result.hostname or "(no hostname)"
    if result.domain:
        host = f"{host}.{result.domain}"
    lines.append(
        f"Attack surface — {host} · {result.root_tag or 'config'} {result.version or '?'}"
    )
    lines.append(
        "PASS is reserved for a config with no warnings. Exposure below is "
        "evidence from this file, not a guess that the box is fine."
    )

    lines.extend(_management(root, result))
    lines.extend(_wan_hardening(root, result))
    lines.extend(_filter_exposure(root, result))
    lines.extend(_nat_exposure(root, result))
    lines.extend(_vpn_crypto(root, result))
    lines.extend(_dns(root, result))
    lines.extend(_logging(root, result))
    lines.extend(_packages(result))
    lines.extend(_secrets_in_backup(root, result))

    if len(lines) == 2:
        lines.append("No management, firewall, NAT, VPN, or DNS exposure was found in this file.")
    text = "\n".join(lines).rstrip() + "\n"
    result.summary["assessment"] = text
    return text


def assess_routeros(result: CheckResult) -> str:
    """Assess a parsed RouterOS export from the rules already collected."""
    lines = [
        f"Attack surface — {result.hostname or '(no identity)'} · RouterOS {result.version or '?'}",
        "PASS is reserved for an export with no warnings.",
    ]
    accepts = [
        rule
        for rule in result.filter_rules
        if not rule.disabled
        and rule.chain.lower() == "input"
        and rule.type.lower() == "accept"
        and not (rule.source or "").strip()
        and not (rule.dst_port or "").strip()
    ]
    if accepts:
        examples = ", ".join(_label(rule.descr, rule.index) for rule in accepts[:5])
        _add(
            result,
            Severity.WARNING,
            "Firewall",
            f"{len(accepts)} input-chain accept rule(s) have no source and no destination port ({examples}). "
            "That is management-plane exposure on every interface the chain sees.",
            path="ip firewall filter",
            remediation="Restrict input accepts to a management source and a specific port, then drop the rest.",
        )
        lines.append(f"Firewall: {len(accepts)} unrestricted input accept(s): {examples}.")
    wan_dstnat = [
        rule
        for rule in result.nat_rules
        if not rule.disabled and "dst-nat" in rule.kind
    ]
    if wan_dstnat:
        _add(
            result,
            Severity.INFO,
            "NAT",
            f"{len(wan_dstnat)} dst-nat rule(s) publish internal targets. Confirm each one is intentional.",
            path="ip firewall nat",
            remediation="Remove unused dst-nat and prefer VPN for admin protocols.",
        )
        lines.append(f"NAT: {len(wan_dstnat)} dst-nat rule(s) publish internal hosts.")
    if not result.filter_rules:
        lines.append("Firewall: no filter rules were in the export.")
    text = "\n".join(lines).rstrip() + "\n"
    result.summary["assessment"] = text
    return text


def apply_posture(result: CheckResult) -> str:
    """Structural PASS only when nothing was warned or failed."""
    if result.source_type != "mikrotik" and not result.valid_xml:
        posture = "INVALID"
    elif result.error_count:
        posture = "FAIL"
    elif result.warning_count:
        posture = "EXPOSED"
    else:
        posture = "PASS"
    result.summary["posture"] = posture
    return posture


def _management(root: ET.Element, result: CheckResult) -> list[str]:
    system = _find(root, "system")
    out: list[str] = []
    if system is None:
        return out
    webgui = _find(system, "webgui")
    protocol = _find_text(webgui, "protocol").lower() or "https"
    bind = _iface_names(_find_text(webgui, "interfaces"))
    if protocol == "http":
        _add(
            result,
            Severity.WARNING,
            "Management",
            "WebGUI protocol is HTTP. Credentials and the session cookie travel in clear text.",
            path="system/webgui/protocol",
            remediation="Set protocol to HTTPS and keep the HTTP-to-HTTPS redirect enabled.",
        )
        out.append("Management: WebGUI is HTTP.")
    if "wan" in bind:
        _add(
            result,
            Severity.ERROR,
            "Management",
            "WebGUI is bound to WAN.",
            path="system/webgui/interfaces",
            remediation="Remove WAN from system/webgui/interfaces. Reach the GUI from LAN or VPN only.",
        )
        out.append("Management: WebGUI is bound to WAN.")
    elif not bind:
        _add(
            result,
            Severity.WARNING,
            "Management",
            "WebGUI has no interface restriction. An empty list binds the GUI on every assigned interface, including WAN.",
            path="system/webgui/interfaces",
            remediation="Set system/webgui/interfaces to the management interface only.",
        )
        out.append("Management: WebGUI has no interface restriction.")
    else:
        out.append(f"Management: WebGUI is {protocol.upper()} on {', '.join(bind)}.")

    ssh_on = _has_flag(system, "enablesshd") or _has_flag(_find(system, "ssh"), "enable")
    ssh = _find(system, "ssh")
    if ssh_on:
        password_auth = _find_text(ssh, "passwordauth").lower()
        key_only = _has_flag(system, "sshdkeyonly") or _has_flag(ssh, "sshdkeyonly")
        port = _find_text(ssh, "port") or "22"
        if password_auth != "disabled" and not key_only:
            _add(
                result,
                Severity.WARNING,
                "Management",
                f"SSH is enabled on port {port} and password authentication is not disabled.",
                path="system/ssh",
                remediation="Disable SSH password authentication and use keys. Do not leave SSH on WAN.",
            )
            out.append(f"Management: SSH port {port} still allows password authentication.")
        else:
            out.append(f"Management: SSH port {port} is key-only.")
    return out


def _wan_hardening(root: ET.Element, result: CheckResult) -> list[str]:
    interfaces = _find(root, "interfaces")
    out: list[str] = []
    if interfaces is None:
        return out
    missing_priv: list[str] = []
    missing_bogon: list[str] = []
    for child in interfaces:
        name = _local(child.tag).lower()
        descr = _find_text(child, "descr").lower()
        if name != "wan" and "wan" not in descr:
            continue
        if not _has_flag(child, "enable"):
            continue
        label = name.upper()
        if not _has_flag(child, "blockpriv"):
            missing_priv.append(label)
        if not _has_flag(child, "blockbogons"):
            missing_bogon.append(label)
    if missing_priv:
        _add(
            result,
            Severity.WARNING,
            "Firewall",
            "Block private networks is off on " + ", ".join(missing_priv) + ". RFC1918 sources can hit rules on that interface.",
            path="interfaces",
            remediation="Enable 'Block private networks and loopback addresses' on each WAN.",
        )
        out.append("WAN: private-network blocking is off on " + ", ".join(missing_priv) + ".")
    if missing_bogon:
        _add(
            result,
            Severity.WARNING,
            "Firewall",
            "Block bogon networks is off on " + ", ".join(missing_bogon) + ".",
            path="interfaces",
            remediation="Enable bogon blocking on each WAN, and keep the bogon list updating.",
        )
        out.append("WAN: bogon blocking is off on " + ", ".join(missing_bogon) + ".")
    return out


def _filter_exposure(root: ET.Element, result: CheckResult) -> list[str]:
    filt = _find(root, "filter")
    out: list[str] = []
    if filt is None:
        return out
    any_any: list[str] = []
    wan_open: list[str] = []
    wan_ports: list[str] = []
    wan_unlogged: list[str] = []
    for index, rule in enumerate(_find_all(filt, "rule")):
        if _find(rule, "disabled") is not None:
            continue
        if _find_text(rule, "type").lower() != "pass":
            continue
        floating = _find(rule, "floating") is not None
        direction = _find_text(rule, "direction").lower()
        inbound = (not floating) or direction in {"", "in", "any", "both"}
        source = _find(rule, "source")
        dest = _find(rule, "destination")
        src_any = _endpoint_is_any(source)
        dst_any = _endpoint_is_any(dest)
        dst_port = _find_text(dest, "port")
        ifaces = set(_iface_names(_find_text(rule, "interface")))
        name = _label(_find_text(rule, "descr"), index)
        if src_any and dst_any and not dst_port:
            any_any.append(name)
        if inbound and "wan" in ifaces and src_any:
            if not dst_port:
                wan_open.append(name)
            else:
                wan_ports.append(f"{name} port {dst_port}")
            if _find(rule, "log") is None:
                wan_unlogged.append(name)
    if any_any:
        _add(
            result,
            Severity.WARNING,
            "Firewall",
            f"{len(any_any)} enabled pass rule(s) are any-to-any with no destination port: "
            + _sample(any_any) + ".",
            path="filter",
            remediation="Replace each any-to-any pass with an explicit source, destination, and port.",
        )
        out.append(f"Firewall: {len(any_any)} any-to-any pass rule(s): {_sample(any_any)}.")
    if wan_open:
        _add(
            result,
            Severity.ERROR,
            "Firewall",
            f"{len(wan_open)} enabled WAN pass rule(s) accept any source to any destination and port: "
            + _sample(wan_open) + ".",
            path="filter",
            remediation="Delete WAN passes that have no destination port. Publish only specific ports, and only to specific hosts.",
        )
        out.append(f"Firewall: {len(wan_open)} WAN rule(s) pass any source to any port: {_sample(wan_open)}.")
    if wan_ports:
        _add(
            result,
            Severity.WARNING,
            "Firewall",
            f"{len(wan_ports)} WAN pass rule(s) accept any source to a published port: "
            + _sample(wan_ports) + ".",
            path="filter",
            remediation="Limit each WAN pass to the destination host that should answer, and log the rule.",
        )
        out.append(f"Firewall: {len(wan_ports)} WAN rule(s) publish a port: {_sample(wan_ports)}.")
    if wan_unlogged:
        _add(
            result,
            Severity.INFO,
            "Firewall",
            f"{len(wan_unlogged)} WAN pass rule(s) do not log. Inbound allows then leave no filter log.",
            path="filter",
            remediation="Enable logging on WAN pass rules, and ship those logs off the firewall.",
        )
        out.append(f"Firewall: {len(wan_unlogged)} WAN pass rule(s) are not logged.")
    return out


def _nat_exposure(root: ET.Element, result: CheckResult) -> list[str]:
    nat = _find(root, "nat")
    out: list[str] = []
    if nat is None:
        return out
    published: list[str] = []
    unspecified: list[str] = []
    one_to_one: list[str] = []
    for index, rule in enumerate(_find_all(nat, "rule")):
        if _find(rule, "disabled") is not None:
            continue
        ifaces = set(_iface_names(_find_text(rule, "interface")))
        if "wan" not in ifaces and ifaces:
            continue
        external = _ports(_find_text(_find(rule, "destination"), "port"))
        internal = _ports(_find_text(rule, "local-port"))
        target = _find_text(rule, "target") or ""
        name = _label(_find_text(rule, "descr"), index)
        hit = sorted((external | internal) & _ADMIN_PORTS)
        if not hit:
            if target and not external and not internal:
                unspecified.append(f"{name} → {target}")
            continue
        published.append(
            f"{name} → {target or '(no target)'} ports {', '.join(str(p) for p in hit)}"
        )
    for index, rule in enumerate(_find_all(nat, "onetoone")):
        if _find(rule, "disabled") is not None:
            continue
        ifaces = set(_iface_names(_find_text(rule, "interface")))
        if ifaces and "wan" not in ifaces:
            continue
        one_to_one.append(_label(_find_text(rule, "descr"), index))
    if published:
        _add(
            result,
            Severity.WARNING,
            "NAT",
            f"{len(published)} WAN port forward(s) publish an admin or data-plane port: "
            + _sample(published) + ".",
            path="nat",
            remediation="Drop forwards that are unused. For the rest, restrict the source and prefer VPN over exposing 22, 443, 3389, Winbox, or database ports.",
        )
        out.append(f"NAT: {len(published)} WAN forward(s) publish admin ports: {_sample(published)}.")
    if unspecified:
        _add(
            result,
            Severity.WARNING,
            "NAT",
            f"{len(unspecified)} WAN forward(s) name a target but no port: "
            + _sample(unspecified) + ".",
            path="nat",
            remediation="Set the external and local port, or remove the forward.",
        )
        out.append(f"NAT: {len(unspecified)} WAN forward(s) have no port: {_sample(unspecified)}.")
    if one_to_one:
        _add(
            result,
            Severity.WARNING,
            "NAT",
            f"{len(one_to_one)} WAN 1:1 NAT mapping(s) publish an entire internal host: "
            + _sample(one_to_one) + ".",
            path="nat/onetoone",
            remediation="Replace 1:1 NAT with port forwards for the specific services that must be reachable.",
        )
        out.append(f"NAT: {len(one_to_one)} WAN 1:1 mapping(s): {_sample(one_to_one)}.")
    return out


def _vpn_crypto(root: ET.Element, result: CheckResult) -> list[str]:
    out: list[str] = []
    openvpn = _find(root, "openvpn")
    if openvpn is not None:
        for tag in ("openvpn-server", "openvpn-client"):
            for index, node in enumerate(_find_all(openvpn, tag)):
                if _find(node, "disable") is not None:
                    continue
                name = _find_text(node, "description") or f"{tag} {index + 1}"
                ciphers = _cipher_names(node)
                weak = sorted(ciphers & _WEAK_OVPN_CIPHERS)
                if weak:
                    _add(
                        result,
                        Severity.ERROR,
                        "VPN",
                        f"OpenVPN {name} allows a broken cipher: {', '.join(weak)}.",
                        path=f"openvpn/{tag}",
                        remediation="Remove BF-CBC, DES, CAST, and 'none'. Use AES-256-GCM or CHACHA20-POLY1305 only.",
                    )
                    out.append(f"VPN: OpenVPN {name} allows {', '.join(weak)}.")
                digest = _find_text(node, "digest").lower()
                if digest in _WEAK_DIGESTS:
                    _add(
                        result,
                        Severity.WARNING,
                        "VPN",
                        f"OpenVPN {name} uses digest {digest}.",
                        path=f"openvpn/{tag}",
                        remediation="Set the digest to SHA256 or SHA512. SHA1 and MD5 are not acceptable for a new tunnel.",
                    )
                    out.append(f"VPN: OpenVPN {name} digest is {digest}.")
                compression = _find_text(node, "compression").lower()
                if _has_flag(node, "comp-lzo") or compression in {"adaptive", "comp-lzo", "yes", "on", "lz4", "lzo"}:
                    _add(
                        result,
                        Severity.WARNING,
                        "VPN",
                        f"OpenVPN {name} has compression enabled ({compression or 'comp-lzo'}). Compression before encryption is the VORACLE exposure.",
                        path=f"openvpn/{tag}",
                        remediation="Disable OpenVPN compression on both ends.",
                    )
                    out.append(f"VPN: OpenVPN {name} has compression enabled.")
    ipsec = _find(root, "ipsec")
    if ipsec is not None:
        for index, phase in enumerate(_find_all(ipsec, "phase1")):
            if _find(phase, "disabled") is not None:
                continue
            name = _find_text(phase, "descr") or f"phase1 {index + 1}"
            ike = _find_text(phase, "iketype").lower()
            if ike in {"ikev1", "ikev1_aggr", "aggressive"} or _has_flag(phase, "aggressive"):
                _add(
                    result,
                    Severity.WARNING,
                    "VPN",
                    f"IPsec {name} uses IKEv1{' aggressive' if 'aggr' in ike or _has_flag(phase, 'aggressive') else ''}. Aggressive mode exposes the identity and weakens the exchange.",
                    path="ipsec/phase1",
                    remediation="Move the tunnel to IKEv2. Do not use aggressive mode.",
                )
                out.append(f"VPN: IPsec {name} is IKEv1.")
            enc, digest, dh = _ipsec_suite(phase)
            weak_enc = sorted(enc & _WEAK_IPSEC_ENC)
            if weak_enc:
                _add(
                    result,
                    Severity.ERROR,
                    "VPN",
                    f"IPsec {name} proposes a broken encryption algorithm: {', '.join(weak_enc)}.",
                    path="ipsec/phase1",
                    remediation="Use AES-GCM or AES-CBC with a 256-bit key. Remove DES, 3DES, and Blowfish.",
                )
                out.append(f"VPN: IPsec {name} encryption includes {', '.join(weak_enc)}.")
            if digest & _WEAK_DIGESTS or any(item in _WEAK_DIGESTS for item in digest):
                shown = ", ".join(sorted(digest & _WEAK_DIGESTS)) or ", ".join(sorted(digest))
                _add(
                    result,
                    Severity.WARNING,
                    "VPN",
                    f"IPsec {name} uses a weak hash ({shown}).",
                    path="ipsec/phase1",
                    remediation="Use SHA256 or SHA384. Drop SHA1 and MD5.",
                )
                out.append(f"VPN: IPsec {name} hash is weak ({shown}).")
            weak_dh = sorted(dh & _WEAK_DH)
            if weak_dh:
                _add(
                    result,
                    Severity.WARNING,
                    "VPN",
                    f"IPsec {name} uses DH group {', '.join(weak_dh)}. Groups 1, 2, and 5 are breakable.",
                    path="ipsec/phase1",
                    remediation="Use DH group 14 or higher, or a 256-bit ECP group.",
                )
                out.append(f"VPN: IPsec {name} uses DH group {', '.join(weak_dh)}.")
    return out


def _cipher_names(node: ET.Element) -> set[str]:
    names: set[str] = set()
    for key in ("cipher", "data-ciphers", "data_ciphers"):
        raw = _find_text(node, key).lower()
        for part in re.split(r"[:,\s]+", raw):
            if part:
                names.add(part)
    return names


def _ipsec_suite(phase: ET.Element) -> tuple[set[str], set[str], set[str]]:
    enc: set[str] = set()
    digest: set[str] = set()
    dh: set[str] = set()
    enc_node = _find(phase, "encryption-algorithm")
    if enc_node is not None:
        name = _find_text(enc_node, "name").lower()
        if name:
            enc.add(name)
    hash_name = _find_text(phase, "hash-algorithm").lower()
    if hash_name:
        digest.add(hash_name.replace("hmac_", ""))
    group = _find_text(phase, "dhgroup")
    if group:
        dh.add(group)
    encryption = _find(phase, "encryption")
    for item in _find_all(encryption, "item"):
        algo = _find(item, "encryption-algorithm")
        name = _find_text(algo, "name").lower()
        if name:
            enc.add(name)
        item_hash = _find_text(item, "hash-algorithm").lower()
        if item_hash:
            digest.add(item_hash.replace("hmac_", ""))
        item_dh = _find_text(item, "dhgroup")
        if item_dh:
            dh.add(item_dh)
    return enc, digest, dh


def _dns(root: ET.Element, result: CheckResult) -> list[str]:
    out: list[str] = []
    unbound = _find(root, "unbound")
    if unbound is None or not _has_flag(unbound, "enable"):
        return out
    active = _iface_names(_find_text(unbound, "active_interface"))
    if "wan" in active or "all" in active:
        _add(
            result,
            Severity.WARNING,
            "DNS",
            "The DNS resolver is enabled on WAN. That is an open resolver if no firewall rule blocks it.",
            path="unbound/active_interface",
            remediation="Bind Unbound to LAN only, and do not pass WAN traffic to port 53.",
        )
        out.append("DNS: resolver is bound to WAN.")
    if not _has_flag(unbound, "dnssec"):
        _add(
            result,
            Severity.WARNING,
            "DNS",
            "DNSSEC is not enabled on the resolver.",
            path="unbound/dnssec",
            remediation="Enable DNSSEC validation on Unbound.",
        )
        out.append("DNS: DNSSEC is off.")
    return out


def _logging(root: ET.Element, result: CheckResult) -> list[str]:
    syslog = _find(root, "syslog")
    remote = _find_text(syslog, "remoteserver") or _find_text(_find(_find(root, "system"), "syslog"), "remoteserver")
    if remote:
        return [f"Logging: remote syslog target is set ({remote})."]
    _add(
        result,
        Severity.WARNING,
        "Logging",
        "No remote syslog server is configured. Filter and auth logs stay on the firewall disk.",
        path="syslog",
        remediation="Send syslog to a collector that is not the firewall. Keep WAN pass rules logging.",
    )
    return ["Logging: no remote syslog server."]


def _packages(result: CheckResult) -> list[str]:
    names = {(pkg.internal_name or pkg.name).lower().replace(" ", "") for pkg in result.packages}
    present = sorted(names & _IDS_PACKAGES)
    if not present:
        _add(
            result,
            Severity.INFO,
            "Packages",
            "No Suricata, Snort, or pfBlocker package is installed. The firewall is not inspecting or sinkholing on its own.",
            path="installedpackages",
            remediation="Add an IDS or DNS blocklist if this edge is expected to do more than stateful filtering.",
        )
        return ["Packages: no IDS or DNS blocklist package is installed."]
    disabled = [
        pkg.name
        for pkg in result.packages
        if (pkg.internal_name or pkg.name).lower().replace(" ", "") in _IDS_PACKAGES
        and pkg.enabled is False
    ]
    if disabled:
        _add(
            result,
            Severity.WARNING,
            "Packages",
            "IDS or blocklist package is installed but disabled: " + ", ".join(disabled) + ".",
            path="installedpackages",
            remediation="Enable the package or remove it so the config matches what you think is running.",
        )
        return [f"Packages: disabled IDS/blocklist: {', '.join(disabled)}."]
    return [f"Packages: IDS/blocklist present ({', '.join(present)})."]


def _secrets_in_backup(root: ET.Element, result: CheckResult) -> list[str]:
    count = 0
    for cert in list(root.iter()):
        if _local(cert.tag).lower() != "cert":
            continue
        if _find_text(cert, "prv"):
            count += 1
    if not count:
        return []
    _add(
        result,
        Severity.WARNING,
        "Secrets",
        f"This backup contains {count} private key(s). The file is a credential store, not a harmless export.",
        path="cert",
        remediation="Store the backup in a protected location. Do not attach it to tickets or leave it in Downloads.",
    )
    return [f"Secrets: backup contains {count} private key(s). The file must be handled as a secret."]


def _sample(items: list[str]) -> str:
    shown = items[:5]
    extra = len(items) - len(shown)
    text = "; ".join(shown)
    if extra > 0:
        text += f"; +{extra} more"
    return text
