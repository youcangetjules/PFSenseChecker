"""Right-click finding write-ups, including what a removal actually stops."""

from __future__ import annotations

from pfsense_checker.finding_analysis import analyse, classify, suggested_filename
from pfsense_checker.models import (
    CheckResult,
    Finding,
    InterfaceInfo,
    RuleInfo,
    Severity,
)


def _result() -> CheckResult:
    result = CheckResult(hostname="guardian", domain="aliniant.net", version="2.6.0")
    result.filter_rules.append(
        RuleInfo(
            index=0,
            kind="filter",
            type="pass",
            interface="wan",
            descr="pbr_whitelist_v4 auto rule",
            source="any",
            destination="any",
        )
    )
    result.filter_rules.append(
        RuleInfo(
            index=1,
            kind="filter",
            type="pass",
            interface="lan",
            descr="",
            source="any",
            destination="any",
        )
    )
    result.interfaces.append(
        InterfaceInfo(name="opt5", device="igb5", enabled=True, kind="physical", descr="spare")
    )
    return result


def test_wan_pass_explains_the_named_rule_and_what_removal_keeps() -> None:
    finding = Finding(
        Severity.ERROR,
        "Firewall",
        "1 enabled WAN pass rule(s) accept any source to any destination and port: "
        "pbr_whitelist_v4 auto rule.",
        path="filter",
        remediation="Delete WAN passes that have no destination port.",
    )
    result = _result()
    assert classify(finding) == "wan_open"
    issue = analyse(finding, result, "issue")
    assert "pbr_whitelist_v4 auto rule" in issue
    assert "state" in issue.lower()
    removal = analyse(finding, result, "removal")
    assert "outbound" in removal.lower() or "return packets" in removal.lower()
    assert "does not change the firewall" in removal.lower() or "changes nothing" in removal.lower()
    fix = analyse(finding, result, "fix")
    assert "destination port" in fix.lower()
    severity = analyse(finding, result, "severity")
    assert "ERROR" in severity
    assert "looks" not in severity.lower()


def test_any_to_any_cites_rule_number() -> None:
    finding = Finding(
        Severity.WARNING,
        "Firewall",
        "1 enabled pass rule(s) are any-to-any with no destination port: rule 2.",
        path="filter",
    )
    text = analyse(finding, _result(), "issue")
    assert "iface=lan" in text
    assert classify(finding) == "any_any"


def test_addressless_interface_names_the_port() -> None:
    finding = Finding(
        Severity.WARNING,
        "Interfaces",
        "OPT5 is enabled but has no IPv4/IPv6 address (fine if it is a switch/bridge/transit port)",
        path="interfaces/opt5",
    )
    text = analyse(finding, _result(), "removal")
    assert "OPT5" in text
    assert "igb5" in text
    assert "disable" in text.lower()


def test_info_ssh_is_not_called_a_compromise() -> None:
    finding = Finding(Severity.INFO, "System", "SSH daemon not enabled", path="system")
    text = analyse(finding, _result(), "severity")
    assert "INFO" in text
    assert "not an exposure" in text.lower() or "not a vulnerability" in analyse(finding, _result(), "issue").lower()


def test_private_key_writeup_does_not_invent_key_material() -> None:
    finding = Finding(
        Severity.WARNING,
        "Secrets",
        "This backup contains 4 private key(s). The file is a credential store, not a harmless export.",
        path="cert",
    )
    blob = "\n".join(analyse(finding, _result(), kind) for kind in ("issue", "severity", "fix", "removal"))
    assert "BEGIN" not in blob
    assert "reissue" in blob.lower()


def test_save_name_is_a_plain_filename() -> None:
    finding = Finding(Severity.WARNING, "DNS", "DNSSEC is not enabled on the resolver.", path="unbound/dnssec")
    name = suggested_filename(finding, "fix", _result())
    assert name == "guardian-DNS-fix-analysis.txt"
    assert "/" not in name and "\\" not in name
