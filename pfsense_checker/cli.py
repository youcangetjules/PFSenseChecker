"""Headless CLI for running a pfSense config check and printing a report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pfsense_checker.checker import check_file
from pfsense_checker.models import Severity

_ORDER = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.INFO: 2}


def _text_report(result) -> str:  # noqa: ANN001
    s = result.summary
    is_mt = getattr(result, "source_type", "") == "mikrotik"
    device = "MikroTik RouterOS" if is_mt else "pfSense/OPNsense"
    parsed_label = "Parsed OK:" if is_mt else "Valid XML:"
    lines = [
        "=" * 60,
        f"{device} Configuration Check Report",
        "=" * 60,
        f"File:      {result.path}",
        f"{parsed_label} {result.valid_xml}",
        f"Version:   {result.version or '(unknown)'}",
        f"Hostname:  {result.hostname or '(unknown)'}",
        f"Result:    {'PASS' if result.ok else 'FAIL'} "
        f"({result.error_count} errors, {result.warning_count} warnings, "
        f"{result.info_count} info)",
        "",
        f"Interfaces: {s.get('interfaces_total', 0)} "
        f"({s.get('interfaces_enabled', 0)} up / {s.get('interfaces_disabled', 0)} down) · "
        f"bridges={s.get('bridges', 0)} vlans={s.get('vlans', 0)} laggs={s.get('laggs', 0)}",
        f"Firewall rules: {s.get('filter_rules', 0)} · NAT: {s.get('nat_rules', 0)} · "
        f"VPN: {s.get('vpn', 0)} · Packages: {s.get('packages', 0)} "
        f"({s.get('packages_disabled', 0)} disabled)",
        "",
        "-- Findings --",
    ]
    for f in sorted(result.findings, key=lambda x: _ORDER[x.severity]):
        lines.append(f.label())
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a pfSense config.xml (headless)")
    parser.add_argument("config", help="Path to config.xml")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument(
        "--fail-on",
        choices=["error", "warning", "never"],
        default="error",
        help="Exit non-zero when findings at/above this severity exist",
    )
    args = parser.parse_args(argv)

    result = check_file(Path(args.config))

    if args.json:
        payload = {
            "path": str(result.path),
            "valid_xml": result.valid_xml,
            "ok": result.ok,
            "errors": result.error_count,
            "warnings": result.warning_count,
            "info": result.info_count,
            "summary": result.summary,
            "findings": [
                {
                    "severity": f.severity.value,
                    "category": f.category,
                    "path": f.path,
                    "line": f.line,
                    "message": f.message,
                }
                for f in result.findings
            ],
        }
        print(json.dumps(payload, indent=2, default=str))
    else:
        print(_text_report(result))

    if args.fail_on == "never":
        return 0
    if args.fail_on == "warning" and (result.error_count or result.warning_count):
        return 1
    if args.fail_on == "error" and result.error_count:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
