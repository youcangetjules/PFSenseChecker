"""Subnet beacon agent — continuous ping + DHCP (+ optional speed), reports to collector."""

from __future__ import annotations

import argparse
import json
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path

from pfsense_checker.monitor.models import BeaconReport, ProbeResult
from pfsense_checker.monitor.probes import dhcp_discover, ping_host, utc_now


def load_config(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not data.get("beacon_id"):
        raise SystemExit("beacon_id is required in beacon config")
    if not data.get("collector_url"):
        raise SystemExit("collector_url is required in beacon config")
    return data


def post_report(url: str, token: str, report: BeaconReport, timeout: float = 10.0) -> None:
    body = json.dumps(report.to_dict()).encode("utf-8")
    req = urllib.request.Request(
        url.rstrip("/") + "/api/report",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "pfsense-beacon/1.0",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp.read()


def _speed_probe(
    url: str,
    *,
    subnet: str = "",
    interface: str = "",
    link_type: str = "",
) -> ProbeResult:
    from pfsense_checker.subnet_health import measure_http_speed

    status, mbps, message = measure_http_speed(url)
    return ProbeResult(
        kind="speed",
        status=status,
        target=url,
        subnet=subnet,
        interface=interface,
        message=message,
        latency_ms=None,
        detail={"mbps": mbps, "link_type": link_type}
        if mbps is not None
        else {"link_type": link_type},
        ts=utc_now(),
    )


def _discover_access(cfg: dict) -> list[dict]:
    """Build accessible_subnets list (config override and/or OS discovery)."""
    from pfsense_checker.subnet_health import (
        discover_local_subnets,
        normalize_link_type,
    )

    configured = cfg.get("subnets") or cfg.get("accessible_subnets") or []
    rows: list[dict] = []
    if isinstance(configured, list) and configured:
        for item in configured:
            if isinstance(item, str):
                rows.append(
                    {
                        "cidr": item,
                        "link_type": normalize_link_type(
                            str(cfg.get("link_type") or "unknown")
                        ),
                        "interface": "",
                        "gateway": "",
                        "ip": "",
                    }
                )
            elif isinstance(item, dict) and (item.get("cidr") or item.get("subnet")):
                rows.append(
                    {
                        "cidr": str(item.get("cidr") or item.get("subnet")),
                        "ip": str(item.get("ip") or ""),
                        "gateway": str(item.get("gateway") or ""),
                        "interface": str(item.get("interface") or ""),
                        "link_type": normalize_link_type(
                            str(item.get("link_type") or cfg.get("link_type") or "")
                        ),
                    }
                )
        return rows

    try:
        found = discover_local_subnets()
    except Exception:  # noqa: BLE001
        found = []
    for a in found:
        rows.append(
            {
                "cidr": a.cidr,
                "ip": a.ip,
                "gateway": a.gateway,
                "interface": a.interface,
                "link_type": a.link_type,
            }
        )
    return rows


def run_cycle(cfg: dict, *, cycle_index: int = 0) -> BeaconReport:
    results = []
    default_link = str(cfg.get("link_type") or "")

    for target in cfg.get("ping_targets") or []:
        if isinstance(target, str):
            host, subnet, iface, link = target, "", "", default_link
        else:
            host = target.get("host") or target.get("ip") or ""
            subnet = target.get("subnet", "")
            iface = target.get("interface", "")
            link = target.get("link_type") or default_link
        if not host:
            continue
        res = ping_host(
            host,
            count=int(cfg.get("ping_count", 2)),
            timeout_sec=float(cfg.get("ping_timeout", 2.0)),
            subnet=subnet,
            interface=iface,
        )
        if link:
            res.detail = dict(res.detail or {})
            res.detail["link_type"] = link
        results.append(res)

    for dhcp in cfg.get("dhcp_targets") or []:
        if isinstance(dhcp, str):
            subnet, bind_ip, iface = dhcp, "0.0.0.0", ""
            enabled = True
            link = default_link
        else:
            subnet = dhcp.get("subnet", "")
            bind_ip = dhcp.get("bind_ip", "0.0.0.0")
            iface = dhcp.get("interface", "")
            enabled = dhcp.get("enabled", True)
            link = dhcp.get("link_type") or default_link
        if not enabled:
            continue
        res = dhcp_discover(
            bind_ip=bind_ip,
            timeout_sec=float(cfg.get("dhcp_timeout", 5.0)),
            subnet=subnet,
            interface=iface,
            release_offer=bool(cfg.get("dhcp_release_offer", True)),
        )
        if link:
            res.detail = dict(res.detail or {})
            res.detail["link_type"] = link
        results.append(res)

    speed_url = str(cfg.get("speed_url") or "").strip()
    every = max(1, int(cfg.get("speed_every_n_cycles", 1)))
    if speed_url and (cycle_index % every == 0):
        results.append(
            _speed_probe(
                speed_url,
                subnet=str(cfg.get("speed_subnet") or ""),
                interface=str(cfg.get("speed_interface") or ""),
                link_type=default_link,
            )
        )

    accessible = _discover_access(cfg)
    by_subnet = {r.subnet: r for r in results if r.kind == "ping" and r.subnet}
    for row in accessible:
        probe = by_subnet.get(row.get("cidr") or "")
        if probe is None:
            continue
        row["ping_status"] = probe.status
        row["ping_ms"] = probe.latency_ms
        row["last_check"] = probe.ts or utc_now()
        if probe.detail.get("link_type") and row.get("link_type") in ("", "unknown"):
            row["link_type"] = probe.detail["link_type"]
    for r in results:
        if r.kind == "speed" and r.detail.get("mbps") is not None:
            for row in accessible:
                row["speed_mbps"] = r.detail.get("mbps")
                row["speed_status"] = r.status
                row["last_check"] = r.ts or utc_now()

    interval = max(10, int(cfg.get("interval_sec", 60)))
    meta = {
        "cycle_ts": utc_now(),
        "configured_pings": len(cfg.get("ping_targets") or []),
        "interval_sec": interval,
        "link_type": default_link
        or (accessible[0]["link_type"] if accessible else "unknown"),
        "accessible_subnets": accessible,
    }

    return BeaconReport(
        beacon_id=cfg["beacon_id"],
        hostname=cfg.get("hostname") or socket.gethostname(),
        site=cfg.get("site", ""),
        version=str(cfg.get("version", "1.0.0")),
        results=results,
        meta=meta,
    )


def run_beacon(cfg: dict) -> None:
    interval = max(10, int(cfg.get("interval_sec", 60)))
    url = cfg["collector_url"]
    token = cfg.get("token", "")
    print(
        f"[beacon] id={cfg['beacon_id']} -> {url} every {interval}s "
        f"(subnet health + link type)"
    )
    cycle = 0
    while True:
        try:
            report = run_cycle(cfg, cycle_index=cycle)
            ok = sum(1 for r in report.results if r.status == "ok")
            fail = sum(1 for r in report.results if r.status != "ok")
            post_report(url, token, report)
            n_sub = len((report.meta or {}).get("accessible_subnets") or [])
            print(
                f"[beacon] reported {len(report.results)} probes "
                f"(ok={ok} fail={fail}) subnets={n_sub}"
            )
        except urllib.error.URLError as exc:
            print(f"[beacon] collector unreachable: {exc}")
        except Exception as exc:  # noqa: BLE001
            print(f"[beacon] cycle error: {exc}")
        cycle += 1
        time.sleep(interval)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="pfSense subnet beacon agent")
    parser.add_argument(
        "--config",
        required=True,
        help="Path to beacon JSON config",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single probe cycle and exit (still posts if possible)",
    )
    args = parser.parse_args(argv)
    cfg = load_config(Path(args.config))
    if args.once:
        report = run_cycle(cfg, cycle_index=0)
        try:
            post_report(cfg["collector_url"], cfg.get("token", ""), report)
            print(json.dumps(report.to_dict(), indent=2))
        except urllib.error.URLError as exc:
            print(f"[beacon] post failed: {exc}")
            print(json.dumps(report.to_dict(), indent=2))
            return 2
        return 0
    run_beacon(cfg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
