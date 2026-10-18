"""SNMPv3 settings for NetCheck (v3 only — no community strings).

Non-secret options live in ``data/snmp.json``. Username and auth/priv
passphrases are stored in gitignored ``secrets.local.json``.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from pfsense_checker.paths import PROJECT_ROOT, ensure_data_dir

_SECRETS_FILE = PROJECT_ROOT / "secrets.local.json"
_SETTINGS_FILE = PROJECT_ROOT / "data" / "snmp.json"

SECURITY_LEVELS = ("authPriv", "authNoPriv", "noAuthNoPriv")
AUTH_PROTOCOLS = ("SHA", "SHA256", "SHA384", "SHA512", "MD5")
PRIV_PROTOCOLS = ("AES", "AES256", "AES192", "DES")


@dataclass
class SnmpV3Settings:
    """Default SNMPv3 credentials / options used by the app."""

    enabled: bool = False
    port: int = 161
    timeout_sec: float = 5.0
    retries: int = 1
    security_level: str = "authPriv"
    auth_protocol: str = "SHA"
    priv_protocol: str = "AES"
    context_name: str = ""
    username: str = ""
    auth_password: str = ""
    priv_password: str = ""
    # Optional host used only for the Setup “Test” button
    test_host: str = ""

    def normalised(self) -> SnmpV3Settings:
        level = self.security_level if self.security_level in SECURITY_LEVELS else "authPriv"
        auth = self.auth_protocol if self.auth_protocol in AUTH_PROTOCOLS else "SHA"
        priv = self.priv_protocol if self.priv_protocol in PRIV_PROTOCOLS else "AES"
        return SnmpV3Settings(
            enabled=bool(self.enabled),
            port=max(1, min(65535, int(self.port or 161))),
            timeout_sec=max(0.5, float(self.timeout_sec or 5.0)),
            retries=max(0, min(5, int(self.retries if self.retries is not None else 1))),
            security_level=level,
            auth_protocol=auth,
            priv_protocol=priv,
            context_name=(self.context_name or "").strip(),
            username=(self.username or "").strip(),
            auth_password=self.auth_password or "",
            priv_password=self.priv_password or "",
            test_host=(self.test_host or "").strip(),
        )


def _read_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def load_snmp_settings() -> SnmpV3Settings:
    public = _read_json(_SETTINGS_FILE)
    secrets = _read_json(_SECRETS_FILE)
    return SnmpV3Settings(
        enabled=bool(public.get("snmp_enabled", public.get("enabled", False))),
        port=int(public.get("snmp_port", public.get("port", 161)) or 161),
        timeout_sec=float(public.get("snmp_timeout_sec", public.get("timeout_sec", 5.0)) or 5.0),
        retries=int(public.get("snmp_retries", public.get("retries", 1)) or 1),
        security_level=str(
            public.get("snmp_security_level", public.get("security_level", "authPriv"))
        ),
        auth_protocol=str(
            public.get("snmp_auth_protocol", public.get("auth_protocol", "SHA"))
        ),
        priv_protocol=str(
            public.get("snmp_priv_protocol", public.get("priv_protocol", "AES"))
        ),
        context_name=str(
            public.get("snmp_context_name", public.get("context_name", "")) or ""
        ),
        test_host=str(public.get("snmp_test_host", public.get("test_host", "")) or ""),
        username=str(secrets.get("snmp_username", "") or ""),
        auth_password=str(secrets.get("snmp_auth_password", "") or ""),
        priv_password=str(secrets.get("snmp_priv_password", "") or ""),
    ).normalised()


def save_snmp_settings(settings: SnmpV3Settings) -> None:
    settings = settings.normalised()
    ensure_data_dir()
    public = _read_json(_SETTINGS_FILE)
    public.update(
        {
            "snmp_enabled": settings.enabled,
            "snmp_port": settings.port,
            "snmp_timeout_sec": settings.timeout_sec,
            "snmp_retries": settings.retries,
            "snmp_security_level": settings.security_level,
            "snmp_auth_protocol": settings.auth_protocol,
            "snmp_priv_protocol": settings.priv_protocol,
            "snmp_context_name": settings.context_name,
            "snmp_test_host": settings.test_host,
            "snmp_version": 3,
        }
    )
    _SETTINGS_FILE.write_text(json.dumps(public, indent=2), encoding="utf-8")

    secrets = _read_json(_SECRETS_FILE)
    secrets["snmp_username"] = settings.username
    secrets["snmp_auth_password"] = settings.auth_password
    secrets["snmp_priv_password"] = settings.priv_password
    _SECRETS_FILE.write_text(json.dumps(secrets, indent=2), encoding="utf-8")


def snmp_configured() -> bool:
    """True when SNMPv3 is enabled and has the credentials its security level needs."""
    s = load_snmp_settings()
    if not s.enabled or not s.username:
        return False
    if s.security_level == "noAuthNoPriv":
        return True
    if s.security_level == "authNoPriv":
        return bool(s.auth_password)
    return bool(s.auth_password and s.priv_password)


def validate_snmp_settings(settings: SnmpV3Settings) -> str:
    """Return an error message, or ``\"\"`` if settings look usable when enabled."""
    s = settings.normalised()
    if not s.enabled:
        return ""
    if not s.username:
        return "SNMPv3 username is required when SNMP is enabled."
    if s.security_level in {"authNoPriv", "authPriv"} and not s.auth_password:
        return "Auth password is required for this security level."
    if s.security_level == "authPriv" and not s.priv_password:
        return "Privacy password is required for authPriv."
    return ""


def pysnmp_available() -> bool:
    try:
        import pysnmp.hlapi  # noqa: F401
    except ImportError:
        try:
            import pysnmp.hlapi.v3arch.asyncio  # noqa: F401
        except ImportError:
            return False
    return True


_AUTH_PROTO = {
    "MD5": "USM_AUTH_HMAC96_MD5",
    "SHA": "USM_AUTH_HMAC96_SHA",
    "SHA256": "USM_AUTH_HMAC192_SHA256",
    "SHA384": "USM_AUTH_HMAC256_SHA384",
    "SHA512": "USM_AUTH_HMAC384_SHA512",
}
_PRIV_PROTO = {
    "DES": "USM_PRIV_CBC56_DES",
    "AES": "USM_PRIV_CFB128_AES",
    "AES192": "USM_PRIV_CFB192_AES",
    "AES256": "USM_PRIV_CFB256_AES",
}


def fetch_snmp_alerts(host: str) -> tuple[str, str]:
    """GET sysDescr/sysUpTime and list IF-MIB interfaces that are down.

    Returns ``(text, error)``. *error* is empty on success.
    """
    if not pysnmp_available():
        return "", "pysnmp is not installed"
    if not snmp_configured():
        return "", "SNMPv3 is not configured (Setup → SNMP)"
    settings = load_snmp_settings()
    host = (host or "").strip()
    if not host:
        return "", "No host address"
    try:
        import asyncio

        from pysnmp.hlapi.v3arch.asyncio import (
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            UsmUserData,
            get_cmd,
            walk_cmd,
        )
        from pysnmp.hlapi.v3arch import asyncio as v3a
    except Exception as exc:  # noqa: BLE001
        return "", f"pysnmp import failed: {exc}"

    auth_name = _AUTH_PROTO.get(settings.auth_protocol, "USM_AUTH_HMAC96_SHA")
    priv_name = _PRIV_PROTO.get(settings.priv_protocol, "USM_PRIV_CFB128_AES")
    auth_proto = getattr(v3a, auth_name, v3a.USM_AUTH_HMAC96_SHA)
    priv_proto = getattr(v3a, priv_name, v3a.USM_PRIV_CFB128_AES)
    context = settings.context_name

    if settings.security_level == "authPriv":
        auth = UsmUserData(
            settings.username,
            authKey=settings.auth_password,
            privKey=settings.priv_password,
            authProtocol=auth_proto,
            privProtocol=priv_proto,
        )
    elif settings.security_level == "authNoPriv":
        auth = UsmUserData(
            settings.username,
            authKey=settings.auth_password,
            authProtocol=auth_proto,
        )
    else:
        auth = UsmUserData(settings.username)

    async def _run() -> tuple[str, str]:
        engine = SnmpEngine()
        target = await UdpTransportTarget.create(
            (host, int(settings.port)),
            timeout=float(settings.timeout_sec),
            retries=int(settings.retries),
        )
        ctx = ContextData(contextName=context) if context else ContextData()
        err_ind, err_stat, _idx, var_binds = await get_cmd(
            engine,
            auth,
            target,
            ctx,
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.3.0")),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.5.0")),
        )
        if err_ind:
            return "", str(err_ind)
        if err_stat:
            return "", str(err_stat)
        lines = [f"SNMPv3 alerts from {host}:{settings.port}", ""]
        labels = ("sysDescr", "sysUpTime", "sysName")
        for label, vb in zip(labels, var_binds, strict=False):
            pretty = vb[1].prettyPrint() if hasattr(vb[1], "prettyPrint") else vb[1]
            lines.append(f"{label}: {pretty}")
        down: list[str] = []
        count = 0
        try:
            async for walk_err, walk_stat, _idx, vbs in walk_cmd(
                engine,
                auth,
                target,
                ctx,
                ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.8")),
                lexicographicMode=False,
            ):
                if walk_err or walk_stat:
                    break
                for vb in vbs:
                    count += 1
                    val = str(vb[1])
                    if val in {"2", "Integer: 2", "down"}:
                        down.append(str(vb[0]))
                    if count >= 128:
                        break
                if count >= 128:
                    break
        except Exception as walk_exc:  # noqa: BLE001
            lines.append(f"(IF-MIB walk skipped: {walk_exc})")
        lines.append("")
        lines.append(f"Interfaces walked: {count}")
        if down:
            lines.append("ifOperStatus down:")
            lines.extend(f"  {oid}" for oid in down[:40])
        else:
            lines.append("No down interfaces reported in IF-MIB ifOperStatus.")
        return "\n".join(lines), ""

    try:
        return asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001
        return "", str(exc)
