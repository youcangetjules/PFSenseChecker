"""SNMPv3 settings tests."""

from __future__ import annotations

import json

from pfsense_checker import snmp


def test_snmp_settings_roundtrip(tmp_path, monkeypatch) -> None:
    settings_file = tmp_path / "snmp.json"
    secrets_file = tmp_path / "secrets.local.json"
    monkeypatch.setattr(snmp, "_SETTINGS_FILE", settings_file)
    monkeypatch.setattr(snmp, "_SECRETS_FILE", secrets_file)
    monkeypatch.setattr(snmp, "ensure_data_dir", lambda: tmp_path)

    cfg = snmp.SnmpV3Settings(
        enabled=True,
        username="monitor",
        security_level="authPriv",
        auth_protocol="SHA256",
        auth_password="auth-secret",
        priv_protocol="AES",
        priv_password="priv-secret",
        port=161,
        test_host="10.0.0.1",
    )
    assert snmp.validate_snmp_settings(cfg) == ""
    snmp.save_snmp_settings(cfg)

    loaded = snmp.load_snmp_settings()
    assert loaded.enabled is True
    assert loaded.username == "monitor"
    assert loaded.auth_password == "auth-secret"
    assert loaded.priv_password == "priv-secret"
    assert loaded.auth_protocol == "SHA256"
    assert loaded.test_host == "10.0.0.1"
    assert snmp.snmp_configured() is True

    public = json.loads(settings_file.read_text(encoding="utf-8"))
    secrets = json.loads(secrets_file.read_text(encoding="utf-8"))
    assert "auth_password" not in public
    assert public["snmp_version"] == 3
    assert secrets["snmp_auth_password"] == "auth-secret"


def test_snmp_validate_requires_priv_for_authpriv() -> None:
    cfg = snmp.SnmpV3Settings(
        enabled=True,
        username="u",
        security_level="authPriv",
        auth_password="a",
        priv_password="",
    )
    assert "Privacy" in snmp.validate_snmp_settings(cfg)
