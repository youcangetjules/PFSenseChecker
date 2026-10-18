"""Secure credential storage via the OS keyring (Windows Credential Manager).

Passwords are never written into site JSON. Site files store only a stable
credential reference ID that maps to a keyring service/username pair.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass

SERVICE_PREFIX = "PFSenseChecker.MikroTik"
SSH_SERVICE_PREFIX = "PFSenseChecker.SSH"


@dataclass(frozen=True)
class CredentialRef:
    """Opaque reference stored in site JSON (no secrets)."""

    ref_id: str
    username: str
    service: str

    def to_dict(self) -> dict[str, str]:
        return {
            "ref_id": self.ref_id,
            "username": self.username,
            "service": self.service,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CredentialRef":
        return cls(
            ref_id=str(d.get("ref_id", "")),
            username=str(d.get("username", "")),
            service=str(d.get("service", "")),
        )


def make_credential_ref(device_name: str, host: str, username: str) -> CredentialRef:
    """Build a stable per-device credential reference."""
    raw = f"{device_name}|{host}|{username}".encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()[:16]
    ref_id = f"mt-{digest}"
    service = f"{SERVICE_PREFIX}.{ref_id}"
    return CredentialRef(ref_id=ref_id, username=username, service=service)


def make_ssh_credential_ref(device_name: str, host: str, username: str) -> CredentialRef:
    """Build a stable per-device SSH credential reference (separate namespace)."""
    raw = f"ssh|{device_name}|{host}|{username}".encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()[:16]
    ref_id = f"ssh-{digest}"
    service = f"{SSH_SERVICE_PREFIX}.{ref_id}"
    return CredentialRef(ref_id=ref_id, username=username, service=service)


def ssh_ref_from_id(ref_id: str, username: str) -> CredentialRef:
    """Rebuild a CredentialRef from a stored ssh ref_id + username."""
    return CredentialRef(
        ref_id=ref_id,
        username=username,
        service=f"{SSH_SERVICE_PREFIX}.{ref_id}",
    )


def store_password(ref: CredentialRef, password: str) -> None:
    """Persist password in the OS credential store."""
    try:
        import keyring
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "The 'keyring' package is required to store MikroTik credentials. "
            "Install it with: pip install keyring"
        ) from exc
    if not ref.username:
        raise ValueError("Credential username is required")
    keyring.set_password(ref.service, ref.username, password)


def get_password(ref: CredentialRef) -> str | None:
    """Retrieve password from the OS credential store, or None if missing."""
    try:
        import keyring
    except ImportError:  # pragma: no cover
        return None
    if not ref.username or not ref.service:
        return None
    return keyring.get_password(ref.service, ref.username)


def delete_password(ref: CredentialRef) -> None:
    """Remove a stored password if present."""
    try:
        import keyring
    except ImportError:  # pragma: no cover
        return
    if not ref.username or not ref.service:
        return
    try:
        keyring.delete_password(ref.service, ref.username)
    except Exception:  # noqa: BLE001
        pass


def new_ephemeral_ref(username: str) -> CredentialRef:
    """Create a one-off credential reference (e.g. ad-hoc test)."""
    ref_id = f"mt-tmp-{uuid.uuid4().hex[:12]}"
    return CredentialRef(
        ref_id=ref_id,
        username=username,
        service=f"{SERVICE_PREFIX}.{ref_id}",
    )
