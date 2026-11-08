"""Load Config / Pull Config log in the way Connect does: keys and the SSH agent
work, and a key-only server is not stuck on a password prompt."""

from __future__ import annotations

import pytest

paramiko = pytest.importorskip("paramiko")

from pfsense_checker import ssh_session as s  # noqa: E402
from pfsense_checker.topology_site import Device  # noqa: E402


class _FakeClient:
    calls: list[dict] = []
    behaviour: list = []  # per attempt: None = accept, or an exception to raise

    def __init__(self) -> None:
        self.closed = False

    def set_missing_host_key_policy(self, _policy) -> None:  # noqa: ANN001
        pass

    def connect(self, **kwargs) -> None:  # noqa: ANN003
        _FakeClient.calls.append(kwargs)
        outcome = _FakeClient.behaviour.pop(0) if _FakeClient.behaviour else None
        if outcome is not None:
            raise outcome

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def fake(monkeypatch):  # noqa: ANN201
    _FakeClient.calls = []
    _FakeClient.behaviour = []
    monkeypatch.setattr(paramiko, "SSHClient", _FakeClient)
    return _FakeClient


def _keys_only() -> Exception:
    return paramiko.BadAuthenticationType("Bad authentication type", ["publickey"])


def test_no_password_uses_keys_and_agent_like_connect(fake) -> None:
    s.connect_client(host="h", port=22, username="u", password=None)
    call = fake.calls[0]
    assert call["password"] is None and call["allow_agent"] and call["look_for_keys"]


def test_password_device_gets_only_the_password(fake) -> None:
    s.connect_client(host="h", port=22, username="u", password="pw")
    assert len(fake.calls) == 1
    call = fake.calls[0]
    assert call["password"] == "pw" and not call["allow_agent"] and not call["look_for_keys"]


def test_key_only_server_retries_with_keys(fake) -> None:
    fake.behaviour = [_keys_only(), None]
    s.connect_client(host="h", port=22, username="u", password="pw", key_path="C:/k/id_ed25519")
    assert len(fake.calls) == 2
    retry = fake.calls[1]
    assert retry["password"] is None and retry["allow_agent"] and retry["look_for_keys"]
    assert retry["key_filename"] == "C:/k/id_ed25519"


def test_password_only_server_rejection_is_not_retried(fake) -> None:
    fake.behaviour = [paramiko.BadAuthenticationType("Bad authentication type", ["password"])]
    with pytest.raises(paramiko.AuthenticationException):
        s.connect_client(host="h", port=22, username="u", password="pw")
    assert len(fake.calls) == 1


def test_pfsense_pull_tries_keys_before_asking_for_a_password(fake, monkeypatch) -> None:
    dev = Device(name="guardian", kind="pfsense", mgmt_ip="10.0.0.1")
    ssh = dev.ensure_ssh()
    ssh.host, ssh.username = "10.0.0.1", "admin"
    monkeypatch.setattr(s, "resolve_ssh_password", lambda *_a, **_k: None)
    fake.behaviour = [paramiko.AuthenticationException("no key accepted")]
    result = s.export_pfsense_config_ssh(dev, password=None)
    assert fake.calls and fake.calls[0]["allow_agent"]  # it tried the keys
    assert not result.ok and result.needs_ssh_password  # and only then asks
