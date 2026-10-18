"""SshAccess model, credential refs, and TCP banner probe."""

from __future__ import annotations

import socket
import threading

from pfsense_checker.credentials import make_ssh_credential_ref, ssh_ref_from_id
from pfsense_checker.ssh_session import identify_kind_from_banner, tcp_banner_probe
from pfsense_checker.topology_site import Device, SiteTopology, SshAccess


def test_ssh_access_roundtrip() -> None:
    site = SiteTopology()
    dev = Device(name="fw1", kind="pfsense")
    dev.mgmt_ip = "10.0.0.1"
    ssh = dev.ensure_ssh()
    assert ssh.host == "10.0.0.1"  # defaults from mgmt_ip
    ssh.username = "admin"
    ssh.port = 2222
    ssh.credential_ref = "ssh-abc123"
    site.devices.append(dev)

    restored = SiteTopology.from_dict(site.to_dict())
    r = restored.device("fw1")
    assert r is not None and r.ssh is not None
    assert (r.ssh.host, r.ssh.port, r.ssh.username) == ("10.0.0.1", 2222, "admin")
    assert r.ssh.credential_ref == "ssh-abc123"


def test_ssh_credential_ref_stable_and_namespaced() -> None:
    a = make_ssh_credential_ref("fw1", "10.0.0.1", "admin")
    b = make_ssh_credential_ref("fw1", "10.0.0.1", "admin")
    assert a.ref_id == b.ref_id and a.ref_id.startswith("ssh-")
    assert a.service.startswith("PFSenseChecker.SSH.")
    rebuilt = ssh_ref_from_id(a.ref_id, "admin")
    assert rebuilt.service == a.service


def test_tcp_banner_probe_against_fake_sshd() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve() -> None:
        conn, _ = server.accept()
        conn.sendall(b"SSH-2.0-FakeSSHd\r\n")
        conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    res = tcp_banner_probe("127.0.0.1", port, timeout=3.0)
    server.close()
    assert res.status == "banner-only"
    assert res.banner.startswith("SSH-2.0")
    assert res.ok


def test_tcp_probe_unreachable() -> None:
    # Port 1 on localhost is almost certainly closed; expect fast refusal
    res = tcp_banner_probe("127.0.0.1", 1, timeout=2.0)
    assert res.status == "unreachable"
    assert not res.ok


def test_identify_kind_from_banner() -> None:
    assert identify_kind_from_banner("SSH-2.0-ROSSSH") == "mikrotik"
    assert identify_kind_from_banner("SSH-2.0-OpenSSH_9.7 FreeBSD-20240701") == "pfsense"
    assert identify_kind_from_banner("SSH-2.0-dropbear_2022.83") == "switch"
    assert identify_kind_from_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0") == "server"
    assert identify_kind_from_banner("") == ""
    assert identify_kind_from_banner("HTTP/1.1 400 Bad Request") == ""


def test_site_subnets_roundtrip() -> None:
    site = SiteTopology(subnets=["192.168.1.0/24", "10.10.0.0/16"])
    restored = SiteTopology.from_dict(site.to_dict())
    assert restored.subnets == ["192.168.1.0/24", "10.10.0.0/16"]
