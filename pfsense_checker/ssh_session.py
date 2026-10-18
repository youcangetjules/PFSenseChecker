"""SSH connectivity for the Session/Login screen.

Two probe levels:
- TCP banner check (stdlib only): confirms an SSH daemon answers.
- Full auth check via paramiko when installed (optional dependency).

Passwords come from the OS keyring via credential refs — never from site JSON.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from pfsense_checker.credentials import (
    get_password,
    make_ssh_credential_ref,
    ssh_ref_from_id,
    store_password,
)
from pfsense_checker.topology_site import Device, SshAccess


def paramiko_available() -> bool:
    try:
        import paramiko  # noqa: F401
    except ImportError:
        return False
    return True


@dataclass
class SshProbeResult:
    status: str  # ok | banner-only | auth-fail | unreachable | no-host
    detail: str = ""
    banner: str = ""

    @property
    def ok(self) -> bool:
        return self.status in ("ok", "banner-only")


def _utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def tcp_banner_probe(host: str, port: int, timeout: float = 5.0) -> SshProbeResult:
    """Stdlib-only reachability check: read the SSH version banner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(256).decode("utf-8", errors="replace").strip()
    except (OSError, socket.timeout) as exc:
        return SshProbeResult(status="unreachable", detail=str(exc))
    if banner.startswith("SSH-"):
        return SshProbeResult(status="banner-only", banner=banner)
    return SshProbeResult(
        status="banner-only",
        banner=banner,
        detail="Port answered but did not present an SSH banner",
    )


def auth_probe(
    host: str,
    port: int,
    username: str,
    password: str | None = None,
    key_path: str = "",
    timeout: float = 8.0,
) -> SshProbeResult:
    """Full SSH authentication via paramiko (required for real login)."""
    try:
        import paramiko
    except ImportError:
        # Do NOT fall back to banner-only — that looks like a password failure.
        return SshProbeResult(
            status="auth-fail",
            detail=(
                "paramiko is not installed — cannot authenticate. "
                'Install with: pip install "paramiko>=3.4.0" '
                "(or Python Modules → Save/Commit)."
            ),
        )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username or None,
            password=password or None,
            key_filename=key_path or None,
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
            allow_agent=bool(not password),
            look_for_keys=bool(not password),
        )
        transport = client.get_transport()
        banner = transport.remote_version if transport else ""
        return SshProbeResult(status="ok", banner=banner)
    except paramiko.AuthenticationException as exc:
        return SshProbeResult(status="auth-fail", detail=str(exc) or "authentication failed")
    except (paramiko.SSHException, OSError) as exc:
        # Still try to report if the daemon answered (MikroTik ROSSSH, etc.).
        banner = ""
        try:
            banner_res = tcp_banner_probe(host, port, min(timeout, 3.0))
            banner = banner_res.banner
        except Exception:  # noqa: BLE001
            pass
        return SshProbeResult(
            status="unreachable",
            detail=str(exc),
            banner=banner,
        )
    finally:
        client.close()


def probe_device(device: Device, *, timeout: float = 8.0) -> SshProbeResult:
    """Probe a device's SSH endpoint and update its SshAccess status."""
    ssh = device.ensure_ssh()
    if not ssh.host:
        ssh.last_status = "no-host"
        ssh.last_error = "No SSH host / management IP set"
        return SshProbeResult(status="no-host", detail=ssh.last_error)

    password = None
    if ssh.credential_ref and ssh.username:
        ref = ssh_ref_from_id(ssh.credential_ref, ssh.username)
        password = get_password(ref)

    if ssh.username and (password or ssh.key_path):
        result = auth_probe(
            ssh.host, ssh.port, ssh.username, password, ssh.key_path, timeout
        )
    else:
        result = tcp_banner_probe(ssh.host, ssh.port, timeout)
        if result.status == "banner-only":
            missing = []
            if not ssh.username:
                missing.append("username")
            if not password and not ssh.key_path:
                missing.append("password or key")
            # Clarify: banner OK does not mean login succeeded.
            kind_hint = ""
            if "rosssh" in (result.banner or "").lower():
                kind_hint = " (MikroTik ROSSSH detected)"
            result = SshProbeResult(
                status=result.status,
                banner=result.banner,
                detail=(
                    f"SSH daemon reachable{kind_hint}; full login needs "
                    + (" and ".join(missing) if missing else "credentials")
                    + '. Requires paramiko for authentication.'
                ),
            )

    ssh.last_status = result.status
    ssh.last_error = result.detail
    if result.ok:
        ssh.last_ok_at = _utcnow()
    # Auto-tag MikroTik from banner when kind is still generic.
    if result.banner:
        guess = identify_kind_from_banner(result.banner)
        if guess and device.kind in ("", "router", "host", "other", "switch"):
            if guess == "mikrotik":
                device.kind = "mikrotik"
    return result


def save_ssh_credentials(device: Device, password: str) -> SshAccess:
    """Store an SSH password in the OS keyring and record the ref."""
    ssh = device.ensure_ssh()
    if not ssh.username:
        raise ValueError("Set an SSH username before saving credentials")
    ref = make_ssh_credential_ref(device.name, ssh.host, ssh.username)
    store_password(ref, password)
    ssh.credential_ref = ref.ref_id
    return ssh


def resolve_ssh_password(
    ssh: SshAccess,
    username: str,
    password: str | None,
) -> str | None:
    """Keyring lookup when *password* is omitted or blank."""
    pwd = (password or "").strip() or None
    if pwd is None and ssh.credential_ref:
        pwd = get_password(ssh_ref_from_id(ssh.credential_ref, username))
        if pwd:
            pwd = pwd.strip() or None
    return pwd


@dataclass
class SshExportResult:
    ok: bool
    path: str = ""
    error: str = ""
    bytes_written: int = 0
    needs_sudo_password: bool = False
    needs_ssh_password: bool = False


def export_mikrotik_verbose_ssh(
    device: Device,
    *,
    password: str | None = None,
    cache_base: Path | None = None,
    timeout: float = 90.0,
) -> SshExportResult:
    """Run ``/export verbose`` over SSH and cache the .rsc locally.

    Uses the device's SSH credentials (keyring). Prefer this when the device
    is already reachable via Login to Routers.
    """
    from pfsense_checker.paths import PROJECT_ROOT
    from pfsense_checker.routeros_rest import _looks_like_export, _safe_filename, cache_dir
    from pfsense_checker.topology_site import CONFIG_SOURCE_LOCAL

    if not paramiko_available():
        return SshExportResult(
            ok=False,
            error='paramiko is required for SSH export — pip install "paramiko>=3.4.0"',
        )
    import paramiko

    ssh = device.ensure_ssh()
    host = (ssh.host or device.mgmt_ip or "").strip()
    if not host:
        return SshExportResult(ok=False, error="No SSH host / management IP set")
    username = (ssh.username or "").strip()
    if not username:
        return SshExportResult(ok=False, error="No SSH username set")

    pwd = resolve_ssh_password(ssh, username, password)
    if not pwd and not ssh.key_path:
        return SshExportResult(
            ok=False,
            error="No SSH password or key — Connect with credentials first",
        )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=int(ssh.port or 22),
            username=username,
            password=pwd or None,
            key_filename=ssh.key_path or None,
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        # RouterOS: print a full verbose export to the SSH channel.
        _stdin, stdout, stderr = client.exec_command(
            "/export verbose",
            timeout=timeout,
        )
        # Channel timeout for large configs
        stdout.channel.settimeout(timeout)
        raw_out = stdout.read()
        raw_err = stderr.read()
        text = raw_out.decode("utf-8", errors="replace")
        err_text = raw_err.decode("utf-8", errors="replace").strip()
        # Strip common SSH/RouterOS noise lines before the first /section.
        text = _strip_routeros_ssh_noise(text)
        if not text.strip():
            return SshExportResult(
                ok=False,
                error=err_text or "Empty response from /export verbose",
            )
        if not _looks_like_export(text):
            hint = (err_text or text[:240]).strip()
            return SshExportResult(
                ok=False,
                error=f"Response does not look like a RouterOS export: {hint}",
            )

        out_dir = cache_dir(cache_base or (PROJECT_ROOT / "data"))
        out_path = out_dir / f"{_safe_filename(device.name, host)}_verbose.rsc"
        out_path.write_text(text, encoding="utf-8")

        from datetime import datetime, timezone

        src = device.attach_local_config(out_path)
        src.source_type = CONFIG_SOURCE_LOCAL
        src.last_status = "ok"
        src.last_error = ""
        src.last_collected_at = (
            datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        )
        device.config_file = str(out_path)
        device.config_source = src
        if (device.kind or "").lower() not in {"mikrotik"}:
            device.kind = "mikrotik"

        return SshExportResult(
            ok=True,
            path=str(out_path),
            bytes_written=len(text.encode("utf-8")),
        )
    except paramiko.AuthenticationException as exc:
        return SshExportResult(ok=False, error=f"Authentication failed: {exc}")
    except Exception as exc:  # noqa: BLE001
        return SshExportResult(ok=False, error=str(exc))
    finally:
        client.close()


def _strip_routeros_ssh_noise(text: str) -> str:
    """Drop banners/prompts so the cached file starts at RouterOS export content."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    start = 0
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("#") and "routeros" in s.lower():
            start = i
            break
        if s.startswith("/"):
            start = i
            break
    return "\n".join(lines[start:]).strip() + ("\n" if lines else "")


# Live config paths on pfSense / OPNsense (FreeBSD). Prefer NanoBSD layout first.
PFSENSE_CONFIG_PATHS: tuple[str, ...] = (
    "/cf/conf/config.xml",
    "/conf/config.xml",
)


def looks_like_firewall_config_xml(text: str) -> bool:
    """True if *text* looks like a pfSense or OPNsense config.xml."""
    head = (text or "")[:8000].lower()
    if "<pfsense" in head or "<opnsense" in head:
        return True
    if "<?xml" in head and ("pfsense" in head or "opnsense" in head):
        return True
    return False


def extract_firewall_config_xml(text: str) -> str:
    """Pull config XML out of noisy sudo/pty output (lecture, Password:)."""
    raw = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    lower = raw.lower()
    starts: list[int] = []
    for token in ("<?xml", "<opnsense", "<pfsense"):
        idx = lower.find(token)
        if idx >= 0:
            starts.append(idx)
    if not starts:
        return ""
    chunk = raw[min(starts) :].strip()
    return chunk if looks_like_firewall_config_xml(chunk) else ""


def detect_firewall_kind_from_xml(text: str) -> str:
    """Return ``opnsense``, ``pfsense``, or '' from config XML content."""
    head = (text or "")[:8000].lower()
    if "<opnsense" in head:
        return "opnsense"
    if "<pfsense" in head:
        return "pfsense"
    return ""


def _ssh_exec_text(client: object, command: str, *, timeout: float) -> tuple[str, str, int]:
    """Run *command* on an open paramiko client; return (stdout, stderr, exit_status)."""
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    stdout.channel.settimeout(timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    status = stdout.channel.recv_exit_status()
    return out, err, int(status)


@dataclass
class SshRunResult:
    """Output of one or more remote shell/RouterOS commands."""

    ok: bool
    output: str = ""
    error: str = ""


def run_ssh_commands(
    device: Device,
    commands: list[str],
    *,
    password: str | None = None,
    timeout: float = 20.0,
) -> SshRunResult:
    """Connect once and run *commands*; concatenate stdout (and stderr on failure)."""
    if not commands:
        return SshRunResult(ok=False, error="No commands")
    if not paramiko_available():
        return SshRunResult(
            ok=False,
            error='paramiko is required — pip install "paramiko>=3.4.0"',
        )
    import paramiko

    ssh = device.ensure_ssh()
    host = (ssh.host or device.mgmt_ip or "").strip()
    if not host:
        return SshRunResult(ok=False, error="No SSH host / management IP set")
    username = (ssh.username or "").strip()
    if not username:
        return SshRunResult(ok=False, error="No SSH username set")
    pwd = resolve_ssh_password(ssh, username, password)
    if not pwd and not ssh.key_path:
        return SshRunResult(
            ok=False,
            error="No SSH password or key — Connect with credentials first",
        )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    chunks: list[str] = []
    try:
        client.connect(
            hostname=host,
            port=int(ssh.port or 22),
            username=username,
            password=pwd or None,
            key_filename=ssh.key_path or None,
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        for command in commands:
            out, err, status = _ssh_exec_text(client, command, timeout=timeout)
            body = (out or "").strip()
            if body:
                if len(commands) > 1:
                    chunks.append(f"$ {command}\n{body}")
                else:
                    chunks.append(body)
            elif status != 0:
                hint = (err or "").strip() or f"exit {status}"
                chunks.append(f"$ {command}\n({hint})")
        text = "\n\n".join(chunks).strip()
        if not text:
            return SshRunResult(ok=False, error="Empty response from device")
        return SshRunResult(ok=True, output=text)
    except paramiko.AuthenticationException as exc:
        return SshRunResult(ok=False, error=f"Authentication failed: {exc}")
    except Exception as exc:  # noqa: BLE001
        return SshRunResult(ok=False, error=str(exc))
    finally:
        client.close()


# Unique sudo -S prompt so we can strip it from pty output. Never put the
# password on the remote command line (it would show in ps).
SUDO_PROMPT = "NETCHECK_SUDO:"


def _pfsense_pull_commands() -> list[str]:
    """Shell commands to try, in order, to read live config.xml (no password)."""
    import shlex

    paths = " ".join(PFSENSE_CONFIG_PATHS)
    read_script = (
        f"for f in {paths}; do "
        '[ -r "$f" ] && cat "$f" && exit 0; '
        "done; "
        f"for f in {paths}; do "
        '[ -e "$f" ] && echo PERMISSION_DENIED:$f >&2; '
        "done; "
        "exit 1"
    )
    sudo_script = (
        f"for f in {paths}; do "
        'sudo -n cat "$f" 2>/dev/null && exit 0; '
        "done; "
        "exit 1"
    )
    return [
        f"/bin/sh -c {shlex.quote(read_script)}",
        f"/bin/sh -c {shlex.quote(sudo_script)}",
    ]


def _pfsense_sudo_stdin_command() -> str:
    """One sudo -S that cats config.xml as root (password on stdin, not argv)."""
    import shlex

    paths = " ".join(PFSENSE_CONFIG_PATHS)
    inner = (
        f"for f in {paths}; do "
        '[ -f "$f" ] && cat "$f" && exit 0; '
        "done; "
        "exit 1"
    )
    return (
        f"sudo -S -p {shlex.quote(SUDO_PROMPT)} "
        f"/bin/sh -c {shlex.quote(inner)}"
    )


def _ssh_sudo_cat(
    client: object, password: str, *, timeout: float
) -> tuple[str, str, int]:
    """Run sudo -S cat via stdin. Same SSH session; password is not logged."""
    stdin, stdout, stderr = client.exec_command(
        _pfsense_sudo_stdin_command(),
        timeout=timeout,
        get_pty=False,
    )
    stdout.channel.settimeout(timeout)
    stdin.write(password + "\n")
    stdin.flush()
    try:
        stdin.channel.shutdown_write()
    except Exception:  # noqa: BLE001
        pass
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if err.strip() == SUDO_PROMPT:
        err = ""
    status = stdout.channel.recv_exit_status()
    return out, err, int(status)


def _sudo_rejected(text: str) -> bool:
    low = (text or "").lower()
    return any(
        needle in low
        for needle in (
            "sorry",
            "try again",
            "incorrect password",
            "not in the sudoers",
            "not allowed to execute",
        )
    )


def _format_pfsense_pull_error(err_text: str, username: str) -> str:
    low = (err_text or "").lower()
    paths = " and ".join(PFSENSE_CONFIG_PATHS)
    if "permission_denied" in low or "permission denied" in low:
        return (
            f"Permission denied reading {paths}.\n\n"
            f"SSH user “{username}” cannot read the live config as itself. "
            "If `sudo id` works on that box, NetCheck will retry with "
            "sudo -S (SSH password first, then a sudo prompt). "
            "Otherwise use admin/root, or download a backup from the web UI."
        )
    if err_text.strip():
        return err_text.strip()
    return (
        f"Could not read {paths}. Is SSH shell access enabled for "
        f"“{username}”?"
    )


def export_pfsense_config_ssh(
    device: Device,
    *,
    password: str | None = None,
    sudo_password: str | None = None,
    cache_base: Path | None = None,
    timeout: float = 60.0,
) -> SshExportResult:
    """Pull ``config.xml`` from pfSense/OPNsense over SSH and cache it locally.

    Tries ``/cf/conf/config.xml`` then ``/conf/config.xml`` (Netgate docs /
    common FreeBSD layout). Uses the same SSH credentials as Connect.
    Order: unprivileged ``cat``, ``sudo -n cat``, then ``sudo -S cat`` with
    *sudo_password* or the SSH password (password on stdin, never on argv).
    """
    from pfsense_checker.paths import PROJECT_ROOT
    from pfsense_checker.routeros_rest import _safe_filename, cache_dir
    from pfsense_checker.topology_site import CONFIG_SOURCE_LOCAL

    if not paramiko_available():
        return SshExportResult(
            ok=False,
            error='paramiko is required for SSH pull — pip install "paramiko>=3.4.0"',
        )
    import paramiko

    ssh = device.ensure_ssh()
    host = (ssh.host or device.mgmt_ip or "").strip()
    if not host:
        return SshExportResult(ok=False, error="No SSH host / management IP set")
    username = (ssh.username or "").strip()
    if not username:
        return SshExportResult(ok=False, error="No SSH username set")

    pwd = resolve_ssh_password(ssh, username, password)
    if not pwd and not ssh.key_path:
        return SshExportResult(
            ok=False,
            error="No SSH password or key — enter credentials to connect",
            needs_ssh_password=True,
        )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    last_err = ""
    try:
        client.connect(
            hostname=host,
            port=int(ssh.port or 22),
            username=username,
            password=pwd or None,
            key_filename=ssh.key_path or None,
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )

        text = ""
        sudo_failed_auth = False
        need_sudo = False
        escalate = (sudo_password or pwd or "").strip()
        from pfsense_checker import app_log

        log = app_log.get_logger("ssh")
        log.info(
            "Pulling config.xml from %s (%s@%s:%s)",
            device.name,
            username,
            host,
            int(ssh.port or 22),
        )
        for cmd in _pfsense_pull_commands():
            log.debug("pfSense pull trying: %s", cmd[:120])
            out, err, status = _ssh_exec_text(client, cmd, timeout=timeout)
            last_err = (err or out or "").strip()
            log.debug(
                "pfSense pull exit=%s stderr=%s",
                status,
                (err or "").strip()[:200],
            )
            if "permission_denied" in last_err.lower():
                need_sudo = True
                break
            candidate = extract_firewall_config_xml(out) or out.lstrip("\ufeff").strip()
            if candidate and looks_like_firewall_config_xml(candidate):
                text = candidate
                log.info("pfSense pull read config without sudo (%s bytes)", len(text))
                break

        # pfSense config.xml is root-only — sudo -S (no PTY; PTY hangs on OpenSSH 10).
        if not text:
            if escalate:
                log.debug("pfSense pull escalating with sudo -S")
                out, err, status = _ssh_sudo_cat(client, escalate, timeout=timeout)
                mixed = f"{out}\n{err}"
                last_err = (err or out or "").strip() or f"sudo exit {status}"
                log.debug(
                    "pfSense sudo exit=%s out_bytes=%s err=%s",
                    status,
                    len(out),
                    (err or "").strip()[:120],
                )
                if _sudo_rejected(mixed):
                    sudo_failed_auth = True
                candidate = extract_firewall_config_xml(mixed)
                if candidate and looks_like_firewall_config_xml(candidate):
                    text = candidate
                    log.info(
                        "pfSense pull read config via sudo (%s bytes)", len(text)
                    )

        # SFTP as a last resort (same permission rules, but no shell quirks).
        if not text:
            try:
                sftp = client.open_sftp()
                try:
                    for path in PFSENSE_CONFIG_PATHS:
                        try:
                            with sftp.open(path, "r") as fh:
                                raw = fh.read()
                            candidate = raw.decode("utf-8", errors="replace")
                            candidate = candidate.lstrip("\ufeff").strip()
                            if candidate and looks_like_firewall_config_xml(candidate):
                                text = candidate
                                break
                        except OSError as exc:
                            last_err = str(exc)
                            continue
                finally:
                    sftp.close()
            except Exception as exc:  # noqa: BLE001
                last_err = last_err or str(exc)

        if not text:
            asked = bool((sudo_password or "").strip())
            need_pw = (not asked) and (need_sudo or sudo_failed_auth)
            err_msg = _format_pfsense_pull_error(last_err, username)
            if sudo_failed_auth:
                err_msg = (
                    f"sudo rejected the password for “{username}”. "
                    "If `sudo id` works in an SSH shell, enter that same "
                    "sudo password when prompted."
                )
            elif need_pw and not sudo_failed_auth:
                err_msg = (
                    f"Live config is not readable as “{username}” "
                    "(sudo -n / SFTP failed).\n\n"
                    "NetCheck will retry with sudo -S using the SSH password, "
                    "or prompt for a separate sudo password."
                )
            if not err_msg.strip():
                err_msg = (
                    f"Could not read config.xml from {host}. "
                    "Check Console (DEBUG) for SSH steps."
                )
            log.warning("pfSense pull failed device=%s: %s", device.name, err_msg)
            return SshExportResult(
                ok=False,
                error=err_msg,
                needs_sudo_password=not asked and (need_sudo or sudo_failed_auth),
            )

        out_dir = cache_dir(cache_base or (PROJECT_ROOT / "data"))
        out_path = out_dir / f"{_safe_filename(device.name, host)}_config.xml"
        out_path.write_text(text, encoding="utf-8")

        src = device.attach_local_config(out_path)
        src.source_type = CONFIG_SOURCE_LOCAL
        src.last_status = "ok"
        src.last_error = ""
        src.last_collected_at = (
            datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        )
        device.config_file = str(out_path)
        device.config_source = src
        guessed = detect_firewall_kind_from_xml(text)
        if guessed and (device.kind or "").lower() not in {"pfsense", "opnsense"}:
            device.kind = guessed
        elif guessed == "opnsense" and (device.kind or "").lower() == "pfsense":
            device.kind = "opnsense"

        try:
            import xml.etree.ElementTree as ET

            root = ET.fromstring(text)
            ver_el = root.find("version")
            if ver_el is not None and (ver_el.text or "").strip():
                device.software_version = ver_el.text.strip()
        except Exception:  # noqa: BLE001
            pass

        return SshExportResult(
            ok=True,
            path=str(out_path),
            bytes_written=len(text.encode("utf-8")),
        )
    except paramiko.AuthenticationException as exc:
        return SshExportResult(
            ok=False,
            error=f"Authentication failed: {exc}",
            needs_ssh_password=True,
        )
    except Exception as exc:  # noqa: BLE001
        return SshExportResult(ok=False, error=str(exc))
    finally:
        client.close()


def identify_kind_from_banner(banner: str) -> str:
    """Best-effort device kind from an SSH version banner ('' if unknown).

    Examples: MikroTik presents 'SSH-2.0-ROSSSH', pfSense/OPNsense present
    'SSH-2.0-OpenSSH_x FreeBSD-...', EdgeOS mentions 'ubnt'.
    """
    b = (banner or "").lower()
    if not b:
        return ""
    if "rosssh" in b or "mikrotik" in b:
        return "mikrotik"
    if "ubnt" in b or "ubiquiti" in b or "edgeos" in b:
        return "ubiquiti"
    if "junos" in b or "juniper" in b or "netscreen" in b:
        return "juniper"
    if "cisco" in b:
        return "router"
    if "freebsd" in b:
        # pfSense and OPNsense both ride FreeBSD; pfsense is our default guess.
        return "pfsense"
    if "dropbear" in b:
        # Dropbear is typical of embedded network gear (switches / APs / CPE).
        return "switch"
    if "windows" in b:
        return "workstation"
    if "openssh" in b:
        return "server"
    return ""


def status_label(status: str) -> tuple[str, str]:
    """(text, color) badge for an SshAccess status."""
    return {
        "ok": ("connected", "#1565c0"),
        "banner-only": ("reachable", "#f9a825"),
        "auth-fail": ("auth failed", "#c62828"),
        "unreachable": ("unreachable", "#c62828"),
        "no-host": ("no host", "#9e9e9e"),
        "never": ("not tested", "#9e9e9e"),
        "": ("not tested", "#9e9e9e"),
    }.get(status, (status, "#9e9e9e"))
