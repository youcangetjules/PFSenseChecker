"""Automatic router log downloads over SSH (pfSense / OPNsense and MikroTik).

Each run logs in once per device (the same way Connect does, so sshguard sees
one successful login) and fetches only what is new since the last run:

* pfSense / OPNsense: the plain-text logs in /var/log (system, filter, dhcpd,
  auth, openvpn, …). A byte cursor per file; a file that got smaller was
  rotated, so it is read from the start. Unreadable files are retried with
  ``sudo -n`` (never a password in the background).
* MikroTik: ``/log print without-paging`` (the router's memory log); lines
  after the last one already saved are appended.

Files: data/device_logs/<device>/<YYYY-MM-DD>/<log>.log, appended to.
Cursors: data/device_logs/state.json (works with the database offline).
Index: one row per downloaded chunk in PostgreSQL (``device_log_downloads``),
written when the database is reachable. No passwords are stored or logged.
Qt-free. (added 2026-11-09)
"""

from __future__ import annotations

import json
import re
import shlex
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from pfsense_checker.paths import PROJECT_ROOT

LOG_ROOT = PROJECT_ROOT / "data" / "device_logs"
STATE_FILE = LOG_ROOT / "state.json"
SETTINGS_FILE = LOG_ROOT / "settings.json"
DEFAULT_HOURS = 6
MAX_BYTES_PER_LOG = 2_000_000  # per file per run; the rest comes next run
PFSENSE_LOGS = (
    "system", "filter", "dhcpd", "auth", "openvpn", "gateways", "resolver",
    "routing", "ntpd", "ipsec", "ppp", "wireless", "nginx", "portalauth",
)
MARK = "@@NETCHECK-LOG@@"
MIKROTIK_LOG = "log"  # the one RouterOS memory log
TAIL_KEEP = 25  # MikroTik: lines remembered to find where the last run stopped
PFSENSE_KINDS = ("pfsense", "opnsense")
MIKROTIK_KINDS = ("mikrotik",)


# --------------------------------------------------------------------------- #
# Settings and cursors


@dataclass
class LogSettings:
    enabled: bool = True
    hours: int = DEFAULT_HOURS  # scheduled run every N hours while NetCheck is open
    on_connect: bool = True  # also after Connect / Load Config

    def normalised(self) -> LogSettings:
        return LogSettings(bool(self.enabled), max(1, min(int(self.hours or DEFAULT_HOURS), 168)),
                           bool(self.on_connect))


def load_settings(path: Path = SETTINGS_FILE) -> LogSettings:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return LogSettings()
    return LogSettings(
        enabled=bool(raw.get("enabled", True)),
        hours=int(raw.get("hours", DEFAULT_HOURS) or DEFAULT_HOURS),
        on_connect=bool(raw.get("on_connect", True)),
    ).normalised()


def save_settings(settings: LogSettings, path: Path = SETTINGS_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    s = settings.normalised()
    path.write_text(json.dumps({"enabled": s.enabled, "hours": s.hours, "on_connect": s.on_connect},
                               indent=2), encoding="utf-8")


def load_state(path: Path = STATE_FILE) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(state: dict[str, Any], path: Path = STATE_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


# --------------------------------------------------------------------------- #
# Paused devices: never repeat a failed login on a timer
#
# A firewall counts failed logins (pfSense's sshguard blocks the address that
# makes them, SSH and web interface both). So after one failed login NetCheck
# stops every automatic login to that device — scheduled log downloads and
# Load All — until a login the operator makes by hand (Connect / Load Config)
# succeeds. (BUG-054)

PAUSE_KEY = "paused"
_AUTH_WORDS = ("authentication", "permission denied", "bad authentication type", "auth fail", "password")


def is_auth_failure(error: object) -> bool:
    """True when *error* is a refused login (not a timeout or an unreachable host)."""
    text = str(error or "").lower()
    return any(word in text for word in _AUTH_WORDS)


def pause(name: str, reason: str, path: Path | None = None) -> None:
    """Stop automatic logins to device *name* until resume()."""
    path = path or STATE_FILE
    state = load_state(path)
    state.setdefault(name, {})[PAUSE_KEY] = {
        "reason": str(reason)[:300],
        "since": datetime.now().isoformat(timespec="seconds"),
    }
    save_state(state, path)


def resume(name: str, path: Path | None = None) -> bool:
    """Allow automatic logins again (a login by hand just worked). True if it was paused."""
    path = path or STATE_FILE
    state = load_state(path)
    if PAUSE_KEY not in (state.get(name) or {}):
        return False
    state[name].pop(PAUSE_KEY, None)
    save_state(state, path)
    return True


def paused(name: str, path: Path | None = None) -> str:
    """Why automatic logins to *name* are paused, or "" when they are not."""
    entry = (load_state(path or STATE_FILE).get(name) or {}).get(PAUSE_KEY)
    if not entry:
        return ""
    return f"{entry.get('reason', 'a login failed')} (since {entry.get('since', '?')})"


# --------------------------------------------------------------------------- #
# Results


@dataclass
class LogChunk:
    log: str
    path: str
    bytes: int
    lines: int
    first_line: str = ""
    last_line: str = ""
    rotated: bool = False


@dataclass
class DeviceLogResult:
    device: str
    kind: str
    ok: bool
    source: str = "schedule"  # schedule / connect / manual
    chunks: list[LogChunk] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # logs that could not be read
    error: str = ""
    started: float = 0.0

    @property
    def new_bytes(self) -> int:
        return sum(c.bytes for c in self.chunks)

    def summary(self) -> str:
        if not self.ok:
            return f"{self.device}: failed — {self.error}"
        if not self.chunks:
            return f"{self.device}: nothing new"
        logs = ", ".join(f"{c.log} {c.lines}" for c in self.chunks)
        return f"{self.device}: {sum(c.lines for c in self.chunks)} new lines ({logs})"


# --------------------------------------------------------------------------- #
# Which devices


def kind_of(device) -> str:  # noqa: ANN001
    k = (getattr(device, "kind", "") or "").lower()
    if k in PFSENSE_KINDS:
        return "pfsense"
    if k in MIKROTIK_KINDS:
        return "mikrotik"
    return ""


def eligible(device) -> bool:  # noqa: ANN001
    """A pfSense / OPNsense / MikroTik with an SSH host and username, not ignored."""
    if getattr(device, "ignored", False) or not kind_of(device):
        return False
    ssh = getattr(device, "ssh", None)
    host = ((ssh.host if ssh else "") or getattr(device, "mgmt_ip", "") or "").strip()
    return bool(host and ssh and (ssh.username or "").strip())


def device_dir(device_name: str, root: Path = LOG_ROOT) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", device_name).strip("_") or "device"
    return root / safe


# --------------------------------------------------------------------------- #
# Remote commands


def pfsense_script(cursors: dict[str, int], names: tuple[str, ...] = PFSENSE_LOGS,
                   max_bytes: int = MAX_BYTES_PER_LOG) -> str:
    """One shell script that prints every log's new bytes after a marker line:
    ``@@NETCHECK-LOG@@ <name> <size> <offset>`` (or ``DENIED``)."""
    parts = []
    for name in names:
        f = f"/var/log/{name}.log"
        off = max(0, int(cursors.get(name, 0) or 0))
        parts.append(
            f'if [ -r {f} ]; then sz=$(stat -f %z {f} 2>/dev/null || wc -c < {f}); o={off}; '
            f'[ "$sz" -lt {off} ] && o=0; echo "{MARK} {name} $sz $o"; '
            f"tail -c +$((o+1)) {f} | head -c {int(max_bytes)}; echo; "
            f'elif [ -e {f} ]; then echo "{MARK} {name} DENIED 0"; fi'
        )
    return "; ".join(parts)


def parse_pfsense(output: bytes) -> dict[str, tuple[str, int, int, bytes]]:
    """{name: (status, size, offset, data)}; status "ok" or "denied"."""
    out: dict[str, tuple[str, int, int, bytes]] = {}
    mark = MARK.encode()
    pieces = output.split(mark + b" ")
    for piece in pieces[1:]:
        head, _, body = piece.partition(b"\n")
        bits = head.decode("utf-8", "replace").split()
        if len(bits) < 3:
            continue
        name = bits[0]
        if bits[1] == "DENIED":
            out[name] = ("denied", 0, 0, b"")
            continue
        try:
            size, offset = int(bits[1]), int(bits[2])
        except ValueError:
            continue
        if body.endswith(b"\n"):
            body = body[:-1]  # the `echo` after each file's data
        out[name] = ("ok", size, offset, body)
    return out


def complete_lines(data: bytes) -> bytes:
    """Only whole lines: a partial last line waits for the next run."""
    if not data or data.endswith(b"\n"):
        return data
    cut = data.rfind(b"\n")
    return data[: cut + 1] if cut >= 0 else b""


def new_mikrotik_lines(lines: list[str], tail: list[str]) -> list[str]:
    """Lines of the memory log after the last ones already saved."""
    lines = [ln for ln in lines if ln.strip()]
    if not tail:
        return lines
    n = len(tail)
    for k in range(n, 0, -1):  # longest saved tail that still matches
        want = tail[-k:]
        for i in range(len(lines) - k, -1, -1):
            if lines[i : i + k] == want:
                return lines[i + k :]
    return lines  # the memory log has moved on past everything we had


_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def clean_routeros(text: str) -> list[str]:
    out = []
    for raw in text.replace("\r", "").split("\n"):
        line = _ANSI.sub("", raw).strip()
        if line and not line.startswith(("Flags:", "Columns:")):
            out.append(line)
    return out


# --------------------------------------------------------------------------- #
# SSH session (injected in tests)


class Session(Protocol):
    def run(self, command: str) -> tuple[bytes, str, int]: ...

    def close(self) -> None: ...


class _ParamikoSession:
    def __init__(self, client: Any, timeout: float) -> None:
        self.client = client
        self.timeout = timeout

    def run(self, command: str) -> tuple[bytes, str, int]:
        _stdin, stdout, stderr = self.client.exec_command(command, timeout=self.timeout)
        stdout.channel.settimeout(self.timeout)
        out = stdout.read()
        err = stderr.read().decode("utf-8", "replace")
        return out, err, int(stdout.channel.recv_exit_status())

    def close(self) -> None:
        self.client.close()


def login_details(device):  # noqa: ANN001, ANN201
    """The device's SSH details with the saved login for its address applied, as
    Connect does (username, key file, keyring reference, port from
    ssh_host_credentials). A copy: the shared Device is not changed."""
    from dataclasses import replace

    ssh = replace(device.ensure_ssh())
    host = (ssh.host or device.mgmt_ip or "").strip()
    ssh.host = host
    try:
        from pfsense_checker import ssh_credentials_db

        row = ssh_credentials_db.get_host_credentials(host) or {}
    except Exception:  # noqa: BLE001 - database offline: use what the device has
        row = {}
    if str(row.get("ssh_user") or "").strip():
        ssh.username = str(row["ssh_user"]).strip()
    if str(row.get("ssh_key_path") or "").strip():
        ssh.key_path = str(row["ssh_key_path"]).strip()
    if str(row.get("ssh_credential_ref") or "").strip():
        ssh.credential_ref = str(row["ssh_credential_ref"]).strip()
    try:
        if int(row.get("ssh_port") or 0) > 0:
            ssh.port = int(row["ssh_port"])
    except (TypeError, ValueError):
        pass
    return ssh


def open_session(device, *, password: str | None = None, timeout: float = 30.0) -> Session:  # noqa: ANN001
    """Log in the way Connect does (saved login, keys / agent, or the keyring password)."""
    from pfsense_checker.ssh_session import connect_client, resolve_ssh_password

    ssh = login_details(device)
    host = ssh.host
    username = (ssh.username or "").strip()
    pwd = resolve_ssh_password(ssh, username, password)
    client = connect_client(host=host, port=int(ssh.port or 22), username=username, password=pwd,
                            key_path=ssh.key_path or "", timeout=timeout)
    return _ParamikoSession(client, timeout)


# --------------------------------------------------------------------------- #
# Download


def _append(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as fh:
        fh.write(data)


def _chunk(log: str, path: Path, data: bytes, rotated: bool = False) -> LogChunk:
    text = data.decode("utf-8", "replace")
    lines = [ln for ln in text.split("\n") if ln.strip()]
    return LogChunk(log=log, path=str(path), bytes=len(data), lines=len(lines),
                    first_line=lines[0][:300] if lines else "", last_line=lines[-1][:300] if lines else "",
                    rotated=rotated)


def download_device_logs(
    device,  # noqa: ANN001
    *,
    source: str = "schedule",
    password: str | None = None,
    root: Path = LOG_ROOT,
    state_path: Path = STATE_FILE,
    session_factory: Callable[..., Session] = open_session,
    now: datetime | None = None,
    timeout: float = 30.0,
) -> DeviceLogResult:
    """Fetch what is new on one device and append it to today's files."""
    kind = kind_of(device)
    result = DeviceLogResult(device=device.name, kind=kind, ok=False, source=source, started=time.time())
    if not kind:
        result.error = "not a pfSense / OPNsense / MikroTik device"
        return result
    day = (now or datetime.now()).strftime("%Y-%m-%d")
    folder = device_dir(device.name, root) / day
    state = load_state(state_path)
    dev_state: dict[str, Any] = state.setdefault(device.name, {})
    if dev_state.get(PAUSE_KEY):  # a login failed before: no automatic retries (BUG-054)
        entry = dev_state[PAUSE_KEY]
        result.error = (f"paused since {entry.get('since', '?')} after a failed login "
                        f"({entry.get('reason', '')}). Connect to it on Login to Routers to resume.")
        return result
    try:
        session = session_factory(device, password=password, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        result.error = f"login failed: {exc}"
        dev_state["last_run"] = datetime.now().isoformat(timespec="seconds")
        dev_state["last_result"] = f"error: {result.error[:200]}"
        if is_auth_failure(exc):  # refused: do not try again until the operator logs in by hand
            dev_state[PAUSE_KEY] = {"reason": str(exc)[:300], "since": dev_state["last_run"]}
            result.error += " — automatic logins to this device are now paused."
        save_state(state, state_path)
        return result
    try:
        if kind == "pfsense":
            _pull_pfsense(session, dev_state, folder, result)
        else:
            _pull_mikrotik(session, dev_state, folder, result)
        result.ok = True
    except Exception as exc:  # noqa: BLE001
        result.error = str(exc)
    finally:
        session.close()
    dev_state["last_run"] = datetime.now().isoformat(timespec="seconds")
    dev_state["last_result"] = "ok" if result.ok else f"error: {result.error[:200]}"
    save_state(state, state_path)
    return result


def _pull_pfsense(session: Session, dev_state: dict[str, Any], folder: Path, result: DeviceLogResult) -> None:
    cursors = {n: int((dev_state.get(n) or {}).get("offset", 0)) for n in PFSENSE_LOGS}
    out, err, status = session.run("/bin/sh -c " + shlex.quote(pfsense_script(cursors)))
    if status != 0 and MARK.encode() not in out:
        raise RuntimeError((err or f"exit {status}").strip()[:300])
    parsed = parse_pfsense(out)
    denied = tuple(n for n, v in parsed.items() if v[0] == "denied")
    if denied:  # root-only logs: sudo without a password, if this user may
        out2, _err2, _st2 = session.run(
            "sudo -n /bin/sh -c " + shlex.quote(pfsense_script(cursors, denied)))
        for name, val in parse_pfsense(out2).items():
            parsed[name] = val
    for name in PFSENSE_LOGS:
        if name not in parsed:
            continue
        status_, size, offset, data = parsed[name]
        if status_ == "denied":
            result.skipped.append(name)
            continue
        old = cursors.get(name, 0)
        rotated = offset == 0 and old > 0
        data = complete_lines(data)
        dev_state[name] = {"offset": offset + len(data), "size": size}
        if data:
            path = folder / f"{name}.log"
            _append(path, data)
            result.chunks.append(_chunk(name, path, data, rotated))


def _pull_mikrotik(session: Session, dev_state: dict[str, Any], folder: Path, result: DeviceLogResult) -> None:
    out, err, status = session.run("/log print without-paging")
    if status != 0 and not out:
        raise RuntimeError((err or f"exit {status}").strip()[:300])
    lines = clean_routeros(out.decode("utf-8", "replace"))
    saved = dev_state.get(MIKROTIK_LOG) or {}
    fresh = new_mikrotik_lines(lines, list(saved.get("tail") or []))
    dev_state[MIKROTIK_LOG] = {"tail": (lines[-TAIL_KEEP:] if lines else list(saved.get("tail") or []))}
    if fresh:
        data = ("\n".join(fresh) + "\n").encode("utf-8")
        path = folder / f"{MIKROTIK_LOG}.log"
        _append(path, data)
        result.chunks.append(_chunk(MIKROTIK_LOG, path, data))


# --------------------------------------------------------------------------- #
# PostgreSQL index

INDEX_TABLE = "device_log_downloads"


def record_index(results: list[DeviceLogResult]) -> tuple[bool, str]:
    """One row per downloaded chunk. (False, reason) when the database is not there."""
    rows = [
        (r.device, r.kind, c.log, c.path, c.bytes, c.lines, c.first_line, c.last_line, c.rotated, r.source)
        for r in results for c in r.chunks
    ]
    if not rows:
        return True, "nothing to index"
    try:
        from pfsense_checker import netcheck_schema
        from pfsense_checker import postgres_db as pg

        with pg.connect() as conn:
            netcheck_schema.ensure_schema(conn)
            with conn.cursor() as cur:
                cur.executemany(
                    f"INSERT INTO {INDEX_TABLE} (device, kind, log_name, local_path, bytes, lines, "
                    "first_line, last_line, rotated, source) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    rows,
                )
        return True, f"{len(rows)} indexed"
    except Exception as exc:  # noqa: BLE001 - files are kept regardless
        return False, str(exc)


def recent_index(limit: int = 200) -> list[tuple]:
    """Newest index rows: (downloaded_at, device, log_name, lines, bytes, source, local_path)."""
    from pfsense_checker import netcheck_schema
    from pfsense_checker import postgres_db as pg

    with pg.connect() as conn:
        netcheck_schema.ensure_schema(conn)
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT downloaded_at, device, log_name, lines, bytes, source, local_path "
                f"FROM {INDEX_TABLE} ORDER BY downloaded_at DESC LIMIT %s",
                (int(limit),),
            )
            return list(cur.fetchall())


def due(last_run_iso: str, hours: int, now: datetime | None = None) -> bool:
    """True when a scheduled run is due (never run, or older than *hours*)."""
    if not last_run_iso:
        return True
    try:
        last = datetime.fromisoformat(last_run_iso)
    except ValueError:
        return True
    return ((now or datetime.now()) - last).total_seconds() >= hours * 3600
