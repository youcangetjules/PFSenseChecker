"""Automatic router log downloads: only new data each run, dated files, cursors, sudo fallback."""

from __future__ import annotations

import re
from datetime import datetime

from pfsense_checker import device_logs as dl
from pfsense_checker.topology_site import Device, SshAccess


class FakePfSense:
    """Pretends to be /var/log on a pfSense box; runs the real script's logic."""

    def __init__(self, files: dict[str, bytes], root_only: tuple[str, ...] = (), sudo: bool = True) -> None:
        self.files = files
        self.root_only = root_only
        self.sudo = sudo
        self.commands: list[str] = []
        self.closed = False

    def run(self, command: str) -> tuple[bytes, str, int]:
        self.commands.append(command)
        as_root = command.startswith("sudo -n ")
        if as_root and not self.sudo:
            return b"", "sudo: a password is required", 1
        out = b""
        for name, off in re.findall(r"/var/log/(\w+)\.log \]; then sz=\S+ [^;]*; o=(\d+);", command):
            if name not in self.files:
                continue
            if name in self.root_only and not as_root:
                out += f"{dl.MARK} {name} DENIED 0\n".encode()
                continue
            data = self.files[name]
            o = int(off)
            if len(data) < o:
                o = 0
            out += f"{dl.MARK} {name} {len(data)} {o}\n".encode() + data[o : o + dl.MAX_BYTES_PER_LOG] + b"\n"
        return out, "", 0

    def close(self) -> None:
        self.closed = True


def _pf() -> Device:
    return Device(name="guardian", kind="pfsense", ssh=SshAccess(host="10.0.0.1", username="admin"))


def test_pfsense_pulls_only_new_bytes_and_whole_lines(tmp_path) -> None:
    box = FakePfSense({"system": b"a 1\nb 2\n", "filter": b"block x\npartial"})
    when = datetime(2026, 11, 9, 9, 0)
    kw = dict(root=tmp_path, state_path=tmp_path / "state.json", session_factory=lambda d, **k: box, now=when)
    r1 = dl.download_device_logs(_pf(), **kw)
    assert r1.ok and box.closed
    assert {c.log: c.lines for c in r1.chunks} == {"system": 2, "filter": 1}  # "partial" waits
    folder = tmp_path / "guardian" / "2026-11-09"
    assert (folder / "filter.log").read_bytes() == b"block x\n"
    box.files["system"] += b"c 3\n"
    box.files["filter"] += b" now done\n"
    r2 = dl.download_device_logs(_pf(), **kw)
    assert {c.log: c.lines for c in r2.chunks} == {"system": 1, "filter": 1}
    assert (folder / "system.log").read_bytes() == b"a 1\nb 2\nc 3\n"
    assert (folder / "filter.log").read_bytes() == b"block x\npartial now done\n"
    r3 = dl.download_device_logs(_pf(), **kw)
    assert r3.ok and not r3.chunks and r3.summary() == "guardian: nothing new"


def test_rotated_log_is_read_from_the_start(tmp_path) -> None:
    box = FakePfSense({"system": b"old line one\nold line two\n"})
    kw = dict(root=tmp_path, state_path=tmp_path / "state.json", session_factory=lambda d, **k: box)
    dl.download_device_logs(_pf(), **kw)
    box.files["system"] = b"new\n"  # rotated: smaller than our cursor
    r = dl.download_device_logs(_pf(), **kw)
    assert r.chunks[0].rotated and r.chunks[0].lines == 1


def test_root_only_logs_use_sudo_n_or_are_skipped(tmp_path) -> None:
    box = FakePfSense({"system": b"s\n", "filter": b"f\n"}, root_only=("filter",))
    kw = dict(root=tmp_path, state_path=tmp_path / "state.json", session_factory=lambda d, **k: box)
    r = dl.download_device_logs(_pf(), **kw)
    assert {c.log for c in r.chunks} == {"system", "filter"}
    assert box.commands[1].startswith("sudo -n /bin/sh -c ") and "password" not in box.commands[1].lower()
    nosudo = FakePfSense({"system": b"s\n", "filter": b"f\n"}, root_only=("filter",), sudo=False)
    r2 = dl.download_device_logs(_pf(), root=tmp_path / "b", state_path=tmp_path / "b.json",
                                 session_factory=lambda d, **k: nosudo)
    assert r2.ok and r2.skipped == ["filter"]


class FakeMikroTik:
    def __init__(self, lines: list[str]) -> None:
        self.lines = lines

    def run(self, command: str) -> tuple[bytes, str, int]:
        assert command == "/log print without-paging"
        return ("\r\n".join(self.lines) + "\r\n").encode(), "", 0

    def close(self) -> None:
        pass


def test_mikrotik_appends_lines_after_the_last_saved(tmp_path) -> None:
    dev = Device(name="crs328", kind="mikrotik", ssh=SshAccess(host="10.0.0.5", username="admin"))
    box = FakeMikroTik(["10:00:00 system,info boot", "10:01:00 dhcp,info lease 1"])
    kw = dict(root=tmp_path, state_path=tmp_path / "state.json", session_factory=lambda d, **k: box)
    assert dl.download_device_logs(dev, **kw).chunks[0].lines == 2
    box.lines = box.lines[1:] + ["10:02:00 dhcp,info lease 2", "10:03:00 system,info admin logged in"]
    r = dl.download_device_logs(dev, **kw)
    assert r.chunks[0].lines == 2
    text = next((tmp_path / "crs328").rglob("log.log")).read_text(encoding="utf-8")
    assert text.splitlines() == ["10:00:00 system,info boot", "10:01:00 dhcp,info lease 1",
                                 "10:02:00 dhcp,info lease 2", "10:03:00 system,info admin logged in"]


def test_login_failure_is_reported_and_state_kept(tmp_path) -> None:
    def refuse(_d, **_k):  # noqa: ANN001, ANN003, ANN202
        raise PermissionError("Authentication failed")

    r = dl.download_device_logs(_pf(), root=tmp_path, state_path=tmp_path / "s.json", session_factory=refuse)
    assert not r.ok and "Authentication failed" in r.error


def test_eligible_devices_and_schedule() -> None:
    assert dl.eligible(_pf())
    assert not dl.eligible(Device(name="sw", kind="netgear", ssh=SshAccess(host="1.2.3.4", username="a")))
    assert not dl.eligible(Device(name="x", kind="mikrotik"))  # no SSH set up
    ignored = _pf()
    ignored.ignored = True
    assert not dl.eligible(ignored)
    now = datetime(2026, 11, 9, 12, 0)
    assert dl.due("", 6, now) and dl.due("2026-11-09T05:59:00", 6, now)
    assert not dl.due("2026-11-09T07:00:00", 6, now)


def test_settings_round_trip(tmp_path) -> None:
    p = tmp_path / "settings.json"
    assert dl.load_settings(p) == dl.LogSettings()
    dl.save_settings(dl.LogSettings(enabled=False, hours=500, on_connect=False), p)
    assert dl.load_settings(p) == dl.LogSettings(enabled=False, hours=168, on_connect=False)


def test_script_is_one_shell_command_with_markers() -> None:
    script = dl.pfsense_script({"system": 120})
    assert "o=120" in script and "/var/log/filter.log" in script and dl.MARK in script
    parsed = dl.parse_pfsense(f"{dl.MARK} system 10 4\nabc\n\n{dl.MARK} auth DENIED 0\n".encode())
    assert parsed["system"] == ("ok", 10, 4, b"abc\n") and parsed["auth"][0] == "denied"
