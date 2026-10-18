"""Tests for 1Password CLI helper — secrets must never appear on argv."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from pfsense_checker import onepassword as opw

CFG = opw.OnePasswordSettings(enabled=True, vault="", title_prefix="NetCheck")
SECRET = "s3cret-PASS!"


def _item_json(password: str = SECRET, username: str = "julian") -> dict:
    return {
        "id": "abc123",
        "title": "NetCheck - julian",
        "tags": ["NetCheck"],
        "fields": [
            {"id": "username", "type": "STRING", "purpose": "USERNAME", "value": username},
            {
                "id": "password",
                "type": "CONCEALED",
                "purpose": "PASSWORD",
                "value": password,
            },
        ],
    }


def test_item_title() -> None:
    assert opw.item_title("julian") == "NetCheck - julian"
    assert opw.item_title("julian", "Work") == "Work - julian"


def test_generate_password_classes() -> None:
    pw = opw.generate_password(20)
    assert len(pw) == 20
    assert any(c.islower() for c in pw)
    assert any(c.isupper() for c in pw)
    assert any(c.isdigit() for c in pw)
    assert any(c in "!@#$%^&*-_=+" for c in pw)
    assert len(opw.generate_password(4)) == 8  # floor at 8


def test_login_template_keeps_password_in_fields_only() -> None:
    blob = opw.login_template("NetCheck - julian", "julian", SECRET)
    dumped = json.dumps(blob)
    assert SECRET in dumped
    assert blob["title"] == "NetCheck - julian"
    assert blob["category"] == "LOGIN"
    assert "NetCheck" in blob["tags"]
    pw_fields = [
        f for f in blob["fields"] if f.get("purpose") == "PASSWORD"
    ]
    assert pw_fields[0]["value"] == SECRET
    assert SECRET not in blob["title"]


def test_save_login_creates_via_stdin_not_argv() -> None:
    captured: dict[str, object] = {}

    def fake_run(op_path, args, *, stdin=None, timeout=0, secrets=()):  # noqa: ANN001
        key = tuple(args[:2])
        if args[:2] == ["item", "get"]:
            return 1, "", "not found"
        if args[:2] == ["item", "list"]:
            return 0, "[]", ""
        if args[:2] == ["item", "create"]:
            captured["args"] = list(args)
            captured["stdin"] = stdin
            captured["op_path"] = op_path
            return 0, json.dumps({"id": "newid"}), ""
        return 1, "", f"unexpected {key}"

    with (
        patch.object(opw, "ensure_ready", return_value="op.exe"),
        patch.object(opw, "_run_op", side_effect=fake_run),
    ):
        title = opw.save_login("julian", SECRET, settings=CFG)

    assert title == "NetCheck - julian"
    args = captured["args"]
    assert isinstance(args, list)
    assert all(SECRET not in str(part) for part in args)
    payload = json.loads(str(captured["stdin"]))
    assert payload["fields"][1]["value"] == SECRET
    assert payload["category"] == "LOGIN"


def test_save_login_edits_existing_via_stdin() -> None:
    captured: dict[str, object] = {}
    item = _item_json("old-password")

    def fake_run(op_path, args, *, stdin=None, timeout=0, secrets=()):  # noqa: ANN001
        if args[:2] == ["item", "get"]:
            return 0, json.dumps(item), ""
        if args[:2] == ["item", "edit"]:
            captured["args"] = list(args)
            captured["stdin"] = stdin
            return 0, "{}", ""
        return 1, "", "unexpected"

    with (
        patch.object(opw, "ensure_ready", return_value="op.exe"),
        patch.object(opw, "_run_op", side_effect=fake_run),
    ):
        opw.save_login("julian", SECRET, settings=CFG)

    args = captured["args"]
    assert isinstance(args, list)
    assert "abc123" in args
    assert all(SECRET not in str(part) for part in args)
    payload = json.loads(str(captured["stdin"]))
    pw = next(f["value"] for f in payload["fields"] if f.get("purpose") == "PASSWORD")
    assert pw == SECRET


def test_load_login_parses_fields() -> None:
    def fake_run(op_path, args, *, stdin=None, timeout=0, secrets=()):  # noqa: ANN001
        if args[:2] == ["item", "get"]:
            return 0, json.dumps(_item_json()), ""
        return 1, "", "unexpected"

    with (
        patch.object(opw, "ensure_ready", return_value="op.exe"),
        patch.object(opw, "_run_op", side_effect=fake_run),
    ):
        secret = opw.load_login("julian", settings=CFG)

    assert secret is not None
    assert secret.username == "julian"
    assert secret.password == SECRET
    assert secret.item_id == "abc123"


def test_save_login_disabled() -> None:
    cfg = opw.OnePasswordSettings(enabled=False)
    with pytest.raises(opw.OnePasswordError, match="disabled"):
        opw.save_login("julian", SECRET, settings=cfg)


def test_run_op_refuses_password_on_argv() -> None:
    with pytest.raises(opw.OnePasswordError, match="command line"):
        opw._run_op(
            "op.exe",
            ["item", "edit", "id", f"password={SECRET}"],
            secrets=(SECRET,),
        )


def test_safe_error_redacts_password() -> None:
    text = opw._safe_error(f"failed: {SECRET} boom", (SECRET,))
    assert SECRET not in text
    assert "••••" in text


def test_humanize_desktop_disconnect() -> None:
    raw = (
        "[ERROR] 2026/09/25 10:46:08 connecting to desktop app: "
        "cannot connect to 1Password app, make sure it is running"
    )
    msg = opw.humanize_cli_error(raw, "")
    assert "2026/09/25" not in msg
    assert "desktop app" in msg.lower()
    assert "Integrate with 1Password CLI" in msg


def test_cli_error_strips_timestamp() -> None:
    raw = "[ERROR] 2026/09/25 10:46:08 item not found"
    assert opw._cli_error(raw, "") == "item not found"


def test_trusted_desktop_path() -> None:
    good = Path(r"C:\Users\julia\AppData\Local\Microsoft\WindowsApps\1Password.exe")
    assert opw._is_trusted_desktop_path(good) is True
    bad = Path(r"C:\Users\julia\Downloads\1Password.exe")
    assert opw._is_trusted_desktop_path(bad) is False
    cwd = Path("1Password.exe")
    assert opw._is_trusted_desktop_path(cwd) is False


def test_get_item_raises_on_desktop_disconnect() -> None:
    raw = (
        "connecting to desktop app: cannot connect to 1Password app, "
        "make sure it is running"
    )

    def fake_run(op_path, args, **kwargs):  # noqa: ANN001
        return 1, "", raw

    with patch.object(opw, "_run_op", side_effect=fake_run):
        with pytest.raises(opw.OnePasswordError, match="desktop app"):
            opw._get_item("op.exe", "NetCheck - julian", vault="")


def test_ensure_ready_starts_desktop_then_retries() -> None:
    calls = {"whoami": 0}

    def fake_run(op_path, args, **kwargs):  # noqa: ANN001
        if args[:1] == ["whoami"]:
            calls["whoami"] += 1
            if calls["whoami"] == 1:
                return (
                    1,
                    "",
                    "cannot connect to 1Password app, make sure it is running",
                )
            return 0, '{"email":"julian@example.com"}', ""
        return 1, "", "unexpected"

    with (
        patch.object(opw, "find_cli", return_value="op.exe"),
        patch.object(opw, "_run_op", side_effect=fake_run),
        patch.object(opw, "_ensure_desktop_app", return_value="started"),
        patch.object(opw.time, "sleep"),
    ):
        path = opw.ensure_ready()
    assert path == "op.exe"
    assert calls["whoami"] == 2


def test_ensure_ready_waits_for_unlock() -> None:
    calls = {"whoami": 0}

    def fake_run(op_path, args, **kwargs):  # noqa: ANN001
        if args[:1] == ["whoami"]:
            calls["whoami"] += 1
            if calls["whoami"] < 3:
                return 1, "", "account is not signed in"
            return 0, '{"email":"julian@example.com"}', ""
        return 1, "", "unexpected"

    with (
        patch.object(opw, "find_cli", return_value="op.exe"),
        patch.object(opw, "_run_op", side_effect=fake_run),
        patch.object(opw, "_foreground_desktop_app"),
        patch.object(opw.time, "sleep"),
    ):
        path = opw.ensure_ready()
    assert path == "op.exe"
    assert calls["whoami"] == 3


def test_humanize_not_signed_in() -> None:
    msg = opw.humanize_cli_error("account is not signed in", "")
    assert "locked" in msg.lower()
    assert "account is not signed in" not in msg.lower() or "Unlock" in msg


def test_cli_status_missing() -> None:
    with patch.object(opw, "find_cli", return_value=None):
        status = opw.cli_status()
    assert status.available is False
    assert status.ready is False
    assert "op" in status.error.lower()


def test_get_item_missing_returns_none() -> None:
    def fake_run(op_path, args, **kwargs):  # noqa: ANN001
        return 1, "", '"NetCheck - julian" isn\'t an item in the vault'

    with patch.object(opw, "_run_op", side_effect=fake_run):
        assert opw._get_item("op.exe", "NetCheck - julian", vault="") is None


def test_get_item_other_error_is_raised() -> None:
    def fake_run(op_path, args, **kwargs):  # noqa: ANN001
        return 1, "", "authorization has not been granted"

    with patch.object(opw, "_run_op", side_effect=fake_run):
        with pytest.raises(opw.OnePasswordError, match="Unlock"):
            opw._get_item("op.exe", "NetCheck - julian", vault="")


def test_allow_gui_does_not_hide_the_process_window() -> None:
    import subprocess
    import sys

    from pfsense_checker import winproc

    hidden = winproc.silent_run_kwargs()
    shown = winproc.silent_run_kwargs(allow_gui=True)
    if sys.platform != "win32":
        assert "startupinfo" not in shown
        return
    assert hidden["startupinfo"].wShowWindow == 0
    assert "startupinfo" not in shown
    no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    assert shown["creationflags"] & no_window
