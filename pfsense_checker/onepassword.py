"""1Password CLI helper for NetCheck sign-in credentials.

Uses the official ``op`` CLI with desktop-app integration. Passwords are
passed only through stdin JSON templates — never as command-line arguments,
and never written to logs.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import string
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pfsense_checker import app_log, winproc

TAG = "NetCheck"
DEFAULT_TITLE_PREFIX = "NetCheck"
LOGIN_URL = "netcheck://login"
_WHOAMI_TIMEOUT = 20
_ITEM_TIMEOUT = 120
_UNLOCK_WAIT_S = 90.0
_POLL_S = 1.5

_SETTINGS_ORG = "NetCheck"
_SETTINGS_APP = "PFSenseChecker"
_KEY_ENABLED = "onepassword/enabled"
_KEY_VAULT = "onepassword/vault"
_KEY_PREFIX = "onepassword/titlePrefix"

_CLI_CANDIDATES = (
    Path.home() / "AppData/Local/Microsoft/WinGet/Links/op.exe",
    Path(r"C:\Program Files\1Password CLI\op.exe"),
    Path(r"C:\Program Files (x86)\1Password CLI\op.exe"),
    Path.home() / "AppData/Local/1Password/app/8/op.exe",
)

_DESKTOP_NAMES = ("1Password.exe",)
_DESKTOP_IMAGE = "1Password.exe"
_DESKTOP_CONNECT_HINT = (
    "Cannot connect to the 1Password desktop app. Start and unlock 1Password, "
    "then confirm Settings → Developer → Integrate with 1Password CLI. "
    "If NetCheck is elevated (Run as administrator) and 1Password is not, "
    "Windows integrity levels block the CLI pipe — run both unelevated."
)
_UNLOCK_HINT = (
    "1Password launched but the account is locked. Unlock it "
    "(Windows Hello or master password), approve the CLI / NetCheck prompt "
    "if 1Password shows one, then click 1Password again if fill has not resumed."
)


class OnePasswordError(RuntimeError):
    """User-facing 1Password CLI failure (message must not contain secrets)."""


@dataclass(frozen=True)
class OnePasswordSettings:
    """Local preferences — no secrets."""

    enabled: bool = True
    vault: str = ""
    title_prefix: str = DEFAULT_TITLE_PREFIX


@dataclass(frozen=True)
class CliStatus:
    available: bool
    path: str = ""
    signed_in: bool = False
    account: str = ""
    error: str = ""

    @property
    def ready(self) -> bool:
        return self.available and self.signed_in


@dataclass(frozen=True)
class LoginSecret:
    username: str
    password: str
    item_id: str = ""
    title: str = ""


def item_title(username: str, prefix: str = DEFAULT_TITLE_PREFIX) -> str:
    """Stable 1Password item title for a NetCheck account."""
    name = (username or "").strip() or "user"
    base = (prefix or DEFAULT_TITLE_PREFIX).strip() or DEFAULT_TITLE_PREFIX
    return f"{base} - {name}"


def generate_password(length: int = 20) -> str:
    """Strong password suitable for NetCheck (min 8). Does not need the CLI."""
    n = max(8, int(length))
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*-_=+"
    alphabet = lower + upper + digits + symbols
    chars = [
        secrets.choice(lower),
        secrets.choice(upper),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]
    chars.extend(secrets.choice(alphabet) for _ in range(n - 4))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def find_cli() -> str | None:
    """Return the ``op`` executable path, or None if it is not installed."""
    for name in ("op", "op.exe"):
        found = shutil.which(name)
        if found:
            return found
    for candidate in _CLI_CANDIDATES:
        try:
            if candidate.is_file():
                return str(candidate)
        except OSError:
            continue
    winget = _winget_op()
    if winget is not None:
        return str(winget)
    return None


def find_desktop_app() -> str | None:
    """Return the 1Password desktop executable (Store alias or classic)."""
    for name in _DESKTOP_NAMES:
        found = shutil.which(name)
        if found and _is_trusted_desktop_path(Path(found)):
            return found
    home = Path.home()
    extras = (
        home / "AppData/Local/Microsoft/WindowsApps/1Password.exe",
        home / "AppData/Local/1Password/app/8/1Password.exe",
        Path(r"C:\Program Files\1Password\app\8\1Password.exe"),
        Path(r"C:\Program Files\1Password\1Password.exe"),
        Path(r"C:\Program Files (x86)\1Password\app\8\1Password.exe"),
    )
    for candidate in extras:
        try:
            if candidate.is_file() and _is_trusted_desktop_path(candidate):
                return str(candidate)
        except OSError:
            continue
    return None


def _winget_op() -> Path | None:
    root = Path.home() / "AppData/Local/Microsoft/WinGet/Packages"
    try:
        if not root.is_dir():
            return None
        for child in root.iterdir():
            if not child.is_dir():
                continue
            if not child.name.startswith("AgileBits.1Password.CLI"):
                continue
            candidate = child / "op.exe"
            if candidate.is_file():
                return candidate
    except OSError:
        return None
    return None


def _is_trusted_desktop_path(path: Path) -> bool:
    """Refuse to launch a random 1Password.exe from cwd or Downloads."""
    name = path.name.lower()
    if name != "1password.exe":
        return False
    text = str(path).replace("/", "\\").lower()
    allowed = (
        "\\windowsapps\\",
        "\\appdata\\local\\1password\\",
        "\\program files\\1password\\",
        "\\program files (x86)\\1password\\",
    )
    return any(part in text for part in allowed)


def _desktop_running() -> bool:
    result = winproc.run(
        [
            "tasklist",
            "/FI",
            f"IMAGENAME eq {_DESKTOP_IMAGE}",
            "/FO",
            "CSV",
            "/NH",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=8,
    )
    out = (result.stdout or "").lower()
    if "no tasks" in out:
        return False
    return _DESKTOP_IMAGE.lower() in out


def _ensure_desktop_app() -> str:
    """``running``, ``started``, or ``missing``."""
    if _desktop_running():
        return "running"
    path = find_desktop_app()
    if not path:
        return "missing"
    try:
        os.startfile(path)  # noqa: S606 — path is allowlisted 1Password.exe
    except OSError:
        return "missing"
    _log().info("Started 1Password desktop app")
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        if _desktop_running():
            time.sleep(1.5)
            return "started"
        time.sleep(0.4)
    return "started" if _desktop_running() else "missing"


def ensure_ready() -> str:
    """Return ``op`` path, starting the desktop app once if the CLI pipe is down."""
    path, _stdout = _ensure_ready()
    return path


def _foreground_desktop_app() -> None:
    """Bring the installed 1Password app forward so the user can unlock it."""
    path = find_desktop_app()
    if not path:
        return
    try:
        os.startfile(path)  # noqa: S606 — allowlisted 1Password.exe
    except OSError:
        return


def _ensure_ready() -> tuple[str, str]:
    """Start 1Password if needed and wait until ``op whoami`` is signed in.

    ``account is not signed in`` means the desktop app is up but locked.
    That is retryable — do not abort on the first locked response.
    """
    path = _require_cli()
    prompted = False
    stdout = ""
    stderr = ""
    deadline = time.monotonic() + _UNLOCK_WAIT_S
    while True:
        code, stdout, stderr = _run_op(
            path, ["whoami", "--format", "json"], timeout=_WHOAMI_TIMEOUT
        )
        if code == 0:
            _log().info("1Password CLI signed in")
            return path, stdout
        message = humanize_cli_error(stderr, stdout) or "1Password CLI failed."
        if not _is_retryable_cli(stderr, stdout):
            _log().warning("1Password CLI failed: %s", message)
            raise OnePasswordError(message)
        if not prompted:
            _log().warning("1Password CLI not ready: %s", message)
            if _is_desktop_disconnected(stderr, stdout):
                state = _ensure_desktop_app()
                if state == "missing":
                    raise OnePasswordError(
                        "1Password CLI is installed, but the desktop app is not "
                        "running and could not be started. Open 1Password from "
                        "the Start menu, unlock it, then try again."
                    )
            else:
                _foreground_desktop_app()
            prompted = True
        if time.monotonic() >= deadline:
            break
        time.sleep(_POLL_S)
    message = humanize_cli_error(stderr, stdout) or _UNLOCK_HINT
    _log().warning("1Password CLI still not ready: %s", message)
    raise OnePasswordError(message)


def load_settings() -> OnePasswordSettings:
    from PySide6.QtCore import QSettings

    qs = QSettings(_SETTINGS_ORG, _SETTINGS_APP)
    prefix = str(qs.value(_KEY_PREFIX, DEFAULT_TITLE_PREFIX) or DEFAULT_TITLE_PREFIX)
    enabled_raw = qs.value(_KEY_ENABLED, True)
    if isinstance(enabled_raw, str):
        enabled = enabled_raw.strip().lower() not in {"0", "false", "no"}
    else:
        enabled = bool(enabled_raw)
    return OnePasswordSettings(
        enabled=enabled,
        vault=str(qs.value(_KEY_VAULT, "") or "").strip(),
        title_prefix=prefix.strip() or DEFAULT_TITLE_PREFIX,
    )


def save_settings(settings: OnePasswordSettings) -> None:
    from PySide6.QtCore import QSettings

    qs = QSettings(_SETTINGS_ORG, _SETTINGS_APP)
    qs.setValue(_KEY_ENABLED, bool(settings.enabled))
    qs.setValue(_KEY_VAULT, (settings.vault or "").strip())
    qs.setValue(
        _KEY_PREFIX,
        (settings.title_prefix or DEFAULT_TITLE_PREFIX).strip() or DEFAULT_TITLE_PREFIX,
    )


def cli_status() -> CliStatus:
    """Probe CLI presence and whether desktop-app integration is signed in."""
    path = find_cli()
    if not path:
        return CliStatus(
            available=False,
            error=(
                "1Password CLI (op) was not found. Install it and enable "
                "Settings → Developer → Integrate with 1Password CLI."
            ),
        )
    try:
        path, stdout = _ensure_ready()
    except OnePasswordError as exc:
        return CliStatus(available=True, path=path, error=str(exc))
    account = _account_from_whoami(stdout)
    return CliStatus(available=True, path=path, signed_in=True, account=account)


def load_login(
    username: str = "",
    *,
    settings: OnePasswordSettings | None = None,
) -> LoginSecret | None:
    """Return the NetCheck login item for *username*, or None if missing."""
    cfg = settings or load_settings()
    if not cfg.enabled:
        raise OnePasswordError("1Password integration is disabled in Options.")
    path = ensure_ready()
    wanted = (username or "").strip()
    title = item_title(wanted, cfg.title_prefix) if wanted else ""
    if title:
        secret = _get_item(path, title, vault=cfg.vault)
        if secret is not None:
            return secret
    for item in _list_tagged_items(path, vault=cfg.vault):
        item_id = str(item.get("id") or "")
        item_title_text = str(item.get("title") or "")
        if wanted and item_title_text != item_title(wanted, cfg.title_prefix):
            # Still try the item — title prefix may have changed.
            if wanted.lower() not in item_title_text.lower():
                continue
        secret = _get_item(path, item_id or item_title_text, vault=cfg.vault)
        if secret is None:
            continue
        if not wanted or secret.username.lower() == wanted.lower():
            return secret
    if wanted:
        return None
    # No username: return the first tagged NetCheck login.
    for item in _list_tagged_items(path, vault=cfg.vault):
        item_id = str(item.get("id") or item.get("title") or "")
        secret = _get_item(path, item_id, vault=cfg.vault)
        if secret is not None:
            return secret
    return None


def save_login(
    username: str,
    password: str,
    *,
    settings: OnePasswordSettings | None = None,
) -> str:
    """Create or update the 1Password Login item. Returns the item title."""
    cfg = settings or load_settings()
    if not cfg.enabled:
        raise OnePasswordError("1Password integration is disabled in Options.")
    name = (username or "").strip()
    if not name:
        raise OnePasswordError("Username is required to save to 1Password.")
    if not password:
        raise OnePasswordError("Password is required to save to 1Password.")
    path = ensure_ready()
    title = item_title(name, cfg.title_prefix)
    existing = _get_item(path, title, vault=cfg.vault)
    if existing is None:
        for item in _list_tagged_items(path, vault=cfg.vault):
            item_id = str(item.get("id") or "")
            if not item_id:
                continue
            secret = _get_item(path, item_id, vault=cfg.vault)
            if secret and secret.username.lower() == name.lower():
                existing = secret
                break
    if existing and existing.item_id:
        _edit_login(path, existing.item_id, name, password, vault=cfg.vault)
    else:
        _create_login(path, title, name, password, vault=cfg.vault)
    _log().info("1Password login item saved title=%s user=%s", title, name)
    return title


def login_template(title: str, username: str, password: str) -> dict[str, Any]:
    """JSON template for ``op item create -`` (password only in field values)."""
    return {
        "title": title,
        "category": "LOGIN",
        "tags": [TAG],
        "urls": [{"label": "NetCheck", "primary": True, "href": LOGIN_URL}],
        "fields": [
            {
                "id": "username",
                "type": "STRING",
                "purpose": "USERNAME",
                "value": username,
            },
            {
                "id": "password",
                "type": "CONCEALED",
                "purpose": "PASSWORD",
                "value": password,
            },
        ],
    }


def _require_cli() -> str:
    path = find_cli()
    if not path:
        raise OnePasswordError(
            "1Password CLI (op) was not found. Install the CLI and enable "
            "Settings → Developer → Integrate with 1Password CLI in the app."
        )
    return path


def _account_from_whoami(stdout: str) -> str:
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return (stdout or "").strip()[:80]
    if not isinstance(data, dict):
        return ""
    email = str(data.get("email") or "").strip()
    url = str(data.get("url") or "").strip()
    if email and url:
        return f"{email} · {url}"
    return email or url


def _list_tagged_items(op_path: str, *, vault: str) -> list[dict[str, Any]]:
    args = [
        "item",
        "list",
        "--categories",
        "Login",
        "--tags",
        TAG,
        "--format",
        "json",
    ]
    _add_vault(args, vault)
    code, stdout, stderr = _run_op(op_path, args, timeout=_ITEM_TIMEOUT)
    if code != 0:
        # An empty vault is often "no items" rather than a hard failure.
        err = _cli_error(stderr, stdout).lower()
        if "not found" in err or "no items" in err:
            return []
        raise OnePasswordError(
            humanize_cli_error(stderr, stdout) or "Could not list 1Password items."
        )
    try:
        data = json.loads(stdout or "[]")
    except json.JSONDecodeError as exc:
        raise OnePasswordError("1Password returned invalid JSON.") from exc
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    return []


def _item_missing(stderr: str, stdout: str) -> bool:
    """True when ``op item get`` failed because the item is not in the vault."""
    err = _cli_error(stderr, stdout).lower()
    needles = (
        "isn't an item",
        "is not an item",
        "not found",
        "could not find item",
        "no such item",
    )
    return any(needle in err for needle in needles)


def _get_item(op_path: str, spec: str, *, vault: str) -> LoginSecret | None:
    if not (spec or "").strip():
        return None
    args = ["item", "get", spec, "--format", "json", "--reveal"]
    _add_vault(args, vault)
    code, stdout, stderr = _run_op(op_path, args, timeout=_ITEM_TIMEOUT)
    if code != 0:
        if _item_missing(stderr, stdout):
            return None
        message = humanize_cli_error(stderr, stdout) or "Could not read the 1Password item."
        _log().warning("1Password item get failed: %s", message)
        raise OnePasswordError(message)
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError as exc:
        raise OnePasswordError("1Password returned invalid JSON.") from exc
    if not isinstance(data, dict):
        raise OnePasswordError("1Password returned an unexpected item payload.")
    return _secret_from_item(data)


def _secret_from_item(data: dict[str, Any]) -> LoginSecret | None:
    username = ""
    password = ""
    for field in data.get("fields") or []:
        if not isinstance(field, dict):
            continue
        purpose = str(field.get("purpose") or "").upper()
        field_id = str(field.get("id") or "").lower()
        value = field.get("value")
        if value is None:
            continue
        text = str(value)
        if purpose == "USERNAME" or field_id == "username":
            username = text
        elif purpose == "PASSWORD" or field_id == "password":
            password = text
    if not password:
        return None
    return LoginSecret(
        username=username,
        password=password,
        item_id=str(data.get("id") or ""),
        title=str(data.get("title") or ""),
    )


def _create_login(
    op_path: str, title: str, username: str, password: str, *, vault: str
) -> None:
    args = ["item", "create", "-", "--format", "json"]
    _add_vault(args, vault)
    payload = json.dumps(login_template(title, username, password))
    code, stdout, stderr = _run_op(
        op_path, args, stdin=payload, timeout=_ITEM_TIMEOUT, secrets=(password,)
    )
    if code != 0:
        raise OnePasswordError(
            _safe_error(
                humanize_cli_error(stderr, stdout) or "Could not create 1Password item.",
                (password,),
            )
        )


def _edit_login(
    op_path: str, item_id: str, username: str, password: str, *, vault: str
) -> None:
    # Fetch full JSON so we preserve notes/URLs while updating username/password.
    args = ["item", "get", item_id, "--format", "json", "--reveal"]
    _add_vault(args, vault)
    code, stdout, stderr = _run_op(
        op_path, args, timeout=_ITEM_TIMEOUT, secrets=(password,)
    )
    if code != 0 or not stdout.strip():
        raise OnePasswordError(
            humanize_cli_error(stderr, stdout) or "Could not read 1Password item to update."
        )
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise OnePasswordError("1Password returned invalid JSON.") from exc
    if not isinstance(data, dict):
        raise OnePasswordError("1Password item JSON was not an object.")
    fields = data.get("fields")
    if not isinstance(fields, list):
        fields = []
        data["fields"] = fields
    saw_user = False
    saw_pw = False
    for field in fields:
        if not isinstance(field, dict):
            continue
        purpose = str(field.get("purpose") or "").upper()
        field_id = str(field.get("id") or "").lower()
        if purpose == "USERNAME" or field_id == "username":
            field["value"] = username
            saw_user = True
        elif purpose == "PASSWORD" or field_id == "password":
            field["value"] = password
            saw_pw = True
    if not saw_user:
        fields.append(
            {
                "id": "username",
                "type": "STRING",
                "purpose": "USERNAME",
                "value": username,
            }
        )
    if not saw_pw:
        fields.append(
            {
                "id": "password",
                "type": "CONCEALED",
                "purpose": "PASSWORD",
                "value": password,
            }
        )
    data["tags"] = sorted(
        {*(str(t) for t in (data.get("tags") or []) if t), TAG}
    )
    edit_args = ["item", "edit", item_id, "--format", "json"]
    _add_vault(edit_args, vault)
    payload = json.dumps(data)
    code, stdout, stderr = _run_op(
        op_path,
        edit_args,
        stdin=payload,
        timeout=_ITEM_TIMEOUT,
        secrets=(password,),
    )
    if code != 0:
        raise OnePasswordError(
            _safe_error(
                humanize_cli_error(stderr, stdout) or "Could not update 1Password item.",
                (password,),
            )
        )


def _add_vault(args: list[str], vault: str) -> None:
    name = (vault or "").strip()
    if name:
        args.extend(["--vault", name])


def _run_op(
    op_path: str,
    args: list[str],
    *,
    stdin: str | None = None,
    timeout: int = _ITEM_TIMEOUT,
    secrets: tuple[str, ...] = (),
) -> tuple[int, str, str]:
    cmd = [op_path, *args]
    _assert_no_secrets_in_argv(cmd, secrets)
    try:
        result = winproc.run(
            cmd,
            input=stdin,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            allow_gui=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise OnePasswordError(
            "1Password timed out. Unlock the 1Password app and try again."
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise OnePasswordError(_safe_error(str(exc), secrets)) from exc
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    return int(result.returncode), stdout, stderr


def _assert_no_secrets_in_argv(cmd: list[str], secrets_in: tuple[str, ...]) -> None:
    for secret in secrets_in:
        if not secret:
            continue
        for part in cmd:
            if secret in part:
                raise OnePasswordError(
                    "Refusing to pass a password on the 1Password command line."
                )


def _is_desktop_disconnected(stderr: str, stdout: str) -> bool:
    text = f"{stderr}\n{stdout}".lower()
    return "cannot connect to 1password app" in text or (
        "connecting to desktop app" in text and "make sure it is running" in text
    )


def _is_locked_or_unsigned(stderr: str, stdout: str) -> bool:
    text = f"{stderr}\n{stdout}".lower()
    needles = (
        "account is not signed in",
        "not currently signed in",
        "please sign in",
        "authorization has not been granted",
        "app is locked",
        "vault is locked",
    )
    return any(n in text for n in needles)


def _is_retryable_cli(stderr: str, stdout: str) -> bool:
    return _is_desktop_disconnected(stderr, stdout) or _is_locked_or_unsigned(
        stderr, stdout
    )


def humanize_cli_error(stderr: str, stdout: str = "") -> str:
    """Turn raw ``op`` log lines into a short operator-facing message."""
    if _is_desktop_disconnected(stderr, stdout):
        return _DESKTOP_CONNECT_HINT
    if _is_locked_or_unsigned(stderr, stdout):
        return _UNLOCK_HINT
    return _cli_error(stderr, stdout)


def _cli_error(stderr: str, stdout: str) -> str:
    text = (stderr or stdout or "").strip()
    if not text:
        return ""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    last = lines[-1] if lines else text
    last = re.sub(r"^\[(?:ERROR|WARN|INFO)\]\s+", "", last)
    last = re.sub(r"^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+", "", last)
    return last[:400]


def _safe_error(text: str, secrets_in: tuple[str, ...]) -> str:
    out = text or ""
    for secret in secrets_in:
        if secret and secret in out:
            out = out.replace(secret, "••••")
    return out


def _log():
    return app_log.get_logger("onepassword")
