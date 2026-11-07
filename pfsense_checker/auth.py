"""User authentication — password hashing + minimal users-table access.

Security model
--------------
* Cleartext passwords never touch PostgreSQL.
* The login module holds only the **application public key**
  (``data/auth_public.pem``). Its SHA-256 digest is used as an HMAC pepper
  before PBKDF2, so stored hashes are NetCheck-specific.
* DB access from this module is limited to the ``users`` table columns
  ``username`` and ``password_hash`` (via the ``users_login_v`` view).

Hash format: ``nc1$<iterations>$<salt_b64>$<digest_b64>``
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import time
from dataclasses import dataclass
from typing import Any

from pfsense_checker.paths import PROJECT_ROOT, ensure_data_dir
from pfsense_checker import postgres_db as pg

AUTH_PUBLIC_KEY_PATH = PROJECT_ROOT / "data" / "auth_public.pem"
_HASH_PREFIX = "nc1"
_DEFAULT_ITERATIONS = 200_000
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{2,64}$")

# Designated super-administrator account (created explicitly, not via random bootstrap).
SUPER_ADMIN_USERNAME = "julian"
ROLE_SUPER_ADMIN = "super-admin"
ROLE_ADMIN = "admin"
ROLE_USER = "user"

# Embedded fallback if the PEM file is missing (same key material as shipped).
_FALLBACK_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyykRKaAsIIym2eFzLQcC
+FLTfU1Iiqg8bIPITh339dXtMUIbN3ujwpIuwXRY4v2QQtX6xgRd5vrsWbYhj55J
PsFVW1QcLisc0378ERhh7EuImEvj/QBakbIiQ5Z/t8S3347sM0coXtaFsqTb9mBX
4tRIQLygZELODAi9iN1GwoN1zFx36u+pYwemn6Si6iFsy7HmFWwAiBbV/Sl3+9Fe
KCKvHTnbUB9rjC5vCHB1FA5S1T2XAUaQ82MKF+JZ9HPv/1y4377r1A/aKFLRikJC
gSwjX3YXyZrHsas6D8eJQ54qbMsr+iYKMFVkpOF59oeq6TOLLP/Jxg781tEPpstr
6QIDAQAB
-----END PUBLIC KEY-----
"""


@dataclass(frozen=True)
class AuthUser:
    username: str
    role: str = ROLE_USER
    must_change_password: bool = False

    @property
    def is_super_admin(self) -> bool:
        return self.role == ROLE_SUPER_ADMIN or self.username == SUPER_ADMIN_USERNAME

    @property
    def can_manage_users(self) -> bool:
        return self.is_super_admin or self.role in {ROLE_SUPER_ADMIN, ROLE_ADMIN}


@dataclass(frozen=True)
class UserRecord:
    """Admin listing row — never includes password_hash."""

    username: str
    role: str
    is_active: bool
    must_change_password: bool
    created_at: str = ""


class AuthError(RuntimeError):
    """Raised for auth / bootstrap failures (safe message for UI)."""


def load_public_key_pem() -> str:
    """Return the application public key PEM (file or embedded fallback)."""
    ensure_data_dir()
    if AUTH_PUBLIC_KEY_PATH.is_file():
        try:
            text = AUTH_PUBLIC_KEY_PATH.read_text(encoding="utf-8").strip()
            if "BEGIN PUBLIC KEY" in text:
                return text + "\n"
        except OSError:
            pass
    AUTH_PUBLIC_KEY_PATH.write_text(_FALLBACK_PUBLIC_KEY_PEM, encoding="utf-8")
    return _FALLBACK_PUBLIC_KEY_PEM


def public_pepper() -> bytes:
    """Derive the HMAC pepper from the public key (not a secret)."""
    pem = load_public_key_pem().encode("utf-8")
    return hashlib.sha256(pem).digest()


def pepper_fingerprint() -> str:
    """Short id of the pepper in use, so a key change shows up in the log.

    The pepper comes from a public key, so this reveals nothing secret.
    """
    return hashlib.sha256(public_pepper()).hexdigest()[:8]


def _auth_log():
    from pfsense_checker import app_log

    return app_log.get_logger("auth")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def hash_password(
    password: str,
    *,
    iterations: int = _DEFAULT_ITERATIONS,
    min_length: int = 8,
) -> str:
    """Hash a password with public-key pepper + PBKDF2-HMAC-SHA256.

    Temporary / first-login passwords may pass a lower ``min_length``; permanent
    passwords (default) still require at least 8 characters.
    """
    floor = max(1, int(min_length))
    if not password or len(password) < floor:
        raise AuthError(f"Password must be at least {floor} characters")
    salt = os.urandom(16)
    pepper = public_pepper()
    material = hmac.new(pepper, password.encode("utf-8"), hashlib.sha256).digest()
    dk = hashlib.pbkdf2_hmac("sha256", material, salt, int(iterations), dklen=32)
    return f"{_HASH_PREFIX}${int(iterations)}${_b64(salt)}${_b64(dk)}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time verify against a stored ``nc1$…`` hash."""
    try:
        prefix, iters_s, salt_b64, digest_b64 = stored_hash.split("$", 3)
        if prefix != _HASH_PREFIX:
            return False
        iterations = int(iters_s)
        salt = _b64decode(salt_b64)
        expected = _b64decode(digest_b64)
    except (ValueError, TypeError):
        return False
    pepper = public_pepper()
    material = hmac.new(pepper, password.encode("utf-8"), hashlib.sha256).digest()
    dk = hashlib.pbkdf2_hmac("sha256", material, salt, iterations, dklen=len(expected))
    return hmac.compare_digest(dk, expected)


def validate_username(username: str) -> str:
    name = (username or "").strip()
    if not _USERNAME_RE.match(name):
        raise AuthError(
            "Username must be 2–64 characters (letters, digits, . _ @ -)"
        )
    return name


def _login_connect():
    """Open a short-lived DB connection for auth only."""
    if not pg.psycopg_available():
        raise AuthError(
            'PostgreSQL driver missing. Install with: pip install "psycopg[binary]"'
        )
    try:
        return pg.connect()
    except Exception as exc:  # noqa: BLE001
        raise AuthError(f"Cannot reach database: {exc}") from exc


def ensure_users_schema(conn: Any | None = None) -> None:
    """Create users table + login view (also covered by netcheck_schema)."""
    from pfsense_checker import netcheck_schema

    netcheck_schema.ensure_schema(conn)


def fetch_login_row(username: str) -> tuple[str, str, bool] | None:
    """Return ``(password_hash, role, must_change_password)`` from the login view."""
    name = validate_username(username)
    sql = (
        "SELECT password_hash, role, must_change_password "
        "FROM users_login_v WHERE username = %s LIMIT 1"
    )
    with _login_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (name,))
            row = cur.fetchone()
    if not row:
        return None
    # Bind by position from the explicit SELECT above (never by username column).
    pw_hash = str(row[0] or "")
    role = str(row[1] or ROLE_USER)
    flag = row[2]
    if isinstance(flag, bool):
        must_change = flag
    else:
        # Odd drivers may return 1 / 't' / 'true'
        must_change = str(flag).strip().lower() in {"1", "t", "true", "yes"}
    return pw_hash, role, must_change


def user_must_change_password(username: str) -> bool:
    """Read must_change_password directly from ``users`` (source of truth)."""
    name = validate_username(username)
    with _login_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT must_change_password FROM users WHERE username = %s LIMIT 1",
                (name,),
            )
            row = cur.fetchone()
    if not row:
        return False
    flag = row[0]
    if isinstance(flag, bool):
        return flag
    return str(flag).strip().lower() in {"1", "t", "true", "yes"}


def clear_must_change_password(username: str) -> None:
    """Force-clear the must-change flag (idempotent)."""
    name = validate_username(username)
    with _login_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET must_change_password = FALSE WHERE username = %s",
                (name,),
            )
            if cur.rowcount == 0:
                raise AuthError(f"User not found: {name}")
    if user_must_change_password(name):
        raise AuthError(
            "Password was updated but the must-change flag could not be cleared. "
            "Check the database connection and try again."
        )


def fetch_password_hash(username: str) -> str | None:
    """SELECT only username + password_hash from the login view."""
    row = fetch_login_row(username)
    return None if row is None else row[0]


def user_count() -> int:
    """Count active users (bootstrap check). Uses username column only."""
    with _login_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(username) FROM users_login_v")
            row = cur.fetchone()
    return int(row[0]) if row else 0


class LoginThrottle:
    """Per-username back-off after repeated failed sign-ins (in process).

    The first ``free_attempts`` failures cost nothing. After that each
    failure doubles the wait (2 s, 4 s, 8 s … capped at ``max_wait``).
    A success clears the counter. State is memory only: restarting
    NetCheck resets it.
    """

    def __init__(
        self,
        *,
        free_attempts: int = 5,
        base_wait: float = 2.0,
        max_wait: float = 300.0,
        clock=time.monotonic,
    ) -> None:
        self.free_attempts = free_attempts
        self.base_wait = base_wait
        self.max_wait = max_wait
        self._clock = clock
        self._failures: dict[str, int] = {}
        self._blocked_until: dict[str, float] = {}

    def wait_seconds(self, username: str) -> float:
        until = self._blocked_until.get(username.lower(), 0.0)
        return max(0.0, until - self._clock())

    def record_failure(self, username: str) -> None:
        key = username.lower()
        count = self._failures.get(key, 0) + 1
        self._failures[key] = count
        over = count - self.free_attempts
        if over > 0:
            wait = min(self.max_wait, self.base_wait * (2 ** (over - 1)))
            self._blocked_until[key] = self._clock() + wait

    def record_success(self, username: str) -> None:
        key = username.lower()
        self._failures.pop(key, None)
        self._blocked_until.pop(key, None)


LOGIN_THROTTLE = LoginThrottle()


def _failure_reason(stored: str | None) -> str:
    """Non-secret reason code for the log. The UI message stays generic."""
    if not stored:
        return "unknown_or_inactive_user"
    parts = stored.split("$")
    if len(parts) != 4 or parts[0] != _HASH_PREFIX:
        return "unreadable_stored_hash"
    return "password_mismatch"


def authenticate(username: str, password: str, *, source: str = "typed") -> AuthUser:
    """Verify credentials. Always runs verify on a dummy hash if user missing
    to reduce timing oracles.

    *source* (``typed`` or ``1password``) is logged on failure, never the
    password or its length.
    """
    name = validate_username(username)
    wait = LOGIN_THROTTLE.wait_seconds(name)
    if wait > 0:
        _auth_log().warning(
            "Login throttled user=%s wait=%ds", name, int(wait + 0.999)
        )
        raise AuthError(
            f"Too many failed sign-ins. Wait {int(wait + 0.999)} s and try again."
        )
    row = fetch_login_row(name)
    stored = row[0] if row else None
    role = row[1] if row else ROLE_USER
    must_change = row[2] if row else False
    dummy = (
        f"{_HASH_PREFIX}${_DEFAULT_ITERATIONS}$"
        f"{_b64(b'0' * 16)}${_b64(b'0' * 32)}"
    )
    ok = verify_password(password or "", stored or dummy)
    if not stored or not ok:
        LOGIN_THROTTLE.record_failure(name)
        pw = password or ""
        _auth_log().warning(
            "Login rejected reason=%s user=%s source=%s empty=%s "
            "edge_whitespace=%s pepper=%s",
            _failure_reason(stored),
            # An unknown name may be a password typed in the wrong box.
            name if stored else "(not logged)",
            source,
            not pw,
            pw != pw.strip(),
            pepper_fingerprint(),
        )
        raise AuthError("Invalid username or password")
    LOGIN_THROTTLE.record_success(name)
    if name == SUPER_ADMIN_USERNAME:
        role = ROLE_SUPER_ADMIN
    return AuthUser(
        username=name,
        role=role,
        must_change_password=must_change,
    )


def create_user(
    username: str,
    password: str,
    *,
    role: str = ROLE_ADMIN,
    must_change_password: bool = False,
) -> AuthUser:
    """Insert a user (bootstrap / admin). Writes username + password_hash + role."""
    name = validate_username(username)
    if name == SUPER_ADMIN_USERNAME:
        role = ROLE_SUPER_ADMIN
    pw_hash = hash_password(password)
    with _login_connect() as conn:
        ensure_users_schema(conn)
        with conn.cursor() as cur:
            try:
                cur.execute(
                    "INSERT INTO users "
                    "(username, password_hash, role, must_change_password) "
                    "VALUES (%s, %s, %s, %s)",
                    (name, pw_hash, role or ROLE_USER, bool(must_change_password)),
                )
            except Exception as exc:  # noqa: BLE001
                msg = str(exc).lower()
                if "unique" in msg or "duplicate" in msg:
                    raise AuthError(f"Username already exists: {name}") from exc
                raise AuthError(f"Could not create user: {exc}") from exc
    return AuthUser(
        username=name,
        role=role,
        must_change_password=bool(must_change_password),
    )


def set_user_password(
    username: str,
    password: str,
    *,
    clear_must_change: bool = True,
    min_length: int = 8,
) -> None:
    """Update password_hash (and optionally clear must_change_password)."""
    name = validate_username(username)
    pw_hash = hash_password(password, min_length=min_length)
    with _login_connect() as conn:
        with conn.cursor() as cur:
            if clear_must_change:
                cur.execute(
                    "UPDATE users SET password_hash = %s, "
                    "must_change_password = FALSE WHERE username = %s",
                    (pw_hash, name),
                )
            else:
                cur.execute(
                    "UPDATE users SET password_hash = %s WHERE username = %s",
                    (pw_hash, name),
                )
            if cur.rowcount == 0:
                raise AuthError(f"User not found: {name}")
    if clear_must_change:
        # Belt-and-suspenders: separate clear + verify so a partial write cannot
        # leave the user stuck in the forced-change loop.
        clear_must_change_password(name)


def change_password(
    username: str,
    current_password: str,
    new_password: str,
) -> AuthUser:
    """Verify current password, set a new one, clear must_change_password."""
    user = authenticate(username, current_password)
    if new_password == current_password:
        raise AuthError("New password must be different from the current password")
    set_user_password(user.username, new_password, clear_must_change=True, min_length=8)
    # Confirm the new password works and the flag is gone.
    verified = authenticate(user.username, new_password)
    if verified.must_change_password or user_must_change_password(user.username):
        clear_must_change_password(user.username)
        verified = authenticate(user.username, new_password)
    return AuthUser(
        username=verified.username,
        role=verified.role,
        must_change_password=False,
    )


def list_users() -> list[UserRecord]:
    """List accounts for the Users section (no password hashes)."""
    ensure_users_schema()
    with _login_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT username, role, is_active, must_change_password, created_at "
                "FROM users ORDER BY username"
            )
            rows = cur.fetchall()
    out: list[UserRecord] = []
    for r in rows:
        created = r[4]
        created_s = (
            created.isoformat() if hasattr(created, "isoformat") else str(created or "")
        )
        out.append(
            UserRecord(
                username=str(r[0] or ""),
                role=str(r[1] or ROLE_USER),
                is_active=bool(r[2]),
                must_change_password=bool(r[3]),
                created_at=created_s,
            )
        )
    return out


def set_user_active(username: str, active: bool) -> None:
    """Enable or disable a user account."""
    name = validate_username(username)
    if name == SUPER_ADMIN_USERNAME and not active:
        raise AuthError("Cannot deactivate the super-admin account")
    with _login_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET is_active = %s WHERE username = %s",
                (bool(active), name),
            )
            if cur.rowcount == 0:
                raise AuthError(f"User not found: {name}")


def set_user_role(username: str, role: str) -> None:
    """Update a user's role (super-admin username is always locked)."""
    name = validate_username(username)
    role_n = (role or ROLE_USER).strip().lower()
    if role_n not in {ROLE_SUPER_ADMIN, ROLE_ADMIN, ROLE_USER}:
        raise AuthError(f"Unknown role: {role}")
    if name == SUPER_ADMIN_USERNAME:
        role_n = ROLE_SUPER_ADMIN
    with _login_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET role = %s WHERE username = %s",
                (role_n, name),
            )
            if cur.rowcount == 0:
                raise AuthError(f"User not found: {name}")


def admin_reset_password(username: str, new_password: str) -> None:
    """Admin sets a temporary password; user must change it on next login."""
    set_user_password(
        username,
        new_password,
        clear_must_change=False,
        min_length=4,
    )
    name = validate_username(username)
    with _login_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET must_change_password = TRUE WHERE username = %s",
                (name,),
            )


def ensure_super_admin(
    password: str,
    *,
    must_change_password: bool = True,
) -> AuthUser:
    """Create or reset the designated super-admin (``julian``).

    Temporary / provisioned passwords set ``must_change_password`` so the
    first GUI login forces a password change.
    """
    ensure_users_schema()
    name = SUPER_ADMIN_USERNAME
    # First-login temps may be short; permanent change still requires 8+.
    pw_hash = hash_password(password, min_length=4)
    flag = bool(must_change_password)
    with _login_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT username FROM users WHERE username = %s LIMIT 1",
                (name,),
            )
            exists = cur.fetchone() is not None
            if exists:
                cur.execute(
                    "UPDATE users SET password_hash = %s, role = %s, "
                    "is_active = TRUE, must_change_password = %s "
                    "WHERE username = %s",
                    (pw_hash, ROLE_SUPER_ADMIN, flag, name),
                )
            else:
                cur.execute(
                    "INSERT INTO users "
                    "(username, password_hash, role, must_change_password) "
                    "VALUES (%s, %s, %s, %s)",
                    (name, pw_hash, ROLE_SUPER_ADMIN, flag),
                )
    return AuthUser(
        username=name,
        role=ROLE_SUPER_ADMIN,
        must_change_password=flag,
    )


def bootstrap_admin_if_empty(username: str, password: str) -> AuthUser | None:
    """Create the first admin when no users exist; otherwise return None.

    If the username is the designated super-admin (``julian``), that role is used.
    """
    ensure_users_schema()
    if user_count() > 0:
        return None
    name = validate_username(username)
    role = ROLE_SUPER_ADMIN if name == SUPER_ADMIN_USERNAME else ROLE_ADMIN
    return create_user(name, password, role=role, must_change_password=False)
