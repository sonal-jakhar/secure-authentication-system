"""Registration, TOTP enrolment, and login workflows.

Uses the existing database, PBKDF2, TOTP, and Fernet modules. This is not a UI.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from src.auth.password import PBKDF2_ITERATIONS, hash_password, verify_password
from src.auth.totp import (
    generate_provisioning_uri,
    generate_qr_png,
    generate_totp_secret,
    verify_totp,
)
from src.crypto.secret_vault import decrypt_totp_secret, encrypt_totp_secret
from src.db.users import (
    DuplicateUsernameError,
    claim_totp_step,
    confirm_pending_totp_secret,
    get_user_by_username,
    insert_user,
    record_login_failure,
    record_login_success,
    set_pending_totp_secret,
)

MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 64
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 256
DEFAULT_FAILED_ATTEMPT_LIMIT = 5
DEFAULT_LOCKOUT_SECONDS = 15 * 60

_DUMMY_SALT_HEX = "00" * 16
_DUMMY_HASH_HEX = "00" * 32


class TotpEnrolmentError(Exception):
    """TOTP enrolment could not start or could not be confirmed."""


@dataclass(frozen=True)
class SecurityPolicy:
    failed_attempt_limit: int = DEFAULT_FAILED_ATTEMPT_LIMIT
    lockout_seconds: int = DEFAULT_LOCKOUT_SECONDS


@dataclass(frozen=True)
class AuthResult:
    success: bool
    code: str
    user_id: int | None = None
    username: str | None = None


@dataclass(frozen=True)
class TotpEnrolment:
    username: str
    provisioning_uri: str
    qr_png: bytes


def register_user(
    connection: sqlite3.Connection,
    username: str,
    password: str,
) -> int:
    """Create a user with a PBKDF2 password hash. TOTP is not enabled yet."""
    cleaned_username = _validate_username(username)
    _validate_password(password)
    salt, password_hash, iterations = hash_password(password)
    return insert_user(
        connection,
        username=cleaned_username,
        password_salt=salt,
        password_hash=password_hash,
        password_iterations=iterations,
    )


def start_totp_enrolment(
    connection: sqlite3.Connection,
    username: str,
    password: str,
    *,
    now: datetime | None = None,
    policy: SecurityPolicy | None = None,
) -> TotpEnrolment:
    """Create a pending encrypted TOTP secret after verifying the password.

    TOTP stays disabled until confirm_totp_enrolment succeeds.
    """
    policy = policy or SecurityPolicy()
    current_time = _utc(now)
    user = _authenticated_user(
        connection, username, password, now=current_time, policy=policy
    )

    secret = generate_totp_secret()
    ciphertext = encrypt_totp_secret(secret)
    set_pending_totp_secret(connection, user["id"], ciphertext)

    uri = generate_provisioning_uri(secret, user["username"])
    return TotpEnrolment(
        username=user["username"],
        provisioning_uri=uri,
        qr_png=generate_qr_png(uri),
    )


def confirm_totp_enrolment(
    connection: sqlite3.Connection,
    username: str,
    password: str,
    otp: str,
    *,
    at_time: float | None = None,
    now: datetime | None = None,
    policy: SecurityPolicy | None = None,
) -> None:
    """Enable TOTP only after a valid OTP for the pending secret."""
    policy = policy or SecurityPolicy()
    current_time = _utc(now)
    user = _authenticated_user(
        connection, username, password, now=current_time, policy=policy
    )
    pending = user["pending_encrypted_totp_secret"]
    if not pending:
        raise TotpEnrolmentError("No pending TOTP enrolment")

    try:
        secret = decrypt_totp_secret(pending)
        result = verify_totp(secret, otp, at_time=at_time)
    except ValueError as exc:
        raise TotpEnrolmentError("Invalid OTP") from exc

    if not result.accepted or result.step is None:
        raise TotpEnrolmentError("Invalid OTP")

    if not confirm_pending_totp_secret(connection, user["id"], result.step):
        raise TotpEnrolmentError("No pending TOTP enrolment")


def login(
    connection: sqlite3.Connection,
    username: str,
    password: str,
    otp: str | None = None,
    *,
    at_time: float | None = None,
    now: datetime | None = None,
    policy: SecurityPolicy | None = None,
) -> AuthResult:
    """Authenticate with password and, when enabled, a TOTP code."""
    policy = policy or SecurityPolicy()
    current_time = _utc(now)

    if not isinstance(username, str) or not isinstance(password, str):
        return AuthResult(success=False, code="invalid_credentials")

    user = get_user_by_username(connection, username.strip())
    if user is None:
        _dummy_password_check(password)
        return AuthResult(success=False, code="invalid_credentials")

    password_ok = _safe_password_check(password, user)
    if not password_ok:
        # Wrong passwords never report lockout, so usernames are not confirmed
        # by the "locked" result. Lockout is stored on the account anyway.
        return _fail_login(connection, user, current_time, policy)

    if _is_locked(user, current_time):
        return AuthResult(success=False, code="locked")

    if user["totp_enabled"]:
        if otp is None:
            return _fail_login(connection, user, current_time, policy)
        replay_or_invalid = _check_totp(connection, user, otp, at_time=at_time)
        if replay_or_invalid == "invalid":
            return _fail_login(connection, user, current_time, policy)
        if replay_or_invalid == "replay":
            return AuthResult(success=False, code="invalid_credentials")

    record_login_success(
        connection,
        user["id"],
        last_login=_iso(current_time),
    )
    return AuthResult(
        success=True,
        code="success",
        user_id=user["id"],
        username=user["username"],
    )


def _authenticated_user(
    connection: sqlite3.Connection,
    username: str,
    password: str,
    *,
    now: datetime,
    policy: SecurityPolicy,
) -> dict:
    result = login(
        connection,
        username,
        password,
        now=now,
        policy=policy,
    )
    if result.code == "locked":
        raise TotpEnrolmentError("Account is locked")
    if not result.success:
        raise TotpEnrolmentError("Invalid credentials")
    user = get_user_by_username(connection, username)
    if user is None:
        raise TotpEnrolmentError("Invalid credentials")
    return user


def _check_totp(
    connection: sqlite3.Connection,
    user: dict,
    otp: str,
    *,
    at_time: float | None,
) -> str:
    ciphertext = user["encrypted_totp_secret"]
    if not ciphertext:
        return "invalid"
    try:
        secret = decrypt_totp_secret(ciphertext)
        result = verify_totp(secret, otp, at_time=at_time)
    except ValueError:
        return "invalid"
    if not result.accepted or result.step is None:
        return "invalid"
    if not claim_totp_step(connection, user["id"], result.step):
        return "replay"
    return "ok"


def _fail_login(
    connection: sqlite3.Connection,
    user: dict,
    now: datetime,
    policy: SecurityPolicy,
) -> AuthResult:
    lock_time = _iso(now + timedelta(seconds=policy.lockout_seconds))
    record_login_failure(
        connection,
        user["id"],
        failed_attempt_limit=policy.failed_attempt_limit,
        locked_until=lock_time,
    )
    return AuthResult(success=False, code="invalid_credentials")


def _safe_password_check(password: str, user: dict) -> bool:
    try:
        return verify_password(
            password,
            user["password_salt"],
            user["password_hash"],
            user["password_iterations"],
        )
    except (TypeError, ValueError):
        return False


def _dummy_password_check(password: str) -> None:
    try:
        verify_password(password, _DUMMY_SALT_HEX, _DUMMY_HASH_HEX, PBKDF2_ITERATIONS)
    except (TypeError, ValueError):
        return


def _is_locked(user: dict, now: datetime) -> bool:
    raw = user["locked_until"]
    if not raw:
        return False
    until = datetime.fromisoformat(raw)
    if until.tzinfo is None:
        until = until.replace(tzinfo=timezone.utc)
    return now < until


def _validate_username(username: object) -> str:
    if not isinstance(username, str):
        raise TypeError("username must be a string")
    cleaned = username.strip()
    if len(cleaned) < MIN_USERNAME_LENGTH or len(cleaned) > MAX_USERNAME_LENGTH:
        raise ValueError("username must be between 3 and 64 characters")
    if not all(character.isalnum() or character in "-_" for character in cleaned):
        raise ValueError("username may contain letters, digits, hyphens and underscores")
    return cleaned


def _validate_password(password: object) -> None:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if len(password) < MIN_PASSWORD_LENGTH or len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError("password must be between 8 and 256 characters")


def _utc(now: datetime | None) -> datetime:
    current = now if now is not None else datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat()
