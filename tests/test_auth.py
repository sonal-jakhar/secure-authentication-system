"""Phase 5 tests for registration, TOTP enrolment, login, replay, and lockout."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pyotp
import pytest

from src.auth.service import (
    SecurityPolicy,
    TotpEnrolmentError,
    confirm_totp_enrolment,
    login,
    register_user,
    start_totp_enrolment,
)
from src.crypto.secret_vault import decrypt_totp_secret
from src.db.users import DuplicateUsernameError, get_user_by_username

PASSWORD = "correct-horse-battery"
FIXED_TIME = 1_700_000_010
NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
POLICY = SecurityPolicy(failed_attempt_limit=5, lockout_seconds=60)


def _secret_from_uri(uri: str) -> str:
    return parse_qs(urlparse(uri).query)["secret"][0]


def _otp(secret: str, at_time: float = FIXED_TIME) -> str:
    return pyotp.TOTP(secret, interval=30).at(at_time)


def test_successful_registration(db_connection):
    user_id = register_user(db_connection, "alice", PASSWORD)
    stored = get_user_by_username(db_connection, "alice")

    assert user_id >= 1
    assert stored is not None
    assert stored["username"] == "alice"
    assert stored["totp_enabled"] == 0
    assert stored["password_iterations"] == 600_000


def test_duplicate_username_registration(db_connection):
    register_user(db_connection, "alice", PASSWORD)
    with pytest.raises(DuplicateUsernameError):
        register_user(db_connection, "Alice", PASSWORD)


def test_invalid_registration_input(db_connection):
    with pytest.raises(ValueError):
        register_user(db_connection, "ab", PASSWORD)
    with pytest.raises(ValueError):
        register_user(db_connection, "alice", "short")
    with pytest.raises(TypeError):
        register_user(db_connection, None, PASSWORD)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        register_user(db_connection, "alice", None)  # type: ignore[arg-type]


def test_successful_login_without_totp(db_connection):
    register_user(db_connection, "alice", PASSWORD)
    result = login(db_connection, "alice", PASSWORD, now=NOW, policy=POLICY)

    assert result.success is True
    assert result.code == "success"
    assert result.username == "alice"
    stored = get_user_by_username(db_connection, "alice")
    assert stored["failed_attempts"] == 0
    assert stored["last_login"]


def test_incorrect_password(db_connection):
    register_user(db_connection, "alice", PASSWORD)
    result = login(db_connection, "alice", "wrong-password", now=NOW, policy=POLICY)

    assert result.success is False
    assert result.code == "invalid_credentials"
    assert result.user_id is None


def test_unknown_username_does_not_reveal_existence(db_connection):
    result = login(db_connection, "nobody", PASSWORD, now=NOW, policy=POLICY)
    assert result.success is False
    assert result.code == "invalid_credentials"


def test_pending_totp_enrolment_and_confirmation(db_connection, fernet_key):
    register_user(db_connection, "alice", PASSWORD)
    enrolment = start_totp_enrolment(
        db_connection, "alice", PASSWORD, now=NOW, policy=POLICY
    )
    pending = get_user_by_username(db_connection, "alice")

    assert pending["totp_enabled"] == 0
    assert pending["pending_encrypted_totp_secret"]
    assert pending["encrypted_totp_secret"] is None
    assert enrolment.provisioning_uri.startswith("otpauth://totp/")
    assert enrolment.qr_png.startswith(b"\x89PNG")

    secret = _secret_from_uri(enrolment.provisioning_uri)
    confirm_totp_enrolment(
        db_connection,
        "alice",
        PASSWORD,
        _otp(secret, FIXED_TIME),
        at_time=FIXED_TIME,
        now=NOW,
        policy=POLICY,
    )
    enabled = get_user_by_username(db_connection, "alice")
    assert enabled["totp_enabled"] == 1
    assert enabled["encrypted_totp_secret"]
    assert enabled["pending_encrypted_totp_secret"] is None


def test_login_without_otp_still_works_while_totp_is_pending(db_connection, fernet_key):
    register_user(db_connection, "alice", PASSWORD)
    start_totp_enrolment(db_connection, "alice", PASSWORD, now=NOW, policy=POLICY)
    result = login(db_connection, "alice", PASSWORD, now=NOW, policy=POLICY)
    assert result.success is True


def test_successful_login_with_totp(db_connection, fernet_key):
    register_user(db_connection, "alice", PASSWORD)
    enrolment = start_totp_enrolment(
        db_connection, "alice", PASSWORD, now=NOW, policy=POLICY
    )
    secret = _secret_from_uri(enrolment.provisioning_uri)
    confirm_totp_enrolment(
        db_connection,
        "alice",
        PASSWORD,
        _otp(secret, FIXED_TIME),
        at_time=FIXED_TIME,
        now=NOW,
        policy=POLICY,
    )
    later = FIXED_TIME + 30
    result = login(
        db_connection,
        "alice",
        PASSWORD,
        _otp(secret, later),
        at_time=later,
        now=NOW,
        policy=POLICY,
    )
    assert result.success is True
    assert result.code == "success"


def test_incorrect_otp(db_connection, fernet_key):
    register_user(db_connection, "alice", PASSWORD)
    enrolment = start_totp_enrolment(
        db_connection, "alice", PASSWORD, now=NOW, policy=POLICY
    )
    secret = _secret_from_uri(enrolment.provisioning_uri)
    confirm_totp_enrolment(
        db_connection,
        "alice",
        PASSWORD,
        _otp(secret, FIXED_TIME),
        at_time=FIXED_TIME,
        now=NOW,
        policy=POLICY,
    )
    result = login(
        db_connection,
        "alice",
        PASSWORD,
        "000000",
        at_time=FIXED_TIME + 30,
        now=NOW,
        policy=POLICY,
    )
    assert result.success is False
    assert result.code == "invalid_credentials"


def test_malformed_otp_is_rejected(db_connection, fernet_key):
    register_user(db_connection, "alice", PASSWORD)
    enrolment = start_totp_enrolment(
        db_connection, "alice", PASSWORD, now=NOW, policy=POLICY
    )
    secret = _secret_from_uri(enrolment.provisioning_uri)
    confirm_totp_enrolment(
        db_connection,
        "alice",
        PASSWORD,
        _otp(secret, FIXED_TIME),
        at_time=FIXED_TIME,
        now=NOW,
        policy=POLICY,
    )
    result = login(
        db_connection,
        "alice",
        PASSWORD,
        "12a456",
        at_time=FIXED_TIME + 30,
        now=NOW,
        policy=POLICY,
    )
    assert result.success is False
    assert result.code == "invalid_credentials"


def test_totp_replay_is_rejected(db_connection, fernet_key):
    register_user(db_connection, "alice", PASSWORD)
    enrolment = start_totp_enrolment(
        db_connection, "alice", PASSWORD, now=NOW, policy=POLICY
    )
    secret = _secret_from_uri(enrolment.provisioning_uri)
    code = _otp(secret, FIXED_TIME)
    confirm_totp_enrolment(
        db_connection,
        "alice",
        PASSWORD,
        code,
        at_time=FIXED_TIME,
        now=NOW,
        policy=POLICY,
    )
    replay = login(
        db_connection,
        "alice",
        PASSWORD,
        code,
        at_time=FIXED_TIME,
        now=NOW,
        policy=POLICY,
    )
    assert replay.success is False
    assert replay.code == "invalid_credentials"


def test_repeated_otp_use_is_rejected(db_connection, fernet_key):
    register_user(db_connection, "alice", PASSWORD)
    enrolment = start_totp_enrolment(
        db_connection, "alice", PASSWORD, now=NOW, policy=POLICY
    )
    secret = _secret_from_uri(enrolment.provisioning_uri)
    confirm_totp_enrolment(
        db_connection,
        "alice",
        PASSWORD,
        _otp(secret, FIXED_TIME),
        at_time=FIXED_TIME,
        now=NOW,
        policy=POLICY,
    )
    later = FIXED_TIME + 30
    code = _otp(secret, later)
    first = login(
        db_connection, "alice", PASSWORD, code, at_time=later, now=NOW, policy=POLICY
    )
    second = login(
        db_connection, "alice", PASSWORD, code, at_time=later, now=NOW, policy=POLICY
    )
    assert first.success is True
    assert second.success is False


def test_account_lockout_after_repeated_failures(db_connection):
    register_user(db_connection, "alice", PASSWORD)
    for _ in range(5):
        failed = login(
            db_connection, "alice", "wrong-password", now=NOW, policy=POLICY
        )
        assert failed.code == "invalid_credentials"

    stored = get_user_by_username(db_connection, "alice")
    assert stored["failed_attempts"] == 5
    assert stored["locked_until"]

    locked = login(db_connection, "alice", PASSWORD, now=NOW, policy=POLICY)
    assert locked.success is False
    assert locked.code == "locked"


def test_lockout_expires(db_connection):
    register_user(db_connection, "alice", PASSWORD)
    for _ in range(5):
        login(db_connection, "alice", "wrong-password", now=NOW, policy=POLICY)

    after_lock = NOW + timedelta(seconds=POLICY.lockout_seconds + 1)
    result = login(db_connection, "alice", PASSWORD, now=after_lock, policy=POLICY)
    assert result.success is True
    stored = get_user_by_username(db_connection, "alice")
    assert stored["failed_attempts"] == 0
    assert stored["locked_until"] is None


def test_wrong_password_does_not_clear_lockout(db_connection):
    register_user(db_connection, "alice", PASSWORD)
    for _ in range(5):
        login(db_connection, "alice", "wrong-password", now=NOW, policy=POLICY)

    login(db_connection, "alice", "still-wrong", now=NOW, policy=POLICY)
    stored = get_user_by_username(db_connection, "alice")
    assert stored["locked_until"]
    assert stored["failed_attempts"] >= 5


def test_no_plaintext_password_or_totp_secret_in_sqlite(db_connection, fernet_key):
    register_user(db_connection, "alice", PASSWORD)
    enrolment = start_totp_enrolment(
        db_connection, "alice", PASSWORD, now=NOW, policy=POLICY
    )
    secret = _secret_from_uri(enrolment.provisioning_uri)
    pending = get_user_by_username(db_connection, "alice")

    assert PASSWORD not in pending["password_salt"]
    assert PASSWORD not in pending["password_hash"]
    assert secret not in pending["pending_encrypted_totp_secret"]
    assert decrypt_totp_secret(pending["pending_encrypted_totp_secret"]) == secret

    confirm_totp_enrolment(
        db_connection,
        "alice",
        PASSWORD,
        _otp(secret, FIXED_TIME),
        at_time=FIXED_TIME,
        now=NOW,
        policy=POLICY,
    )
    enabled = get_user_by_username(db_connection, "alice")
    assert enabled["pending_encrypted_totp_secret"] is None
    assert secret not in enabled["encrypted_totp_secret"]
    assert decrypt_totp_secret(enabled["encrypted_totp_secret"]) == secret


def test_confirm_enrolment_without_pending_secret_fails(db_connection):
    register_user(db_connection, "alice", PASSWORD)
    with pytest.raises(TotpEnrolmentError):
        confirm_totp_enrolment(
            db_connection,
            "alice",
            PASSWORD,
            "123456",
            at_time=FIXED_TIME,
            now=NOW,
            policy=POLICY,
        )
