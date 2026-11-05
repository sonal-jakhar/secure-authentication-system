"""Integration tests for the demo-only takeover simulation."""

from __future__ import annotations

import time

import pyotp
import pytest

import seed_demo_users
import takeover_sim
from seed_demo_users import COHORT_A
from src.crypto.secret_vault import decrypt_totp_secret, generate_fernet_key
from src.auth.totp import TOTP_INTERVAL_SECONDS
from src.db.connection import get_connection
from src.db.users import get_user_by_username


@pytest.fixture
def seeded_demo_db(tmp_path, monkeypatch):
    database_path = tmp_path / "demo.db"
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("FERNET_KEY", generate_fernet_key())
    monkeypatch.setattr(seed_demo_users, "DEMO_DATABASE_PATH", database_path)
    monkeypatch.setattr(takeover_sim, "DEMO_DATABASE_PATH", database_path)
    seed_demo_users.seed_demo_users()
    return database_path


def test_legacy_takeover_accepts_seeded_cohort_a_password(seeded_demo_db):
    _, username, password = COHORT_A[0]

    assert takeover_sim.attempt_takeover_legacy(username, password)
    assert not takeover_sim.attempt_takeover_legacy(
        username, "incorrect-fictional-password"
    )


def test_secure_takeover_requires_totp_when_password_is_correct(seeded_demo_db):
    _, username, password = COHORT_A[0]

    result = takeover_sim.attempt_takeover_secure(username, password)

    assert not result.success
    assert result.code == "invalid_credentials"


def test_secure_takeover_rejects_wrong_totp(seeded_demo_db):
    _, username, password = COHORT_A[0]

    result = takeover_sim.attempt_takeover_secure(username, password, "000000")

    assert not result.success
    assert result.code == "invalid_credentials"


def test_secure_takeover_accepts_correct_live_totp(seeded_demo_db):
    _, username, password = COHORT_A[0]
    connection = get_connection(seeded_demo_db)
    try:
        user = get_user_by_username(connection, username)
        assert user is not None
        secret = decrypt_totp_secret(user["encrypted_totp_secret"])
        last_step = user["last_accepted_totp_step"]
    finally:
        connection.close()
    current_step = int(time.time()) // TOTP_INTERVAL_SECONDS
    code_step = max(current_step, last_step + 1)
    otp = pyotp.TOTP(secret, interval=TOTP_INTERVAL_SECONDS).at(
        code_step * TOTP_INTERVAL_SECONDS
    )

    result = takeover_sim.attempt_takeover_secure(username, password, otp)

    assert result.success
    assert result.code == "success"


def test_secure_takeover_surfaces_existing_lockout_result(seeded_demo_db):
    _, username, password = COHORT_A[0]

    for attempt in range(5):
        result = takeover_sim.attempt_takeover_secure(
            username, f"fictional-wrong-password-{attempt}"
        )
        assert not result.success
        assert result.code == "invalid_credentials"

    locked_result = takeover_sim.attempt_takeover_secure(username, password)

    assert not locked_result.success
    assert locked_result.code == "locked"