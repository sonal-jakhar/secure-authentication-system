"""Tests for the isolated demo legacy-user migration."""

from __future__ import annotations

import pytest

import migrate_on_login
import seed_demo_users
from seed_demo_users import COHORT_B
from src.auth.service import AuthResult, register_user
from src.db.connection import get_connection
from src.db.users import get_user_by_username
from app.legacy_auth import get_legacy_connection


@pytest.fixture
def seeded_demo_db(tmp_path, monkeypatch, fernet_key):
    database_path = tmp_path / "demo.db"
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setattr(seed_demo_users, "DEMO_DATABASE_PATH", database_path)
    monkeypatch.setattr(migrate_on_login, "DEMO_DATABASE_PATH", database_path)
    seed_demo_users.seed_demo_users()
    return database_path


def test_migration_creates_valid_secure_user_and_removes_legacy_row(
    seeded_demo_db,
):
    _, username, password = COHORT_B[0]

    result = migrate_on_login.migrate_legacy_user(username, password)

    assert result.success
    assert result.code == "migrated"
    connection = get_connection(seeded_demo_db)
    try:
        assert get_user_by_username(connection, username) is not None
        login_result = migrate_on_login.login(connection, username, password)
        assert login_result.success
        assert login_result.username == username
    finally:
        connection.close()

    connection = get_legacy_connection(seeded_demo_db)
    try:
        assert connection.execute(
            "SELECT 1 FROM legacy_users WHERE username = ?", (username,)
        ).fetchone() is None
    finally:
        connection.close()


def test_wrong_password_leaves_legacy_user_untouched(seeded_demo_db):
    _, username, _ = COHORT_B[0]

    result = migrate_on_login.migrate_legacy_user(
        username, "fictional-wrong-password"
    )

    assert not result.success
    assert result.code == "invalid_legacy_credentials"
    connection = get_legacy_connection(seeded_demo_db)
    try:
        assert connection.execute(
            "SELECT 1 FROM legacy_users WHERE username = ?", (username,)
        ).fetchone() is not None
        assert get_user_by_username(connection, username) is None
    finally:
        connection.close()


def test_second_call_uses_normal_secure_login(seeded_demo_db):
    _, username, password = COHORT_B[0]
    first_result = migrate_on_login.migrate_legacy_user(username, password)

    assert first_result.success
    second_result = migrate_on_login.migrate_legacy_user(username, password)

    assert isinstance(second_result, AuthResult)
    assert second_result.success
    assert second_result.code == "success"
    assert second_result.username == username


def test_existing_secure_user_is_not_overwritten(seeded_demo_db):
    _, username, password = COHORT_B[0]
    connection = get_legacy_connection(seeded_demo_db)
    try:
        register_user(connection, username, "fictional-existing-secure-password")
        before = get_user_by_username(connection, username)
        assert before is not None
    finally:
        connection.close()

    result = migrate_on_login.migrate_legacy_user(username, password)

    assert not result.success
    assert result.code == "secure_account_already_exists"
    connection = get_legacy_connection(seeded_demo_db)
    try:
        after = get_user_by_username(connection, username)
        assert after is not None
        assert after["password_hash"] == before["password_hash"]
        assert after["password_salt"] == before["password_salt"]
        assert connection.execute(
            "SELECT 1 FROM legacy_users WHERE username = ?", (username,)
        ).fetchone() is not None
    finally:
        connection.close()