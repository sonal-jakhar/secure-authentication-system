"""Phase 2 tests for the SQLite database layer."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.db.connection import get_connection, initialize_database
from src.db.schema import EXPECTED_USER_COLUMNS
from src.db.users import (
    DuplicateUsernameError,
    claim_totp_step,
    get_user_by_username,
    insert_user,
)


def _sample_user_fields(**overrides):
    fields = {
        "username": "alice",
        "password_salt": "salt-placeholder",
        "password_hash": "hash-placeholder",
        "password_iterations": 100_000,
    }
    fields.update(overrides)
    return fields


def test_initialize_database_creates_file_and_parent_directory(tmp_path: Path):
    db_path = tmp_path / "nested" / "dir" / "users.db"
    created = initialize_database(db_path)

    assert created == db_path
    assert db_path.exists()
    assert db_path.parent.is_dir()


def test_users_table_and_columns_exist(db_connection):
    row = db_connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
        ("users",),
    ).fetchone()
    assert row is not None
    assert row["name"] == "users"

    columns = [
        info["name"]
        for info in db_connection.execute("PRAGMA table_info(users)").fetchall()
    ]
    assert tuple(columns) == EXPECTED_USER_COLUMNS


def test_insert_user_succeeds(db_connection):
    user_id = insert_user(db_connection, **_sample_user_fields())

    assert isinstance(user_id, int)
    assert user_id >= 1

    stored = get_user_by_username(db_connection, "alice")
    assert stored is not None
    assert stored["id"] == user_id
    assert stored["username"] == "alice"
    assert stored["password_salt"] == "salt-placeholder"
    assert stored["password_hash"] == "hash-placeholder"
    assert stored["password_iterations"] == 100_000
    assert stored["encrypted_totp_secret"] is None
    assert stored["pending_encrypted_totp_secret"] is None
    assert stored["totp_enabled"] == 0
    assert stored["last_accepted_totp_step"] is None
    assert stored["failed_attempts"] == 0
    assert stored["locked_until"] is None
    assert stored["created_at"]
    assert stored["last_login"] is None


def test_duplicate_username_rejected_case_insensitive(db_connection):
    insert_user(db_connection, **_sample_user_fields(username="Alice"))

    with pytest.raises(DuplicateUsernameError):
        insert_user(db_connection, **_sample_user_fields(username="alice"))

    with pytest.raises(DuplicateUsernameError):
        insert_user(db_connection, **_sample_user_fields(username="ALICE"))


def test_get_user_by_username_retrieves_existing_user(db_connection):
    insert_user(db_connection, **_sample_user_fields(username="Bob"))

    by_same_case = get_user_by_username(db_connection, "Bob")
    by_other_case = get_user_by_username(db_connection, "bob")

    assert by_same_case is not None
    assert by_other_case is not None
    assert by_same_case["id"] == by_other_case["id"]
    assert by_same_case["username"] == "Bob"


def test_get_user_by_username_returns_none_when_missing(db_connection):
    assert get_user_by_username(db_connection, "does-not-exist") is None


def test_temporary_database_is_not_project_database(db_path: Path):
    assert db_path.name == "test_users.db"
    assert "pytest" in str(db_path) or "tmp" in str(db_path).lower()
    assert db_path != Path("data") / "users.db"


def test_claim_totp_step_rejects_replay(db_connection):
    user_id = insert_user(db_connection, **_sample_user_fields(username="carol"))
    db_connection.execute(
        "UPDATE users SET totp_enabled = 1 WHERE id = ?",
        (user_id,),
    )
    db_connection.commit()

    assert claim_totp_step(db_connection, user_id, 100) is True
    assert claim_totp_step(db_connection, user_id, 100) is False
    assert claim_totp_step(db_connection, user_id, 99) is False
    assert claim_totp_step(db_connection, user_id, 101) is True
