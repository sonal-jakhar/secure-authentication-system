"""Tests for the isolated fictional cohort seeder."""

from __future__ import annotations

import sqlite3

import pytest

import seed_demo_users
from src.auth.service import register_user
from src.crypto.secret_vault import decrypt_totp_secret


@pytest.fixture
def demo_database(tmp_path, monkeypatch, fernet_key):
    monkeypatch.setenv("APP_ENV", "test")
    path = tmp_path / "demo.db"
    monkeypatch.setattr(seed_demo_users, "DEMO_DATABASE_PATH", path)
    return path


def test_cohort_a_is_seeded_with_shared_legacy_hashes_and_confirmed_totp(
    demo_database,
):
    seed_demo_users.seed_demo_users()
    connection = sqlite3.connect(demo_database)
    connection.row_factory = sqlite3.Row
    try:
        alice, bob = seed_demo_users.COHORT_A[:2]
        legacy_hashes = [
            connection.execute(
                "SELECT password_hash FROM legacy_users WHERE email = ?", (email,)
            ).fetchone()["password_hash"]
            for email, _, _ in (alice, bob)
        ]
        secure_users = [
            connection.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            for _, username, _ in (alice, bob)
        ]

        assert legacy_hashes[0] == legacy_hashes[1]
        assert secure_users[0]["password_hash"] != secure_users[1]["password_hash"]
        assert secure_users[0]["password_salt"] != secure_users[1]["password_salt"]

        for _, username, _ in seed_demo_users.COHORT_A:
            user = connection.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            assert user is not None
            assert user["totp_enabled"] == 1
            assert user["encrypted_totp_secret"]
            assert user["pending_encrypted_totp_secret"] is None
            assert user["last_accepted_totp_step"] is not None
            assert decrypt_totp_secret(user["encrypted_totp_secret"])
    finally:
        connection.close()


def test_cohort_b_is_legacy_only_and_seeding_is_idempotent(demo_database):
    seed_demo_users.seed_demo_users()
    seed_demo_users.seed_demo_users()
    connection = sqlite3.connect(demo_database)
    try:
        assert connection.execute("SELECT COUNT(*) FROM legacy_users").fetchone()[0] == 8
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 6
        for _, username, _ in seed_demo_users.COHORT_B:
            assert connection.execute(
                "SELECT 1 FROM legacy_users WHERE username = ?", (username,)
            ).fetchone()
            assert connection.execute(
                "SELECT 1 FROM users WHERE username = ?", (username,)
            ).fetchone() is None
    finally:
        connection.close()


def test_matching_preexisting_cohort_b_secure_user_does_not_break_seeding(
    demo_database,
):
    seed_demo_users.seed_demo_users()
    _, username, password = seed_demo_users.COHORT_B[0]
    connection = sqlite3.connect(demo_database)
    connection.row_factory = sqlite3.Row
    try:
        user_id = register_user(connection, username, password)
    finally:
        connection.close()

    seed_demo_users.seed_demo_users()

    connection = sqlite3.connect(demo_database)
    try:
        secure_users = connection.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]
        matching_user = connection.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        assert secure_users == 7
        assert matching_user[0] == user_id
        assert connection.execute(
            "SELECT COUNT(*) FROM legacy_users"
        ).fetchone()[0] == 8
    finally:
        connection.close()


def test_seeding_refuses_production_before_creating_database(tmp_path, monkeypatch):
    path = tmp_path / "demo.db"
    monkeypatch.setattr(seed_demo_users, "DEMO_DATABASE_PATH", path)
    monkeypatch.setenv("APP_ENV", "production")

    with pytest.raises(RuntimeError, match="cannot be seeded in production"):
        seed_demo_users.seed_demo_users()

    assert not path.exists()