"""Tests for the isolated, fictional legacy-auth demonstration."""

from __future__ import annotations

import re

from app.legacy_auth import get_legacy_connection, legacy_register, legacy_verify


def test_legacy_hash_format_and_verification(tmp_path):
    connection = get_legacy_connection(tmp_path / "demo.db")
    try:
        legacy_register(connection, "alice@example.test", "alice", "fictional-pass")
        row = connection.execute(
            "SELECT password_hash FROM legacy_users WHERE email = ?",
            ("alice@example.test",),
        ).fetchone()

        assert row is not None
        assert re.fullmatch(r"[0-9a-f]{40}", row["password_hash"])
        assert legacy_verify(connection, "alice@example.test", "fictional-pass")
        assert not legacy_verify(connection, "alice@example.test", "wrong-pass")
        assert not legacy_verify(connection, "missing@example.test", "fictional-pass")
    finally:
        connection.close()


def test_identical_passwords_produce_identical_hashes(tmp_path):
    connection = get_legacy_connection(tmp_path / "demo.db")
    try:
        legacy_register(connection, "alice@example.test", "alice", "same-fictional-pass")
        legacy_register(connection, "bob@example.test", "bob", "same-fictional-pass")
        hashes = [
            row["password_hash"]
            for row in connection.execute(
                "SELECT password_hash FROM legacy_users ORDER BY id"
            )
        ]

        assert len(hashes) == 2
        assert hashes[0] == hashes[1]
    finally:
        connection.close()


def test_legacy_table_has_no_salt_column(tmp_path):
    connection = get_legacy_connection(tmp_path / "demo.db")
    try:
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(legacy_users)")
        }

        assert columns == {"id", "email", "username", "password_hash", "created_at"}
    finally:
        connection.close()