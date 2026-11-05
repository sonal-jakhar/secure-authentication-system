"""Tests for the isolated demo-database breach export."""

from __future__ import annotations

import sqlite3

import pyotp

import leak_export
from app.legacy_auth import get_legacy_connection, legacy_register
from src.auth.service import confirm_totp_enrolment, register_user, start_totp_enrolment
from src.db.connection import initialize_database


def test_export_contains_only_stored_hash_data_and_separates_cohort_b(
    tmp_path, monkeypatch, fernet_key
):
    database_path = tmp_path / "demo.db"
    monkeypatch.setattr(leak_export, "DEMO_DATABASE_PATH", database_path)
    initialize_database(database_path)
    connection = get_legacy_connection(database_path)
    cohort_a_password = "fictional-known-test-password-a"
    cohort_b_password = "fictional-known-test-password-b"
    cohort_a_email = "known_a@example.test"
    cohort_a_username = "known_a"
    cohort_b_email = "known_b@example.test"
    cohort_b_username = "known_b"
    secure_only_username = "migrated_user"

    try:
        legacy_register(
            connection, cohort_a_email, cohort_a_username, cohort_a_password
        )
        legacy_register(
            connection, cohort_b_email, cohort_b_username, cohort_b_password
        )
        register_user(connection, cohort_a_username, cohort_a_password)
        register_user(connection, secure_only_username, "fictional-secure-only-password")
        enrollment = start_totp_enrolment(
            connection, cohort_a_username, cohort_a_password
        )
        otp = pyotp.parse_uri(enrollment.provisioning_uri).now()
        confirm_totp_enrolment(
            connection, cohort_a_username, cohort_a_password, otp
        )
    finally:
        connection.close()

    legacy_dump, secure_dump = leak_export.export_breach_dump()
    rendered_dump = repr((legacy_dump, secure_dump))

    assert cohort_a_password not in rendered_dump
    assert cohort_b_password not in rendered_dump
    assert {row["email"] for row in legacy_dump} == {
        cohort_a_email,
        cohort_b_email,
    }
    assert {row["username"] for row in secure_dump} == {
        cohort_a_username,
        secure_only_username,
    }
    assert all(
        set(row) == {"email", "password_hash"}
        for row in legacy_dump
    )
    assert all(
        set(row)
        == {"username", "password_hash", "salt", "encrypted_totp_secret"}
        for row in secure_dump
    )
    cohort_a_record = next(
        row for row in secure_dump if row["username"] == cohort_a_username
    )
    assert cohort_a_record["encrypted_totp_secret"]