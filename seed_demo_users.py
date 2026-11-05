"""Seed fictional legacy and secure cohorts into the isolated demo database."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pyotp
from dotenv import load_dotenv

from app.legacy_auth import get_legacy_connection, legacy_register, legacy_verify
from src.auth.password import verify_password
from src.auth.service import (
    confirm_totp_enrolment,
    register_user,
    start_totp_enrolment,
)
from src.db.connection import initialize_database
from src.db.users import get_user_by_username

PROJECT_ROOT = Path(__file__).resolve().parent
DEMO_DATABASE_PATH = PROJECT_ROOT / "data" / "demo.db"

_SHARED_PASSWORD = "fictional-shared-demo-password"
COHORT_A = (
    ("demo_alice@example.test", "demo_alice", _SHARED_PASSWORD),
    ("demo_bob@example.test", "demo_bob", _SHARED_PASSWORD),
    ("demo_cara@example.test", "demo_cara", "fictional-cara-demo-password"),
    ("demo_diego@example.test", "demo_diego", "fictional-diego-demo-password"),
    ("demo_eli@example.test", "demo_eli", "fictional-eli-demo-password"),
    ("demo_farah@example.test", "demo_farah", "fictional-farah-demo-password"),
)
COHORT_B = (
    ("demo_gus@example.test", "demo_gus", "fictional-gus-demo-password"),
    ("demo_hana@example.test", "demo_hana", "fictional-hana-demo-password"),
)


def seed_demo_users() -> None:
    """Idempotently seed fictional users, refusing production environments."""
    load_dotenv(PROJECT_ROOT / ".env")
    if os.getenv("APP_ENV", "").strip().casefold() == "production":
        raise RuntimeError("Demo users cannot be seeded in production.")

    initialize_database(DEMO_DATABASE_PATH)
    connection = get_legacy_connection(DEMO_DATABASE_PATH)
    try:
        for email, username, password in COHORT_A:
            _ensure_legacy_user(connection, email, username, password)
            _ensure_secure_user(connection, username, password)

        for email, username, password in COHORT_B:
            _ensure_legacy_user(connection, email, username, password)
            secure_user = get_user_by_username(connection, username)
            if secure_user is not None and not _secure_user_password_matches(
                secure_user, password
            ):
                raise RuntimeError(
                    "A secure demo account conflicts with existing data."
                )
    finally:
        connection.close()


def _ensure_legacy_user(
    connection: sqlite3.Connection,
    email: str,
    username: str,
    password: str,
) -> None:
    rows = connection.execute(
        "SELECT email, username FROM legacy_users "
        "WHERE email = ? COLLATE NOCASE OR username = ? COLLATE NOCASE",
        (email, username),
    ).fetchall()
    if not rows:
        legacy_register(connection, email, username, password)
        return

    if (
        len(rows) != 1
        or rows[0]["email"].casefold() != email.casefold()
        or rows[0]["username"].casefold() != username.casefold()
        or not legacy_verify(connection, email, password)
    ):
        raise RuntimeError("A seeded legacy demo account conflicts with existing data.")


def _ensure_secure_user(
    connection: sqlite3.Connection,
    username: str,
    password: str,
) -> None:
    user = get_user_by_username(connection, username)
    if user is None:
        register_user(connection, username, password)
        user = get_user_by_username(connection, username)
    if user is None:
        raise RuntimeError("A secure demo account could not be created.")

    if not _secure_user_password_matches(user, password):
        raise RuntimeError("A seeded secure demo account conflicts with existing data.")

    if user["totp_enabled"]:
        if not user["encrypted_totp_secret"] or user["pending_encrypted_totp_secret"]:
            raise RuntimeError("A secure demo account has incomplete TOTP enrollment.")
        return

    enrollment = start_totp_enrolment(connection, username, password)
    otp = pyotp.parse_uri(enrollment.provisioning_uri).now()
    confirm_totp_enrolment(connection, username, password, otp)

    enrolled_user = get_user_by_username(connection, username)
    if (
        enrolled_user is None
        or not enrolled_user["totp_enabled"]
        or not enrolled_user["encrypted_totp_secret"]
        or enrolled_user["pending_encrypted_totp_secret"]
    ):
        raise RuntimeError("A secure demo account's TOTP enrollment did not complete.")


def _secure_user_password_matches(user: dict, password: str) -> bool:
    try:
        return verify_password(
            password,
            user["password_salt"],
            user["password_hash"],
            user["password_iterations"],
        )
    except (TypeError, ValueError):
        return False


if __name__ == "__main__":
    seed_demo_users()
    print("Fictional demo cohorts are ready in data/demo.db.")