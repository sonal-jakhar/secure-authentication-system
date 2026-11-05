"""Migrate fictional legacy demo users into the secure demo account table."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from app.legacy_auth import get_legacy_connection, legacy_verify
from src.auth.service import AuthResult, login, register_user
from src.db.connection import initialize_database
from src.db.users import DuplicateUsernameError, get_user_by_username

DEMO_DATABASE_PATH = Path(__file__).resolve().parent / "data" / "demo.db"


@dataclass(frozen=True)
class MigrationResult:
    success: bool
    code: str
    username: str


def migrate_legacy_user(
    username: str,
    password: str,
) -> MigrationResult | AuthResult:
    """Migrate a verified legacy user, or log in if already migrated.

    The existing register_user API hashes the supplied plaintext password with
    a fresh PBKDF2 salt, commits the secure row, and applies its schema defaults
    (TOTP disabled, nullable TOTP fields, and zeroed lockout counters).
    """
    initialize_database(DEMO_DATABASE_PATH)
    connection = get_legacy_connection(DEMO_DATABASE_PATH)
    try:
        legacy_row = connection.execute(
            "SELECT email FROM legacy_users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()

        if legacy_row is None:
            return login(connection, username, password)

        if get_user_by_username(connection, username) is not None:
            return MigrationResult(
                success=False,
                code="secure_account_already_exists",
                username=username,
            )

        email = legacy_row["email"]
        if not legacy_verify(connection, email, password):
            return MigrationResult(
                success=False,
                code="invalid_legacy_credentials",
                username=username,
            )

        try:
            register_user(connection, username, password)
        except DuplicateUsernameError:
            return MigrationResult(
                success=False,
                code="secure_account_already_exists",
                username=username,
            )

        cursor = connection.execute(
            "DELETE FROM legacy_users WHERE email = ? AND username = ? COLLATE NOCASE",
            (email, username),
        )
        if cursor.rowcount != 1:
            connection.rollback()
            raise RuntimeError("Legacy row changed after secure account creation.")
        connection.commit()
        return MigrationResult(success=True, code="migrated", username=username)
    finally:
        connection.close()