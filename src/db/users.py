"""Data-access functions for the users table.

These helpers only run parameterised SQL. Authentication, hashing, OTP,
and lockout decisions belong in later phases.
"""

from __future__ import annotations

import sqlite3


class DuplicateUsernameError(Exception):
    """Raised when inserting a username that already exists (case-insensitive)."""


def insert_user(
    connection: sqlite3.Connection,
    *,
    username: str,
    password_salt: str,
    password_hash: str,
    password_iterations: int,
    encrypted_totp_secret: str | None = None,
    pending_encrypted_totp_secret: str | None = None,
    totp_enabled: int = 0,
) -> int:
    """Insert a user row and return the new id."""
    sql = """
        INSERT INTO users (
            username,
            password_salt,
            password_hash,
            password_iterations,
            encrypted_totp_secret,
            pending_encrypted_totp_secret,
            totp_enabled
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """
    try:
        cursor = connection.execute(
            sql,
            (
                username,
                password_salt,
                password_hash,
                password_iterations,
                encrypted_totp_secret,
                pending_encrypted_totp_secret,
                totp_enabled,
            ),
        )
        connection.commit()
    except sqlite3.IntegrityError as exc:
        if "unique" in str(exc).lower():
            raise DuplicateUsernameError(
                f"Username already exists: {username}"
            ) from exc
        raise
    return int(cursor.lastrowid)


def get_user_by_username(
    connection: sqlite3.Connection,
    username: str,
) -> dict | None:
    """Return a user row as a dict, or None if the username is not found."""
    sql = "SELECT * FROM users WHERE username = ? COLLATE NOCASE"
    row = connection.execute(sql, (username,)).fetchone()
    if row is None:
        return None
    return dict(row)


def get_user_by_id(connection: sqlite3.Connection, user_id: int) -> dict | None:
    row = connection.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if row is None:
        return None
    return dict(row)


def set_pending_totp_secret(
    connection: sqlite3.Connection,
    user_id: int,
    ciphertext: str,
) -> None:
    """Store an encrypted TOTP secret as pending. Does not enable TOTP."""
    cursor = connection.execute(
        """
        UPDATE users
        SET pending_encrypted_totp_secret = ?
        WHERE id = ?
        """,
        (ciphertext, user_id),
    )
    if cursor.rowcount != 1:
        connection.rollback()
        raise ValueError("User was not found")
    connection.commit()


def confirm_pending_totp_secret(
    connection: sqlite3.Connection,
    user_id: int,
    accepted_step: int,
) -> bool:
    """Atomically enable TOTP from the pending secret and record the OTP step."""
    connection.commit()
    connection.execute("BEGIN IMMEDIATE")
    try:
        cursor = connection.execute(
            """
            UPDATE users
            SET encrypted_totp_secret = pending_encrypted_totp_secret,
                pending_encrypted_totp_secret = NULL,
                totp_enabled = 1,
                last_accepted_totp_step = ?
            WHERE id = ?
              AND pending_encrypted_totp_secret IS NOT NULL
            """,
            (accepted_step, user_id),
        )
        if cursor.rowcount != 1:
            connection.rollback()
            return False
        connection.commit()
        return True
    except Exception:
        connection.rollback()
        raise


def claim_totp_step(
    connection: sqlite3.Connection,
    user_id: int,
    step: int,
) -> bool:
    """Accept a TOTP step only if it is newer than last_accepted_totp_step.

    The SELECT comparison and UPDATE run in one IMMEDIATE transaction so the
    same step cannot be consumed twice.
    """
    connection.commit()
    connection.execute("BEGIN IMMEDIATE")
    try:
        row = connection.execute(
            """
            SELECT last_accepted_totp_step
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
        if row is None:
            connection.rollback()
            return False
        last_step = row["last_accepted_totp_step"]
        if last_step is not None and step <= last_step:
            connection.rollback()
            return False
        cursor = connection.execute(
            """
            UPDATE users
            SET last_accepted_totp_step = ?
            WHERE id = ?
              AND (last_accepted_totp_step IS NULL OR last_accepted_totp_step < ?)
            """,
            (step, user_id, step),
        )
        if cursor.rowcount != 1:
            connection.rollback()
            return False
        connection.commit()
        return True
    except Exception:
        connection.rollback()
        raise


def record_login_failure(
    connection: sqlite3.Connection,
    user_id: int,
    *,
    failed_attempt_limit: int,
    locked_until: str | None,
) -> dict | None:
    """Atomically increment failed_attempts and lock when the limit is reached."""
    connection.commit()
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            """
            UPDATE users
            SET failed_attempts = failed_attempts + 1,
                locked_until = CASE
                    WHEN failed_attempts + 1 >= ? THEN ?
                    ELSE locked_until
                END
            WHERE id = ?
            """,
            (failed_attempt_limit, locked_until, user_id),
        )
        row = connection.execute(
            """
            SELECT failed_attempts, locked_until
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return dict(row) if row is not None else None


def record_login_success(
    connection: sqlite3.Connection,
    user_id: int,
    *,
    last_login: str,
) -> None:
    """Clear lockout counters after a successful authentication."""
    connection.commit()
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            """
            UPDATE users
            SET failed_attempts = 0,
                locked_until = NULL,
                last_login = ?
            WHERE id = ?
            """,
            (last_login, user_id),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
