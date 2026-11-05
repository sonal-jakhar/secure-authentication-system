"""Deliberately insecure legacy-auth simulation; never use for real credentials.

This module stores unsalted SHA-1 password digests only to support a fictional,
local security demonstration. It is separate from the real account database
and must never be used for real accounts or credentials.
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
from pathlib import Path

DEFAULT_DEMO_DATABASE_PATH = Path(__file__).resolve().parents[1] / "data" / "demo.db"

LEGACY_USERS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS legacy_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def get_legacy_connection(
    db_path: str | Path | None = None,
) -> sqlite3.Connection:
    """Open the isolated demo database and ensure its legacy table exists."""
    path = Path(db_path) if db_path is not None else DEFAULT_DEMO_DATABASE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute(LEGACY_USERS_TABLE_SQL)
        connection.commit()
    except Exception:
        connection.close()
        raise
    return connection


def legacy_register(
    connection: sqlite3.Connection,
    email: str,
    username: str,
    password: str,
) -> int:
    """Register a fictional demo user using an intentionally weak SHA-1 hash."""
    if not isinstance(email, str) or not email.strip():
        raise ValueError("email must not be empty")
    if not isinstance(username, str) or not username.strip():
        raise ValueError("username must not be empty")
    if not isinstance(password, str) or not password:
        raise ValueError("password must not be empty")

    password_hash = hashlib.sha1(
        password.encode("utf-8"), usedforsecurity=False
    ).hexdigest()
    cursor = connection.execute(
        "INSERT INTO legacy_users (email, username, password_hash) "
        "VALUES (?, ?, ?)",
        (email.strip(), username.strip(), password_hash),
    )
    connection.commit()
    return int(cursor.lastrowid)


def legacy_verify(
    connection: sqlite3.Connection,
    email: str,
    password: str,
) -> bool:
    """Verify a fictional demo user's password against its unsalted SHA-1 hash."""
    if not isinstance(email, str) or not email.strip():
        return False
    if not isinstance(password, str) or not password:
        return False

    row = connection.execute(
        "SELECT password_hash FROM legacy_users WHERE email = ?",
        (email.strip(),),
    ).fetchone()
    if row is None:
        return False
    candidate_hash = hashlib.sha1(
        password.encode("utf-8"), usedforsecurity=False
    ).hexdigest()
    return hmac.compare_digest(candidate_hash, row["password_hash"])