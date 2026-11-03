"""SQLite schema for the users table.

This module holds SQL only. It does not hash passwords, generate OTPs,
or apply login/lockout business rules.
"""

USERS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE
        CONSTRAINT username_not_blank CHECK (length(trim(username)) > 0),
    password_salt TEXT NOT NULL
        CONSTRAINT password_salt_not_blank CHECK (length(password_salt) > 0),
    password_hash TEXT NOT NULL
        CONSTRAINT password_hash_not_blank CHECK (length(password_hash) > 0),
    password_iterations INTEGER NOT NULL
        CONSTRAINT password_iterations_positive CHECK (password_iterations > 0),
    encrypted_totp_secret TEXT,
    pending_encrypted_totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0
        CONSTRAINT totp_enabled_flag CHECK (totp_enabled IN (0, 1)),
    last_accepted_totp_step INTEGER,
    failed_attempts INTEGER NOT NULL DEFAULT 0
        CONSTRAINT failed_attempts_non_negative CHECK (failed_attempts >= 0),
    locked_until TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_login TEXT,
    CONSTRAINT users_username_unique UNIQUE (username COLLATE NOCASE)
);
"""

EXPECTED_USER_COLUMNS = (
    "id",
    "username",
    "password_salt",
    "password_hash",
    "password_iterations",
    "encrypted_totp_secret",
    "pending_encrypted_totp_secret",
    "totp_enabled",
    "last_accepted_totp_step",
    "failed_attempts",
    "locked_until",
    "created_at",
    "last_login",
)
