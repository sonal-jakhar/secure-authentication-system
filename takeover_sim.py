"""Fictional account-takeover demonstrations against the isolated demo DB."""

from __future__ import annotations

from pathlib import Path

from app.legacy_auth import get_legacy_connection, legacy_verify
from src.auth.service import AuthResult, login
from src.db.connection import get_connection

DEMO_DATABASE_PATH = Path(__file__).resolve().parent / "data" / "demo.db"


def attempt_takeover_legacy(username: str, cracked_password: str) -> bool:
    """Verify a fictional password against the legacy demo store."""
    connection = get_legacy_connection(DEMO_DATABASE_PATH)
    try:
        row = connection.execute(
            "SELECT email FROM legacy_users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()
        if row is None:
            return False
        return legacy_verify(connection, row["email"], cracked_password)
    finally:
        connection.close()


def attempt_takeover_secure(
    username: str,
    cracked_password: str,
    otp: str | None = None,
) -> AuthResult:
    """Call the existing secure login flow against the demo database."""
    connection = get_connection(DEMO_DATABASE_PATH)
    try:
        return login(connection, username, cracked_password, otp)
    finally:
        connection.close()