"""SQLite database layer."""

from src.db.connection import get_connection, get_database_path, initialize_database
from src.db.schema import EXPECTED_USER_COLUMNS
from src.db.users import (
    DuplicateUsernameError,
    claim_totp_step,
    confirm_pending_totp_secret,
    get_user_by_id,
    get_user_by_username,
    insert_user,
    record_login_failure,
    record_login_success,
    set_pending_totp_secret,
)

__all__ = [
    "DuplicateUsernameError",
    "EXPECTED_USER_COLUMNS",
    "claim_totp_step",
    "confirm_pending_totp_secret",
    "get_connection",
    "get_database_path",
    "get_user_by_id",
    "get_user_by_username",
    "initialize_database",
    "insert_user",
    "record_login_failure",
    "record_login_success",
    "set_pending_totp_secret",
]
