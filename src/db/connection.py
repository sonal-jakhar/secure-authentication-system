"""SQLite connection helpers.

The database path comes from DATABASE_PATH in the environment (see
.env.example). Relative paths are resolved from the project root.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from dotenv import load_dotenv

from src.db.schema import USERS_TABLE_SQL

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_DATABASE_PATH = "data/users.db"


def get_database_path(raw_path: str | None = None) -> Path:
    """Return the SQLite file path from config, without machine-specific defaults."""
    load_dotenv(_PROJECT_ROOT / ".env")
    value = raw_path if raw_path is not None else os.getenv("DATABASE_PATH", _DEFAULT_DATABASE_PATH)
    path = Path(value)
    if not path.is_absolute():
        path = _PROJECT_ROOT / path
    return path


def get_connection(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Open a SQLite connection with row access by column name."""
    path = get_database_path(str(db_path) if db_path is not None else None)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(db_path: str | Path | None = None) -> Path:
    """Create the parent directory, database file, and users table if needed."""
    path = get_database_path(str(db_path) if db_path is not None else None)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = get_connection(path)
    try:
        connection.execute(USERS_TABLE_SQL)
        connection.commit()
    finally:
        connection.close()
    return path
