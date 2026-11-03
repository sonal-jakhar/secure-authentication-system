"""Shared fixtures. Tests use a temporary SQLite file, never data/users.db."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.crypto.secret_vault import generate_fernet_key
from src.db.connection import get_connection, initialize_database


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "test_users.db"
    initialize_database(path)
    return path


@pytest.fixture
def db_connection(db_path: Path):
    connection = get_connection(db_path)
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture
def fernet_key(monkeypatch: pytest.MonkeyPatch) -> str:
    key = generate_fernet_key()
    monkeypatch.setenv("FERNET_KEY", key)
    return key
