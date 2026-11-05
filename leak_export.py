"""Export stored demo-database fields for the local breach simulation only."""

from __future__ import annotations

from pathlib import Path

from app.legacy_auth import DEFAULT_DEMO_DATABASE_PATH
from src.db.connection import get_connection

DEMO_DATABASE_PATH = DEFAULT_DEMO_DATABASE_PATH
_EXPORT_MARKER = object()


class _ExportedDump(list):
    __slots__ = ("_kind",)

    def __init__(self, rows, kind: str, marker: object) -> None:
        if marker is not _EXPORT_MARKER:
            raise TypeError("Dump rows must come from export_breach_dump().")
        super().__init__(rows)
        self._kind = kind


def _is_exported_dump(dump: object, kind: str) -> bool:
    return isinstance(dump, _ExportedDump) and dump._kind == kind


def export_breach_dump() -> tuple[
    list[dict[str, str]], list[dict[str, str | None]]
]:
    """Return only password-store fields visible in a demo database dump.

    Legacy records are identified by email; secure records are identified by
    username, matching the fields actually stored in each table.
    """
    if not Path(DEMO_DATABASE_PATH).is_file():
        raise FileNotFoundError("Demo database not found; seed it before exporting.")

    connection = get_connection(DEMO_DATABASE_PATH)
    try:
        legacy_dump = [
            dict(row)
            for row in connection.execute(
                "SELECT email, password_hash "
                "FROM legacy_users ORDER BY email COLLATE NOCASE"
            )
        ]
        secure_dump = [
            dict(row)
            for row in connection.execute(
                "SELECT users.username AS username, "
                "users.password_hash AS password_hash, "
                "users.password_salt AS salt, "
                "users.encrypted_totp_secret AS encrypted_totp_secret "
                "FROM users "
                "ORDER BY users.username COLLATE NOCASE"
            )
        ]
    finally:
        connection.close()

    return (
        _ExportedDump(legacy_dump, "legacy", _EXPORT_MARKER),
        _ExportedDump(secure_dump, "secure", _EXPORT_MARKER),
    )