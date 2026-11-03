"""PBKDF2-HMAC-SHA256 password hashing.

This module only hashes and verifies passwords. It does not register users,
log anyone in, or write to the database.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

PBKDF2_HASH_NAME = "sha256"
PBKDF2_ITERATIONS = 600_000
SALT_LENGTH_BYTES = 16
DERIVED_KEY_LENGTH_BYTES = 32


def hash_password(password: str) -> tuple[str, str, int]:
    """Return (salt_hex, hash_hex, iterations) for a new password.

    A fresh 16-byte salt is generated for every call.
    """
    password_bytes = _password_bytes(password)
    salt = secrets.token_bytes(SALT_LENGTH_BYTES)
    derived = hashlib.pbkdf2_hmac(
        PBKDF2_HASH_NAME,
        password_bytes,
        salt,
        PBKDF2_ITERATIONS,
        dklen=DERIVED_KEY_LENGTH_BYTES,
    )
    return salt.hex(), derived.hex(), PBKDF2_ITERATIONS


def verify_password(
    password: str,
    salt: str,
    stored_hash: str,
    iterations: int,
) -> bool:
    """Return True if password matches the stored salt, hash, and iteration count."""
    password_bytes = _password_bytes(password)
    salt_bytes = _parse_hex_bytes(salt, SALT_LENGTH_BYTES, "salt")
    stored_hash_bytes = _parse_hex_bytes(
        stored_hash, DERIVED_KEY_LENGTH_BYTES, "stored_hash"
    )
    iteration_count = _parse_iterations(iterations)
    derived = hashlib.pbkdf2_hmac(
        PBKDF2_HASH_NAME,
        password_bytes,
        salt_bytes,
        iteration_count,
        dklen=DERIVED_KEY_LENGTH_BYTES,
    )
    return hmac.compare_digest(derived, stored_hash_bytes)


def _password_bytes(password: object) -> bytes:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if password == "":
        raise ValueError("password must not be empty")
    return password.encode("utf-8")


def _parse_hex_bytes(value: object, expected_length: int, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a hexadecimal string")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid hexadecimal") from exc
    if len(decoded) != expected_length:
        raise ValueError(
            f"{field_name} must decode to exactly {expected_length} bytes"
        )
    return decoded


def _parse_iterations(iterations: object) -> int:
    if isinstance(iterations, bool) or not isinstance(iterations, int):
        raise TypeError("iterations must be an integer")
    if iterations < 1:
        raise ValueError("iterations must be a positive integer")
    return iterations
