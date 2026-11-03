"""Phase 3 tests for PBKDF2 password hashing."""

from __future__ import annotations

import pytest

from src.auth.password import (
    DERIVED_KEY_LENGTH_BYTES,
    PBKDF2_ITERATIONS,
    SALT_LENGTH_BYTES,
    hash_password,
    verify_password,
)

PASSWORD = "correct-horse-battery-staple"


def test_correct_password_verifies():
    salt, stored_hash, iterations = hash_password(PASSWORD)
    assert verify_password(PASSWORD, salt, stored_hash, iterations) is True


def test_incorrect_password_is_rejected():
    salt, stored_hash, iterations = hash_password(PASSWORD)
    assert verify_password("wrong-password", salt, stored_hash, iterations) is False


def test_identical_passwords_get_different_salts():
    salt_one, _, _ = hash_password(PASSWORD)
    salt_two, _, _ = hash_password(PASSWORD)
    assert salt_one != salt_two


def test_identical_passwords_with_different_salts_get_different_hashes():
    _, hash_one, _ = hash_password(PASSWORD)
    _, hash_two, _ = hash_password(PASSWORD)
    assert hash_one != hash_two


def test_empty_password_is_rejected_on_hash_and_verify():
    salt, stored_hash, iterations = hash_password(PASSWORD)

    with pytest.raises(ValueError, match="empty"):
        hash_password("")

    with pytest.raises(ValueError, match="empty"):
        verify_password("", salt, stored_hash, iterations)


def test_invalid_salt_hash_and_iteration_inputs_are_rejected():
    salt, stored_hash, iterations = hash_password(PASSWORD)

    with pytest.raises(TypeError):
        hash_password(None)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        verify_password(PASSWORD, None, stored_hash, iterations)  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        verify_password(PASSWORD, "not-hex", stored_hash, iterations)

    with pytest.raises(ValueError):
        verify_password(PASSWORD, "aa", stored_hash, iterations)

    with pytest.raises(TypeError):
        verify_password(PASSWORD, salt, None, iterations)  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        verify_password(PASSWORD, salt, "zzzz", iterations)

    with pytest.raises(ValueError):
        verify_password(PASSWORD, salt, "aa", iterations)

    with pytest.raises(TypeError):
        verify_password(PASSWORD, salt, stored_hash, "600000")  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        verify_password(PASSWORD, salt, stored_hash, True)  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        verify_password(PASSWORD, salt, stored_hash, 0)

    with pytest.raises(ValueError):
        verify_password(PASSWORD, salt, stored_hash, -1)


def test_hash_output_length_and_iteration_count():
    salt, stored_hash, iterations = hash_password(PASSWORD)

    assert iterations == PBKDF2_ITERATIONS
    assert iterations == 600_000
    assert len(bytes.fromhex(salt)) == SALT_LENGTH_BYTES
    assert len(bytes.fromhex(salt)) == 16
    assert len(bytes.fromhex(stored_hash)) == DERIVED_KEY_LENGTH_BYTES
    assert len(bytes.fromhex(stored_hash)) == 32
    assert len(salt) == SALT_LENGTH_BYTES * 2
    assert len(stored_hash) == DERIVED_KEY_LENGTH_BYTES * 2
