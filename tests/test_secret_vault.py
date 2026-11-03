"""Phase 4 tests for Fernet TOTP-secret encryption. Keys stay in the test env."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from src.crypto.secret_vault import (
    CorruptedCiphertextError,
    InvalidFernetKeyError,
    MissingFernetKeyError,
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_fernet_key,
)


@pytest.fixture
def fernet_key(monkeypatch: pytest.MonkeyPatch) -> str:
    key = generate_fernet_key()
    monkeypatch.setenv("FERNET_KEY", key)
    return key


def test_fernet_encrypt_decrypt_round_trip(fernet_key: str):
    secret = "JBSWY3DPEHPK3PXP"
    token = encrypt_totp_secret(secret)
    assert decrypt_totp_secret(token) == secret
    assert token != secret


def test_repeated_encryption_produces_different_ciphertexts(fernet_key: str):
    secret = "JBSWY3DPEHPK3PXP"
    first = encrypt_totp_secret(secret)
    second = encrypt_totp_secret(secret)
    assert first != second
    assert decrypt_totp_secret(first) == secret
    assert decrypt_totp_secret(second) == secret


def test_invalid_fernet_key_is_rejected(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FERNET_KEY", "not-a-valid-fernet-key")
    with pytest.raises(InvalidFernetKeyError):
        encrypt_totp_secret("JBSWY3DPEHPK3PXP")


def test_corrupted_ciphertext_is_rejected(fernet_key: str):
    token = encrypt_totp_secret("JBSWY3DPEHPK3PXP")
    corrupted = ("A" if token[0] != "A" else "B") + token[1:]
    with pytest.raises(CorruptedCiphertextError):
        decrypt_totp_secret(corrupted)


def test_missing_fernet_key_is_rejected(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FERNET_KEY", "")
    with pytest.raises(MissingFernetKeyError):
        encrypt_totp_secret("JBSWY3DPEHPK3PXP")


def test_generate_fernet_key_is_usable():
    key = generate_fernet_key()
    fernet = Fernet(key.encode("ascii"))
    token = fernet.encrypt(b"probe")
    assert fernet.decrypt(token) == b"probe"
