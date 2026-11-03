"""Fernet encryption for TOTP secrets stored at rest.

This module does not log or print plaintext secrets or keys.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


class SecretVaultError(Exception):
    """Base error for TOTP secret encryption."""


class MissingFernetKeyError(SecretVaultError):
    """FERNET_KEY is unset or blank."""


class InvalidFernetKeyError(SecretVaultError):
    """FERNET_KEY is present but is not a valid Fernet key."""


class CorruptedCiphertextError(SecretVaultError):
    """Ciphertext is not a valid Fernet token for the configured key."""


def generate_fernet_key() -> str:
    """Return a new url-safe Fernet key for placing in .env (not in source)."""
    return Fernet.generate_key().decode("ascii")


def encrypt_totp_secret(plaintext_secret: str) -> str:
    """Encrypt a TOTP secret and return the Fernet token as text."""
    if not isinstance(plaintext_secret, str) or plaintext_secret == "":
        raise ValueError("TOTP secret must be a non-empty string")
    token = _fernet_from_env().encrypt(plaintext_secret.encode("utf-8"))
    return token.decode("ascii")


def decrypt_totp_secret(ciphertext: str) -> str:
    """Decrypt a Fernet token back to the TOTP secret."""
    if not isinstance(ciphertext, str) or ciphertext == "":
        raise ValueError("ciphertext must be a non-empty string")
    try:
        token = ciphertext.encode("ascii")
    except UnicodeEncodeError as exc:
        raise CorruptedCiphertextError("ciphertext is not valid Fernet token text") from exc
    try:
        plaintext = _fernet_from_env().decrypt(token)
    except InvalidToken as exc:
        raise CorruptedCiphertextError("ciphertext is corrupted or was encrypted with another key") from exc
    return plaintext.decode("utf-8")


def _fernet_from_env() -> Fernet:
    load_dotenv(_PROJECT_ROOT / ".env")
    raw = os.getenv("FERNET_KEY")
    if raw is None or raw.strip() == "":
        raise MissingFernetKeyError("FERNET_KEY is missing. Set it in the environment or .env")
    key = raw.strip().encode("ascii")
    try:
        return Fernet(key)
    except (ValueError, TypeError) as exc:
        raise InvalidFernetKeyError("FERNET_KEY is not a valid Fernet key") from exc
