"""Educational hashing comparison. Not used by registration or login."""

from __future__ import annotations

import hashlib

from src.auth.password import PBKDF2_ITERATIONS, hash_password

# Fixed sample only. Never a real credential, and never sent to the auth service.
SAMPLE_DEMO_PASSWORD = "demo-only-sample-password"


def unsalted_sha1_hex(password: str) -> str:
    """Insecure hash used only to illustrate the LinkedIn 2012 storage mistake."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest()


def pbkdf2_demo_digest(password: str) -> tuple[str, str, int]:
    """Return (salt_hex, hash_hex, iterations) using the project's PBKDF2 helper."""
    return hash_password(password)
