"""Bounded offline attack simulation for this project's exported demo dumps.

No hash-file, network, or external-target input is supported. PBKDF2 at
600,000 iterations is computationally expensive, not literally uncrackable;
the secure simulation is time-boxed and does not claim exhaustive recovery.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Iterable, Mapping
from pathlib import Path

from leak_export import _is_exported_dump
from src.auth.password import PBKDF2_ITERATIONS, verify_password

WORDLIST_PATH = Path(__file__).with_name("wordlist.txt")
# Synthetic weak-password patterns are informed by NIST SP 800-63B section
# 5.1.1.2 and the OWASP Authentication Cheat Sheet's blocklist guidance; no
# breach-derived password corpus is bundled.
LEGACY_FIELDS = {"email", "password_hash"}
SECURE_FIELDS = {"email", "password_hash", "salt", "encrypted_totp_secret"}
SECURE_SAMPLE_NOTE = (
    f"Time-boxed sample using {PBKDF2_ITERATIONS:,} PBKDF2 iterations per guess; "
    "PBKDF2 is computationally expensive, not impossible to crack. "
    "This is not an exhaustive search."
)


def load_wordlist() -> list[str]:
    """Load only the bundled, synthetic candidate list."""
    return [
        line.strip()
        for line in WORDLIST_PATH.read_text(encoding="ascii").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def attack_legacy(
    dump: Iterable[Mapping[str, object]],
    wordlist: Iterable[str],
) -> dict[str, object]:
    """Match exported unsalted SHA-1 rows against candidate passwords."""
    entries = _validate_dump(dump, LEGACY_FIELDS, "legacy")
    started = time.perf_counter()

    # Candidate hashes are computed once, then reused for every exported row.
    hash_to_password: dict[str, str] = {}
    for candidate in wordlist:
        if isinstance(candidate, str):
            digest = hashlib.sha1(
                candidate.encode("utf-8"), usedforsecurity=False
            ).hexdigest()
            hash_to_password.setdefault(digest, candidate)

    cracked_accounts = []
    for entry in entries:
        password = hash_to_password.get(entry["password_hash"])
        if password is not None:
            cracked_accounts.append({"email": entry["email"], "password": password})

    elapsed = time.perf_counter() - started
    return {
        "cracked_count": len(cracked_accounts),
        "elapsed_seconds": elapsed,
        "hashes_per_second": len(hash_to_password) / max(elapsed, 1e-12),
        "cracked_accounts": cracked_accounts,
    }


def attack_secure(
    dump: Iterable[Mapping[str, object]],
    wordlist: Iterable[str],
    time_budget_seconds: float = 30,
) -> dict[str, object]:
    """Try bundled-wordlist candidates against exported PBKDF2 rows until timeout."""
    entries = _validate_dump(dump, SECURE_FIELDS, "secure")
    candidates = [candidate for candidate in wordlist if isinstance(candidate, str)]
    started = time.perf_counter()
    deadline = started + max(0.0, float(time_budget_seconds))
    guesses = 0
    cracked_accounts = []

    for entry in entries:
        for candidate in candidates:
            if time.perf_counter() >= deadline:
                break
            guesses += 1
            try:
                matched = verify_password(
                    candidate,
                    entry["salt"],
                    entry["password_hash"],
                    PBKDF2_ITERATIONS,
                )
            except (TypeError, ValueError):
                matched = False
            if matched:
                cracked_accounts.append(
                    {"email": entry["email"], "password": candidate}
                )
                break
        if time.perf_counter() >= deadline:
            break

    elapsed = time.perf_counter() - started
    return {
        "cracked_count": len(cracked_accounts),
        "elapsed_seconds": elapsed,
        "guesses_per_second": guesses / max(elapsed, 1e-12),
        "cracked_accounts": cracked_accounts,
        "note": SECURE_SAMPLE_NOTE,
    }


def _validate_dump(
    dump: Iterable[Mapping[str, object]],
    expected_fields: set[str],
    expected_kind: str,
) -> list[dict[str, object]]:
    raw_entries = list(dump)
    if not raw_entries:
        return []
    if not _is_exported_dump(dump, expected_kind):
        raise ValueError("Input must come from export_breach_dump().")

    entries = []
    for entry in raw_entries:
        if not isinstance(entry, Mapping) or set(entry) != expected_fields:
            raise ValueError("Input must use the corresponding exported dump fields.")
        if not isinstance(entry.get("email"), str):
            raise ValueError("Exported dump entries must include an email.")
        if not isinstance(entry.get("password_hash"), str):
            raise ValueError("Exported dump entries must include a password hash.")
        entries.append(dict(entry))
    return entries