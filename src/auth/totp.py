"""TOTP secret, URI, QR, and verification helpers.

Verification returns the matching time-step so a later authentication
phase can compare it with last_accepted_totp_step. This module does not
read or write SQLite and does not enforce replay protection by itself.
"""

from __future__ import annotations

import hmac
import io
import re
import time
from dataclasses import dataclass

import pyotp
import qrcode

TOTP_INTERVAL_SECONDS = 30
TOTP_DIGITS = 6
TOTP_VALID_WINDOW = 1
DEFAULT_ISSUER = "Secure Authentication System"

_OTP_PATTERN = re.compile(rf"^\d{{{TOTP_DIGITS}}}$")


@dataclass(frozen=True)
class TotpVerificationResult:
    """Outcome of a TOTP check.

    accepted: True if the code matches the current step or one step of drift.
    step: the matching counter (unix_time // 30) when accepted, else None.
    """

    accepted: bool
    step: int | None


def generate_totp_secret() -> str:
    """Return a new random Base32 secret for an authenticator app."""
    return pyotp.random_base32()


def generate_provisioning_uri(
    secret: str,
    username: str,
    issuer: str = DEFAULT_ISSUER,
) -> str:
    """Return an otpauth:// URI that authenticator apps can import."""
    _require_secret(secret)
    if not isinstance(username, str) or username.strip() == "":
        raise ValueError("username must be a non-empty string")
    if not isinstance(issuer, str) or issuer.strip() == "":
        raise ValueError("issuer must be a non-empty string")
    totp = _build_totp(secret)
    return totp.provisioning_uri(name=username.strip(), issuer_name=issuer.strip())


def generate_qr_png(provisioning_uri: str) -> bytes:
    """Return PNG bytes for a QR code that encodes the provisioning URI."""
    if not isinstance(provisioning_uri, str) or provisioning_uri.strip() == "":
        raise ValueError("provisioning_uri must be a non-empty string")
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def verify_totp(
    secret: str,
    code: str,
    *,
    at_time: float | None = None,
) -> TotpVerificationResult:
    """Check a TOTP code against the secret.

    Accepts the current 30-second step and one step before or after
    (clock drift). Pass at_time in tests instead of waiting on the clock.

    Replay protection is not applied here. Callers should persist
    result.step and later reject codes whose step is not newer than
    last_accepted_totp_step.
    """
    _require_secret(secret)
    _require_otp_format(code)

    timestamp = time.time() if at_time is None else at_time
    totp = _build_totp(secret)
    current_step = int(timestamp) // TOTP_INTERVAL_SECONDS

    for offset in range(-TOTP_VALID_WINDOW, TOTP_VALID_WINDOW + 1):
        step = current_step + offset
        expected = totp.at(step * TOTP_INTERVAL_SECONDS)
        if hmac.compare_digest(expected, code):
            return TotpVerificationResult(accepted=True, step=step)

    return TotpVerificationResult(accepted=False, step=None)


def _build_totp(secret: str) -> pyotp.TOTP:
    return pyotp.TOTP(
        secret,
        digits=TOTP_DIGITS,
        interval=TOTP_INTERVAL_SECONDS,
    )


def _require_secret(secret: object) -> None:
    if not isinstance(secret, str) or secret.strip() == "":
        raise ValueError("TOTP secret must be a non-empty string")
    try:
        pyotp.TOTP(secret).at(0)
    except Exception as exc:
        raise ValueError("TOTP secret must be valid Base32") from exc


def _require_otp_format(code: object) -> None:
    if not isinstance(code, str) or _OTP_PATTERN.fullmatch(code) is None:
        raise ValueError(f"OTP must be a {TOTP_DIGITS}-digit string")
