"""Phase 4 tests for TOTP helpers. Timestamps are fixed; no real 30s waits."""

from __future__ import annotations

import pyotp
import pytest

from src.auth.totp import (
    TOTP_INTERVAL_SECONDS,
    generate_provisioning_uri,
    generate_qr_png,
    generate_totp_secret,
    verify_totp,
)

FIXED_TIME = 1_700_000_000


def test_totp_secret_generation():
    secret = generate_totp_secret()
    assert isinstance(secret, str)
    assert secret != generate_totp_secret()
    pyotp.TOTP(secret).at(FIXED_TIME)


def test_provisioning_uri_generation():
    secret = generate_totp_secret()
    uri = generate_provisioning_uri(secret, "alice")

    assert uri.startswith("otpauth://totp/")
    assert "alice" in uri
    assert "secret=" in uri
    assert "issuer=Secure%20Authentication%20System" in uri


def test_qr_code_generation():
    secret = generate_totp_secret()
    uri = generate_provisioning_uri(secret, "bob")
    png = generate_qr_png(uri)

    assert isinstance(png, bytes)
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    assert len(png) > 100


def test_valid_otp_is_accepted():
    secret = generate_totp_secret()
    code = pyotp.TOTP(secret, interval=TOTP_INTERVAL_SECONDS).at(FIXED_TIME)

    result = verify_totp(secret, code, at_time=FIXED_TIME)

    assert result.accepted is True
    assert result.step == FIXED_TIME // TOTP_INTERVAL_SECONDS


def test_invalid_otp_is_rejected():
    secret = generate_totp_secret()
    result = verify_totp(secret, "000000", at_time=FIXED_TIME)

    assert result.accepted is False
    assert result.step is None


def test_malformed_otp_is_rejected():
    secret = generate_totp_secret()

    with pytest.raises(ValueError):
        verify_totp(secret, "")
    with pytest.raises(ValueError):
        verify_totp(secret, "12345")
    with pytest.raises(ValueError):
        verify_totp(secret, "1234567")
    with pytest.raises(ValueError):
        verify_totp(secret, "12a456")
    with pytest.raises(ValueError):
        verify_totp(secret, "123 456")
    with pytest.raises(ValueError):
        verify_totp(secret, None)  # type: ignore[arg-type]


def test_otp_within_clock_drift_window_is_accepted():
    secret = generate_totp_secret()
    totp = pyotp.TOTP(secret, interval=TOTP_INTERVAL_SECONDS)
    previous_code = totp.at(FIXED_TIME - TOTP_INTERVAL_SECONDS)
    next_code = totp.at(FIXED_TIME + TOTP_INTERVAL_SECONDS)
    outside_code = totp.at(FIXED_TIME - (2 * TOTP_INTERVAL_SECONDS))

    previous = verify_totp(secret, previous_code, at_time=FIXED_TIME)
    nxt = verify_totp(secret, next_code, at_time=FIXED_TIME)
    outside = verify_totp(secret, outside_code, at_time=FIXED_TIME)

    assert previous.accepted is True
    assert previous.step == (FIXED_TIME - TOTP_INTERVAL_SECONDS) // TOTP_INTERVAL_SECONDS
    assert nxt.accepted is True
    assert nxt.step == (FIXED_TIME + TOTP_INTERVAL_SECONDS) // TOTP_INTERVAL_SECONDS
    assert outside.accepted is False
    assert outside.step is None
