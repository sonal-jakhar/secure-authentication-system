"""Authentication helpers and workflows."""

from src.auth.password import hash_password, verify_password
from src.auth.service import (
    AuthResult,
    SecurityPolicy,
    TotpEnrolment,
    TotpEnrolmentError,
    confirm_totp_enrolment,
    login,
    register_user,
    start_totp_enrolment,
)
from src.auth.totp import (
    TotpVerificationResult,
    generate_provisioning_uri,
    generate_qr_png,
    generate_totp_secret,
    verify_totp,
)

__all__ = [
    "AuthResult",
    "SecurityPolicy",
    "TotpEnrolment",
    "TotpEnrolmentError",
    "TotpVerificationResult",
    "confirm_totp_enrolment",
    "generate_provisioning_uri",
    "generate_qr_png",
    "generate_totp_secret",
    "hash_password",
    "login",
    "register_user",
    "start_totp_enrolment",
    "verify_password",
    "verify_totp",
]
