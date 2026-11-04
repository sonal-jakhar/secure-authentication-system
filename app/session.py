"""Authentication-related Streamlit session keys.

Streamlit session state is convenient for a lab demonstration. It is not a
production session manager (no signed cookies, idle timeout, or CSRF model).
"""

from __future__ import annotations

from collections.abc import MutableMapping

AUTH_USER_ID = "auth_user_id"
AUTH_USERNAME = "auth_username"
ENROL_QR_PNG = "enrol_qr_png"
ENROL_MANUAL_KEY = "enrol_manual_key"
NAV_PAGE = "nav_page"

_AUTH_KEYS = (
    AUTH_USER_ID,
    AUTH_USERNAME,
    ENROL_QR_PNG,
    ENROL_MANUAL_KEY,
)


def is_authenticated(state: MutableMapping) -> bool:
    return bool(state.get(AUTH_USERNAME))


def establish_session(state: MutableMapping, *, user_id: int, username: str) -> None:
    clear_enrolment(state)
    state[AUTH_USER_ID] = user_id
    state[AUTH_USERNAME] = username


def clear_enrolment(state: MutableMapping) -> None:
    state.pop(ENROL_QR_PNG, None)
    state.pop(ENROL_MANUAL_KEY, None)


def logout(state: MutableMapping) -> None:
    for key in _AUTH_KEYS:
        state.pop(key, None)


def login_error_message(code: str) -> str:
    if code == "locked":
        return "This account is temporarily locked. Try again later."
    return "Invalid username, password, or one-time code."
