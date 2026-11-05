"""Session helpers used by the Streamlit UI."""

from app.session import (
    AUTH_USER_ID,
    AUTH_USERNAME,
    ENROL_MANUAL_KEY,
    ENROL_QR_PNG,
    consume_flash,
    establish_session,
    is_authenticated,
    login_error_message,
    logout,
    set_flash,
)


def test_establish_and_logout_clear_auth_and_enrolment_state():
    state = {
        ENROL_QR_PNG: b"png",
        ENROL_MANUAL_KEY: "SECRET",
    }
    establish_session(state, user_id=3, username="alice")
    assert is_authenticated(state)
    assert ENROL_QR_PNG not in state
    assert ENROL_MANUAL_KEY not in state

    logout(state)
    assert not is_authenticated(state)
    assert AUTH_USERNAME not in state
    assert AUTH_USER_ID not in state


def test_flash_message_is_consumed_once():
    state: dict = {}
    set_flash(state, "Account created. You can sign in now.")
    first = consume_flash(state)
    second = consume_flash(state)
    assert first == ("Account created. You can sign in now.", "success")
    assert second is None


def test_login_error_messages_are_generic():
    assert "locked" in login_error_message("locked").lower()
    assert login_error_message("invalid_credentials") == (
        "Invalid username, password, or one-time code."
    )
    assert "hash" not in login_error_message("invalid_credentials").lower()
