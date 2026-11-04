"""Streamlit AppTest coverage for registration, login, TOTP setup, and logout."""

from __future__ import annotations

from pathlib import Path

import pyotp
import pytest
from streamlit.testing.v1 import AppTest

APP_PATH = Path(__file__).resolve().parents[1] / "app.py"


@pytest.fixture
def app(tmp_path, monkeypatch, fernet_key) -> AppTest:
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "ui_users.db"))
    at = AppTest.from_file(str(APP_PATH), default_timeout=60)
    at.run()
    assert not at.exception
    return at


def _open(at: AppTest, page: str) -> AppTest:
    at.sidebar.radio[0].set_value(page)
    at.run()
    assert not at.exception
    return at


def _register(at: AppTest, username: str = "alice", password: str = "password12") -> AppTest:
    _open(at, "Register")
    at.text_input("Choose a username").input(username)
    at.text_input("Password").input(password)
    at.text_input("Confirm password").input(password)
    at.button("Create account").click().run()
    assert not at.exception
    return at


def _login(
    at: AppTest,
    username: str = "alice",
    password: str = "password12",
    otp: str = "",
) -> AppTest:
    _open(at, "Login")
    at.text_input("Username").input(username)
    at.text_input("Password").input(password)
    at.text_input("One-time code (if 2FA is enabled)").input(otp)
    at.button("Sign in").click().run()
    assert not at.exception
    return at


def test_unauthenticated_dashboard_is_blocked(app: AppTest):
    _open(app, "Dashboard")
    warning_text = " ".join(item.value for item in app.warning)
    assert "sign in" in warning_text.lower()
    markdown = " ".join(getattr(item, "value", "") or "" for item in app.markdown)
    assert "Welcome," not in markdown


def test_register_and_login_through_the_interface(app: AppTest):
    _register(app)
    _login(app)
    titles = [item.value for item in app.title]
    assert any("Dashboard" in str(title) for title in titles)
    assert app.session_state["auth_username"] == "alice"


def test_logout_clears_authentication_state(app: AppTest):
    _register(app)
    _login(app)
    app.button("Log out").click().run()
    assert "auth_username" not in app.session_state
    _open(app, "Dashboard")
    warning_text = " ".join(item.value for item in app.warning)
    assert "sign in" in warning_text.lower()


def test_totp_enrolment_through_the_interface(app: AppTest):
    _register(app)
    _login(app)
    app.text_input("Account password").input("password12")
    app.button("Generate authenticator QR code").click().run()
    assert app.session_state.get("enrol_manual_key")
    secret = app.session_state["enrol_manual_key"]
    code = pyotp.TOTP(secret, interval=30).now()
    confirm_password = [
        widget
        for widget in app.text_input
        if widget.label == "Account password" and widget.key == "enrol_confirm_password"
    ]
    if confirm_password:
        confirm_password[0].input("password12")
    else:
        app.text_input["enrol_confirm_password"].input("password12")
    app.text_input("6-digit code from your authenticator").input(code)
    app.button("Confirm and enable 2FA").click().run()
    assert "enrol_manual_key" not in app.session_state
    info_text = " ".join(item.value for item in app.info)
    assert "enabled" in info_text.lower()
