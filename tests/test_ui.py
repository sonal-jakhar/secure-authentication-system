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
    at = AppTest.from_file(str(APP_PATH), default_timeout=90)
    at.run()
    assert not at.exception
    return at


def _open(at: AppTest, page: str) -> AppTest:
    at.session_state["nav_page"] = page
    at.run()
    assert not at.exception
    return at


def _register(at: AppTest, username: str = "alice", password: str = "password12") -> AppTest:
    _open(at, "Register")
    at.text_input(key="register_username").input(username)
    at.text_input(key="register_password").input(password)
    at.text_input(key="register_confirm").input(password)
    at.button(key="register_submit").click().run()
    assert not at.exception
    return at


def _login(
    at: AppTest,
    username: str = "alice",
    password: str = "password12",
    otp: str = "",
) -> AppTest:
    _open(at, "Login")
    at.text_input(key="login_username").input(username)
    at.text_input(key="login_password").input(password)
    at.text_input(key="login_otp").input(otp)
    at.button(key="login_submit").click().run()
    assert not at.exception
    return at


def _visible_text(at: AppTest) -> str:
    parts: list[str] = []
    for group in (at.title, at.header, at.subheader, at.markdown, at.text, at.caption):
        for item in group:
            value = getattr(item, "value", None)
            if value:
                parts.append(str(value))
    return " ".join(parts)


def test_unauthenticated_dashboard_is_blocked(app: AppTest):
    _open(app, "Dashboard")
    warning_text = " ".join(item.value for item in app.warning)
    assert "sign in" in warning_text.lower()
    assert "Welcome," not in _visible_text(app)


def test_register_and_login_through_the_interface(app: AppTest):
    _register(app)
    success_text = " ".join(item.value for item in app.success)
    assert "account created" in success_text.lower()
    _login(app)
    titles = [item.value for item in app.title]
    assert any("Dashboard" in str(title) for title in titles)
    assert app.session_state["auth_username"] == "alice"
    assert "Welcome, alice" in _visible_text(app)
    assert "password_hash" not in _visible_text(app)
    assert "password_salt" not in _visible_text(app)


def test_password_mismatch_is_rejected(app: AppTest):
    _open(app, "Register")
    app.text_input(key="register_username").input("alice")
    app.text_input(key="register_password").input("password12")
    app.text_input(key="register_confirm").input("password99")
    app.button(key="register_submit").click().run()
    error_text = " ".join(item.value for item in app.error)
    assert "do not match" in error_text.lower()
    assert "auth_username" not in app.session_state


def test_invalid_login_shows_generic_error(app: AppTest):
    _register(app)
    _login(app, password="wrong-password")
    error_text = " ".join(item.value for item in app.error)
    assert "invalid username, password, or one-time code" in error_text.lower()
    assert "auth_username" not in app.session_state


def test_logout_clears_authentication_state(app: AppTest):
    _register(app)
    _login(app)
    app.button(key="logout_button").click().run()
    assert "auth_username" not in app.session_state
    assert "enrol_manual_key" not in app.session_state
    _open(app, "Dashboard")
    warning_text = " ".join(item.value for item in app.warning)
    assert "sign in" in warning_text.lower()


def test_totp_enrolment_through_the_interface(app: AppTest):
    _register(app)
    _login(app)
    app.text_input(key="enrol_start_password").input("password12")
    app.button(key="start_totp_submit").click().run()
    assert app.session_state.get("enrol_manual_key")
    secret = app.session_state["enrol_manual_key"]
    code = pyotp.TOTP(secret, interval=30).now()
    app.text_input(key="enrol_confirm_password").input("password12")
    app.text_input(key="enrol_otp").input(code)
    app.button(key="confirm_totp_submit").click().run()
    assert "enrol_manual_key" not in app.session_state
    combined = _visible_text(app) + " " + " ".join(item.value for item in app.info)
    combined += " " + " ".join(item.value for item in app.success)
    assert "enabled" in combined.lower()


def test_case_study_page_is_educational(app: AppTest):
    _open(app, "Case study")
    text = _visible_text(app).lower()
    assert "linkedin" in text
    assert "6.5 million" in text
    assert "117 million" in text
    assert "sha-1" in text
    assert "pbkdf2" in text
    assert "does not authenticate" in text
