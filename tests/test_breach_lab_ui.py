"""Tests for the Breach Lab workspace navigation and stage routing."""

from __future__ import annotations

import time
from pathlib import Path

import pyotp
import pytest
from streamlit.testing.v1 import AppTest

import app.breach_lab as breach_lab
import leak_export
import seed_demo_users
import takeover_sim
from seed_demo_users import COHORT_A
from src.auth.totp import TOTP_INTERVAL_SECONDS
from src.crypto.secret_vault import decrypt_totp_secret
from src.db.connection import get_connection, initialize_database
from src.db.users import get_user_by_username

APP_PATH = Path(__file__).resolve().parents[1] / "app.py"


@pytest.fixture
def app(tmp_path, monkeypatch, fernet_key) -> AppTest:
    demo_path = tmp_path / "demo.db"
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setattr(breach_lab, "DEMO_DATABASE_PATH", demo_path)
    monkeypatch.setattr(leak_export, "DEMO_DATABASE_PATH", demo_path)
    monkeypatch.setattr(seed_demo_users, "DEMO_DATABASE_PATH", demo_path)
    monkeypatch.setattr(takeover_sim, "DEMO_DATABASE_PATH", demo_path)
    test_app = AppTest.from_file(str(APP_PATH), default_timeout=90)
    test_app.run()
    assert not test_app.exception
    return test_app


def _visible_text(test_app: AppTest) -> str:
    parts = []
    for group in (
        test_app.title,
        test_app.header,
        test_app.subheader,
        test_app.markdown,
        test_app.text,
        test_app.caption,
    ):
        parts.extend(
            str(item.value)
            for item in group
            if getattr(item, "value", None)
        )
    return " ".join(parts)


def test_workspace_header_and_single_stage_routing(app: AppTest):
    account_text = _visible_text(app)
    assert "Secure Authentication Lab" in account_text
    assert "LinkedIn Password Breach (2012)" in account_text
    assert "LOCAL DEMO" in account_text
    assert "Sign in" in account_text

    app.session_state["app_section"] = "Breach Lab"
    app.session_state["breach_lab_stage"] = breach_lab.BREACH_LAB_STAGES[0]
    app.run()
    assert not app.exception

    expected_titles = {
        "Seed Demo Users": "Seed Demo Users",
        "Simulate Database Breach": "Simulate Database Breach",
        "Password Attack": "Password Attack",
        "Account Takeover": "Account Takeover",
    }
    for stage, expected_title in expected_titles.items():
        app.session_state["breach_lab_stage"] = stage
        app.run()
        assert not app.exception
        visible_stage_titles = {
            str(item.value)
            for item in app.subheader
            if str(item.value) in expected_titles.values()
        }
        assert visible_stage_titles == {expected_title}


def test_seed_action_stays_in_temporary_demo_database(app: AppTest):
    app.session_state["app_section"] = "Breach Lab"
    app.session_state["breach_lab_stage"] = "Seed Demo Users"
    app.run()
    app.button(key="lab_seed_button").click().run(timeout=300)
    app.button(key="lab_seed_button").click().run(timeout=300)

    assert not app.exception
    assert any("Demo users are ready" in item.value for item in app.success)
    assert breach_lab.DEMO_DATABASE_PATH.exists()
    assert not seed_demo_users.DEMO_DATABASE_PATH.samefile(
        Path(__file__).resolve().parents[1] / "data" / "demo.db"
    )

    app.session_state["breach_lab_stage"] = "Simulate Database Breach"
    app.run()
    app.button(key="lab_export_button").click().run()
    assert not app.exception
    assert any("Demo database export is ready" in item.value for item in app.success)


def test_seed_action_displays_the_specific_failure(app: AppTest, monkeypatch):
    def fail_seeding():
        raise RuntimeError("FERNET_KEY is not a valid Fernet key")

    monkeypatch.setattr(seed_demo_users, "seed_demo_users", fail_seeding)
    app.session_state["app_section"] = "Breach Lab"
    app.session_state["breach_lab_stage"] = "Seed Demo Users"
    app.run()
    app.button(key="lab_seed_button").click().run()

    assert not app.exception
    assert any(
        "FERNET_KEY is not a valid Fernet key" in item.value
        for item in app.error
    )


def test_takeover_requires_totp_and_shows_selected_users_qr(app: AppTest, monkeypatch):
    seed_demo_users.seed_demo_users()
    _, username, password = COHORT_A[0]
    app.session_state["app_section"] = "Breach Lab"
    app.session_state["breach_lab_stage"] = "Account Takeover"
    app.session_state["lab_takeover_store"] = "Secure"
    app.run()
    assert not app.exception
    assert any(
        "required for this secure demo account" in item.label
        for item in app.text_input
    )

    requested_usernames = []
    generate_uri = breach_lab.generate_provisioning_uri

    def record_qr_username(secret, qr_username, issuer="Secure Authentication System"):
        requested_usernames.append(qr_username)
        return generate_uri(secret, qr_username, issuer)

    monkeypatch.setattr(breach_lab, "generate_provisioning_uri", record_qr_username)
    app.checkbox(key="lab_takeover_show_qr").check().run()
    assert not app.exception
    assert len(app.image) == 1
    assert requested_usernames == [username]
    assert any("wait for the next" in item.value for item in app.caption)

    app.text_input(key="lab_takeover_password").input(password)
    app.button(key="lab_takeover_submit").click().run()
    assert not app.exception
    assert any("secure login rejected" in item.value.lower() for item in app.error)
    assert not app.success

    connection = get_connection(breach_lab.DEMO_DATABASE_PATH)
    try:
        user = get_user_by_username(connection, username)
        assert user is not None
        secret = decrypt_totp_secret(user["encrypted_totp_secret"])
        current_step = int(time.time()) // TOTP_INTERVAL_SECONDS
        totp = pyotp.TOTP(secret, interval=TOTP_INTERVAL_SECONDS)
        valid_codes = {
            totp.at((current_step + offset) * TOTP_INTERVAL_SECONDS)
            for offset in (-1, 0, 1)
        }
        invalid_otp = next(
            f"{candidate:06d}"
            for candidate in range(1_000_000)
            if f"{candidate:06d}" not in valid_codes
        )
        accepted_step = user["last_accepted_totp_step"]
        login_step = max(current_step, accepted_step + 1)
        valid_otp = totp.at(login_step * TOTP_INTERVAL_SECONDS)
    finally:
        connection.close()

    app.text_input(key="lab_takeover_otp").input(invalid_otp)
    app.button(key="lab_takeover_submit").click().run()
    assert not app.exception
    assert any("secure login rejected" in item.value.lower() for item in app.error)
    assert not app.success

    app.text_input(key="lab_takeover_otp").input(valid_otp)
    app.button(key="lab_takeover_submit").click().run()
    assert not app.exception
    assert any("accepted the password and TOTP code" in item.value for item in app.success)


def test_totp_qr_missing_enrollment_is_explained(app: AppTest):
    initialize_database(breach_lab.DEMO_DATABASE_PATH)
    app.session_state["app_section"] = "Breach Lab"
    app.session_state["breach_lab_stage"] = "Account Takeover"
    app.session_state["lab_takeover_store"] = "Secure"
    app.session_state["lab_takeover_show_qr"] = True
    app.run()

    assert not app.exception
    assert any(
        "No confirmed TOTP setup is available" in item.value
        for item in app.warning
    )
    assert not app.image
