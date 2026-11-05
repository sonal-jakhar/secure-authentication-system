"""Tests for the Breach Lab workspace navigation and stage routing."""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

import app.breach_lab as breach_lab
import seed_demo_users

APP_PATH = Path(__file__).resolve().parents[1] / "app.py"


@pytest.fixture
def app(tmp_path, monkeypatch, fernet_key) -> AppTest:
    demo_path = tmp_path / "demo.db"
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setattr(breach_lab, "DEMO_DATABASE_PATH", demo_path)
    monkeypatch.setattr(seed_demo_users, "DEMO_DATABASE_PATH", demo_path)
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
        "Legacy Account Migration": "Legacy Account Migration",
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
    app.button(key="lab_seed_button").click().run()

    assert not app.exception
    assert any("Demo users are ready" in item.value for item in app.success)
    assert breach_lab.DEMO_DATABASE_PATH.exists()
    assert not seed_demo_users.DEMO_DATABASE_PATH.samefile(
        Path(__file__).resolve().parents[1] / "data" / "demo.db"
    )
