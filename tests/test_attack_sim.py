"""Correctness tests for the local demo breach attack simulation."""

from __future__ import annotations

import time

import pyotp
import pytest

import attack_sim
import leak_export
from app.legacy_auth import get_legacy_connection, legacy_register
from seed_demo_users import COHORT_A
from src.auth.service import confirm_totp_enrolment, register_user, start_totp_enrolment
from src.db.connection import initialize_database


def _build_demo_database(path, monkeypatch, fernet_key):
    monkeypatch.setattr(leak_export, "DEMO_DATABASE_PATH", path)
    initialize_database(path)
    connection = get_legacy_connection(path)
    return connection


def test_legacy_attack_recovers_every_seeded_cohort_a_password(
    tmp_path, monkeypatch, fernet_key
):
    connection = _build_demo_database(tmp_path / "demo.db", monkeypatch, fernet_key)
    expected = {}
    try:
        for email, username, password in COHORT_A:
            legacy_register(connection, email, username, password)
            expected[email] = password
    finally:
        connection.close()

    legacy_dump, _ = leak_export.export_breach_dump()
    wordlist = attack_sim.load_wordlist()
    assert {password for _, _, password in COHORT_A} <= set(wordlist)

    result = attack_sim.attack_legacy(legacy_dump, wordlist)

    assert result["cracked_count"] == len(expected)
    assert {
        account["email"]: account["password"]
        for account in result["cracked_accounts"]
    } == expected


def test_secure_attack_cracks_correct_first_candidate(
    tmp_path, monkeypatch, fernet_key
):
    database_path = tmp_path / "demo.db"
    connection = _build_demo_database(database_path, monkeypatch, fernet_key)
    email = "first_guess@example.test"
    username = "first_guess"
    password = "fictional-first-guess-password"
    try:
        legacy_register(connection, email, username, password)
        register_user(connection, username, password)
        enrollment = start_totp_enrolment(connection, username, password)
        code = pyotp.parse_uri(enrollment.provisioning_uri).now()
        confirm_totp_enrolment(connection, username, password, code)
    finally:
        connection.close()

    _, secure_dump = leak_export.export_breach_dump()
    result = attack_sim.attack_secure(
        secure_dump,
        [password, "fictional-incorrect-password"],
        time_budget_seconds=5,
    )

    assert result["cracked_count"] == 1
    assert result["cracked_accounts"] == [{"email": email, "password": password}]
    assert "time-boxed sample" in result["note"].lower()


def test_secure_attack_stops_near_its_budget_without_a_match(
    tmp_path, monkeypatch, fernet_key
):
    database_path = tmp_path / "demo.db"
    connection = _build_demo_database(database_path, monkeypatch, fernet_key)
    email = "budget_test@example.test"
    username = "budget_test"
    try:
        legacy_register(connection, email, username, "fictional-correct-password")
        register_user(connection, username, "fictional-correct-password")
    finally:
        connection.close()

    _, secure_dump = leak_export.export_breach_dump()
    budget = 0.1
    started = time.perf_counter()
    result = attack_sim.attack_secure(
        secure_dump,
        [f"fictional-wrong-password-{index}" for index in range(5000)],
        time_budget_seconds=budget,
    )
    wall_elapsed = time.perf_counter() - started

    assert result["cracked_count"] == 0
    assert wall_elapsed <= budget + 2.0


def test_secure_attack_handles_empty_dump():
    result = attack_sim.attack_secure([], attack_sim.load_wordlist())

    assert result["cracked_count"] == 0
    assert result["cracked_accounts"] == []


def test_attack_rejects_non_export_dump_shapes():
    with pytest.raises(ValueError, match="export_breach_dump"):
        attack_sim.attack_legacy(
            [{"email": "outside@example.test", "password_hash": "abc"}],
            ["password"],
        )