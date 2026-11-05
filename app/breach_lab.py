"""Single-page Streamlit interface for fictional breach demonstrations."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import streamlit as st

import attack_sim
import leak_export
import seed_demo_users
import takeover_sim
from app.legacy_auth import get_legacy_connection
from src.auth.service import TotpEnrolmentError
from src.auth.totp import (
    TOTP_INTERVAL_SECONDS,
    generate_provisioning_uri,
    generate_qr_png,
)
from src.crypto.secret_vault import (
    SecretVaultError,
    decrypt_totp_secret,
)
from src.db.connection import get_connection
from src.db.users import get_user_by_username

DEMO_DATABASE_PATH = Path(__file__).resolve().parents[1] / "data" / "demo.db"
BREACH_LAB_STAGES = (
    "Seed Demo Users",
    "Simulate Database Breach",
    "Password Attack",
    "Account Takeover",
)


def render_breach_lab() -> None:
    stage = st.session_state.get("breach_lab_stage", BREACH_LAB_STAGES[0])
    st.caption("Fictional accounts in the isolated demo database only.")
    if stage == "Password Attack":
        _attack_section()
        return

    with st.container(border=True):
        if stage == "Seed Demo Users":
            _seed_section()
        elif stage == "Simulate Database Breach":
            _export_section()
        elif stage == "Account Takeover":
            _takeover_section()
        else:
            st.warning("Select a workflow stage from the sidebar.")


def _seed_section() -> None:
    st.subheader("Seed Demo Users")
    st.write("Create the fictional cohorts in `data/demo.db`.")
    if st.button("Seed demo users", key="lab_seed_button"):
        try:
            seed_demo_users.seed_demo_users()
        except (
            OSError,
            sqlite3.Error,
            RuntimeError,
            TypeError,
            ValueError,
            SecretVaultError,
            TotpEnrolmentError,
        ) as exc:
            st.error(f"Demo seeding failed: {exc}")
        else:
            st.success("Demo users are ready.")
            for key in (
                "lab_legacy_dump",
                "lab_secure_dump",
                "lab_legacy_attack",
                "lab_secure_attack",
            ):
                st.session_state.pop(key, None)

    st.dataframe(_demo_user_roster(), width="stretch", hide_index=True)


def _demo_user_roster() -> list[dict[str, str]]:
    if not DEMO_DATABASE_PATH.is_file():
        return []
    connection = get_legacy_connection(DEMO_DATABASE_PATH)
    try:
        legacy_names = {
            row["username"]
            for row in connection.execute("SELECT username FROM legacy_users")
        }
        try:
            secure_names = {
                row["username"]
                for row in connection.execute("SELECT username FROM users")
            }
        except Exception:
            secure_names = set()
    finally:
        connection.close()

    roster = []
    for cohort, users in (("A", seed_demo_users.COHORT_A), ("B", seed_demo_users.COHORT_B)):
        for _, username, _ in users:
            stores = []
            if username in legacy_names:
                stores.append("legacy_users")
            if username in secure_names:
                stores.append("users")
            roster.append(
                {
                    "username": username,
                    "stores": ", ".join(stores) if stores else "Not seeded",
                    "cohort": f"Cohort {cohort}",
                }
            )
    return roster


def _export_section() -> None:
    st.subheader("Simulate Database Breach")
    st.write("Export the stored fields visible in a database dump.")
    if st.button("Export demo database", key="lab_export_button"):
        try:
            legacy_dump, secure_dump = leak_export.export_breach_dump()
        except Exception:
            st.error("Could not export the demo database. Seed the demo users first.")
        else:
            st.session_state["lab_legacy_dump"] = legacy_dump
            st.session_state["lab_secure_dump"] = secure_dump
            st.session_state.pop("lab_legacy_attack", None)
            st.session_state.pop("lab_secure_attack", None)
            st.success("Demo database export is ready.")

    legacy_dump = st.session_state.get("lab_legacy_dump")
    secure_dump = st.session_state.get("lab_secure_dump")
    if legacy_dump is None or secure_dump is None:
        st.info("Export the demo database to view both stored dumps.")
        return

    legacy_col, secure_col = st.columns(2)
    with legacy_col:
        st.markdown("**Legacy dump**")
        st.dataframe(legacy_dump, width="stretch", hide_index=True)
    with secure_col:
        st.markdown("**Secure dump**")
        st.dataframe(secure_dump, width="stretch", hide_index=True)


def _attack_section() -> None:
    from src.auth.password import PBKDF2_ITERATIONS

    st.subheader("Password Attack")
    st.caption("Compare the exported legacy and secure password stores.")
    legacy_col, secure_col = st.columns(2)
    with legacy_col:
        with st.container(border=True):
            st.markdown("**Legacy · unsalted SHA-1**")
            st.write("Fast, deterministic hashes. Equal passwords produce equal hashes.")
            st.markdown("**Attack legacy dump**")
            if st.button("Run legacy attack", key="lab_legacy_attack_button"):
                dump = st.session_state.get("lab_legacy_dump")
                if dump is None:
                    st.warning("Export the demo database first.")
                else:
                    st.session_state["lab_legacy_attack"] = attack_sim.attack_legacy(
                        dump, attack_sim.load_wordlist()
                    )
            _render_attack_result(
                st.session_state.get("lab_legacy_attack"), "hashes_per_second"
            )

    with secure_col:
        with st.container(border=True):
            st.markdown("**Secure · salted PBKDF2-HMAC-SHA256**")
            st.write(
                f"Unique salts and {PBKDF2_ITERATIONS:,} iterations increase the cost "
                "of each guess; weak passwords are still guessable."
            )
            st.markdown("**Attack secure dump**")
            if st.button("Run secure attack", key="lab_secure_attack_button"):
                dump = st.session_state.get("lab_secure_dump")
                if dump is None:
                    st.warning("Export the demo database first.")
                else:
                    st.session_state["lab_secure_attack"] = attack_sim.attack_secure(
                        dump, attack_sim.load_wordlist()
                    )
            _render_attack_result(
                st.session_state.get("lab_secure_attack"), "guesses_per_second"
            )


def _render_attack_result(result: dict[str, object] | None, rate_key: str) -> None:
    if result is None:
        st.info("No results yet.")
        return

    metrics = st.columns(3)
    metrics[0].metric("Cracked", str(result["cracked_count"]))
    metrics[1].metric("Elapsed", f"{result['elapsed_seconds']:.2f} s")
    metrics[2].metric("Rate", f"{result[rate_key]:,.1f}/s")
    if "note" in result:
        st.caption(str(result["note"]))
    cracked_accounts = result["cracked_accounts"]
    if cracked_accounts:
        st.dataframe(cracked_accounts, width="stretch", hide_index=True)
    else:
        st.caption("No passwords matched the bundled candidate list.")


def _takeover_section() -> None:
    st.subheader("Account Takeover")
    usernames = [username for _, username, _ in seed_demo_users.COHORT_A]
    username = st.selectbox("Cohort A username", usernames, key="lab_takeover_user")
    store = st.radio(
        "Credential store",
        ("Legacy", "Secure"),
        horizontal=True,
        key="lab_takeover_store",
    )
    with st.form("lab_takeover_form"):
        password = st.text_input(
            "Recovered password", type="password", key="lab_takeover_password"
        )
        otp = None
        if store == "Secure":
            otp = st.text_input(
                "One-time code (required for this secure demo account)",
                key="lab_takeover_otp",
            )
        submitted = st.form_submit_button("Attempt takeover", key="lab_takeover_submit")

    show_qr = st.checkbox(
        "Show the secure account's TOTP QR code in this app",
        key="lab_takeover_show_qr",
    )
    if show_qr and store == "Secure":
        _show_totp_qr(username)

    if submitted:
        if store == "Legacy":
            result = takeover_sim.attempt_takeover_legacy(username, password)
        else:
            result = takeover_sim.attempt_takeover_secure(
                username, password, (otp or "").strip() or None
            )
        st.session_state["lab_takeover_result"] = (username, store, result)

    saved_result = st.session_state.get("lab_takeover_result")
    if saved_result:
        result_username, result_store, result = saved_result
        st.caption(f"Result for {result_username} in the {result_store.lower()} store.")
        if result_store == "Legacy":
            if result:
                st.success("Success: the password matches the legacy record.")
            else:
                st.error("Fail: the password did not match the legacy record.")
        elif result.code == "locked":
            st.warning("Locked: the secure service reports this account is temporarily locked.")
        elif result.success:
            st.success("Success: the secure service accepted the password and TOTP code.")
        else:
            st.error("Fail: secure login rejected the supplied password or one-time code.")


def _show_totp_qr(username: str) -> None:
    connection = get_connection(DEMO_DATABASE_PATH)
    try:
        user = get_user_by_username(connection, username)
    finally:
        connection.close()
    if user is None or not user["totp_enabled"] or not user["encrypted_totp_secret"]:
        st.warning("No confirmed TOTP setup is available for this account.")
        return
    try:
        secret = decrypt_totp_secret(user["encrypted_totp_secret"])
        uri = generate_provisioning_uri(secret, user["username"])
        qr_png = generate_qr_png(uri)
    except SecretVaultError as exc:
        st.error(f"TOTP display is unavailable: {exc}")
        return
    except ValueError:
        st.error("The stored TOTP enrollment is invalid and cannot be displayed.")
        return
    st.image(qr_png, caption="Scan with an authenticator app to generate a current code.")
    st.caption(
        "If you just seeded the demo, wait for the next "
        f"{TOTP_INTERVAL_SECONDS}-second code; the enrollment code was already used."
    )
