"""Single-page Streamlit interface for fictional breach demonstrations."""

from __future__ import annotations

from pathlib import Path

import streamlit as st

import attack_sim
import leak_export
import migrate_on_login
import seed_demo_users
import takeover_sim
from app.legacy_auth import get_legacy_connection
from migrate_on_login import MigrationResult
from src.auth.service import AuthResult
from src.auth.totp import generate_provisioning_uri, generate_qr_png
from src.crypto.secret_vault import MissingFernetKeyError, decrypt_totp_secret
from src.db.connection import get_connection
from src.db.users import get_user_by_username

DEMO_DATABASE_PATH = Path(__file__).resolve().parents[1] / "data" / "demo.db"


def render_breach_lab() -> None:
    st.title("Breach Lab")
    st.caption("Fictional accounts in the isolated demo database only.")

    _seed_section()
    st.divider()
    _export_section()
    st.divider()
    _attack_section()
    st.divider()
    _takeover_section()
    st.divider()
    _migration_section()


def _seed_section() -> None:
    st.subheader("1. Seed demo users")
    st.write("Create the fictional cohorts in `data/demo.db`.")
    if st.button("Seed demo users", key="lab_seed_button"):
        try:
            seed_demo_users.seed_demo_users()
        except Exception:
            st.error("Demo seeding failed. Check the local demo configuration.")
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
    st.subheader("2. Simulate database breach")
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
    st.subheader("3. Attack the exported dumps")
    st.write("The secure simulation uses a 30-second time budget.")
    legacy_col, secure_col = st.columns(2)
    with legacy_col:
        st.markdown("**Attack legacy dump**")
        if st.button("Run legacy attack", key="lab_legacy_attack_button"):
            dump = st.session_state.get("lab_legacy_dump")
            if dump is None:
                st.warning("Export the demo database first.")
            else:
                st.session_state["lab_legacy_attack"] = attack_sim.attack_legacy(
                    dump, attack_sim.load_wordlist()
                )
        _render_attack_result(st.session_state.get("lab_legacy_attack"), "hashes_per_second")

    with secure_col:
        st.markdown("**Attack secure dump**")
        if st.button("Run secure attack", key="lab_secure_attack_button"):
            dump = st.session_state.get("lab_secure_dump")
            if dump is None:
                st.warning("Export the demo database first.")
            else:
                st.session_state["lab_secure_attack"] = attack_sim.attack_secure(
                    dump, attack_sim.load_wordlist()
                )
        _render_attack_result(st.session_state.get("lab_secure_attack"), "guesses_per_second")


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
    st.subheader("4. Attempt takeover")
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
            otp = st.text_input("One-time code (optional)", key="lab_takeover_otp")
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
        uri = generate_provisioning_uri(
            secret,
            username,
            issuer="Secure Authentication Demo",
        )
        qr_png = generate_qr_png(uri)
    except MissingFernetKeyError:
        st.error("TOTP display is unavailable because the local key is not configured.")
        return
    st.image(qr_png, caption="Scan with an authenticator app to generate a current code.")


def _migration_presence(username: str) -> tuple[bool, bool]:
    connection = get_legacy_connection(DEMO_DATABASE_PATH)
    try:
        legacy_exists = connection.execute(
            "SELECT 1 FROM legacy_users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone() is not None
        secure_exists = get_user_by_username(connection, username) is not None
        return legacy_exists, secure_exists
    finally:
        connection.close()


def _migration_section() -> None:
    st.subheader("5. Migrate a legacy user")
    usernames = [username for _, username, _ in seed_demo_users.COHORT_B]
    with st.form("lab_migration_form"):
        username = st.selectbox("Cohort B username", usernames, key="lab_migration_user")
        password = st.text_input(
            "Known demo password", type="password", key="lab_migration_password"
        )
        submitted = st.form_submit_button("Migrate user", key="lab_migration_submit")

    if submitted:
        before = _migration_presence(username)
        try:
            result = migrate_on_login.migrate_legacy_user(username, password)
        except Exception:
            st.error("Migration failed. Check the state of the isolated demo database.")
        else:
            after = _migration_presence(username)
            st.session_state["lab_migration_result"] = (username, result, before, after)

    saved_result = st.session_state.get("lab_migration_result")
    if not saved_result:
        return
    result_username, result, before, after = saved_result
    if isinstance(result, MigrationResult):
        if result.success:
            st.success(f"{result_username} was migrated to the secure store.")
        else:
            st.error(f"Migration failed: {result.code.replace('_', ' ')}.")
    elif isinstance(result, AuthResult):
        if result.success:
            st.success("No legacy row remained; normal secure login succeeded.")
        else:
            st.error(f"No migration was needed; secure login returned {result.code}.")

    st.dataframe(
        [
            {
                "State": "Before",
                "legacy_users": "Present" if before[0] else "Absent",
                "users": "Present" if before[1] else "Absent",
            },
            {
                "State": "After",
                "legacy_users": "Present" if after[0] else "Absent",
                "users": "Present" if after[1] else "Absent",
            },
        ],
        width="stretch",
        hide_index=True,
    )