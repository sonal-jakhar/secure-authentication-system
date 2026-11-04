"""Streamlit pages. All authentication goes through src.auth.service."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import streamlit as st

from app.demo import SAMPLE_DEMO_PASSWORD, pbkdf2_demo_digest, unsalted_sha1_hex
from app.session import (
    AUTH_USERNAME,
    ENROL_MANUAL_KEY,
    ENROL_QR_PNG,
    NAV_PAGE,
    clear_enrolment,
    establish_session,
    is_authenticated,
    login_error_message,
    logout,
)
from app.theme import apply
from src.auth.password import PBKDF2_ITERATIONS
from src.auth.service import (
    TotpEnrolmentError,
    confirm_totp_enrolment,
    login,
    register_user,
    start_totp_enrolment,
)
from src.crypto.secret_vault import MissingFernetKeyError
from src.db.connection import get_connection, initialize_database
from src.db.users import DuplicateUsernameError, get_user_by_username

PAGES = (
    "Overview",
    "Register",
    "Login",
    "Dashboard",
    "Case study",
)


def run() -> None:
    apply()
    initialize_database()
    _sidebar()
    page = st.session_state.get(NAV_PAGE, "Overview")
    if page == "Overview":
        _overview()
    elif page == "Register":
        _register()
    elif page == "Login":
        _login()
    elif page == "Dashboard":
        _dashboard()
    else:
        _case_study()
    st.markdown(
        '<p class="footnote">Demonstration only. Streamlit session state is not '
        "a production-grade session mechanism.</p>",
        unsafe_allow_html=True,
    )


def _sidebar() -> None:
    st.sidebar.markdown("### Secure Auth Lab")
    st.sidebar.caption("Password hashing and TOTP · college demonstration")
    if is_authenticated(st.session_state):
        st.sidebar.success(f"Signed in as {st.session_state[AUTH_USERNAME]}")
    else:
        st.sidebar.info("Not signed in")
    current = st.session_state.get(NAV_PAGE, "Overview")
    if current not in PAGES:
        current = "Overview"
    choice = st.sidebar.radio("Navigate", list(PAGES), index=PAGES.index(current))
    st.session_state[NAV_PAGE] = choice
    st.sidebar.markdown(
        "Use **Register** and **Login** for the live system. "
        "**Case study** is educational and is not part of authentication."
    )


def _overview() -> None:
    st.markdown('<div class="eyebrow">Information and Network Security</div>', unsafe_allow_html=True)
    st.title("Secure User Authentication")
    st.markdown(
        """
        <div class="hero-card">
          <p class="muted">
            This demonstration registers and authenticates users with
            <strong>PBKDF2-HMAC-SHA256</strong> password hashing, optional
            <strong>TOTP</strong> two-factor authentication, and
            <strong>Fernet</strong> encryption of authenticator secrets at rest.
          </p>
          <p class="muted">
            Passwords are never stored in plaintext. The dashboard never shows
            hashes, salts, or encryption keys.
          </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    left, right = st.columns(2)
    with left:
        st.subheader("What you can do")
        st.markdown(
            "- Create an account\n"
            "- Sign in with your password\n"
            "- Enable an authenticator app (optional)\n"
            "- Review the LinkedIn 2012 password-storage case study"
        )
    with right:
        st.subheader("What this app does not do")
        st.markdown(
            "- It does not store or display your password\n"
            "- It does not crack or search leaked password lists\n"
            "- It does not claim Streamlit cookies are a full session server"
        )


def _register() -> None:
    st.title("Create an account")
    st.caption("Usernames may contain letters, digits, hyphens and underscores.")
    with st.form("register_form"):
        username = st.text_input("Choose a username")
        password = st.text_input("Password", type="password")
        confirm = st.text_input("Confirm password", type="password")
        submitted = st.form_submit_button("Create account")
    if not submitted:
        return
    if password != confirm:
        st.error("Passwords do not match.")
        return
    connection = get_connection()
    try:
        register_user(connection, username, password)
    except DuplicateUsernameError:
        st.error("That username is not available.")
        return
    except (TypeError, ValueError) as exc:
        st.error(str(exc))
        return
    finally:
        connection.close()
    st.success("Account created. You can sign in from the Login page.")
    st.session_state[NAV_PAGE] = "Login"
    st.rerun()


def _login() -> None:
    st.title("Sign in")
    st.caption("If you enabled two-factor authentication, enter the 6-digit code as well.")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        otp = st.text_input("One-time code (if 2FA is enabled)")
        submitted = st.form_submit_button("Sign in")
    if not submitted:
        return
    otp_value = otp.strip() or None
    connection = get_connection()
    try:
        result = login(connection, username, password, otp_value)
    finally:
        connection.close()
    if not result.success or result.user_id is None or result.username is None:
        st.error(login_error_message(result.code))
        return
    establish_session(
        st.session_state, user_id=result.user_id, username=result.username
    )
    st.session_state[NAV_PAGE] = "Dashboard"
    st.success("Signed in.")
    st.rerun()


def _dashboard() -> None:
    st.title("Dashboard")
    if not is_authenticated(st.session_state):
        st.warning("Please sign in to view your dashboard.")
        return

    username = st.session_state[AUTH_USERNAME]
    connection = get_connection()
    try:
        user = get_user_by_username(connection, username)
    finally:
        connection.close()
    if user is None:
        logout(st.session_state)
        st.warning("Please sign in to view your dashboard.")
        return

    totp_enabled = bool(user["totp_enabled"])
    st.markdown(f"### Welcome, {username}")
    st.markdown(
        f'<span class="status-pill status-on">Authenticated</span>'
        f'<span class="status-pill {"status-on" if totp_enabled else "status-off"}">'
        f'2FA {"enabled" if totp_enabled else "not enabled"}</span>',
        unsafe_allow_html=True,
    )
    st.write("")
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown('<div class="panel-card">', unsafe_allow_html=True)
        st.markdown("**Account**")
        st.write(f"Username: `{username}`")
        st.write("Password: stored as a salted PBKDF2 hash only")
        st.markdown("</div>", unsafe_allow_html=True)
    with col_b:
        st.markdown('<div class="panel-card">', unsafe_allow_html=True)
        st.markdown("**Two-factor authentication**")
        if totp_enabled:
            st.write("An authenticator app is required at sign-in.")
        else:
            st.write("Optional. Enable it below when you are ready.")
        st.markdown("</div>", unsafe_allow_html=True)

    if totp_enabled:
        clear_enrolment(st.session_state)
        st.info("Two-factor authentication is already enabled on this account.")
    else:
        _enrolment_panel(username)

    if st.button("Log out"):
        logout(st.session_state)
        st.session_state[NAV_PAGE] = "Login"
        st.rerun()


def _enrolment_panel(username: str) -> None:
    st.subheader("Enable two-factor authentication")
    st.caption("Re-enter your password to start. TOTP stays off until you confirm a valid code.")

    with st.form("start_totp_form"):
        password = st.text_input("Account password", type="password", key="enrol_start_password")
        start = st.form_submit_button("Generate authenticator QR code")
    if start:
        connection = get_connection()
        try:
            enrolment = start_totp_enrolment(connection, username, password)
        except TotpEnrolmentError:
            st.error("Could not start 2FA setup. Check your password.")
            return
        except MissingFernetKeyError:
            st.error("Two-factor setup is not configured on this server.")
            return
        finally:
            connection.close()
        secret = _secret_from_uri(enrolment.provisioning_uri)
        st.session_state[ENROL_QR_PNG] = enrolment.qr_png
        if secret:
            st.session_state[ENROL_MANUAL_KEY] = secret
        st.success("Scan the QR code, then confirm with a one-time code.")

    qr_png = st.session_state.get(ENROL_QR_PNG)
    if not qr_png:
        return

    st.image(qr_png, caption="Scan with Google Authenticator, Authy, or a similar app.")
    manual = st.session_state.get(ENROL_MANUAL_KEY)
    if manual:
        with st.expander("Enter key manually instead"):
            st.code(manual, language=None)
            st.caption("Treat this key like a password. It is shown only during setup.")

    with st.form("confirm_totp_form"):
        password = st.text_input("Account password", type="password", key="enrol_confirm_password")
        otp = st.text_input("6-digit code from your authenticator")
        confirm = st.form_submit_button("Confirm and enable 2FA")
    if not confirm:
        return
    connection = get_connection()
    try:
        confirm_totp_enrolment(connection, username, password, otp.strip())
    except TotpEnrolmentError:
        st.error("Could not confirm 2FA. Check the password and one-time code.")
        return
    except MissingFernetKeyError:
        st.error("Two-factor setup is not configured on this server.")
        return
    finally:
        connection.close()
    clear_enrolment(st.session_state)
    st.success("Two-factor authentication is now enabled.")
    st.rerun()


def _case_study() -> None:
    st.title("Case study: LinkedIn password breach")
    st.caption("Educational material. This page does not authenticate users.")
    st.markdown(
        """
        In **June 2012**, LinkedIn disclosed that attackers had obtained a file of
        about **6.5 million password hashes**. Those hashes were SHA-1 values stored
        **without unique salts**. The same password therefore produced the same hash
        for every account that used it, and SHA-1 is fast to compute, so large
        collections of guesses could be checked cheaply.

        In **May 2016** a much larger set of LinkedIn credentials resurfaced for sale
        and in public dumps, involving on the order of **117 million accounts**
        (email addresses paired with hashed passwords). The later figure is the
        scale of the *exposed credential set*, not a separate claim that every
        one of those passwords was cracked.

        **Why unsalted SHA-1 was inadequate**
        - Identical passwords share one hash, so one cracked hash compromises every
          user who chose that password.
        - Precomputed tables (rainbow tables) can look up common SHA-1 hashes.
        - SHA-1 is designed to be fast, which helps attackers try huge guess lists.

        **Why unique salts and slow hashing matter**
        - A unique salt means two users with the same password get different stored
          hashes, so a cracked hash does not automatically match every other row.
        - A slow, iterated function such as PBKDF2 makes each guess expensive.

        **How this project stores passwords**
        Registration calls `hash_password()` in the existing backend:
        **PBKDF2-HMAC-SHA256**, **600,000 iterations**, a **16-byte random salt**
        per password, and a **32-byte** derived key. Verification uses
        `hmac.compare_digest()`. That path is independent of the SHA-1 demo below.
        """
    )
    st.subheader("Safe hashing demonstration")
    st.info(
        "This uses a fixed sample string. It is not a real password, not from a "
        "breach, and not sent through login or registration."
    )
    st.code(SAMPLE_DEMO_PASSWORD, language=None)
    if st.button("Compare unsalted SHA-1 with salted PBKDF2"):
        sha_one = unsalted_sha1_hex(SAMPLE_DEMO_PASSWORD)
        sha_two = unsalted_sha1_hex(SAMPLE_DEMO_PASSWORD)
        with st.spinner("Deriving two PBKDF2 hashes (600,000 iterations each)..."):
            salt_a, hash_a, iterations = pbkdf2_demo_digest(SAMPLE_DEMO_PASSWORD)
            salt_b, hash_b, _ = pbkdf2_demo_digest(SAMPLE_DEMO_PASSWORD)
        st.markdown("**Unsalted SHA-1 (insecure illustration only)**")
        st.code(f"first  = {sha_one}\nsecond = {sha_two}", language=None)
        if sha_one == sha_two:
            st.warning("The SHA-1 digest is identical every time for the same input.")
        st.markdown(
            f"**This project's PBKDF2-HMAC-SHA256 ({iterations:,} iterations)**"
        )
        st.code(
            f"salt A = {salt_a}\nhash A = {hash_a}\n\n"
            f"salt B = {salt_b}\nhash B = {hash_b}",
            language=None,
        )
        if salt_a != salt_b and hash_a != hash_b:
            st.success(
                "Different random salts produced different stored hashes for the "
                "same sample string."
            )
        st.caption(
            f"PBKDF2 iteration count in this project: {PBKDF2_ITERATIONS:,}. "
            "This button does not crack hashes and does not use leaked credentials."
        )


def _secret_from_uri(uri: str) -> str | None:
    values = parse_qs(urlparse(uri).query).get("secret")
    if not values:
        return None
    return values[0]
