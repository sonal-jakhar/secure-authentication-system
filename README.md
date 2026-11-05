# Secure User Authentication System Using Password Hashing and OTP

College Information and Network Security project. Users register and log in with hashed passwords and an optional TOTP second factor.

## Technology stack

- Python
- Streamlit (UI)
- SQLite (user storage)
- PBKDF2-HMAC-SHA256 (password hashing; Python standard library)
- PyOTP (TOTP-based two-factor authentication)
- Fernet from the `cryptography` package (encrypt TOTP secrets at rest)
- Pytest (tests)

## Current status

Phases 1–6 are implemented: project setup, SQLite, password hashing, TOTP and Fernet, authentication workflows, and the Streamlit demonstration UI.

Streamlit session state is used only for this lab UI. It is not a production session manager.

## Project structure

```text
.
├── app.py            # Streamlit entry point
├── app/              # UI, session helpers, educational demo
├── src/
│   ├── auth/         # Password hashing, TOTP, registration/login
│   ├── crypto/       # Fernet helpers
│   └── db/           # SQLite access
├── tests/
├── data/             # Local SQLite files (gitignored except this folder)
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

## Setup commands

Run these from the project root (`Secure-Authentication-System`).

### 1. Create and activate a virtual environment

Windows (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 3. Create a local environment file and Fernet key

```powershell
copy .env.example .env
python -c "from src.crypto.secret_vault import generate_fernet_key; print(generate_fernet_key())"
```

Paste the printed value into `.env` as `FERNET_KEY=...`. Do not commit `.env`.

### 4. Run tests

```powershell
python -m pytest tests -v
```

### 5. Launch the Streamlit app

```powershell
streamlit run app.py
```

Then open the local URL Streamlit prints (usually `http://localhost:8501`).
