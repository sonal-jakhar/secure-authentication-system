# Secure User Authentication System Using Password Hashing and OTP

College Information and Network Security project. Users will register and log in with hashed passwords and a TOTP second factor.

## Technology stack

- Python
- Streamlit (UI)
- SQLite (user storage)
- PBKDF2-HMAC-SHA256 (password hashing; Python standard library)
- PyOTP (TOTP-based two-factor authentication)
- Fernet from the `cryptography` package (encrypt TOTP secrets at rest)
- Pytest (tests)

## Current status

**Phase 1: project setup only.** Folder layout, dependencies, ignore rules, and environment template are in place. Authentication, hashing, OTP, database schema, and UI are not implemented yet.

## Project structure

```text
.
├── app/              # Streamlit UI (later phases)
├── src/
│   ├── auth/         # Password hashing and OTP (later phases)
│   ├── crypto/       # Fernet helpers (later phases)
│   └── db/           # SQLite access (later phases)
├── tests/            # Pytest tests (later phases)
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

Windows (Command Prompt):

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 3. Create a local environment file

```powershell
copy .env.example .env
```

macOS / Linux:

```bash
cp .env.example .env
```

Leave `FERNET_KEY` empty until a later phase generates a real key.

### 4. Confirm the test runner works

```powershell
python -m pytest
```

Phase 1 has no tests yet. Pytest will report `collected 0 items` / `no tests ran` and exit with code **5**. That is pytest’s normal “no tests collected” status, not an install failure. A later phase will add tests so the exit code becomes 0.

Do **not** run Streamlit yet. There is no application entry point in this phase.
