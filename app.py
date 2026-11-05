"""Streamlit entry point. Authentication logic lives in src.auth.service."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st

from app.ui import run

st.set_page_config(
    page_title="Secure Authentication System",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed",
)

run()
