"""Visual styling for the Streamlit demonstration UI."""

from __future__ import annotations

import streamlit as st

CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Source+Sans+3:wght@400;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: "Source Sans 3", "Segoe UI", sans-serif;
    }

    .stApp {
        background:
            radial-gradient(1200px 500px at 10% -10%, #14324a 0%, transparent 55%),
            linear-gradient(180deg, #0e1720 0%, #111c27 40%, #0c141c 100%);
        color: #e8eef4;
    }

    [data-testid="stSidebar"] {
        background: #0b141c;
        border-right: 1px solid #243544;
    }

    [data-testid="stSidebar"] * {
        color: #d7e3ee;
    }

    h1, h2, h3 {
        letter-spacing: -0.02em;
        color: #f4f8fb !important;
    }

    .hero-card, .panel-card {
        background: rgba(18, 32, 45, 0.92);
        border: 1px solid #2b4254;
        border-radius: 16px;
        padding: 1.25rem 1.4rem;
        margin-bottom: 1rem;
        box-shadow: 0 12px 40px rgba(0, 0, 0, 0.18);
    }

    .eyebrow {
        color: #7dcec4;
        font-size: 0.78rem;
        font-weight: 700;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        margin-bottom: 0.35rem;
    }

    .muted {
        color: #a9bbc9;
        line-height: 1.55;
    }

    .status-pill {
        display: inline-block;
        padding: 0.2rem 0.65rem;
        border-radius: 999px;
        font-size: 0.82rem;
        font-weight: 600;
        margin-right: 0.4rem;
    }

    .status-on { background: #134e4a; color: #99f6e4; }
    .status-off { background: #3f2d12; color: #fde68a; }

    code, .stCode, pre {
        font-family: "IBM Plex Mono", ui-monospace, monospace !important;
    }

    .stButton > button {
        background: #1f8a80;
        color: white;
        border: 0;
        border-radius: 10px;
        font-weight: 600;
        padding: 0.45rem 1rem;
    }

    .stButton > button:hover {
        background: #176e66;
        color: white;
    }

    .footnote {
        color: #8aa0b2;
        font-size: 0.85rem;
        margin-top: 1.5rem;
    }
</style>
"""


def apply() -> None:
    st.markdown(CSS, unsafe_allow_html=True)
