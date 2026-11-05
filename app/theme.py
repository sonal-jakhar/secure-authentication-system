"""Visual styling for the Streamlit demonstration UI."""

from __future__ import annotations

import streamlit as st

CSS = """
<style>
    :root {
        --ink: #202b36;
        --muted: #5f6b77;
        --line: #dce2e8;
        --surface: #ffffff;
        --canvas: #f2f4f7;
        --navy: #183b62;
        --navy-hover: #112d4b;
        --blue: #245b8f;
        --green-bg: #e8f4ec;
        --green-ink: #24613a;
        --amber-bg: #fff4dc;
        --amber-ink: #75530d;
    }

    html, body, [class*="css"] {
        font-family: "Segoe UI", Tahoma, sans-serif;
        color: var(--ink);
    }

    .stApp { background: var(--canvas); }

    [data-testid="stToolbar"],
    [data-testid="stDecoration"],
    #MainMenu {
        display: none !important;
    }

    [data-testid="stMain"] > div {
        max-width: 1120px;
        padding-top: 2rem;
    }

    [data-testid="stSidebar"] {
        background: #fff;
        border-right: 1px solid var(--line);
    }

    [data-testid="stSidebar"] * { color: var(--ink); }
    [data-testid="stSidebar"] [data-testid="stRadio"] label { color: var(--ink); }

    h1, h2, h3 {
        color: var(--ink) !important;
        font-weight: 600 !important;
        letter-spacing: 0;
    }

    h1 { font-size: 1.9rem !important; }
    h2 { font-size: 1.4rem !important; }
    h3 { font-size: 1.12rem !important; }

    .app-header-title {
        color: var(--ink);
        font-size: 1.25rem;
        font-weight: 650;
        line-height: 1.35;
    }

    .eyebrow {
        color: var(--blue);
        font-size: 0.76rem;
        font-weight: 600;
        text-transform: uppercase;
        margin-bottom: 0.35rem;
    }

    .muted, [data-testid="stCaptionContainer"] { color: var(--muted); }

    div[data-testid="stForm"] {
        max-width: 680px;
        margin: 0 auto 1rem;
        padding: 1.1rem 1.25rem;
        background: var(--surface);
        border: 1px solid var(--line);
        border-radius: 5px;
    }

    .status-pill {
        display: inline-block;
        padding: 0.22rem 0.58rem;
        border: 1px solid transparent;
        border-radius: 4px;
        font-size: 0.82rem;
        font-weight: 600;
        margin-right: 0.45rem;
    }

    .status-on { background: var(--green-bg); color: var(--green-ink); }
    .status-off { background: var(--amber-bg); color: var(--amber-ink); }

    code, .stCode, pre { font-family: Consolas, "Courier New", monospace !important; }

    .stButton > button,
    [data-testid="stFormSubmitButton"] > button {
        min-height: 2.45rem;
        padding: 0.45rem 1rem;
        color: #fff;
        background: var(--navy);
        border: 1px solid var(--navy);
        border-radius: 4px;
        font-weight: 600;
    }

    .stButton > button:hover,
    [data-testid="stFormSubmitButton"] > button:hover {
        color: #fff;
        background: var(--navy-hover);
        border-color: var(--navy-hover);
    }

    [data-testid="stVerticalBlockBorderWrapper"] {
        background: var(--surface);
        border-color: var(--line);
        border-radius: 5px;
    }

    [data-testid="stTextInput"] input {
        background: #fff;
        border-color: #cbd3dc;
        border-radius: 4px;
    }

    [data-testid="stTextInput"] input:focus {
        border-color: var(--blue);
        box-shadow: 0 0 0 1px var(--blue);
    }

    hr { border-color: var(--line); }

    .footnote {
        color: var(--muted);
        font-size: 0.82rem;
        margin-top: 2rem;
        border-top: 1px solid var(--line);
        padding-top: 0.75rem;
    }
</style>
"""


def apply() -> None:
    st.markdown(CSS, unsafe_allow_html=True)
