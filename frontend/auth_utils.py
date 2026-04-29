# frontend/auth_utils.py
# ─── Shared auth utilities for all Sentinel page files ───────────────────────

import streamlit as st
import requests

API = "http://127.0.0.1:8000"


def require_auth():
    """
    Call this at the top of every page file.
    Stops the page if the JWT is missing OR empty (e.g. after a server restart
    where session state keys persist but values reset to "").
    """
    token = st.session_state.get("jwt", "")
    if not token or not isinstance(token, str) or len(token.strip()) < 10:
        st.warning("🔒 You must be logged in to view this page.")
        st.page_link("streamlit_app.py", label="← Go to Login")
        st.stop()


def get_token() -> str:
    """Returns the raw JWT string."""
    return st.session_state.get("jwt", "")


def get_auth_headers() -> dict:
    """Returns the Authorization header dict for the current session."""
    return {"Authorization": f"Bearer {get_token()}"}


def get_role() -> str:
    return st.session_state.get("role", "")


def get_email() -> str:
    return st.session_state.get("email", "")


def api_get(path: str, **kwargs) -> requests.Response:
    return requests.get(f"{API}{path}", headers=get_auth_headers(), **kwargs)


def api_post(path: str, **kwargs) -> requests.Response:
    return requests.post(f"{API}{path}", headers=get_auth_headers(), **kwargs)