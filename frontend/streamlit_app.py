import streamlit as st
import requests

# ─── CONFIG ───────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Sentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

API = "http://127.0.0.1:8000"

# ─── AUTH GATE ────────────────────────────────────────────────────────────────
# Check for a real non-empty token — not just whether the key exists.
# The key can exist with value "" if a previous login attempt failed silently.
_token = st.session_state.get("jwt", "")
if not _token or len(_token.strip()) < 10:
    from login import show_login
    show_login()
    st.stop()

role  = st.session_state["role"]
email = st.session_state.get("email", "")
st.code(st.session_state.get('jwt', 'NO TOKEN'))

# ─── HELPER: authenticated API calls ─────────────────────────────────────────
def auth_headers() -> dict:
    return {"Authorization": f"Bearer {st.session_state['jwt']}"}

def api_get(path: str, **kwargs):
    return requests.get(f"{API}{path}", headers=auth_headers(), **kwargs)

def api_post(path: str, **kwargs):
    return requests.post(f"{API}{path}", headers=auth_headers(), **kwargs)

# ─── SIDEBAR ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(f"**{email}**")
    role_colors = {"admin": "🔴", "analyst": "🟡", "viewer": "🟢"}
    st.markdown(f"{role_colors.get(role, '⚪')} `{role}`")
    st.divider()

    if role in ("admin", "analyst"):
        st.page_link("pages/1_Asset_Inventory.py",        label="📋 Asset Inventory")
        st.page_link("pages/2_Risk_Dashboard.py",         label="📊 Risk Dashboard")
        st.page_link("pages/3_Vulnerability_Explorer.py", label="🔍 Vulnerability Explorer")
        st.page_link("pages/5_AI_Chat.py",                label="🤖 AI Chat")

    if role == "admin":
        st.page_link("pages/6_Orphan_Tracker.py", label="👻 Orphan Tracker")

    st.page_link("pages/4_Asset_Detail.py", label="🏠 Asset Detail")

    st.divider()
    if st.button("Log out"):
        st.session_state.clear()
        st.rerun()

# ─── CUSTOM CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .stApp { background-color: #0D1117; }
    [data-testid="stSidebar"] { background-color: #0F2744; }
    [data-testid="stMetric"] {
        background-color: #1E293B;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px;
    }
    [data-testid="stMetricLabel"] { color: #94A3B8 !important; font-size: 13px !important; }
    [data-testid="stMetricValue"] { color: #F8FAFC !important; font-size: 28px !important; font-weight: 700 !important; }
    h1, h2, h3 { color: #F8FAFC !important; }
    p, div { color: #CBD5E1; }
    hr { border-color: #334155; }
</style>
""", unsafe_allow_html=True)


# ─── FETCH STATS ─────────────────────────────────────────────────────────────
# No @st.cache_data — caching was causing stale 401 errors to persist across
# login sessions. With 300 assets this is fast enough without caching.
def fetch_stats(token: str):
    try:
        response = requests.get(
            f"{API}/stats",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        if response.status_code == 200:
            return response.json(), None
        if response.status_code == 401:
            return None, "Session expired — please log out and log back in."
        return None, f"API error: {response.status_code}"
    except requests.exceptions.ConnectionError:
        return None, "Backend not running. Start with: uvicorn main:app --reload"
    except requests.exceptions.Timeout:
        return None, "Backend timed out."


# ─── PAGE HEADER ──────────────────────────────────────────────────────────────
col_logo, col_title = st.columns([1, 8])
with col_logo:
    st.markdown("# 🛡️")
with col_title:
    st.markdown("# Sentinel")
    st.markdown(
        "<p style='color:#94A3B8; margin-top:-12px;'>"
        "AI-Driven Cyber Asset & Attack Surface Management</p>",
        unsafe_allow_html=True
    )

st.divider()

# ─── BACKEND STATUS ───────────────────────────────────────────────────────────
try:
    health = requests.get(f"{API}/", timeout=3)
    if health.status_code == 200:
        st.success("✅ Backend connected — Sentinel API is running")
    else:
        st.error("⚠️ Backend returned an unexpected response")
except Exception:
    st.error("❌ Backend not running. Run: `uvicorn main:app --reload`")

st.markdown("## 📊 Security Overview")

# ─── STATS CARDS ─────────────────────────────────────────────────────────────
stats, error = fetch_stats(st.session_state["jwt"])

if error:
    st.warning(f"Could not load stats: {error}")
else:
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(label="🖥️ Total Assets", value=stats["total_assets"])
    with col2:
        st.metric(label="🔴 Critical Risk", value=stats["critical_count"],
                  delta=f"{stats['critical_count']} need immediate action", delta_color="inverse")
    with col3:
        st.metric(label="🌐 Internet Exposed", value=stats["exposed_count"],
                  delta="publicly reachable", delta_color="inverse")
    with col4:
        st.metric(label="👻 Orphan Assets", value=stats["orphan_count"],
                  delta="no owner assigned", delta_color="inverse")

    st.markdown("")
    col5, col6, col7, _ = st.columns(4)
    with col5:
        st.metric(label="⚠️ High Risk Assets", value=stats["high_risk_count"],
                  delta="risk score ≥ 70", delta_color="inverse")
    with col6:
        st.metric(label="🐛 Total CVEs", value=stats["total_vulns"])
    with col7:
        st.metric(label="💥 Active Exploits", value=stats["exploit_count"],
                  delta="exploits in the wild", delta_color="inverse")

# ─── QUICK NAVIGATION ────────────────────────────────────────────────────────
st.divider()
st.markdown("## 🧭 Navigate")
st.markdown("<p style='color:#94A3B8'>Use the sidebar or click below to go to a page:</p>",
            unsafe_allow_html=True)

nav1, nav2, nav3 = st.columns(3)
with nav1:
    st.page_link("pages/1_Asset_Inventory.py", label="📋 Asset Inventory")
    st.page_link("pages/2_Risk_Dashboard.py",  label="📊 Risk Dashboard")
with nav2:
    st.page_link("pages/3_Vulnerability_Explorer.py", label="🔍 Vulnerability Explorer")
    st.page_link("pages/4_Asset_Detail.py",           label="🏠 Asset Detail")
with nav3:
    st.page_link("pages/5_AI_Chat.py",        label="🤖 AI Chat Assistant")
    st.page_link("pages/6_Orphan_Tracker.py", label="👻 Orphan Tracker")

# ─── FOOTER ───────────────────────────────────────────────────────────────────
st.divider()
st.markdown(
    "<p style='text-align:center; color:#475569; font-size:12px;'>"
    "Sentinel v2.0 — AI-Driven Cyber Asset & Attack Surface Management | "
    "Phase 7 Complete ✅</p>",
    unsafe_allow_html=True
)