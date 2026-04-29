import streamlit as st
import requests
import pandas as pd
import sys, os

# ─── CONFIG ──────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Orphan Tracker — Sentinel",
    page_icon="👻",
    layout="wide"
)

# ── shared auth ───────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from auth_utils import require_auth, get_auth_headers, get_role, API

require_auth()

# ─── ADMIN ROLE GATE ─────────────────────────────────────────────────────────
# /orphans is admin-only on the backend — block non-admins before even calling it
if get_role() != "admin":
    st.error("🔒 This page is restricted to admin users.")
    st.page_link("streamlit_app.py", label="← Back to Dashboard")
    st.stop()

# ─── SIDEBAR ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ Sentinel")
    st.page_link("streamlit_app.py", label="🏠 Home / Dashboard")
    st.divider()

# ─── CUSTOM CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .stApp { background-color: #0D1117; }
    [data-testid="stSidebar"] { background-color: #0F2744; }
    h1, h2, h3 { color: #F8FAFC !important; }
    p, div { color: #CBD5E1; }
    hr { border-color: #334155; }
    [data-testid="stMetric"] {
        background-color: #1E293B;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px;
    }
    [data-testid="stMetricLabel"] { color: #94A3B8 !important; }
    [data-testid="stMetricValue"] { color: #F8FAFC !important; font-weight:700 !important; }
</style>
""", unsafe_allow_html=True)


# ─── HELPER FUNCTIONS ────────────────────────────────────────────────────────

def fetch_orphans(token: str):
    """Fetch all orphan assets from the /orphans endpoint."""
    try:
        response = requests.get(
            f"{API}/orphans",
            headers={"Authorization": f"Bearer {token}"},
            timeout=30
        )
        if response.status_code == 200:
            return response.json(), None
        if response.status_code == 401:
            return None, "Session expired — please log out and log back in."
        if response.status_code == 403:
            return None, "Admin access required."
        return None, f"API error {response.status_code}"
    except requests.exceptions.ConnectionError:
        return None, "Backend not running."
    except requests.exceptions.Timeout:
        return None, "Request timed out."


def color_risk_level(val):
    colors = {
        "Critical": "background-color:#450A0A; color:#FCA5A5;",
        "High":     "background-color:#431407; color:#FED7AA;",
        "Medium":   "background-color:#422006; color:#FDE68A;",
        "Low":      "background-color:#052E16; color:#86EFAC;",
    }
    return colors.get(val, "")


def color_risk_score(val):
    try:
        v = float(val)
        if v >= 80:   return "background-color:#450A0A; color:#FCA5A5;"
        elif v >= 60: return "background-color:#431407; color:#FED7AA;"
        elif v >= 40: return "background-color:#422006; color:#FDE68A;"
        else:         return "background-color:#052E16; color:#86EFAC;"
    except:
        return ""


def color_exposed(val):
    if val == "🌐 Yes": return "background-color:#450A0A; color:#FCA5A5;"
    return "background-color:#052E16; color:#86EFAC;"


def format_orphans_for_table(orphans):
    rows = []
    for a in orphans:
        vuln_count = len(a.get("vulnerabilities", []))
        rows.append({
            "Asset ID":    a.get("asset_id", ""),
            "Type":        a.get("asset_type", ""),
            "Environment": a.get("environment", ""),
            "Criticality": a.get("criticality", ""),
            "IP Address":  a.get("ip_address", "—"),
            "Exposed":     "🌐 Yes" if a.get("internet_exposed") else "🔒 No",
            "Risk Score":  round(a.get("risk_score") or 0, 1),
            "Risk Level":  a.get("risk_level") or "Unknown",
            "CVEs":        vuln_count,
            "OS":          f"{a.get('os', {}).get('name', '')} "
                           f"{a.get('os', {}).get('version', '')}".strip() or "—",
        })
    return pd.DataFrame(rows)


# ─── PAGE HEADER ─────────────────────────────────────────────────────────────
st.markdown("# 👻 Orphan Asset Tracker")
st.markdown(
    "<p style='color:#94A3B8'>Assets with no assigned owner. "
    "These are unmonitored and may go unpatched — a serious security risk.</p>",
    unsafe_allow_html=True
)
st.divider()

# ─── WHY ORPHANS ARE DANGEROUS ───────────────────────────────────────────────
st.markdown("""
<div style='background:#1C0A0A; border:1px solid #7F1D1D;
            border-radius:10px; padding:16px; margin-bottom:20px;'>
    <p style='color:#FCA5A5; font-weight:600; margin:0 0 8px 0;'>
        ⚠️ Why Orphan Assets Are a Security Risk
    </p>
    <p style='color:#FCA5A5; font-size:13px; margin:0;'>
        • <b>No one monitors them</b> — alerts and scan results go unreviewed<br>
        • <b>Patches go unapplied</b> — CVEs remain open indefinitely<br>
        • <b>No incident response</b> — if breached, no one is responsible<br>
        • <b>Shadow IT risk</b> — asset may have been forgotten entirely
    </p>
</div>
""", unsafe_allow_html=True)

# ─── FETCH DATA ───────────────────────────────────────────────────────────────
data, error = fetch_orphans(st.session_state["jwt"])

if error:
    st.error(f"❌ {error}")
    st.stop()

orphans = data.get("orphan_assets", [])
total   = data.get("total", 0)

# ─── SUMMARY CARDS ───────────────────────────────────────────────────────────
st.markdown("### 📊 Orphan Summary")

m1, m2, m3, m4 = st.columns(4)

critical_orphans  = sum(1 for a in orphans if a.get("risk_level") == "Critical")
exposed_orphans   = sum(1 for a in orphans if a.get("internet_exposed"))
high_risk_orphans = sum(1 for a in orphans if (a.get("risk_score") or 0) >= 70)
total_orphan_cves = sum(len(a.get("vulnerabilities", [])) for a in orphans)

with m1:
    st.metric("👻 Total Orphans",    total)
with m2:
    st.metric("🔴 Critical Risk",    critical_orphans)
with m3:
    st.metric("🌐 Internet Exposed", exposed_orphans)
with m4:
    st.metric("🐛 Total CVEs",       total_orphan_cves)

st.divider()

# ─── NO ORPHANS CASE ─────────────────────────────────────────────────────────
if not orphans:
    st.success(
        "✅ Great news! All assets have an assigned owner. "
        "No orphan assets found."
    )
    st.stop()

# ─── ORPHAN TABLE ─────────────────────────────────────────────────────────────
st.markdown(f"### 🗂️ Orphan Assets ({total} found)")

df = format_orphans_for_table(orphans)
df = df.sort_values("Risk Score", ascending=False)

styled_df = (
    df.style
    .map(color_risk_score, subset=["Risk Score"])
    .map(color_risk_level, subset=["Risk Level"])
    .map(color_exposed,    subset=["Exposed"])
    .format({"Risk Score": "{:.1f}"})
)

st.dataframe(
    styled_df,
    hide_index=True,
    use_container_width=False,
    height=min(80 + len(df) * 38, 500),
)

# ─── EXPORT ───────────────────────────────────────────────────────────────────
csv = df.to_csv(index=False).encode("utf-8")
st.download_button(
    label="⬇️ Export Orphans to CSV",
    data=csv,
    file_name="sentinel_orphans.csv",
    mime="text/csv",
)

st.divider()

# ─── HIGHEST RISK ORPHANS ─────────────────────────────────────────────────────
st.markdown("### 🔥 Highest Priority Orphans")
st.markdown(
    "<p style='color:#94A3B8; font-size:13px;'>"
    "These orphan assets have the highest risk scores "
    "and need ownership assigned immediately.</p>",
    unsafe_allow_html=True
)

top_orphans = sorted(
    orphans,
    key=lambda x: x.get("risk_score") or 0,
    reverse=True
)[:5]

for i, asset in enumerate(top_orphans, 1):
    risk_score = asset.get("risk_score") or 0
    risk_level = asset.get("risk_level") or "Unknown"
    exposed    = asset.get("internet_exposed", False)

    score_color = (
        "#EF4444" if risk_score >= 80 else
        "#F97316" if risk_score >= 60 else
        "#F59E0B" if risk_score >= 40 else
        "#10B981"
    )

    st.markdown(
        f"""
        <div style='background:#1E293B; border:1px solid #334155;
                    border-left:4px solid {score_color};
                    border-radius:8px; padding:14px; margin-bottom:10px;'>
            <div style='display:flex; justify-content:space-between;
                        align-items:center;'>
                <div>
                    <span style='color:#F8FAFC; font-weight:700;
                                 font-size:15px;'>
                        #{i} {asset.get("asset_id")}
                    </span>
                    <span style='color:#94A3B8; font-size:13px;
                                 margin-left:10px;'>
                        {asset.get("asset_type")} · {asset.get("environment")}
                    </span>
                </div>
                <div style='text-align:right;'>
                    <span style='color:{score_color}; font-weight:700;
                                 font-size:16px;'>
                        {risk_score:.1f}
                    </span>
                    <span style='color:#94A3B8; font-size:12px;'> / 100</span>
                </div>
            </div>
            <div style='margin-top:8px; font-size:12px; color:#94A3B8;'>
                IP: {asset.get("ip_address", "—")} &nbsp;|&nbsp;
                {"🌐 Internet Exposed" if exposed else "🔒 Internal"} &nbsp;|&nbsp;
                {len(asset.get("vulnerabilities", []))} CVEs &nbsp;|&nbsp;
                Risk Level: <span style='color:{score_color}'>{risk_level}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )