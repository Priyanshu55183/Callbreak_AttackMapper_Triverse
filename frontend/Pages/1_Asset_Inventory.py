import streamlit as st
import requests
import pandas as pd
import sys, os

# ── shared auth ───────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from auth_utils import require_auth, get_auth_headers, API

st.set_page_config(
    page_title="Asset Inventory — Sentinel",
    page_icon="📋",
    layout="wide"
)

require_auth()   # ← redirects to login if no JWT

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

    /* Filter container */
    [data-testid="stExpander"] {
        background-color: #1E293B;
        border: 1px solid #334155;
        border-radius: 10px;
    }

    /* Dataframe */
    [data-testid="stDataFrame"] {
        border: 1px solid #334155;
        border-radius: 10px;
    }

    /* Badge styles used in risk column */
    .badge-critical {
        background-color: #450A0A;
        color: #FCA5A5;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: 600;
    }
    .badge-high {
        background-color: #431407;
        color: #FED7AA;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: 600;
    }
    .badge-medium {
        background-color: #422006;
        color: #FDE68A;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: 600;
    }
    .badge-low {
        background-color: #052E16;
        color: #86EFAC;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)


# ─── HELPER FUNCTIONS ────────────────────────────────────────────────────────

def fetch_assets(token: str, environment=None, criticality=None,
                 internet_exposed=None, owner_status=None):
    """Fetch assets from FastAPI with optional filters."""
    try:
        params = {}
        if environment and environment != "All":
            params["environment"] = environment
        if criticality and criticality != "All":
            params["criticality"] = criticality
        if internet_exposed != "All":
            if internet_exposed == "Yes":
                params["internet_exposed"] = True
            elif internet_exposed == "No":
                params["internet_exposed"] = False
        if owner_status and owner_status != "All":
            params["owner_status"] = owner_status

        params["slim"] = True

        response = requests.get(
            f"{API}/assets",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
            timeout=30
        )

        if response.status_code == 200:
            return response.json(), None
        if response.status_code == 401:
            return None, "Session expired — please log out and log back in."
        return None, f"API error {response.status_code}"

    except requests.exceptions.ConnectionError:
        return None, "Backend not running."
    except requests.exceptions.Timeout:
        return None, "Request timed out."


def risk_badge(level):
    """Return a coloured HTML badge for a risk level."""
    level = level or "Unknown"
    css = {
        "Critical": "badge-critical",
        "High":     "badge-high",
        "Medium":   "badge-medium",
        "Low":      "badge-low",
    }.get(level, "badge-low")
    return f'<span class="{css}">{level}</span>'


def format_assets_for_table(assets):
    """
    Convert the list of asset dicts from the API into a clean DataFrame.
    We pick only the columns we want to show and rename them nicely.
    """
    rows = []
    for a in assets:
        # Pull owner info safely
        owner = a.get("owner") or {}
        vuln_count = len(a.get("vulnerabilities", []))

        rows.append({
            "Asset ID":       a.get("asset_id", ""),
            "Type":           a.get("asset_type", ""),
            "Environment":    a.get("environment", ""),
            "Criticality":    a.get("criticality", ""),
            "IP Address":     a.get("ip_address", ""),
            "OS":             f"{a.get('os', {}).get('name', '')} "
                              f"{a.get('os', {}).get('version', '')}".strip(),
            "Software":       f"{a.get('software', {}).get('name', '')} "
                              f"{a.get('software', {}).get('version', '')}".strip(),
            "Exposed":        "🌐 Yes" if a.get("internet_exposed") else "🔒 No",
            "Risk Score":     round(a.get("risk_score") or 0, 1),
            "Risk Level":     a.get("risk_level", "Unknown"),
            "CVEs":           vuln_count,
            "Owner":          owner.get("team", "—") or "—",
            "Owner Status":   owner.get("status", "unknown"),
        })

    return pd.DataFrame(rows)


def color_risk_score(val):
    """
    Apply background colour to risk score cells in the dataframe.
    This is used with df.style.applymap()
    """
    if val >= 80:
        return "background-color: #450A0A; color: #FCA5A5;"
    elif val >= 60:
        return "background-color: #431407; color: #FED7AA;"
    elif val >= 40:
        return "background-color: #422006; color: #FDE68A;"
    else:
        return "background-color: #052E16; color: #86EFAC;"


def color_risk_level(val):
    """Apply background colour to risk level cells."""
    colors = {
        "Critical": "background-color: #450A0A; color: #FCA5A5;",
        "High":     "background-color: #431407; color: #FED7AA;",
        "Medium":   "background-color: #422006; color: #FDE68A;",
        "Low":      "background-color: #052E16; color: #86EFAC;",
    }
    return colors.get(val, "")


def color_owner_status(val):
    """Highlight orphan assets in red."""
    if val == "orphan":
        return "background-color: #450A0A; color: #FCA5A5;"
    return "background-color: #052E16; color: #86EFAC;"


# ─── PAGE HEADER ─────────────────────────────────────────────────────────────
st.markdown("# 📋 Asset Inventory")
st.markdown(
    "<p style='color:#94A3B8'>Browse, filter and search all assets "
    "in your environment.</p>",
    unsafe_allow_html=True
)
st.divider()

# ─── FILTERS ─────────────────────────────────────────────────────────────────
# We put filters in an expander to save screen space
with st.expander("🔍 Filters", expanded=True):
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        environment = st.selectbox(
            "Environment",
            ["All", "Production", "Staging", "Development"],
        )

    with col2:
        criticality = st.selectbox(
            "Criticality",
            ["All", "High", "Medium", "Low"],
        )

    with col3:
        internet_exposed = st.selectbox(
            "Internet Exposed",
            ["All", "Yes", "No"],
        )

    with col4:
        owner_status = st.selectbox(
            "Owner Status",
            ["All", "assigned", "orphan"],
        )

# ─── FETCH DATA ───────────────────────────────────────────────────────────────
# Fetch assets based on current filter selections
# When filters change, Streamlit reruns the page automatically
# so this fetch always uses the latest filter values
data, error = fetch_assets(
    st.session_state["jwt"],
    environment=environment,
    criticality=criticality,
    internet_exposed=internet_exposed,
    owner_status=owner_status,
)

if error:
    st.error(f"❌ {error}")
    st.stop()   # stop rendering the rest of the page

assets = data.get("assets", [])
total  = data.get("total", 0)

# ─── SEARCH BOX ───────────────────────────────────────────────────────────────
# Client-side search — filters the already-fetched data
# No new API call needed — just filter the DataFrame
search = st.text_input(
    "🔎 Search by Asset ID, IP Address or Software",
    placeholder="e.g. ASSET-1042 or nginx or 192.168..."
)

# ─── BUILD DATAFRAME ──────────────────────────────────────────────────────────
if not assets:
    st.warning("No assets found matching your filters.")
    st.stop()

df = format_assets_for_table(assets)

# Apply search filter if user typed something
if search:
    mask = (
        df["Asset ID"].str.contains(search, case=False, na=False) |
        df["IP Address"].str.contains(search, case=False, na=False) |
        df["Software"].str.contains(search, case=False, na=False)
    )
    df = df[mask]

# ─── RESULTS COUNT ────────────────────────────────────────────────────────────
st.markdown(
    f"<p style='color:#94A3B8'>Showing "
    f"<b style='color:#F8FAFC'>{len(df)}</b> of "
    f"<b style='color:#F8FAFC'>{total}</b> assets</p>",
    unsafe_allow_html=True
)

# ─── STYLED TABLE ─────────────────────────────────────────────────────────────
# Apply colour styling to specific columns
styled_df = (
    df.style
    .map(color_risk_score,   subset=["Risk Score"])
    .map(color_risk_level,   subset=["Risk Level"])
    .map(color_owner_status, subset=["Owner Status"])
    .format({"Risk Score": "{:.1f}"})
)

st.dataframe(
    styled_df,
    width="stretch",        # fill full page width
    height=500,             # fixed height with scroll
    hide_index=True,        # don't show row numbers
)

# ─── EXPORT ───────────────────────────────────────────────────────────────────
st.divider()

# Convert DataFrame to CSV for download
csv = df.to_csv(index=False).encode("utf-8")

st.download_button(
    label="⬇️ Export to CSV",
    data=csv,
    file_name="sentinel_assets.csv",
    mime="text/csv",
)

# ─── QUICK STATS BELOW TABLE ──────────────────────────────────────────────────
if len(df) > 0:
    st.divider()
    st.markdown("### 📊 Quick Stats for Current View")

    qcol1, qcol2, qcol3, qcol4 = st.columns(4)

    with qcol1:
        critical_in_view = len(df[df["Risk Level"] == "Critical"])
        st.metric("Critical Risk", critical_in_view)

    with qcol2:
        exposed_in_view = len(df[df["Exposed"] == "🌐 Yes"])
        st.metric("Internet Exposed", exposed_in_view)

    with qcol3:
        orphans_in_view = len(df[df["Owner Status"] == "orphan"])
        st.metric("Orphan Assets", orphans_in_view)

    with qcol4:
        avg_risk = df["Risk Score"].mean()
        st.metric("Avg Risk Score", f"{avg_risk:.1f}")