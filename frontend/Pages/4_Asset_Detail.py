"""
pages/4_Asset_Detail.py
─────────────────────────────────────────────────────────────────────────────
Asset Detail Page
- Search for any asset by ID
- Full asset info: IP, OS, software, ports, environment
- Owner info with orphan badge
- All linked CVEs with CVSS scores
- Risk score with colour-coded badge
─────────────────────────────────────────────────────────────────────────────
"""

import streamlit as st
import requests
import pandas as pd
import sys, os

# ─── CONFIG ──────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Asset Detail — Sentinel",
    page_icon="🏠",
    layout="wide"
)

# ── shared auth ───────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from auth_utils import require_auth, get_auth_headers, API

require_auth()

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
    h1, h2, h3, h4 { color: #F8FAFC !important; }
    p, div { color: #CBD5E1; }
    hr { border-color: #334155; }

    .info-card {
        background-color: #1E293B;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 12px;
    }
    .info-label {
        color: #94A3B8;
        font-size: 12px;
        margin-bottom: 2px;
    }
    .info-value {
        color: #F8FAFC;
        font-size: 15px;
        font-weight: 600;
    }
    .badge-critical { background:#450A0A; color:#FCA5A5; padding:3px 12px; border-radius:12px; font-weight:600; font-size:13px; }
    .badge-high     { background:#431407; color:#FED7AA; padding:3px 12px; border-radius:12px; font-weight:600; font-size:13px; }
    .badge-medium   { background:#422006; color:#FDE68A; padding:3px 12px; border-radius:12px; font-weight:600; font-size:13px; }
    .badge-low      { background:#052E16; color:#86EFAC; padding:3px 12px; border-radius:12px; font-weight:600; font-size:13px; }
    .badge-orphan   { background:#450A0A; color:#FCA5A5; padding:3px 12px; border-radius:12px; font-weight:600; font-size:13px; }
    .badge-assigned { background:#052E16; color:#86EFAC; padding:3px 12px; border-radius:12px; font-weight:600; font-size:13px; }
</style>
""", unsafe_allow_html=True)


# ─── HELPER FUNCTIONS ────────────────────────────────────────────────────────

def fetch_asset(asset_id: str, token: str):
    """Fetch full asset detail including ML analysis from FastAPI."""
    try:
        response = requests.get(
            f"{API}/analyze/{asset_id.strip()}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15
        )
        if response.status_code == 200:
            return response.json(), None
        elif response.status_code == 401:
            return None, "Session expired — please log out and log back in."
        elif response.status_code == 404:
            return None, f"Asset '{asset_id}' not found."
        return None, f"API error {response.status_code}"
    except requests.exceptions.ConnectionError:
        return None, "Backend not running."
    except requests.exceptions.Timeout:
        return None, "Request timed out."


def fetch_all_asset_ids(token: str):
    """Fetch just asset IDs for the dropdown selector."""
    try:
        response = requests.get(
            f"{API}/assets",
            params={"slim": True},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30
        )
        if response.status_code == 200:
            assets = response.json().get("assets", [])
            return [a["asset_id"] for a in assets]
        return []
    except:
        return []


def risk_badge_html(level):
    css = {
        "Critical": "badge-critical",
        "High":     "badge-high",
        "Medium":   "badge-medium",
        "Low":      "badge-low",
    }.get(level or "Low", "badge-low")
    return f'<span class="{css}">{level or "Unknown"}</span>'


def severity_color(val):
    colors = {
        "Critical": "background-color:#450A0A; color:#FCA5A5;",
        "High":     "background-color:#431407; color:#FED7AA;",
        "Medium":   "background-color:#422006; color:#FDE68A;",
        "Low":      "background-color:#052E16; color:#86EFAC;",
    }
    return colors.get(val, "")


def cvss_color(val):
    try:
        v = float(val)
        if v >= 9.0:   return "background-color:#450A0A; color:#FCA5A5;"
        elif v >= 7.0: return "background-color:#431407; color:#FED7AA;"
        elif v >= 4.0: return "background-color:#422006; color:#FDE68A;"
        else:          return "background-color:#052E16; color:#86EFAC;"
    except:
        return ""


def bool_color(val):
    if val == "✅ Yes": return "background-color:#052E16; color:#86EFAC;"
    elif val == "❌ No": return "background-color:#450A0A; color:#FCA5A5;"
    return ""


# ─── PAGE HEADER ─────────────────────────────────────────────────────────────
st.markdown("# 🏠 Asset Detail")
st.markdown(
    "<p style='color:#94A3B8'>Deep dive into any asset — "
    "full info, CVEs, risk score and owner.</p>",
    unsafe_allow_html=True
)
st.divider()

# ─── ASSET SELECTOR ───────────────────────────────────────────────────────────
col_input, col_or, col_select = st.columns([3, 1, 3])

with col_input:
    typed_id = st.text_input(
        "Type Asset ID",
        placeholder="e.g. ASSET-1042",
    )

with col_or:
    st.markdown(
        "<p style='text-align:center; padding-top:32px; "
        "color:#94A3B8;'>— or —</p>",
        unsafe_allow_html=True
    )

with col_select:
    all_ids = fetch_all_asset_ids(st.session_state["jwt"])
    if all_ids:
        selected_id = st.selectbox(
            "Pick from list",
            options=[""] + sorted(all_ids),
        )
    else:
        selected_id = ""
        st.warning("Could not load asset list.")

# Typed ID takes priority over dropdown
asset_id = typed_id.strip().upper() if typed_id.strip() else selected_id

if not asset_id:
    st.info("👆 Type an Asset ID or pick one from the dropdown to view its details.")
    st.stop()

# ─── FETCH ASSET ─────────────────────────────────────────────────────────────
response_data, error = fetch_asset(asset_id, st.session_state["jwt"])

if error:
    st.error(f"❌ {error}")
    st.stop()

asset           = response_data.get("asset", {})
ml_analysis     = response_data.get("ml_analysis", {})
recommendations = response_data.get("recommendations", [])

# ─── ASSET HEADER ────────────────────────────────────────────────────────────
owner      = asset.get("owner") or {}
risk_level = ml_analysis.get("risk_level") or asset.get("risk_level") or "Unknown"
risk_score = ml_analysis.get("risk_score") or asset.get("risk_score") or 0

st.markdown(f"## {asset['asset_id']} — {asset['asset_type']}")

header_col1, header_col2, header_col3, header_col4 = st.columns(4)

with header_col1:
    st.markdown(
        f"<div class='info-card'>"
        f"<div class='info-label'>Risk Level</div>"
        f"<div style='margin-top:6px'>{risk_badge_html(risk_level)}</div>"
        f"</div>",
        unsafe_allow_html=True
    )

with header_col2:
    st.markdown(
        f"<div class='info-card'>"
        f"<div class='info-label'>Risk Score</div>"
        f"<div class='info-value'>{risk_score:.1f} / 100</div>"
        f"</div>",
        unsafe_allow_html=True
    )

with header_col3:
    st.markdown(
        f"<div class='info-card'>"
        f"<div class='info-label'>Environment</div>"
        f"<div class='info-value'>{asset.get('environment', '—')}</div>"
        f"</div>",
        unsafe_allow_html=True
    )

with header_col4:
    exposed = asset.get("internet_exposed", False)
    st.markdown(
        f"<div class='info-card'>"
        f"<div class='info-label'>Internet Exposed</div>"
        f"<div class='info-value'>{'🌐 Yes' if exposed else '🔒 No'}</div>"
        f"</div>",
        unsafe_allow_html=True
    )

st.divider()

# ─── ASSET DETAILS ────────────────────────────────────────────────────────────
st.markdown("#### 🖥️ Asset Information")

detail_col1, detail_col2 = st.columns(2)

with detail_col1:
    os_info = asset.get("os") or {}
    sw_info = asset.get("software") or {}

    st.markdown(
        f"<div class='info-card'>"
        f"<div class='info-label'>IP Address</div>"
        f"<div class='info-value'>{asset.get('ip_address', '—')}</div>"
        f"<div class='info-label' style='margin-top:10px;'>Domain</div>"
        f"<div class='info-value'>{asset.get('domain', '—')}</div>"
        f"<div class='info-label' style='margin-top:10px;'>Criticality</div>"
        f"<div class='info-value'>{asset.get('criticality', '—')}</div>"
        f"</div>",
        unsafe_allow_html=True
    )

with detail_col2:
    st.markdown(
        f"<div class='info-card'>"
        f"<div class='info-label'>Operating System</div>"
        f"<div class='info-value'>"
        f"{os_info.get('name', '—')} {os_info.get('version', '')}</div>"
        f"<div class='info-label' style='margin-top:10px;'>Software</div>"
        f"<div class='info-value'>"
        f"{sw_info.get('name', '—')} v{sw_info.get('version', '—')}</div>"
        f"<div class='info-label' style='margin-top:10px;'>Last Scan</div>"
        f"<div class='info-value'>{asset.get('last_scan_date', '—')}</div>"
        f"</div>",
        unsafe_allow_html=True
    )

# ─── OWNER SECTION ────────────────────────────────────────────────────────────
st.markdown("#### 👤 Owner Information")

owner_status = owner.get("status", "orphan")
owner_badge  = (
    f"<span class='badge-orphan'>👻 Orphan</span>"
    if owner_status == "orphan"
    else f"<span class='badge-assigned'>✅ Assigned</span>"
)

st.markdown(
    f"<div class='info-card'>"
    f"<div style='display:flex; align-items:center; gap:12px;'>"
    f"<div>"
    f"<div class='info-label'>Status</div>"
    f"<div style='margin-top:4px'>{owner_badge}</div>"
    f"</div>"
    f"<div style='margin-left:24px;'>"
    f"<div class='info-label'>Team</div>"
    f"<div class='info-value'>{owner.get('team', '—') or '—'}</div>"
    f"</div>"
    f"<div style='margin-left:24px;'>"
    f"<div class='info-label'>Email</div>"
    f"<div class='info-value'>{owner.get('email', '—') or '—'}</div>"
    f"</div>"
    f"</div>"
    f"</div>",
    unsafe_allow_html=True
)

if owner_status == "orphan":
    st.markdown("""
        <div style='background:#1C0A0A; border:1px solid #7F1D1D;
                    border-radius:8px; padding:12px; margin-top:8px;'>
            <p style='color:#FCA5A5; margin:0; font-size:13px;'>
                ⚠️ <b>No owner assigned.</b>
                This is a security risk — unowned assets may not be
                monitored or patched regularly.
            </p>
        </div>
        """, unsafe_allow_html=True)

st.divider()

# ─── VULNERABILITIES SECTION ─────────────────────────────────────────────────
vulns = asset.get("vulnerabilities", [])

st.markdown(f"#### 🐛 Vulnerabilities ({len(vulns)} CVEs detected)")

if not vulns:
    st.success("✅ No vulnerabilities detected for this asset.")
else:
    vuln_rows = []
    for v in vulns:
        vuln_rows.append({
            "CVE ID":      v.get("cve", ""),
            "Severity":    v.get("severity", "Unknown"),
            "CVSS":        v.get("cvss_score") or 0.0,
            "Exploit":     "✅ Yes" if v.get("exploit_available") else "❌ No",
            "Patch":       "✅ Yes" if v.get("patch_available") else "❌ No",
            "Description": v.get("description", "")[:100] + "..."
                           if len(v.get("description", "")) > 100
                           else v.get("description", ""),
        })

    vuln_df = pd.DataFrame(vuln_rows).sort_values("CVSS", ascending=False)

    styled_vulns = (
        vuln_df.style
        .map(severity_color, subset=["Severity"])
        .map(cvss_color,     subset=["CVSS"])
        .map(bool_color,     subset=["Exploit", "Patch"])
        .format({"CVSS": "{:.1f}"})
    )

    st.dataframe(
        styled_vulns,
        hide_index=True,
        use_container_width=False,
        height=min(80 + len(vuln_rows) * 38, 400),
    )

    exploit_count   = sum(1 for v in vulns if v.get("exploit_available"))
    unpatched_count = sum(1 for v in vulns if not v.get("patch_available"))

    vc1, vc2, vc3 = st.columns(3)
    with vc1:
        st.metric("Total CVEs",      len(vulns))
    with vc2:
        st.metric("Active Exploits", exploit_count)
    with vc3:
        st.metric("Unpatched",       unpatched_count)

st.divider()

# ─── RISK SCORE BREAKDOWN ────────────────────────────────────────────────────
st.markdown("#### 📊 Risk Score Breakdown")
st.markdown(
    "<p style='color:#94A3B8; font-size:13px;'>How the risk score is calculated:</p>",
    unsafe_allow_html=True
)

score_color = (
    "#EF4444" if risk_score >= 80 else
    "#F97316" if risk_score >= 60 else
    "#F59E0B" if risk_score >= 40 else
    "#10B981"
)

st.markdown(
    f"""
    <div style='background:#1E293B; border-radius:10px; padding:16px;'>
        <div style='display:flex; justify-content:space-between; margin-bottom:8px;'>
            <span style='color:#94A3B8;'>Overall Risk Score</span>
            <span style='color:{score_color}; font-weight:700; font-size:18px;'>
                {risk_score:.1f} / 100
            </span>
        </div>
        <div style='background:#334155; border-radius:6px; height:12px;'>
            <div style='background:{score_color}; width:{min(risk_score, 100):.0f}%;
                        height:12px; border-radius:6px;'></div>
        </div>
        <div style='display:flex; justify-content:space-between; margin-top:6px;'>
            <span style='color:#10B981; font-size:11px;'>Low (0)</span>
            <span style='color:#F59E0B; font-size:11px;'>Medium (40)</span>
            <span style='color:#F97316; font-size:11px;'>High (60)</span>
            <span style='color:#EF4444; font-size:11px;'>Critical (80+)</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

st.markdown("")

factors = []
if asset.get("internet_exposed"):
    factors.append(("🌐 Internet Exposed",    "High impact — publicly reachable surface", "#EF4444"))
if asset.get("criticality") == "High":
    factors.append(("🔑 High Criticality",    "Business-critical asset",                  "#F97316"))
if vulns and exploit_count > 0:
    factors.append(("💥 Active Exploits",
                    f"{exploit_count} CVE(s) with known exploits in the wild",             "#EF4444"))
if vulns and unpatched_count > 0:
    factors.append(("🩹 Unpatched CVEs",
                    f"{unpatched_count} CVE(s) with no patch available",                   "#F59E0B"))
if owner.get("status") == "orphan":
    factors.append(("👻 No Owner",            "Unowned assets are rarely monitored",       "#F97316"))

if factors:
    st.markdown(
        "<p style='color:#94A3B8; font-size:13px; margin-top:12px;'>"
        "Contributing risk factors:</p>",
        unsafe_allow_html=True
    )
    for icon_label, desc, color in factors:
        st.markdown(
            f"<div style='display:flex; align-items:center; gap:10px; "
            f"padding:8px 12px; background:#1E293B; border-left:3px solid {color}; "
            f"border-radius:6px; margin-bottom:6px;'>"
            f"<span style='color:{color}; font-weight:600;'>{icon_label}</span>"
            f"<span style='color:#94A3B8; font-size:13px;'>{desc}</span>"
            f"</div>",
            unsafe_allow_html=True
        )

# ─── ML ANALYSIS SECTION ─────────────────────────────────────────────────────
if ml_analysis:
    st.divider()
    st.markdown("#### 🤖 ML Analysis — Feature Breakdown")
    st.markdown(
        f"<p style='color:#94A3B8; font-size:13px;'>"
        f"Model confidence: <b style='color:#F8FAFC'>"
        f"{ml_analysis.get('confidence', 0)*100:.1f}%</b> — "
        f"top features that drove the risk score:</p>",
        unsafe_allow_html=True
    )

    top_features = ml_analysis.get("top_features", [])
    for feat in top_features:
        importance = feat.get("importance", 0)
        bar_width  = int(importance * 400)
        feat_color = (
            "#EF4444" if importance > 0.20 else
            "#F97316" if importance > 0.12 else
            "#F59E0B" if importance > 0.06 else
            "#10B981"
        )
        st.markdown(
            f"""
            <div style='margin-bottom:8px;'>
                <div style='display:flex; justify-content:space-between;
                            margin-bottom:3px;'>
                    <span style='color:#94A3B8; font-size:12px;
                                 font-family:monospace;'>
                        {feat['feature']}
                    </span>
                    <span style='color:#F8FAFC; font-size:12px;'>
                        value: {feat['value']} &nbsp;|&nbsp;
                        weight: {importance:.4f}
                    </span>
                </div>
                <div style='background:#1E293B; border-radius:4px; height:8px;'>
                    <div style='background:{feat_color};
                                width:{min(bar_width, 400)}px;
                                height:8px; border-radius:4px;'></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

# ─── RECOMMENDATIONS SECTION ──────────────────────────────────────────────────
if recommendations:
    st.divider()
    st.markdown("#### 🛡️ Recommended Actions")
    st.markdown(
        "<p style='color:#94A3B8; font-size:13px;'>"
        "Prioritised remediation steps based on ML risk analysis:</p>",
        unsafe_allow_html=True
    )

    priority_colors = {
        "CRITICAL": "#EF4444",
        "HIGH":     "#F97316",
        "MEDIUM":   "#F59E0B",
        "LOW":      "#10B981",
    }

    for i, rec in enumerate(recommendations, 1):
        priority = rec.get("priority", "LOW")
        color    = priority_colors.get(priority, "#10B981")
        st.markdown(
            f"""
            <div style='display:flex; align-items:flex-start; gap:12px;
                        padding:12px; background:#1E293B;
                        border-left:4px solid {color};
                        border-radius:6px; margin-bottom:8px;'>
                <span style='background:{color}22; color:{color};
                             font-size:11px; font-weight:700;
                             padding:2px 8px; border-radius:4px;
                             white-space:nowrap;'>
                    {priority}
                </span>
                <span style='color:#CBD5E1; font-size:13px;'>
                    {rec.get("action", "")}
                </span>
            </div>
            """,
            unsafe_allow_html=True
        )