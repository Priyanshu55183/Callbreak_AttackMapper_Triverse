"""
pages/7_Admin_Panel.py
───────────────────────────────────────────────────────────────────────────────
Sentinel Admin Panel — Admin only

Features:
  1. Add Asset form  (POST /assets)
  2. Asset table with Delete buttons (DELETE /assets/{id})
  3. Generate & download PDF report
  4. Send test email alert
  5. Send weekly report email
───────────────────────────────────────────────────────────────────────────────
"""

import streamlit as st
import requests
import pandas as pd
import sys, os
from datetime import datetime

# ─── CONFIG ──────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Admin Panel — Sentinel",
    page_icon="⚙️",
    layout="wide"
)

# ── shared auth ───────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from auth_utils import require_auth, get_role, API

require_auth()

# ─── ADMIN GATE ───────────────────────────────────────────────────────────────
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
    [data-testid="stMetricValue"] { color: #F8FAFC !important; font-weight: 700 !important; }

    div[data-testid="stForm"] {
        background-color: #1E293B;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 20px;
    }
    .section-header {
        background: linear-gradient(90deg, #0F2744, #1E293B);
        border-left: 4px solid #1A56DB;
        border-radius: 0 8px 8px 0;
        padding: 10px 16px;
        margin-bottom: 16px;
    }
</style>
""", unsafe_allow_html=True)


# ─── HELPER FUNCTIONS ────────────────────────────────────────────────────────

def fetch_all_assets(token):
    try:
        r = requests.get(
            f"{API}/assets",
            params={"slim": True},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30
        )
        if r.status_code == 200:
            return r.json().get("assets", [])
        return []
    except:
        return []


def fetch_stats(token):
    try:
        r = requests.get(
            f"{API}/stats",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10
        )
        return r.json() if r.status_code == 200 else {}
    except:
        return {}


def delete_asset(asset_id: str, token: str):
    try:
        r = requests.delete(
            f"{API}/assets/{asset_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15
        )
        if r.status_code == 200:
            return True, "Deleted successfully."
        if r.status_code == 404:
            return False, f"Asset '{asset_id}' not found."
        return False, f"API error {r.status_code}: {r.text[:100]}"
    except Exception as e:
        return False, str(e)


def create_asset(payload: dict, token: str):
    try:
        r = requests.post(
            f"{API}/assets",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
            timeout=30
        )
        if r.status_code == 200:
            return True, r.json()
        return False, r.json().get("detail", f"API error {r.status_code}")
    except Exception as e:
        return False, str(e)


def generate_pdf_report(token: str):
    try:
        r = requests.post(
            f"{API}/report/generate",
            headers={"Authorization": f"Bearer {token}"},
            timeout=60
        )
        if r.status_code == 200:
            return r.content, None
        return None, f"API error {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return None, str(e)


def send_alert_email(alert_type: str, token: str, recipient: str = ""):
    try:
        r = requests.post(
            f"{API}/alerts/send",
            json={"alert_type": alert_type, "recipient": recipient},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30
        )
        if r.status_code == 200:
            return True, r.json()
        return False, r.json().get("detail", f"API error {r.status_code}")
    except Exception as e:
        return False, str(e)


# ─── PAGE HEADER ─────────────────────────────────────────────────────────────
st.markdown("# ⚙️ Admin Panel")
st.markdown(
    "<p style='color:#94A3B8'>Manage assets, generate reports, and configure alerts.</p>",
    unsafe_allow_html=True
)
st.divider()

token = st.session_state["jwt"]

# ─── SECTION 1: STATS OVERVIEW ───────────────────────────────────────────────
st.markdown("""
<div class="section-header">
  <span style="color:#F8FAFC; font-weight:700; font-size:16px;">📊 Current Inventory Status</span>
</div>
""", unsafe_allow_html=True)

stats = fetch_stats(token)
if stats:
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1: st.metric("🖥️ Total Assets",    stats.get("total_assets", 0))
    with c2: st.metric("🔴 Critical",         stats.get("critical_count", 0))
    with c3: st.metric("🌐 Exposed",          stats.get("exposed_count", 0))
    with c4: st.metric("👻 Orphans",          stats.get("orphan_count", 0))
    with c5: st.metric("💥 Active Exploits",  stats.get("exploit_count", 0))

st.divider()

# ─── SECTION 2: ADD ASSET ────────────────────────────────────────────────────
st.markdown("""
<div class="section-header">
  <span style="color:#F8FAFC; font-weight:700; font-size:16px;">➕ Add New Asset</span>
</div>
""", unsafe_allow_html=True)

with st.form("add_asset_form", clear_on_submit=True):

    # Row 1 — Core identity
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        asset_id = st.text_input("Asset ID *", placeholder="e.g. ASSET-9001")
    with col2:
        asset_type = st.selectbox("Type *", [
            "Server", "Workstation", "IoT Device", "Router",
            "Firewall", "Database", "Container", "Cloud Instance", "API Gateway"
        ])
    with col3:
        environment = st.selectbox("Environment *", ["Production", "Staging", "Development"])
    with col4:
        criticality = st.selectbox("Criticality *", ["High", "Medium", "Low"])

    # Row 2 — Network
    col5, col6, col7 = st.columns(3)
    with col5:
        ip_address = st.text_input("IP Address", placeholder="e.g. 10.0.1.42")
    with col6:
        domain = st.text_input("Domain", placeholder="e.g. server.company.com")
    with col7:
        internet_exposed = st.checkbox("Internet Exposed", value=False)

    # Row 3 — OS + Software
    col8, col9, col10, col11 = st.columns(4)
    with col8:
        os_name = st.text_input("OS Name", placeholder="e.g. Ubuntu")
    with col9:
        os_version = st.text_input("OS Version", placeholder="e.g. 22.04")
    with col10:
        software_name = st.text_input("Software", placeholder="e.g. nginx")
    with col11:
        software_version = st.text_input("Version", placeholder="e.g. 1.18.0")

    # Row 4 — Owner
    st.markdown("**Owner Details** *(leave blank for orphan)*")
    col12, col13, col14 = st.columns(3)
    with col12:
        owner_team = st.text_input("Owner Team", placeholder="e.g. DevOps")
    with col13:
        owner_email = st.text_input("Owner Email", placeholder="e.g. devops@company.com")
    with col14:
        last_scan = st.date_input("Last Scan Date", value=datetime.today())

    st.markdown("<br>", unsafe_allow_html=True)

    submitted = st.form_submit_button("➕ Add Asset", use_container_width=True, type="primary")

    if submitted:
        if not asset_id.strip():
            st.error("❌ Asset ID is required.")
        else:
            # Build payload
            payload = {
                "asset_id":         asset_id.strip().upper(),
                "asset_type":       asset_type,
                "environment":      environment,
                "criticality":      criticality,
                "ip_address":       ip_address.strip() or None,
                "domain":           domain.strip() or None,
                "internet_exposed": internet_exposed,
                "os_name":          os_name.strip() or None,
                "os_version":       os_version.strip() or None,
                "software_name":    software_name.strip() or None,
                "software_version": software_version.strip() or None,
                "last_scan_date":   str(last_scan),
                "vulnerabilities":  [],
            }

            if owner_team.strip() or owner_email.strip():
                payload["owner"] = {
                    "team":   owner_team.strip() or None,
                    "email":  owner_email.strip() or None,
                    "status": "assigned",
                }
            else:
                payload["owner"] = None

            with st.spinner(f"Creating asset {payload['asset_id']}..."):
                success, result = create_asset(payload, token)

            if success:
                risk_lvl = result.get("ml_scoring", {}).get("risk_level", "Unknown")
                risk_scr = result.get("ml_scoring", {}).get("risk_score", 0)
                st.success(
                    f"✅ Asset **{payload['asset_id']}** created! "
                    f"Risk: **{risk_lvl}** ({risk_scr:.1f}/100). "
                    f"CVE source: `{result.get('cve_source', 'unknown')}`"
                )
                st.rerun()
            else:
                st.error(f"❌ Failed to create asset: {result}")

st.divider()

# ─── SECTION 3: ASSET MANAGEMENT TABLE ───────────────────────────────────────
st.markdown("""
<div class="section-header">
  <span style="color:#F8FAFC; font-weight:700; font-size:16px;">🗂️ Asset Management</span>
</div>
""", unsafe_allow_html=True)

assets = fetch_all_assets(token)

if not assets:
    st.warning("No assets found or backend not reachable.")
else:
    # Search filter for the table
    search = st.text_input(
        "🔎 Filter assets",
        placeholder="Search by Asset ID, type, environment...",
        key="admin_search"
    )

    df = pd.DataFrame([{
        "Asset ID":    a.get("asset_id"),
        "Type":        a.get("asset_type"),
        "Environment": a.get("environment"),
        "Criticality": a.get("criticality"),
        "Risk Level":  a.get("risk_level", "—"),
        "Risk Score":  round(a.get("risk_score") or 0, 1),
        "Exposed":     "🌐 Yes" if a.get("internet_exposed") else "🔒 No",
        "Owner":       (a.get("owner") or {}).get("team", "—") or "—",
        "Status":      (a.get("owner") or {}).get("status", "orphan"),
    } for a in assets])

    if search:
        mask = (
            df["Asset ID"].str.contains(search, case=False, na=False) |
            df["Type"].str.contains(search, case=False, na=False) |
            df["Environment"].str.contains(search, case=False, na=False)
        )
        df = df[mask]

    def color_risk(val):
        return {
            "Critical": "background-color:#450A0A; color:#FCA5A5;",
            "High":     "background-color:#431407; color:#FED7AA;",
            "Medium":   "background-color:#422006; color:#FDE68A;",
            "Low":      "background-color:#052E16; color:#86EFAC;",
        }.get(val, "")

    def color_status(val):
        if val == "orphan":
            return "background-color:#450A0A; color:#FCA5A5;"
        return "background-color:#052E16; color:#86EFAC;"

    styled = (
        df.style
        .map(color_risk,   subset=["Risk Level"])
        .map(color_status, subset=["Status"])
        .format({"Risk Score": "{:.1f}"})
    )

    st.markdown(
        f"<p style='color:#94A3B8;'>Showing <b style='color:#F8FAFC'>{len(df)}</b> "
        f"of <b style='color:#F8FAFC'>{len(assets)}</b> assets</p>",
        unsafe_allow_html=True
    )
    st.dataframe(styled, hide_index=True, height=350)

    # ── Delete Asset ─────────────────────────────────────────────────────────
    st.markdown("#### 🗑️ Delete an Asset")
    st.markdown(
        "<p style='color:#94A3B8; font-size:13px;'>⚠️ This permanently removes the asset, "
        "all its CVEs, and its owner record from the database.</p>",
        unsafe_allow_html=True
    )

    del_col1, del_col2 = st.columns([3, 1])
    with del_col1:
        asset_ids_sorted = sorted([a["asset_id"] for a in assets])
        asset_to_delete = st.selectbox(
            "Select asset to delete",
            options=["— select —"] + asset_ids_sorted,
            key="delete_select"
        )
    with del_col2:
        st.markdown("<br>", unsafe_allow_html=True)
        delete_confirmed = st.button("🗑️ Delete", type="primary", key="delete_btn")

    if delete_confirmed:
        if asset_to_delete == "— select —":
            st.error("Please select an asset first.")
        else:
            with st.spinner(f"Deleting {asset_to_delete}..."):
                ok, msg = delete_asset(asset_to_delete, token)
            if ok:
                st.success(f"✅ {asset_to_delete} deleted.")
                st.rerun()
            else:
                st.error(f"❌ {msg}")

st.divider()

# ─── SECTION 4: PDF REPORT ────────────────────────────────────────────────────
st.markdown("""
<div class="section-header">
  <span style="color:#F8FAFC; font-weight:700; font-size:16px;">📄 Generate PDF Report</span>
</div>
""", unsafe_allow_html=True)

st.markdown(
    "<p style='color:#94A3B8;'>Generate a professional weekly security report "
    "covering all assets, CVEs, orphans, and remediation recommendations.</p>",
    unsafe_allow_html=True
)

report_col1, report_col2 = st.columns([2, 1])

with report_col1:
    if st.button("📄 Generate Report", type="primary", key="gen_report"):
        with st.spinner("Generating PDF report... (this may take 5–10 seconds)"):
            pdf_bytes, err = generate_pdf_report(token)

        if err:
            st.error(f"❌ {err}")
        else:
            ts = datetime.now().strftime("%Y-%m-%d")
            st.success("✅ Report generated successfully!")
            st.download_button(
                label="⬇️ Download PDF Report",
                data=pdf_bytes,
                file_name=f"sentinel_report_{ts}.pdf",
                mime="application/pdf",
                key="download_report"
            )

with report_col2:
    st.markdown(
        """
        <div style='background:#1E293B; border:1px solid #334155; border-radius:10px; padding:14px;'>
          <p style='color:#94A3B8; font-size:13px; margin:0;'>
            📋 <b style='color:#F8FAFC;'>Report includes:</b><br>
            • Executive summary metrics<br>
            • Top 10 highest-risk assets<br>
            • Dangerous CVEs (exploit+unpatched)<br>
            • Orphan asset list<br>
            • Prioritised recommendations
          </p>
        </div>
        """,
        unsafe_allow_html=True
    )

st.divider()

# ─── SECTION 5: EMAIL ALERTS ─────────────────────────────────────────────────
st.markdown("""
<div class="section-header">
  <span style="color:#F8FAFC; font-weight:700; font-size:16px;">📧 Email Alerts</span>
</div>
""", unsafe_allow_html=True)

st.markdown(
    "<p style='color:#94A3B8;'>Send manual alert emails to the configured recipient. "
    "Automatic alerts fire when new high-risk assets are added.</p>",
    unsafe_allow_html=True
)

alert_col1, alert_col2 = st.columns([2, 1])

with alert_col1:
    custom_recipient = st.text_input(
        "Override recipient email (optional)",
        placeholder="Leave blank to use ALERT_EMAIL_RECIPIENT from .env",
        key="alert_recipient"
    )

with alert_col2:
    st.markdown("<br>", unsafe_allow_html=True)
    alert_type = st.selectbox(
        "Alert type",
        ["weekly_report", "critical_summary", "orphan_summary"],
        key="alert_type"
    )

if st.button("📧 Send Alert Email", key="send_alert"):
    with st.spinner("Sending email..."):
        ok, result = send_alert_email(alert_type, token, custom_recipient)
    if ok:
        recipient = result.get("recipient", "configured address")
        st.success(f"✅ Email sent to **{recipient}**")
    else:
        st.error(f"❌ Failed: {result}")

# Email setup info
with st.expander("📋 Email Setup Instructions (expand if alerts aren't working)"):
    st.markdown("""
    **Add these to your `.env` file:**
    ```
    ALERT_EMAIL_SENDER=yourname@gmail.com
    ALERT_EMAIL_PASSWORD=xxxx xxxx xxxx xxxx
    ALERT_EMAIL_RECIPIENT=security-team@yourcompany.com
    ```

    **How to get a Gmail App Password:**
    1. Go to [myaccount.google.com](https://myaccount.google.com) → Security
    2. Enable **2-Step Verification** (required first)
    3. Search **"App Passwords"** → Generate one for "Mail"
    4. Copy the 16-character password into `.env` as `ALERT_EMAIL_PASSWORD`

    > ⚠️ Do NOT use your real Gmail password. App Passwords are separate tokens.

    **For Outlook / Office 365:**
    ```
    SMTP_HOST=smtp.office365.com
    SMTP_PORT=587
    ```

    **For SendGrid (recommended for production):**
    ```
    SMTP_HOST=smtp.sendgrid.net
    SMTP_PORT=587
    ALERT_EMAIL_SENDER=verified@yourdomain.com
    ALERT_EMAIL_PASSWORD=SG.your-sendgrid-api-key
    ```
    """)