import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import sys, os

# ─── CONFIG ──────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Risk Dashboard — Sentinel",
    page_icon="📊",
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
    [data-testid="stMetricValue"] {
        color: #F8FAFC !important;
        font-weight: 700 !important;
    }
</style>
""", unsafe_allow_html=True)

# ─── CHART THEME ─────────────────────────────────────────────────────────────
CHART_LAYOUT = dict(
    paper_bgcolor="#1E293B",
    plot_bgcolor="#1E293B",
    font=dict(color="#CBD5E1", size=12),
    margin=dict(l=20, r=20, t=40, b=20),
    showlegend=True,
    legend=dict(
        bgcolor="#1E293B",
        bordercolor="#334155",
        borderwidth=1,
        font=dict(color="#CBD5E1")
    )
)

RISK_COLORS = {
    "Critical": "#EF4444",
    "High":     "#F97316",
    "Medium":   "#F59E0B",
    "Low":      "#10B981",
}

# ─── HELPER FUNCTIONS ────────────────────────────────────────────────────────

def fetch_all_assets(token: str):
    """Fetch all assets in slim mode for chart data."""
    try:
        response = requests.get(
            f"{API}/assets",
            params={"slim": True},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30
        )
        if response.status_code == 200:
            return response.json().get("assets", []), None
        if response.status_code == 401:
            return [], "Session expired — please log out and log back in."
        return [], f"API error {response.status_code}"
    except requests.exceptions.ConnectionError:
        return [], "Backend not running."
    except requests.exceptions.Timeout:
        return [], "Request timed out."


def fetch_risk_summary(token: str):
    """Fetch top 10 highest risk assets."""
    try:
        response = requests.get(
            f"{API}/risk-summary",
            headers={"Authorization": f"Bearer {token}"},
            timeout=30
        )
        if response.status_code == 200:
            return response.json().get("top_risk_assets", []), None
        if response.status_code == 401:
            return [], "Session expired — please log out and log back in."
        return [], f"API error {response.status_code}"
    except requests.exceptions.ConnectionError:
        return [], "Backend not running."
    except requests.exceptions.Timeout:
        return [], "Request timed out."


def fetch_stats(token: str):
    """Fetch summary stats for metric cards."""
    try:
        response = requests.get(
            f"{API}/stats",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10
        )
        if response.status_code == 200:
            return response.json(), None
        if response.status_code == 401:
            return None, "Session expired — please log out and log back in."
        return None, f"API error {response.status_code}"
    except Exception:
        return None, "Could not load stats."


# ─── PAGE HEADER ─────────────────────────────────────────────────────────────
st.markdown("# 📊 Risk Dashboard")
st.markdown(
    "<p style='color:#94A3B8'>Visual breakdown of your organisation's "
    "security risk posture.</p>",
    unsafe_allow_html=True
)
st.divider()

# ─── FETCH ALL DATA ───────────────────────────────────────────────────────────
token = st.session_state["jwt"]

assets, err1      = fetch_all_assets(token)
top_assets, err2  = fetch_risk_summary(token)
stats, err3       = fetch_stats(token)

for err in [err1, err2, err3]:
    if err:
        st.error(f"❌ {err}")
        st.stop()

df = pd.DataFrame(assets)

if df.empty:
    st.warning("No asset data available.")
    st.stop()

# ─── METRIC CARDS ────────────────────────────────────────────────────────────
st.markdown("### 🎯 At a Glance")

c1, c2, c3, c4, c5 = st.columns(5)

with c1:
    st.metric("🖥️ Total Assets",    stats["total_assets"])
with c2:
    st.metric("🔴 Critical Risk",   stats["critical_count"])
with c3:
    st.metric("🌐 Exposed",         stats["exposed_count"])
with c4:
    st.metric("👻 Orphans",         stats["orphan_count"])
with c5:
    st.metric("💥 Active Exploits", stats["exploit_count"])

st.divider()

# ─── ROW 1: Top 10 Bar Chart + Donut Chart ────────────────────────────────────
st.markdown("### 🏆 Top Risk Assets & Distribution")

chart_col1, chart_col2 = st.columns([3, 2])

with chart_col1:
    st.markdown("#### Top 10 Highest Risk Assets")

    if top_assets:
        top_df = pd.DataFrame(top_assets)
        top_df["color"] = top_df["risk_level"].map(RISK_COLORS).fillna("#64748B")

        fig_bar = go.Figure()

        for level, color in RISK_COLORS.items():
            mask = top_df["risk_level"] == level
            if mask.any():
                subset = top_df[mask]
                fig_bar.add_trace(go.Bar(
                    y=subset["asset_id"],
                    x=subset["risk_score"],
                    name=level,
                    orientation="h",
                    marker_color=color,
                    text=subset["risk_score"].round(1),
                    textposition="outside",
                    hovertemplate=(
                        "<b>%{y}</b><br>"
                        "Risk Score: %{x:.1f}<br>"
                        f"Level: {level}<extra></extra>"
                    )
                ))

        fig_bar.update_layout(
            **CHART_LAYOUT,
            height=380,
            xaxis=dict(
                title="Risk Score",
                range=[0, 110],
                gridcolor="#334155",
                color="#94A3B8"
            ),
            yaxis=dict(
                title="",
                color="#94A3B8",
                categoryorder="total ascending"
            ),
            barmode="overlay",
        )

        st.plotly_chart(fig_bar, use_container_width=False)
    else:
        st.info("No risk data available.")

with chart_col2:
    st.markdown("#### Risk Level Distribution")

    risk_counts = df["risk_level"].value_counts().reset_index()
    risk_counts.columns = ["Risk Level", "Count"]

    order = ["Critical", "High", "Medium", "Low"]
    risk_counts["Risk Level"] = pd.Categorical(
        risk_counts["Risk Level"], categories=order, ordered=True
    )
    risk_counts = risk_counts.sort_values("Risk Level")

    colors = [RISK_COLORS.get(l, "#64748B") for l in risk_counts["Risk Level"]]

    fig_donut = go.Figure(go.Pie(
        labels=risk_counts["Risk Level"],
        values=risk_counts["Count"],
        hole=0.55,
        marker_colors=colors,
        textinfo="label+percent",
        textfont=dict(color="#F8FAFC", size=12),
        hovertemplate="<b>%{label}</b><br>Assets: %{value}<br>%{percent}<extra></extra>"
    ))

    fig_donut.add_annotation(
        text=f"<b>{len(df)}</b><br>Assets",
        x=0.5, y=0.5,
        font=dict(size=16, color="#F8FAFC"),
        showarrow=False
    )

    fig_donut.update_layout(
        **CHART_LAYOUT,
        height=380,
    )

    st.plotly_chart(fig_donut, use_container_width=False)

st.divider()

# ─── ROW 2: Risk by Environment + Exposed vs Internal ─────────────────────────
st.markdown("### 🌍 Risk by Environment & Exposure")

env_col1, env_col2 = st.columns(2)

with env_col1:
    st.markdown("#### Risk by Environment")

    env_risk = (
        df.groupby(["environment", "risk_level"])
        .size()
        .reset_index(name="count")
    )

    fig_env = go.Figure()

    for level in ["Critical", "High", "Medium", "Low"]:
        subset = env_risk[env_risk["risk_level"] == level]
        if not subset.empty:
            fig_env.add_trace(go.Bar(
                name=level,
                x=subset["environment"],
                y=subset["count"],
                marker_color=RISK_COLORS[level],
                hovertemplate=(
                    f"<b>{level}</b><br>"
                    "Environment: %{x}<br>"
                    "Assets: %{y}<extra></extra>"
                )
            ))

    fig_env.update_layout(
        **CHART_LAYOUT,
        height=320,
        barmode="stack",
        xaxis=dict(title="Environment", color="#94A3B8", gridcolor="#334155"),
        yaxis=dict(title="Number of Assets", color="#94A3B8", gridcolor="#334155"),
    )

    st.plotly_chart(fig_env, use_container_width=False)

with env_col2:
    st.markdown("#### Internet Exposed vs Internal")

    exposed_counts = df["internet_exposed"].value_counts().reset_index()
    exposed_counts.columns = ["Exposed", "Count"]
    exposed_counts["Label"] = exposed_counts["Exposed"].map(
        {True: "🌐 Internet Exposed", False: "🔒 Internal Only"}
    )

    fig_exp = go.Figure(go.Pie(
        labels=exposed_counts["Label"],
        values=exposed_counts["Count"],
        hole=0.5,
        marker_colors=["#EF4444", "#10B981"],
        textinfo="label+percent",
        textfont=dict(color="#F8FAFC", size=12),
        hovertemplate="<b>%{label}</b><br>Assets: %{value}<br>%{percent}<extra></extra>"
    ))

    fig_exp.update_layout(
        **CHART_LAYOUT,
        height=320,
    )

    st.plotly_chart(fig_exp, use_container_width=False)

st.divider()

# ─── ROW 3: Risk Score Distribution Histogram ─────────────────────────────────
st.markdown("### 📈 Risk Score Distribution")

fig_hist = px.histogram(
    df,
    x="risk_score",
    nbins=20,
    color_discrete_sequence=["#3B82F6"],
    labels={"risk_score": "Risk Score", "count": "Number of Assets"},
    title=""
)

for score, label, color in [
    (40,  "Low→Medium",    "#F59E0B"),
    (60,  "Medium→High",   "#F97316"),
    (80,  "High→Critical", "#EF4444"),
]:
    fig_hist.add_vline(
        x=score,
        line_dash="dash",
        line_color=color,
        annotation_text=label,
        annotation_font_color=color,
        annotation_position="top right"
    )

fig_hist.update_layout(
    **CHART_LAYOUT,
    height=280,
    xaxis=dict(title="Risk Score (0-100)", gridcolor="#334155", color="#94A3B8"),
    yaxis=dict(title="Number of Assets", gridcolor="#334155", color="#94A3B8"),
)

st.plotly_chart(fig_hist, use_container_width=False)

st.divider()

# ─── ROW 4: Criticality Breakdown ────────────────────────────────────────────
st.markdown("### 🔑 Asset Criticality Breakdown")

crit_col1, crit_col2 = st.columns(2)

with crit_col1:
    crit_counts = df["criticality"].value_counts().reset_index()
    crit_counts.columns = ["Criticality", "Count"]

    fig_crit = px.bar(
        crit_counts,
        x="Criticality",
        y="Count",
        color="Criticality",
        color_discrete_map={
            "High":   "#EF4444",
            "Medium": "#F59E0B",
            "Low":    "#10B981",
        },
        title="Assets by Criticality Level"
    )

    fig_crit.update_layout(
        **{k: v for k, v in CHART_LAYOUT.items() if k != "showlegend"},
        height=280,
        showlegend=False,
        xaxis=dict(color="#94A3B8", gridcolor="#334155"),
        yaxis=dict(color="#94A3B8", gridcolor="#334155"),
    )

    st.plotly_chart(fig_crit, use_container_width=False)

with crit_col2:
    type_risk = (
        df.groupby("asset_type")["risk_score"]
        .mean()
        .reset_index()
        .sort_values("risk_score", ascending=False)
        .head(8)
    )
    type_risk.columns = ["Asset Type", "Avg Risk Score"]

    fig_type = px.bar(
        type_risk,
        x="Asset Type",
        y="Avg Risk Score",
        color="Avg Risk Score",
        color_continuous_scale=["#10B981", "#F59E0B", "#EF4444"],
        title="Average Risk Score by Asset Type"
    )

    fig_type.update_layout(
        **{k: v for k, v in CHART_LAYOUT.items() if k != "showlegend"},
        height=280,
        showlegend=False,
        xaxis=dict(color="#94A3B8", gridcolor="#334155", tickangle=-30),
        yaxis=dict(color="#94A3B8", gridcolor="#334155"),
        coloraxis_showscale=False,
    )

    st.plotly_chart(fig_type, use_container_width=False)