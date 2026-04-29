"""
pages/8_Asset_Graph.py
───────────────────────────────────────────────────────────────────────────────
Sentinel Asset Graph — interactive network visualization

Each node = one asset, colored by risk level:
  🔴 Critical  (#EF4444)
  🟠 High      (#F97316)
  🟡 Medium    (#F59E0B)
  🟢 Low       (#10B981)

Node size = proportional to risk score
Edges = shared software, same environment, or shared CVE

Uses Plotly for rendering (already in your stack from Risk Dashboard)
No extra installs needed.
───────────────────────────────────────────────────────────────────────────────
"""

import streamlit as st
import requests
import plotly.graph_objects as go
import networkx as nx
import pandas as pd
import math
import sys, os

# ─── CONFIG ──────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Asset Graph — Sentinel",
    page_icon="🕸️",
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

    st.markdown("### 🕸️ Graph Controls")
    edge_mode = st.radio(
        "Show edges for assets sharing:",
        ["Same Environment", "Same Software", "Any CVE", "None (nodes only)"],
        index=0,
    )
    max_nodes = st.slider("Max assets to display", 30, 300, 100, step=10)
    st.divider()
    st.markdown(
        """
        <p style='color:#94A3B8; font-size:12px;'>
        <b style='color:#EF4444;'>● Critical</b> &nbsp;
        <b style='color:#F97316;'>● High</b> &nbsp;
        <b style='color:#F59E0B;'>● Medium</b> &nbsp;
        <b style='color:#10B981;'>● Low</b><br><br>
        Node size ∝ Risk Score<br>
        Hover a node for details
        </p>
        """,
        unsafe_allow_html=True
    )

# ─── CUSTOM CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .stApp { background-color: #0D1117; }
    [data-testid="stSidebar"] { background-color: #0F2744; }
    h1, h2, h3 { color: #F8FAFC !important; }
    p, div { color: #CBD5E1; }
    hr { border-color: #334155; }
    [data-testid="stMetric"] {
        background-color: #1E293B; border: 1px solid #334155;
        border-radius: 10px; padding: 16px;
    }
    [data-testid="stMetricLabel"] { color: #94A3B8 !important; }
    [data-testid="stMetricValue"] { color: #F8FAFC !important; font-weight: 700 !important; }
</style>
""", unsafe_allow_html=True)

# ─── CONSTANTS ───────────────────────────────────────────────────────────────
RISK_COLOR = {
    "Critical": "#EF4444",
    "High":     "#F97316",
    "Medium":   "#F59E0B",
    "Low":      "#10B981",
    "Unknown":  "#64748B",
}


# ─── HELPERS ─────────────────────────────────────────────────────────────────

def fetch_assets(token: str):
    try:
        r = requests.get(
            f"{API}/assets",
            params={"slim": True},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30
        )
        if r.status_code == 200:
            return r.json().get("assets", []), None
        if r.status_code == 401:
            return [], "Session expired."
        return [], f"API error {r.status_code}"
    except requests.exceptions.ConnectionError:
        return [], "Backend not running."
    except requests.exceptions.Timeout:
        return [], "Request timed out."


def fetch_vulnerabilities(token: str):
    """Fetch all CVEs so we can build shared-CVE edges."""
    try:
        r = requests.get(
            f"{API}/vulnerabilities",
            headers={"Authorization": f"Bearer {token}"},
            timeout=30
        )
        if r.status_code == 200:
            return r.json().get("vulnerabilities", [])
        return []
    except:
        return []


def build_graph(assets: list, edge_mode: str, vulns: list) -> nx.Graph:
    """
    Build a NetworkX graph from asset data.
    Nodes are assets. Edges depend on the selected edge_mode.
    """
    G = nx.Graph()

    # Add nodes
    for a in assets:
        G.add_node(
            a["asset_id"],
            risk_level  = a.get("risk_level") or "Unknown",
            risk_score  = a.get("risk_score") or 0,
            asset_type  = a.get("asset_type", ""),
            environment = a.get("environment", ""),
            software    = a.get("software", {}).get("name", "") or "",
            ip          = a.get("ip_address", "—") or "—",
            exposed     = a.get("internet_exposed", False),
            owner_status= (a.get("owner") or {}).get("status", "orphan"),
        )

    if edge_mode == "None (nodes only)":
        return G

    # ── Edge mode: Same Environment ───────────────────────────────────────────
    if edge_mode == "Same Environment":
        from collections import defaultdict
        env_map = defaultdict(list)
        for a in assets:
            env_map[a.get("environment", "")].append(a["asset_id"])
        for env, ids in env_map.items():
            # Connect pairs within same environment (limit to avoid too many edges)
            for i in range(len(ids)):
                for j in range(i + 1, min(i + 4, len(ids))):
                    G.add_edge(ids[i], ids[j], weight=0.5, label=env)

    # ── Edge mode: Same Software ──────────────────────────────────────────────
    elif edge_mode == "Same Software":
        from collections import defaultdict
        sw_map = defaultdict(list)
        for a in assets:
            sw = a.get("software", {}).get("name", "") or ""
            if sw:
                sw_map[sw].append(a["asset_id"])
        for sw, ids in sw_map.items():
            for i in range(len(ids)):
                for j in range(i + 1, min(i + 4, len(ids))):
                    G.add_edge(ids[i], ids[j], weight=0.8, label=sw)

    # ── Edge mode: Shared CVE ─────────────────────────────────────────────────
    elif edge_mode == "Any CVE":
        from collections import defaultdict
        cve_asset_map = defaultdict(list)
        for v in vulns:
            cid = v.get("cve", "")
            aid = v.get("asset_id", "")
            if cid and aid and G.has_node(aid):
                cve_asset_map[cid].append(aid)
        for cve, ids in cve_asset_map.items():
            unique_ids = list(set(ids))
            for i in range(len(unique_ids)):
                for j in range(i + 1, min(i + 3, len(unique_ids))):
                    G.add_edge(unique_ids[i], unique_ids[j], weight=1.0, label=cve)

    return G


def layout_graph(G: nx.Graph) -> dict:
    """Compute 2D positions using spring layout."""
    if len(G.nodes) == 0:
        return {}
    # Use spring layout — nodes repel each other, edges pull them together
    # k controls ideal edge length; larger = more spread out
    k_val = 2.0 / math.sqrt(max(len(G.nodes), 1))
    pos = nx.spring_layout(G, k=k_val, iterations=50, seed=42)
    return pos


def build_plotly_figure(G: nx.Graph, pos: dict) -> go.Figure:
    """Convert NetworkX graph + positions to Plotly Figure."""

    # ── Edge traces ───────────────────────────────────────────────────────────
    edge_x, edge_y = [], []
    for u, v in G.edges():
        if u in pos and v in pos:
            x0, y0 = pos[u]
            x1, y1 = pos[v]
            edge_x += [x0, x1, None]
            edge_y += [y0, y1, None]

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        mode="lines",
        line=dict(width=0.8, color="#334155"),
        hoverinfo="none",
        showlegend=False,
    )

    # ── Node traces — one per risk level for proper legend ───────────────────
    node_traces = []

    for level, color in RISK_COLOR.items():
        nodes_in_level = [
            n for n, d in G.nodes(data=True) if d.get("risk_level") == level
        ]
        if not nodes_in_level:
            continue

        nx_list, ny_list, ntext, nsize, nhover = [], [], [], [], []

        for nid in nodes_in_level:
            if nid not in pos:
                continue
            x, y = pos[nid]
            d = G.nodes[nid]
            score = d.get("risk_score", 0)

            nx_list.append(x)
            ny_list.append(y)
            nsize.append(10 + score * 0.25)   # size from 10 to 35
            ntext.append(nid)

            exposed_txt = "🌐 Exposed" if d.get("exposed") else "🔒 Internal"
            owner_txt   = "👻 Orphan" if d.get("owner_status") == "orphan" else "✅ Owned"
            nhover.append(
                f"<b>{nid}</b><br>"
                f"Type: {d.get('asset_type', '')}<br>"
                f"Risk: <b style='color:{color};'>{level}</b> ({score:.1f}/100)<br>"
                f"Software: {d.get('software', '—')}<br>"
                f"IP: {d.get('ip', '—')}<br>"
                f"{exposed_txt} | {owner_txt}<br>"
                f"Env: {d.get('environment', '')}"
            )

        node_traces.append(go.Scatter(
            x=nx_list, y=ny_list,
            mode="markers+text",
            name=level,
            marker=dict(
                size=nsize,
                color=color,
                line=dict(width=1.5, color="#0D1117"),
                opacity=0.9,
            ),
            text=[""] * len(nx_list),   # labels off by default (too cluttered)
            textposition="top center",
            textfont=dict(size=8, color="#94A3B8"),
            hovertext=nhover,
            hoverinfo="text",
            hoverlabel=dict(
                bgcolor="#1E293B",
                bordercolor=color,
                font=dict(color="#F8FAFC", size=12),
            ),
        ))

    # ── Figure layout ─────────────────────────────────────────────────────────
    fig = go.Figure(
        data=[edge_trace] + node_traces,
        layout=go.Layout(
            paper_bgcolor="#0D1117",
            plot_bgcolor="#0D1117",
            font=dict(color="#CBD5E1"),
            showlegend=True,
            legend=dict(
                bgcolor="#1E293B",
                bordercolor="#334155",
                borderwidth=1,
                font=dict(color="#CBD5E1", size=12),
                title=dict(text="Risk Level", font=dict(color="#94A3B8")),
                x=0.01, y=0.99,
            ),
            hovermode="closest",
            margin=dict(b=0, l=0, r=0, t=0),
            xaxis=dict(
                showgrid=False, zeroline=False,
                showticklabels=False, visible=False,
            ),
            yaxis=dict(
                showgrid=False, zeroline=False,
                showticklabels=False, visible=False,
            ),
            dragmode="pan",
        )
    )

    return fig


# ─── PAGE HEADER ─────────────────────────────────────────────────────────────
st.markdown("# 🕸️ Asset Attack Surface Graph")
st.markdown(
    "<p style='color:#94A3B8'>Visual map of your entire asset inventory. "
    "Node color = risk level. Node size = risk score. "
    "Hover a node for full details.</p>",
    unsafe_allow_html=True
)
st.divider()

# ─── FETCH DATA ───────────────────────────────────────────────────────────────
token = st.session_state["jwt"]

with st.spinner("Loading asset graph..."):
    assets, err = fetch_assets(token)
    vulns = fetch_vulnerabilities(token) if edge_mode == "Any CVE" else []

if err:
    st.error(f"❌ {err}")
    st.stop()

if not assets:
    st.warning("No assets found.")
    st.stop()

# Limit nodes (sorted by risk score desc for best visual)
assets_sorted = sorted(assets, key=lambda a: a.get("risk_score") or 0, reverse=True)
assets_display = assets_sorted[:max_nodes]

# ─── SUMMARY METRICS ─────────────────────────────────────────────────────────
m1, m2, m3, m4, m5 = st.columns(5)

critical_c = sum(1 for a in assets_display if a.get("risk_level") == "Critical")
high_c     = sum(1 for a in assets_display if a.get("risk_level") == "High")
medium_c   = sum(1 for a in assets_display if a.get("risk_level") == "Medium")
low_c      = sum(1 for a in assets_display if a.get("risk_level") == "Low")
exposed_c  = sum(1 for a in assets_display if a.get("internet_exposed"))

with m1: st.metric("🖥️ Assets Shown", len(assets_display))
with m2: st.metric("🔴 Critical", critical_c)
with m3: st.metric("🟠 High", high_c)
with m4: st.metric("🟡 Medium", medium_c)
with m5: st.metric("🟢 Low", low_c)

st.divider()

# ─── BUILD & RENDER GRAPH ─────────────────────────────────────────────────────
with st.spinner("Building network graph..."):
    G = build_graph(assets_display, edge_mode, vulns)
    pos = layout_graph(G)
    fig = build_plotly_figure(G, pos)

st.plotly_chart(fig, use_container_width=True, config={
    "displayModeBar": True,
    "scrollZoom": True,
    "modeBarButtonsToRemove": ["select2d", "lasso2d"],
    "displaylogo": False,
})

# ─── GRAPH INFO BOX ───────────────────────────────────────────────────────────
edge_count = G.number_of_edges()
st.markdown(
    f"<p style='color:#475569; font-size:12px; text-align:center;'>"
    f"{G.number_of_nodes()} nodes · {edge_count} edges · "
    f"Edge mode: {edge_mode} · "
    f"Scroll to zoom · Click+drag to pan</p>",
    unsafe_allow_html=True
)

st.divider()

# ─── DATA TABLE BELOW GRAPH ───────────────────────────────────────────────────
with st.expander("📋 Asset Data Table (click to expand)", expanded=False):
    df = pd.DataFrame([{
        "Asset ID":    a.get("asset_id"),
        "Type":        a.get("asset_type"),
        "Environment": a.get("environment"),
        "Risk Level":  a.get("risk_level", "Unknown"),
        "Risk Score":  round(a.get("risk_score") or 0, 1),
        "Exposed":     "🌐 Yes" if a.get("internet_exposed") else "🔒 No",
        "Software":    a.get("software", {}).get("name", "—"),
    } for a in assets_display])

    def color_risk(val):
        return {
            "Critical": "background-color:#450A0A; color:#FCA5A5;",
            "High":     "background-color:#431407; color:#FED7AA;",
            "Medium":   "background-color:#422006; color:#FDE68A;",
            "Low":      "background-color:#052E16; color:#86EFAC;",
        }.get(val, "")

    styled = df.style.map(color_risk, subset=["Risk Level"]).format({"Risk Score": "{:.1f}"})
    st.dataframe(styled, hide_index=True, height=400)

    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇️ Export Graph Data as CSV",
        data=csv,
        file_name="sentinel_graph_export.csv",
        mime="text/csv"
    )