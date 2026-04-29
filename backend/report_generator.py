"""
report_generator.py
───────────────────────────────────────────────────────────────────────────────
Sentinel Weekly PDF Report Generator

Generates a professional multi-page PDF report with:
  - Cover page with date and overall risk posture
  - Executive summary metrics
  - Risk distribution breakdown
  - Top 10 highest-risk assets table
  - Top dangerous CVEs (exploit + unpatched)
  - Orphan assets section
  - Recommendations summary

Install: pip install reportlab
───────────────────────────────────────────────────────────────────────────────
"""

from io import BytesIO
from datetime import datetime
from typing import Optional

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)


# ── SENTINEL BRAND COLORS ─────────────────────────────────────────────────────
# These mirror the Streamlit dashboard's dark-mode palette

C_BG         = colors.HexColor("#0D1117")
C_CARD       = colors.HexColor("#1E293B")
C_BORDER     = colors.HexColor("#334155")
C_TEXT       = colors.HexColor("#CBD5E1")
C_TEXT_LIGHT = colors.HexColor("#94A3B8")
C_WHITE      = colors.HexColor("#F8FAFC")
C_BLUE       = colors.HexColor("#1A56DB")
C_NAVY       = colors.HexColor("#0F2744")

C_CRITICAL   = colors.HexColor("#EF4444")
C_HIGH       = colors.HexColor("#F97316")
C_MEDIUM     = colors.HexColor("#F59E0B")
C_LOW        = colors.HexColor("#10B981")
C_CRITICAL_BG = colors.HexColor("#450A0A")
C_HIGH_BG     = colors.HexColor("#431407")
C_MEDIUM_BG   = colors.HexColor("#422006")
C_LOW_BG      = colors.HexColor("#052E16")

PAGE_W, PAGE_H = A4     # 595 x 842 points


# ── HEADER / FOOTER ───────────────────────────────────────────────────────────

def _on_page(canvas, doc):
    """Draws header + footer on every page."""
    canvas.saveState()
    w, h = A4

    # ── Header bar ──────────────────────────────────────────────────────────
    canvas.setFillColor(C_NAVY)
    canvas.rect(0, h - 28*mm, w, 28*mm, fill=1, stroke=0)

    canvas.setFillColor(C_WHITE)
    canvas.setFont("Helvetica-Bold", 13)
    canvas.drawString(20*mm, h - 16*mm, "SENTINEL")

    canvas.setFillColor(C_TEXT_LIGHT)
    canvas.setFont("Helvetica", 9)
    canvas.drawString(20*mm, h - 22*mm, "AI-Driven Cyber Asset & Attack Surface Management")

    # Badge: CONFIDENTIAL
    canvas.setFillColor(C_CRITICAL)
    canvas.roundRect(w - 52*mm, h - 22*mm, 32*mm, 10*mm, 4, fill=1, stroke=0)
    canvas.setFillColor(C_WHITE)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawCentredString(w - 36*mm, h - 16*mm, "CONFIDENTIAL")

    # ── Footer bar ──────────────────────────────────────────────────────────
    canvas.setFillColor(C_CARD)
    canvas.rect(0, 0, w, 14*mm, fill=1, stroke=0)

    ts = datetime.now().strftime("Generated: %Y-%m-%d %H:%M UTC")
    canvas.setFillColor(C_TEXT_LIGHT)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(20*mm, 5*mm, ts)
    canvas.drawRightString(w - 20*mm, 5*mm, f"Page {doc.page}")

    canvas.restoreState()


# ── STYLE HELPERS ─────────────────────────────────────────────────────────────

def _styles():
    base = getSampleStyleSheet()

    title = ParagraphStyle(
        "SentinelTitle",
        fontName="Helvetica-Bold", fontSize=28,
        textColor=C_WHITE, alignment=TA_CENTER, spaceAfter=6,
    )
    subtitle = ParagraphStyle(
        "SentinelSubtitle",
        fontName="Helvetica", fontSize=13,
        textColor=C_TEXT_LIGHT, alignment=TA_CENTER, spaceAfter=4,
    )
    section = ParagraphStyle(
        "SentinelSection",
        fontName="Helvetica-Bold", fontSize=14,
        textColor=C_WHITE, spaceBefore=8, spaceAfter=4,
    )
    body = ParagraphStyle(
        "SentinelBody",
        fontName="Helvetica", fontSize=10,
        textColor=C_TEXT, leading=16, spaceAfter=4,
    )
    small = ParagraphStyle(
        "SentinelSmall",
        fontName="Helvetica", fontSize=8,
        textColor=C_TEXT_LIGHT, leading=12,
    )
    table_header = ParagraphStyle(
        "SentinelTH",
        fontName="Helvetica-Bold", fontSize=9,
        textColor=C_WHITE, alignment=TA_CENTER,
    )
    table_cell = ParagraphStyle(
        "SentinelTD",
        fontName="Helvetica", fontSize=9,
        textColor=C_TEXT, alignment=TA_LEFT,
    )
    label = ParagraphStyle(
        "SentinelLabel",
        fontName="Helvetica-Bold", fontSize=8,
        textColor=C_TEXT_LIGHT, spaceBefore=2,
    )

    return {
        "title": title, "subtitle": subtitle, "section": section,
        "body": body, "small": small, "th": table_header,
        "td": table_cell, "label": label,
    }


def _risk_color(level: str):
    return {
        "Critical": C_CRITICAL,
        "High":     C_HIGH,
        "Medium":   C_MEDIUM,
        "Low":      C_LOW,
    }.get(level, C_TEXT_LIGHT)


def _risk_bg(level: str):
    return {
        "Critical": C_CRITICAL_BG,
        "High":     C_HIGH_BG,
        "Medium":   C_MEDIUM_BG,
        "Low":      C_LOW_BG,
    }.get(level, C_CARD)


# ── METRIC BOX HELPER ─────────────────────────────────────────────────────────

def _metric_table(metrics: list) -> Table:
    """
    Renders a row of metric cards.
    metrics = [(label, value, color), ...]
    """
    labels = [Paragraph(f"<font color='#{m[2].hexval()[2:] if hasattr(m[2],'hexval') else '94A3B8'}'>{m[0]}</font>",
                        ParagraphStyle("ml", fontName="Helvetica", fontSize=8, textColor=C_TEXT_LIGHT, alignment=TA_CENTER))
              for m in metrics]
    values = [Paragraph(f"<b>{m[1]}</b>",
                        ParagraphStyle("mv", fontName="Helvetica-Bold", fontSize=20, textColor=m[2], alignment=TA_CENTER))
              for m in metrics]

    col_w = (PAGE_W - 40*mm) / len(metrics)
    t = Table([labels, values], colWidths=[col_w]*len(metrics))
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), C_CARD),
        ("GRID",         (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",   (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 10),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("ROUNDEDCORNERS", [4]),
    ]))
    return t


# ── SECTION: COVER PAGE ───────────────────────────────────────────────────────

def _cover_page(story, s, stats, week_label):
    # Big dark background block
    story.append(Spacer(1, 20*mm))

    story.append(Paragraph("🛡️ SENTINEL", s["title"]))
    story.append(Paragraph("Weekly Security Report", s["subtitle"]))
    story.append(Paragraph(week_label, s["subtitle"]))
    story.append(Spacer(1, 10*mm))

    # Overall posture banner
    critical = stats.get("critical_count", 0)
    total    = stats.get("total_assets", 1)
    pct      = critical / total * 100

    if pct > 20:
        posture_label = "CRITICAL POSTURE"
        posture_color = C_CRITICAL
    elif pct > 10:
        posture_label = "HIGH RISK POSTURE"
        posture_color = C_HIGH
    elif pct > 5:
        posture_label = "MODERATE POSTURE"
        posture_color = C_MEDIUM
    else:
        posture_label = "HEALTHY POSTURE"
        posture_color = C_LOW

    banner = Table(
        [[Paragraph(f"<b>{posture_label}</b>",
                    ParagraphStyle("pb", fontName="Helvetica-Bold", fontSize=16,
                                   textColor=posture_color, alignment=TA_CENTER))]],
        colWidths=[PAGE_W - 40*mm],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_CARD),
        ("BOX",          (0,0), (-1,-1), 2, posture_color),
        ("TOPPADDING",   (0,0), (-1,-1), 14),
        ("BOTTOMPADDING",(0,0), (-1,-1), 14),
    ]))
    story.append(banner)
    story.append(Spacer(1, 6*mm))

    story.append(Paragraph(
        f"This report summarises the security posture of <b>{total}</b> assets "
        f"monitored by Sentinel. <b style='color:red'>{critical}</b> assets are classified as Critical Risk "
        f"and require immediate attention.",
        s["body"]
    ))

    story.append(PageBreak())


# ── SECTION: EXECUTIVE SUMMARY ────────────────────────────────────────────────

def _executive_summary(story, s, stats):
    story.append(Paragraph("Executive Summary", s["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceAfter=6))

    # Metric cards — row 1
    row1 = [
        ("Total Assets",     str(stats.get("total_assets", 0)),   C_WHITE),
        ("Critical Risk",    str(stats.get("critical_count", 0)),  C_CRITICAL),
        ("High Risk",        str(stats.get("high_risk_count", 0)), C_HIGH),
        ("Internet Exposed", str(stats.get("exposed_count", 0)),   C_HIGH),
    ]
    story.append(_metric_table(row1))
    story.append(Spacer(1, 3*mm))

    row2 = [
        ("Orphan Assets",   str(stats.get("orphan_count", 0)),   C_MEDIUM),
        ("Total CVEs",      str(stats.get("total_vulns", 0)),     C_WHITE),
        ("Active Exploits", str(stats.get("exploit_count", 0)),   C_CRITICAL),
        ("Patch Coverage",  f"{max(0, 100 - (stats.get('exploit_count',0) / max(stats.get('total_vulns',1),1))*100):.0f}%",
                                                                   C_LOW),
    ]
    story.append(_metric_table(row2))
    story.append(Spacer(1, 6*mm))

    # Key findings
    findings = []
    c = stats.get("critical_count", 0)
    e = stats.get("exploit_count", 0)
    o = stats.get("orphan_count", 0)
    exp = stats.get("exposed_count", 0)

    if c > 0:
        findings.append(f"<b><font color='#EF4444'>CRITICAL:</font></b> {c} asset(s) scored Critical risk — immediate remediation required.")
    if e > 0:
        findings.append(f"<b><font color='#F97316'>EXPLOIT:</font></b> {e} CVE(s) with active exploits in the wild.")
    if o > 0:
        findings.append(f"<b><font color='#F59E0B'>ORPHAN:</font></b> {o} asset(s) have no assigned owner.")
    if exp > 0:
        findings.append(f"<b><font color='#F97316'>EXPOSURE:</font></b> {exp} asset(s) are publicly internet-exposed.")
    if not findings:
        findings.append("<b><font color='#10B981'>HEALTHY:</font></b> No critical issues detected this period.")

    for f in findings:
        story.append(Paragraph(f"• {f}", s["body"]))

    story.append(Spacer(1, 4*mm))


# ── SECTION: TOP RISK ASSETS TABLE ───────────────────────────────────────────

def _top_assets_table(story, s, top_assets):
    story.append(Paragraph("Top 10 Highest Risk Assets", s["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceAfter=6))

    if not top_assets:
        story.append(Paragraph("No asset data available.", s["body"]))
        return

    headers = ["Asset ID", "Type", "Environment", "Risk Score", "Risk Level", "Exposed", "CVEs"]
    col_widths = [42*mm, 28*mm, 30*mm, 24*mm, 24*mm, 20*mm, 18*mm]

    rows = [[Paragraph(h, ParagraphStyle("h", fontName="Helvetica-Bold", fontSize=9,
                                          textColor=C_WHITE, alignment=TA_CENTER))
             for h in headers]]

    for a in top_assets[:10]:
        level = a.get("risk_level") or "Unknown"
        score = a.get("risk_score") or 0
        vuln_count = len(a.get("vulnerabilities", []))
        exposed = "Yes" if a.get("internet_exposed") else "No"

        row = [
            Paragraph(a.get("asset_id", ""), s["td"]),
            Paragraph(a.get("asset_type", ""), s["td"]),
            Paragraph(a.get("environment", ""), s["td"]),
            Paragraph(f"<b>{score:.1f}</b>",
                      ParagraphStyle("sc", fontName="Helvetica-Bold", fontSize=10,
                                     textColor=_risk_color(level), alignment=TA_CENTER)),
            Paragraph(level,
                      ParagraphStyle("lv", fontName="Helvetica-Bold", fontSize=9,
                                     textColor=_risk_color(level), alignment=TA_CENTER)),
            Paragraph(exposed, s["td"]),
            Paragraph(str(vuln_count), s["td"]),
        ]
        rows.append(row)

    t = Table(rows, colWidths=col_widths, repeatRows=1)

    # Build row-level background colors
    ts_cmds = [
        ("BACKGROUND",   (0, 0), (-1, 0),  C_NAVY),
        ("GRID",         (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",   (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("ALIGN",        (3, 1), (5, -1),  "CENTER"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
    ]

    for row_idx, a in enumerate(top_assets[:10], start=1):
        level = a.get("risk_level") or "Unknown"
        bg = _risk_bg(level)
        ts_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), bg))

    t.setStyle(TableStyle(ts_cmds))
    story.append(t)
    story.append(Spacer(1, 6*mm))


# ── SECTION: DANGEROUS CVEs ───────────────────────────────────────────────────

def _dangerous_cves_section(story, s, vulnerabilities):
    danger = [
        v for v in vulnerabilities
        if v.get("exploit_available") and not v.get("patch_available")
    ]
    danger = sorted(danger, key=lambda v: v.get("cvss_score") or 0, reverse=True)[:10]

    story.append(Paragraph("Most Dangerous CVEs (Exploit + Unpatched)", s["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceAfter=6))

    if not danger:
        story.append(Paragraph("✅ No CVEs with active exploits and missing patches found.", s["body"]))
        return

    story.append(Paragraph(
        f"The following {len(danger)} CVE(s) have active exploits in the wild and no patch available. "
        "These are the highest-priority remediation targets.",
        s["body"]
    ))
    story.append(Spacer(1, 3*mm))

    headers = ["CVE ID", "Asset ID", "Severity", "CVSS", "Description"]
    col_widths = [35*mm, 35*mm, 22*mm, 18*mm, 65*mm]

    rows = [[Paragraph(h, ParagraphStyle("h", fontName="Helvetica-Bold", fontSize=9,
                                          textColor=C_WHITE, alignment=TA_CENTER))
             for h in headers]]

    for v in danger:
        desc = (v.get("description") or "")[:90] + ("..." if len(v.get("description","")) > 90 else "")
        level = v.get("severity", "Unknown")
        rows.append([
            Paragraph(v.get("cve", ""), s["td"]),
            Paragraph(v.get("asset_id", ""), s["td"]),
            Paragraph(level,
                      ParagraphStyle("sv", fontName="Helvetica-Bold", fontSize=9,
                                     textColor=_risk_color(level), alignment=TA_CENTER)),
            Paragraph(f"{v.get('cvss_score', 0):.1f}",
                      ParagraphStyle("cv", fontName="Helvetica-Bold", fontSize=9,
                                     textColor=_risk_color(level), alignment=TA_CENTER)),
            Paragraph(desc, s["small"]),
        ])

    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  C_NAVY),
        ("BACKGROUND",   (0, 1), (-1, -1), C_CRITICAL_BG),
        ("GRID",         (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(t)
    story.append(Spacer(1, 6*mm))


# ── SECTION: ORPHAN ASSETS ────────────────────────────────────────────────────

def _orphan_section(story, s, orphans):
    story.append(Paragraph("Orphan Assets", s["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceAfter=6))

    if not orphans:
        story.append(Paragraph("✅ All assets have assigned owners.", s["body"]))
        return

    story.append(Paragraph(
        f"{len(orphans)} asset(s) have no assigned owner. These assets are unmonitored "
        "and unlikely to be patched. Assign ownership immediately.",
        s["body"]
    ))
    story.append(Spacer(1, 3*mm))

    headers = ["Asset ID", "Type", "Environment", "Risk Score", "Risk Level", "Exposed", "CVEs"]
    col_widths = [42*mm, 28*mm, 30*mm, 24*mm, 24*mm, 20*mm, 18*mm]

    rows = [[Paragraph(h, ParagraphStyle("h", fontName="Helvetica-Bold", fontSize=9,
                                          textColor=C_WHITE, alignment=TA_CENTER))
             for h in headers]]

    for a in sorted(orphans, key=lambda x: x.get("risk_score") or 0, reverse=True)[:10]:
        level = a.get("risk_level") or "Unknown"
        score = a.get("risk_score") or 0
        vuln_count = len(a.get("vulnerabilities", []))
        exposed = "Yes" if a.get("internet_exposed") else "No"
        rows.append([
            Paragraph(a.get("asset_id", ""), s["td"]),
            Paragraph(a.get("asset_type", ""), s["td"]),
            Paragraph(a.get("environment", ""), s["td"]),
            Paragraph(f"<b>{score:.1f}</b>",
                      ParagraphStyle("sc", fontName="Helvetica-Bold", fontSize=10,
                                     textColor=_risk_color(level), alignment=TA_CENTER)),
            Paragraph(level,
                      ParagraphStyle("lv", fontName="Helvetica-Bold", fontSize=9,
                                     textColor=_risk_color(level), alignment=TA_CENTER)),
            Paragraph(exposed, s["td"]),
            Paragraph(str(vuln_count), s["td"]),
        ])

    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  C_NAVY),
        ("BACKGROUND",   (0, 1), (-1, -1), C_HIGH_BG),
        ("GRID",         (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",   (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(t)
    story.append(Spacer(1, 6*mm))


# ── SECTION: RECOMMENDATIONS ──────────────────────────────────────────────────

def _recommendations_section(story, s, stats):
    story.append(Paragraph("Recommendations", s["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceAfter=6))

    recs = []

    if stats.get("exploit_count", 0) > 0:
        recs.append(("CRITICAL", C_CRITICAL,
                     f"Immediately patch or isolate the {stats['exploit_count']} asset(s) "
                     "with active exploits and no available patch."))

    if stats.get("critical_count", 0) > 0:
        recs.append(("HIGH", C_HIGH,
                     f"Schedule emergency patching for {stats['critical_count']} Critical-risk asset(s) "
                     "within 24-48 hours."))

    if stats.get("orphan_count", 0) > 0:
        recs.append(("HIGH", C_HIGH,
                     f"Assign owners to {stats['orphan_count']} orphan asset(s). "
                     "Unowned assets represent unmonitored attack surface."))

    if stats.get("exposed_count", 0) > 0:
        recs.append(("MEDIUM", C_MEDIUM,
                     f"Review firewall and network access policies for {stats['exposed_count']} "
                     "internet-exposed asset(s). Consider VPN or WAF."))

    recs.append(("LOW", C_LOW,
                 "Maintain weekly scanning cadence and ensure all assets have "
                 "a last_scan_date within the past 30 days."))

    for priority, color, text in recs:
        row_data = [[
            Paragraph(f"<b>{priority}</b>",
                      ParagraphStyle("pri", fontName="Helvetica-Bold", fontSize=9,
                                     textColor=color, alignment=TA_CENTER)),
            Paragraph(text, s["body"]),
        ]]
        t = Table(row_data, colWidths=[22*mm, PAGE_W - 40*mm - 22*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (0, 0), C_CARD),
            ("BACKGROUND",   (1, 0), (1, 0), C_CARD),
            ("LINEAFTER",    (0, 0), (0, 0), 3, color),
            ("TOPPADDING",   (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
            ("LEFTPADDING",  (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
            ("BOX",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ]))
        story.append(t)
        story.append(Spacer(1, 2*mm))

    story.append(Spacer(1, 6*mm))


# ── MAIN ENTRY POINT ─────────────────────────────────────────────────────────

def generate_report(
    stats: dict,
    top_assets: list,
    vulnerabilities: list,
    orphans: list,
    week_label: Optional[str] = None,
) -> bytes:
    """
    Build the full PDF report and return raw bytes.

    Args:
        stats:           dict from GET /stats
        top_assets:      list from GET /risk-summary
        vulnerabilities: list from GET /vulnerabilities (all)
        orphans:         list from GET /orphans
        week_label:      e.g. "Week of 2025-04-28"

    Returns:
        PDF as bytes — ready to write to disk or return as HTTP response.
    """
    if not week_label:
        week_label = f"Week of {datetime.now().strftime('%Y-%m-%d')}"

    buf = BytesIO()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=35*mm, bottomMargin=20*mm,
        title=f"Sentinel Report — {week_label}",
        author="Sentinel v2.0",
        subject="Weekly Security Report",
    )

    s = _styles()
    story = []

    # 1. Cover
    _cover_page(story, s, stats, week_label)

    # 2. Executive summary
    _executive_summary(story, s, stats)
    story.append(Spacer(1, 4*mm))

    # 3. Top risk assets
    _top_assets_table(story, s, top_assets)

    # 4. Dangerous CVEs
    story.append(PageBreak())
    _dangerous_cves_section(story, s, vulnerabilities)

    # 5. Orphan assets
    story.append(Spacer(1, 4*mm))
    _orphan_section(story, s, orphans)

    # 6. Recommendations
    story.append(PageBreak())
    _recommendations_section(story, s, stats)

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return buf.getvalue()