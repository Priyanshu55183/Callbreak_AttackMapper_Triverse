"""
email_alerts.py
───────────────────────────────────────────────────────────────────────────────
Sentinel Email Alert Engine
Sends alert emails when:
  - An asset crosses a risk threshold (Critical / High)
  - A new Critical CVE with active exploit is found
  - An asset becomes an orphan

Setup:
  Add to your .env file:
    ALERT_EMAIL_SENDER=yourname@gmail.com
    ALERT_EMAIL_PASSWORD=xxxx xxxx xxxx xxxx   ← Gmail App Password (not your real password)
    ALERT_EMAIL_RECIPIENT=security-team@yourcompany.com

  How to generate a Gmail App Password:
    1. Go to myaccount.google.com → Security
    2. Enable 2-Step Verification (required)
    3. Search "App Passwords" → Generate for "Mail"
    4. Copy the 16-char password into .env

  For non-Gmail (Outlook, SendGrid, etc.) — see SMTP config at the bottom.
───────────────────────────────────────────────────────────────────────────────
"""

import os
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional

# ── ENV LOADER ─────────────────────────────────────────────────────────────────
# Load .env immediately so environment variables are available whether this
# module is imported by FastAPI or run directly as a script.
# python-dotenv is idempotent: calling it multiple times is safe.
try:
    from dotenv import load_dotenv as _load_dotenv
    # override=False so that real env vars (set by the OS/CI) take precedence
    _load_dotenv(override=False)
except ImportError:
    pass  # dotenv not installed — rely on system env vars


# ── SMTP CONFIG ────────────────────────────────────────────────────────────────
# Resolved lazily through a function so that values are always fresh
# (important when running tests or when .env is loaded after import).

def _cfg():
    """Return current SMTP config from environment."""
    return {
        "host":      os.environ.get("SMTP_HOST",             "smtp.gmail.com"),
        "port":      int(os.environ.get("SMTP_PORT",         "587")),
        "sender":    os.environ.get("ALERT_EMAIL_SENDER",    "").strip(),
        "password":  os.environ.get("ALERT_EMAIL_PASSWORD",  "").strip(),
        "recipient": os.environ.get("ALERT_EMAIL_RECIPIENT", "").strip(),
    }


# ── HELPER: send one email ─────────────────────────────────────────────────────

def _send_email(subject: str, html_body: str, recipient: Optional[str] = None) -> dict:
    """
    Low-level SMTP sender.
    Returns {"success": True} or {"success": False, "error": "..."}
    """
    cfg = _cfg()
    to_addr = (recipient or cfg["recipient"]).strip()

    # ── Validate config before touching the network ──────────────────────────
    missing = []
    if not cfg["sender"]:
        missing.append("ALERT_EMAIL_SENDER")
    if not cfg["password"]:
        missing.append("ALERT_EMAIL_PASSWORD")
    if not to_addr:
        missing.append("ALERT_EMAIL_RECIPIENT")

    if missing:
        return {
            "success": False,
            "error": f"Missing .env variable(s): {', '.join(missing)}. "
                     f"Make sure your .env file is in the backend directory and "
                     f"contains all three required keys."
        }

    # ── Build the MIME message ───────────────────────────────────────────────
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"Sentinel Security <{cfg['sender']}>"
    msg["To"]      = to_addr

    msg.attach(MIMEText(html_body, "html"))

    # ── SMTP with STARTTLS (Gmail / most providers) ──────────────────────────
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()  # re-identify after STARTTLS
            server.login(cfg["sender"], cfg["password"])
            server.sendmail(cfg["sender"], to_addr, msg.as_string())
        return {"success": True, "recipient": to_addr}

    except smtplib.SMTPAuthenticationError as e:
        hint = ""
        if "535" in str(e) or "Username and Password not accepted" in str(e):
            hint = (
                " — Gmail rejected the credentials. "
                "Make sure you are using an App Password (not your Gmail login password). "
                "Generate one at: myaccount.google.com → Security → App Passwords. "
                "Also confirm that 2-Step Verification is enabled on the sender account."
            )
        return {"success": False, "error": f"SMTP authentication failed{hint}"}

    except smtplib.SMTPConnectError as e:
        return {
            "success": False,
            "error": f"Could not connect to {cfg['host']}:{cfg['port']} — "
                     f"check your internet connection or firewall. Detail: {e}"
        }

    except smtplib.SMTPRecipientsRefused as e:
        return {
            "success": False,
            "error": f"Recipient address was refused by the server: {to_addr}. Detail: {e}"
        }

    except smtplib.SMTPException as e:
        return {"success": False, "error": f"SMTP error: {e}"}

    except TimeoutError:
        return {
            "success": False,
            "error": f"Connection to {cfg['host']}:{cfg['port']} timed out. "
                     "Check your firewall — port 587 must be open."
        }

    except Exception as e:
        return {"success": False, "error": f"Unexpected error: {type(e).__name__}: {e}"}


# ── EMAIL TEMPLATE BASE ───────────────────────────────────────────────────────

def _wrap_html(title: str, badge_color: str, badge_label: str, body_html: str) -> str:
    """Wraps content in a branded HTML email template."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body       {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                      background: #0D1117; color: #CBD5E1; margin: 0; padding: 0; }}
        .container {{ max-width: 640px; margin: 30px auto; background: #1E293B;
                      border-radius: 12px; overflow: hidden;
                      border: 1px solid #334155; }}
        .header    {{ background: #0F2744; padding: 24px 32px;
                      border-bottom: 1px solid #334155; }}
        .header h1 {{ color: #F8FAFC; margin: 0; font-size: 22px; }}
        .header p  {{ color: #94A3B8; margin: 4px 0 0 0; font-size: 13px; }}
        .badge     {{ display: inline-block; background: {badge_color}22;
                      color: {badge_color}; border: 1px solid {badge_color}55;
                      padding: 4px 14px; border-radius: 20px;
                      font-size: 12px; font-weight: 700; margin-top: 10px; }}
        .body      {{ padding: 28px 32px; }}
        .field     {{ margin-bottom: 12px; }}
        .label     {{ color: #64748B; font-size: 11px; text-transform: uppercase;
                      letter-spacing: 0.8px; margin-bottom: 2px; }}
        .value     {{ color: #F8FAFC; font-size: 14px; font-weight: 600; }}
        .divider   {{ border: none; border-top: 1px solid #334155;
                      margin: 20px 0; }}
        .footer    {{ background: #0D1117; padding: 14px 32px; text-align: center;
                      color: #475569; font-size: 11px; }}
        .cve-row   {{ background: #0D1117; border-radius: 6px; padding: 10px 14px;
                      margin-bottom: 8px; border-left: 3px solid {badge_color}; }}
        .cta       {{ display: inline-block; background: #1A56DB; color: #fff;
                      padding: 10px 22px; border-radius: 8px;
                      text-decoration: none; font-weight: 600;
                      font-size: 13px; margin-top: 16px; }}
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🛡️ Sentinel Security Alert</h1>
          <p>Automated notification from your Cyber Asset Management system</p>
          <span class="badge">{badge_label}</span>
        </div>
        <div class="body">
          <h2 style="color:#F8FAFC; margin-top:0;">{title}</h2>
          {body_html}
          <hr class="divider">
          <p style="color:#64748B; font-size:12px; margin:0;">
            Generated: {ts}<br>
            This is an automated alert from Sentinel v2.0.
          </p>
        </div>
        <div class="footer">Sentinel — AI-Driven Cyber Asset &amp; Attack Surface Management</div>
      </div>
    </body>
    </html>
    """


# ── ALERT TYPE 1: Critical / High Risk Asset ──────────────────────────────────

def send_critical_asset_alert(asset: dict, recipient: Optional[str] = None) -> dict:
    asset_id   = asset.get("asset_id", "Unknown")
    risk_level = asset.get("risk_level", "Unknown")
    risk_score = asset.get("risk_score", 0)
    env        = asset.get("environment", "Unknown")
    ip         = asset.get("ip_address", "—")
    exposed    = "🌐 Yes" if asset.get("internet_exposed") else "🔒 No"
    vulns      = asset.get("vulnerabilities", [])
    crit_vulns = [v for v in vulns if v.get("severity") in ("Critical", "High")]

    badge_color = "#EF4444" if risk_level == "Critical" else "#F97316"
    badge_label = f"⚠️ {risk_level.upper()} RISK"

    cve_rows = ""
    for v in crit_vulns[:5]:
        exploit_tag = "🔴 EXPLOIT" if v.get("exploit_available") else ""
        patch_tag   = "🩹 PATCH AVAILABLE" if v.get("patch_available") else "❌ NO PATCH"
        cve_rows += f"""
        <div class="cve-row">
          <span style="color:#F8FAFC; font-weight:600;">{v.get('cve', '')}</span>
          &nbsp;·&nbsp;
          <span style="color:#94A3B8;">CVSS {v.get('cvss_score', 0):.1f}</span>
          &nbsp;·&nbsp;
          <span style="color:#EF4444;">{exploit_tag}</span>
          &nbsp;·&nbsp;
          <span style="color:#10B981;">{patch_tag}</span>
        </div>
        """

    body_html = f"""
    <div class="field"><div class="label">Asset ID</div>
      <div class="value">{asset_id}</div></div>
    <div class="field"><div class="label">Risk Score</div>
      <div class="value" style="color:{badge_color};">{risk_score:.1f} / 100</div></div>
    <div class="field"><div class="label">Environment</div>
      <div class="value">{env}</div></div>
    <div class="field"><div class="label">IP Address</div>
      <div class="value">{ip}</div></div>
    <div class="field"><div class="label">Internet Exposed</div>
      <div class="value">{exposed}</div></div>
    <div class="field"><div class="label">CVE Count</div>
      <div class="value">{len(vulns)} total · {len(crit_vulns)} critical/high</div></div>
    {"<hr class='divider'><p style='color:#94A3B8;font-size:13px;margin-bottom:10px;'>Top CVEs on this asset:</p>" + cve_rows if cve_rows else ""}
    <p style="color:#94A3B8; font-size:13px; margin-top:16px;">
      This asset requires <strong style="color:{badge_color};">immediate attention</strong>.
      Log into Sentinel to review full details and remediation recommendations.
    </p>
    """

    html = _wrap_html(
        title=f"High-Risk Asset Detected: {asset_id}",
        badge_color=badge_color,
        badge_label=badge_label,
        body_html=body_html,
    )
    return _send_email(
        subject=f"[Sentinel Alert] {risk_level} Risk Asset: {asset_id} (Score: {risk_score:.0f}/100)",
        html_body=html,
        recipient=recipient,
    )


# ── ALERT TYPE 2: Critical CVE with Active Exploit ────────────────────────────

def send_exploit_cve_alert(asset_id: str, cve_list: list, recipient: Optional[str] = None) -> dict:
    dangerous = [
        v for v in cve_list
        if v.get("exploit_available") and not v.get("patch_available")
        and v.get("severity") in ("Critical", "High")
    ]
    if not dangerous:
        return {"success": False, "error": "No dangerous CVEs to alert on"}

    cve_rows = ""
    for v in dangerous:
        cve_rows += f"""
        <div class="cve-row">
          <strong style="color:#EF4444;">{v.get('cve', '')}</strong>
          &nbsp;·&nbsp; CVSS <strong>{v.get('cvss_score', 0):.1f}</strong>
          &nbsp;·&nbsp; {v.get('severity', '')}
          <div style="color:#94A3B8; font-size:12px; margin-top:4px;">
            {v.get('description', '')[:120]}...
          </div>
        </div>
        """

    body_html = f"""
    <div style="background:#1C0A0A; border:1px solid #7F1D1D; border-radius:8px;
                padding:14px; margin-bottom:18px;">
      <p style="color:#FCA5A5; margin:0; font-weight:700;">
        ☠️ {len(dangerous)} exploit(s) with NO available patch detected on {asset_id}
      </p>
      <p style="color:#FCA5A5; margin:4px 0 0 0; font-size:13px;">
        These CVEs have active exploits in the wild. No patch exists yet.
        This asset should be <strong>isolated or taken offline</strong> immediately.
      </p>
    </div>
    <p style="color:#94A3B8; font-size:13px;">Dangerous CVEs detected:</p>
    {cve_rows}
    """

    html = _wrap_html(
        title=f"☠️ Unpatched Exploits on {asset_id}",
        badge_color="#EF4444",
        badge_label="CRITICAL — ACTIVE EXPLOIT",
        body_html=body_html,
    )
    return _send_email(
        subject=f"[Sentinel CRITICAL] Unpatched exploit CVEs on {asset_id} — Immediate Action Required",
        html_body=html,
        recipient=recipient,
    )


# ── ALERT TYPE 3: Orphan Asset Created ────────────────────────────────────────

def send_orphan_alert(asset_id: str, risk_score: float, risk_level: str,
                      recipient: Optional[str] = None) -> dict:
    badge_color = "#F97316"
    body_html = f"""
    <p style="color:#CBD5E1;">
      A new asset has been added to the inventory with <strong>no owner assigned</strong>.
      Orphan assets are not monitored and rarely get patched — a significant security gap.
    </p>
    <div class="field"><div class="label">Asset ID</div>
      <div class="value">{asset_id}</div></div>
    <div class="field"><div class="label">Risk Score</div>
      <div class="value" style="color:{badge_color};">{risk_score:.1f} / 100  ({risk_level})</div></div>
    <div style="background:#1C1000; border:1px solid #7C4700; border-radius:8px;
                padding:14px; margin-top:16px;">
      <p style="color:#FED7AA; margin:0; font-size:13px;">
        ⚠️ Please assign an owner to this asset immediately via the Sentinel Admin Panel.
      </p>
    </div>
    """
    html = _wrap_html(
        title=f"Orphan Asset Added: {asset_id}",
        badge_color=badge_color,
        badge_label="⚠️ ORPHAN ASSET",
        body_html=body_html,
    )
    return _send_email(
        subject=f"[Sentinel Alert] Orphan Asset Added: {asset_id} — No Owner Assigned",
        html_body=html,
        recipient=recipient,
    )


# ── ALERT TYPE 4: Weekly Report Ready ─────────────────────────────────────────

def send_report_ready_alert(stats: dict, recipient: Optional[str] = None) -> dict:
    body_html = f"""
    <p style="color:#CBD5E1;">
      Your weekly Sentinel security report has been generated.
      Download it from the Admin Panel.
    </p>
    <div class="field"><div class="label">Total Assets</div>
      <div class="value">{stats.get('total_assets', 0)}</div></div>
    <div class="field"><div class="label">Critical Risk Assets</div>
      <div class="value" style="color:#EF4444;">{stats.get('critical_count', 0)}</div></div>
    <div class="field"><div class="label">Internet Exposed</div>
      <div class="value" style="color:#F97316;">{stats.get('exposed_count', 0)}</div></div>
    <div class="field"><div class="label">Orphan Assets</div>
      <div class="value" style="color:#F59E0B;">{stats.get('orphan_count', 0)}</div></div>
    <div class="field"><div class="label">Total CVEs Tracked</div>
      <div class="value">{stats.get('total_vulns', 0)}</div></div>
    <div class="field"><div class="label">Active Exploits</div>
      <div class="value" style="color:#EF4444;">{stats.get('exploit_count', 0)}</div></div>
    """
    html = _wrap_html(
        title="Weekly Security Report Ready",
        badge_color="#1A56DB",
        badge_label="📄 WEEKLY REPORT",
        body_html=body_html,
    )
    ts = datetime.now().strftime("%Y-%m-%d")
    return _send_email(
        subject=f"[Sentinel] Weekly Security Report — {ts}",
        html_body=html,
        recipient=recipient,
    )


# ── TEST HELPER ────────────────────────────────────────────────────────────────
# Run from the backend directory:
#   cd sentinel/backend && python email_alerts.py

if __name__ == "__main__":
    # Re-load with override=True so the script always picks up the local .env
    # even if stale values were cached in the environment.
    try:
        from dotenv import load_dotenv
        loaded = load_dotenv(override=True)
        if not loaded:
            print("⚠️  No .env file found in the current directory.")
            print("   Run from the backend folder:  cd sentinel/backend && python email_alerts.py\n")
    except ImportError:
        print("⚠️  python-dotenv not installed.  pip install python-dotenv\n")

    cfg = _cfg()
    print("🔧 Sentinel Email Alert — Config Check")
    print("─" * 50)
    print(f"   Sender    : {cfg['sender']    or '❌ NOT SET  ← ALERT_EMAIL_SENDER missing'}")
    print(f"   Recipient : {cfg['recipient'] or '❌ NOT SET  ← ALERT_EMAIL_RECIPIENT missing'}")
    print(f"   Password  : {'✅ SET' if cfg['password'] else '❌ NOT SET  ← ALERT_EMAIL_PASSWORD missing'}")
    print(f"   SMTP      : {cfg['host']}:{cfg['port']}")
    print("─" * 50)

    if not cfg['sender'] or not cfg['password'] or not cfg['recipient']:
        print("\n❌ Fix the missing values above, then re-run.")
        print("\n   Your .env should contain:")
        print("     ALERT_EMAIL_SENDER=you@gmail.com")
        print("     ALERT_EMAIL_PASSWORD=abcd efgh ijkl mnop   # 16-char Gmail App Password")
        print("     ALERT_EMAIL_RECIPIENT=receiver@example.com")
        print("\n   Gmail App Password steps:")
        print("     1. myaccount.google.com → Security")
        print("     2. Enable 2-Step Verification")
        print("     3. Search 'App Passwords' → Generate for 'Mail'")
        print("     4. Paste the 16-char code (spaces are fine) into .env")
    else:
        print("\n📤 Sending test email …")
        result = send_report_ready_alert({
            "total_assets":   300,
            "critical_count": 12,
            "exposed_count":  45,
            "orphan_count":   8,
            "total_vulns":    892,
            "exploit_count":  34,
        })
        if result["success"]:
            print(f"✅ Test email sent successfully → {result['recipient']}")
        else:
            print(f"❌ Failed: {result['error']}")