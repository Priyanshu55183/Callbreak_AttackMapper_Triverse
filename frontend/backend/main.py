from dotenv import load_dotenv
load_dotenv()  # MUST be before any os.environ.get() calls

# ─── PART 1: IMPORTS ─────────────────────────────────────────────────────────
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from sqlalchemy.orm import Session, joinedload   # ← added joinedload
import os
import uuid as uuid_lib
import jwt as pyjwt

import ollama
try:
    from groq import Groq
    _GROQ_AVAILABLE = True
except ImportError:
    _GROQ_AVAILABLE = False
import chromadb
from sentence_transformers import SentenceTransformer

from smart_rag import build_rag_context
from db import get_db, Asset, Vulnerability, Owner, UserRole
from fastapi.responses import Response   # for returning PDF bytes


# Lazy-import report + email so server still starts if reportlab is missing
def _get_report_generator():
    try:
        from report_generator import generate_report
        return generate_report
    except ImportError:
        return None


def _get_email_alerts():
    try:
        import email_alerts
        return email_alerts
    except ImportError:
        return None

# ─── PART 2: APP + MODEL SETUP ───────────────────────────────────────────────

app = FastAPI(
    title="Sentinel API",
    description="AI-Driven Cyber Asset & Attack Surface Management",
    version="2.0"
)

embed_model = SentenceTransformer("all-MiniLM-L6-v2")

chroma_client = chromadb.PersistentClient(path="chroma_db")
collection = chroma_client.get_or_create_collection(name="cyber_assets")

# ── AI backend configuration ──────────────────────────────────────────────────
# The system tries Groq first (fast cloud inference).
# If Groq is unavailable or the API key is missing, it falls back to
# Ollama running locally with phi3 — exactly as before.
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
# ── Current production models (April 2026) ───────────────────────────────────
# llama-3.3-70b-versatile  → best quality, production-stable     ← DEFAULT
# llama-3.1-8b-instant     → fastest, lower quality
# qwen/qwen3-32b           → great reasoning, long context
# Do NOT use: llama3-70b-8192, llama3-8b-8192  (decommissioned)
GROQ_MODEL   = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "phi3")

groq_client = None
if _GROQ_AVAILABLE and GROQ_API_KEY:
    try:
        groq_client = Groq(api_key=GROQ_API_KEY)
        # Quick connectivity probe — if the key is wrong this raises immediately
        # so we discover it at startup, not mid-request.
        print("✅ Groq client initialised — using cloud inference")
    except Exception as _groq_init_err:
        groq_client = None
        print(f"⚠️  Groq init failed ({_groq_init_err}) — will use Ollama fallback")
else:
    if not _GROQ_AVAILABLE:
        print("⚠️  groq package not installed — using Ollama fallback")
    else:
        print("⚠️  GROQ_API_KEY not set — using Ollama fallback")


# ─── PART 2B: AUTH SETUP ─────────────────────────────────────────────────────

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")

import requests as _req
import json as _json
import base64 as _b64

bearer_scheme = HTTPBearer()

# Cache JWKS keys so we don't fetch on every single request
_jwks_cache: dict = {}

def _get_jwks_key(kid: str) -> dict:
    """
    Fetch Supabase's public JWKS keys and return the one matching kid.
    Caches keys in memory for the lifetime of the server process.
    """
    global _jwks_cache
    if kid in _jwks_cache:
        return _jwks_cache[kid]

    jwks_url = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"
    try:
        resp = _req.get(jwks_url, timeout=10)
        resp.raise_for_status()
        keys = resp.json().get("keys", [])
        for key in keys:
            _jwks_cache[key["kid"]] = key
        if kid in _jwks_cache:
            return _jwks_cache[kid]
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Could not fetch auth keys: {e}")

    raise HTTPException(status_code=401, detail=f"No public key found for kid={kid}")


def decode_jwt(token: str) -> dict:
    """
    Validate and decode a Supabase-issued JWT.
    Supabase uses ES256 (asymmetric keypair) — we fetch the public key
    from their JWKS endpoint and verify with python-jose.
    """
    # Step 1: read the header to get kid + alg without verifying yet
    try:
        header_b64 = token.split(".")[0]
        # Add padding so b64decode doesn't fail
        padding = 4 - len(header_b64) % 4
        header = _json.loads(_b64.urlsafe_b64decode(header_b64 + "=" * padding))
    except Exception:
        raise HTTPException(status_code=401, detail="Malformed token header")

    kid = header.get("kid", "")
    alg = header.get("alg", "ES256")

    # Step 2: get the matching public key
    public_key = _get_jwks_key(kid)

    # Step 3: verify and decode using python-jose
    try:
        from jose import jwt as jose_jwt
        from jose.exceptions import JWTError
        payload = jose_jwt.decode(
            token,
            public_key,
            algorithms=[alg],
            options={"verify_aud": False},
        )
        return payload
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token invalid: {str(e)}")


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> dict:
    """
    FastAPI dependency — decodes JWT, fetches role from user_roles table.
    Returns {"user_id": ..., "role": ..., "email": ...}
    """
    payload = decode_jwt(credentials.credentials)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token missing user ID")

    user_role = db.query(UserRole).filter(UserRole.user_id == user_id).first()
    if not user_role:
        raise HTTPException(
            status_code=403,
            detail="User has no role assigned — contact your admin"
        )

    return {
        "user_id": user_id,
        "role":    user_role.role,
        "email":   payload.get("email", ""),
    }


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


def require_analyst_or_above(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user["role"] not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Analyst or admin access required")
    return current_user


def require_any_role(current_user: dict = Depends(get_current_user)) -> dict:
    return current_user


# ─── PART 3: HEALTH CHECK ────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"message": "Sentinel backend is running", "version": "2.0"}


# ─── PART 3B: AUTH ENDPOINTS ─────────────────────────────────────────────────

from supabase import create_client as supabase_create_client

_SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
_SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")

if not _SUPABASE_URL or not _SUPABASE_KEY:
    raise RuntimeError("SUPABASE_URL and SUPABASE_KEY must be set in .env")

_supabase = supabase_create_client(_SUPABASE_URL, _SUPABASE_KEY)

VALID_ROLES = ("admin", "analyst", "viewer")


@app.post("/auth/signup")
def signup(body: dict, db: Session = Depends(get_db)):
    """
    Register a new user in Supabase Auth and assign them an app role.

    Request body:
        {
            "email":    "user@example.com",
            "password": "securepassword",
            "role":     "analyst"           # admin / analyst / viewer
        }

    Flow:
    1. Validate role is one of the three allowed values.
    2. Call Supabase Auth sign_up — creates the user in Supabase.
    3. Write a row into user_roles so get_current_user can resolve the role.
    4. Return success — user can now log in via /auth/login.
    """
    email    = body.get("email", "").strip()
    password = body.get("password", "")
    role     = body.get("role", "viewer").strip().lower()

    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password are required")

    if role not in VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role '{role}'. Must be one of: admin, analyst, viewer"
        )

    # Step 1: Create the user in Supabase Auth
    try:
        response = _supabase.auth.sign_up({"email": email, "password": password})
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Signup failed: {str(e)}")

    if not response.user:
        raise HTTPException(
            status_code=400,
            detail="Signup failed — user may already exist or email is invalid"
        )

    user_id = response.user.id  # UUID string from Supabase

    # Step 2: Upsert role into user_roles table
    existing_role = db.query(UserRole).filter(UserRole.user_id == user_id).first()

    if existing_role:
        # User already has a role row — update it
        existing_role.role  = role
        existing_role.email = email
        db.commit()
    else:
        new_user_role = UserRole(
            id      = uuid_lib.uuid4(),
            user_id = user_id,
            role    = role,
            email   = email,
        )
        db.add(new_user_role)
        db.commit()

    return {
        "message": "User created successfully",
        "email":   email,
        "role":    role,
    }


@app.post("/auth/login")
def login(body: dict, db: Session = Depends(get_db)):
    """
    Exchange email + password for a JWT + app role.

    Request body:  { "email": "...", "password": "..." }
    Response:      { "access_token": "...", "role": "...", "email": "..." }
    """
    email    = body.get("email", "")
    password = body.get("password", "")

    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password are required")

    try:
        response = _supabase.auth.sign_in_with_password(
            {"email": email, "password": password}
        )
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user_id      = response.user.id
    access_token = response.session.access_token

    user_role = db.query(UserRole).filter(UserRole.user_id == user_id).first()
    role = user_role.role if user_role else "viewer"

    return {
        "access_token": access_token,
        "role":         role,
        "email":        email,
    }


@app.get("/auth/me")
def get_me(current_user: dict = Depends(get_current_user)):
    return current_user


# ─── PART 4: ASSET ENDPOINTS ─────────────────────────────────────────────────

@app.get("/assets")
def get_assets(
    db: Session = Depends(get_db),
    environment:      str  = None,
    criticality:      str  = None,
    internet_exposed: bool = None,
    owner_status:     str  = None,
    slim:             bool = True,
    current_user: dict = Depends(require_analyst_or_above),
):
    # ── FIX: eager-load owner + vulnerabilities in ONE query ──────────────────
    # Without joinedload, SQLAlchemy lazy-loads each relationship separately
    # inside the loop below — that's 300 extra DB round-trips for 300 assets,
    # which causes the 30-second timeout Streamlit was hitting.
    query = db.query(Asset).options(
        joinedload(Asset.owner),
        joinedload(Asset.vulnerabilities),
    )

    if environment:
        query = query.filter(Asset.environment == environment)

    if criticality:
        query = query.filter(Asset.criticality == criticality)

    if internet_exposed is not None:
        query = query.filter(Asset.internet_exposed == internet_exposed)

    if owner_status:
        query = query.join(Owner).filter(Owner.status == owner_status)

    assets = query.all()

    if slim:
        def slim_dict(a):
            owner = a.owner
            return {
                "asset_id":        a.asset_id,
                "asset_type":      a.asset_type,
                "environment":     a.environment,
                "criticality":     a.criticality,
                "ip_address":      a.ip_address,
                "domain":          a.domain,
                "internet_exposed": a.internet_exposed,
                "os": {
                    "name":    a.os_name,
                    "version": a.os_version,
                },
                "software": {
                    "name":    a.software_name,
                    "version": a.software_version,
                },
                "risk_score":  a.risk_score,
                "risk_level":  a.risk_level,
                "last_scan_date": str(a.last_scan_date) if a.last_scan_date else None,
                "owner": {
                    "team":   owner.team if owner else None,
                    "email":  owner.email if owner else None,
                    "status": owner.status if owner else "orphan",
                } if owner else None,
                "vulnerabilities": [],
            }
        return {"assets": [slim_dict(a) for a in assets], "total": len(assets)}

    return {
        "assets": [a.to_dict() for a in assets],
        "total":  len(assets)
    }


@app.get("/assets/{asset_id}")
def get_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_analyst_or_above),
):
    asset = (
        db.query(Asset)
        .options(joinedload(Asset.owner), joinedload(Asset.vulnerabilities))
        .filter(Asset.asset_id == asset_id)
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")
    return asset.to_dict()


@app.delete("/assets/{asset_id}")
def delete_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    """
    Permanently delete an asset and all related records (CVEs, owner).
    Admin only.
    Cascade delete works because the Owner and Vulnerability models have
    foreign key back-references to Asset.
    """
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")

    # Delete related vulnerability records
    db.query(Vulnerability).filter(Vulnerability.asset_id == asset_id).delete()

    # Delete related owner record
    db.query(Owner).filter(Owner.asset_id == asset_id).delete()

    # Delete the asset itself
    db.delete(asset)
    db.commit()

    # Remove from ChromaDB (best-effort — don't crash if it fails)
    try:
        collection.delete(where={"asset_id": asset_id})
    except Exception as e:
        print(f"⚠️  ChromaDB delete failed for {asset_id}: {e}")

    return {"message": f"Asset '{asset_id}' deleted successfully", "asset_id": asset_id}


@app.get("/risk-summary")
def get_risk_summary(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_analyst_or_above),
):
    # ── FIX: eager-load relationships so to_dict() doesn't trigger N+1 ────────
    top_assets = (
        db.query(Asset)
        .options(joinedload(Asset.owner), joinedload(Asset.vulnerabilities))
        .filter(Asset.risk_score != None)
        .order_by(Asset.risk_score.desc())
        .limit(10)
        .all()
    )
    return {
        "top_risk_assets": [a.to_dict() for a in top_assets],
        "total_returned":  len(top_assets)
    }


@app.get("/vulnerabilities")
def get_vulnerabilities(
    db:               Session = Depends(get_db),
    severity:         str  = None,
    exploit_available: bool = None,
    patch_available:   bool = None,
    current_user: dict = Depends(require_analyst_or_above),
):
    query = db.query(Vulnerability)

    if severity:
        query = query.filter(Vulnerability.severity == severity)

    if exploit_available is not None:
        query = query.filter(Vulnerability.exploit_available == exploit_available)

    if patch_available is not None:
        query = query.filter(Vulnerability.patch_available == patch_available)

    vulns = query.all()
    return {
        "vulnerabilities": [v.to_dict() for v in vulns],
        "total":           len(vulns)
    }


@app.get("/orphans")
def get_orphans(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    orphan_assets = (
        db.query(Asset)
        .options(joinedload(Asset.owner), joinedload(Asset.vulnerabilities))
        .join(Owner)
        .filter(Owner.status == "orphan")
        .all()
    )
    return {
        "orphan_assets": [a.to_dict() for a in orphan_assets],
        "total":         len(orphan_assets)
    }


@app.post("/report/generate")
def generate_weekly_report(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    """
    Generate a full weekly PDF security report.
    Returns raw PDF bytes as application/pdf.
    Admin only.

    The report includes:
      - Executive summary metrics
      - Top 10 highest risk assets
      - Dangerous CVEs (exploit + unpatched)
      - Orphan asset list
      - Prioritised recommendations
    """
    generate_report = _get_report_generator()
    if generate_report is None:
        raise HTTPException(
            status_code=503,
            detail="reportlab is not installed. Run: pip install reportlab"
        )

    # ── Gather all data ───────────────────────────────────────────────────────
    from sqlalchemy.orm import joinedload as _jl

    # Stats
    total_assets    = db.query(Asset).count()
    critical_count  = db.query(Asset).filter(Asset.risk_level == "Critical").count()
    exposed_count   = db.query(Asset).filter(Asset.internet_exposed == True).count()
    orphan_count    = db.query(Owner).filter(Owner.status == "orphan").count()
    high_risk_count = db.query(Asset).filter(Asset.risk_score >= 70).count()
    total_vulns     = db.query(Vulnerability).count()
    exploit_count   = db.query(Vulnerability).filter(Vulnerability.exploit_available == True).count()

    stats = {
        "total_assets":    total_assets,
        "critical_count":  critical_count,
        "exposed_count":   exposed_count,
        "orphan_count":    orphan_count,
        "high_risk_count": high_risk_count,
        "total_vulns":     total_vulns,
        "exploit_count":   exploit_count,
    }

    # Top 10 assets by risk
    top_assets_orm = (
        db.query(Asset)
        .options(_jl(Asset.owner), _jl(Asset.vulnerabilities))
        .filter(Asset.risk_score != None)
        .order_by(Asset.risk_score.desc())
        .limit(10)
        .all()
    )
    top_assets = [a.to_dict() for a in top_assets_orm]

    # All vulnerabilities
    all_vulns_orm = db.query(Vulnerability).all()
    vulnerabilities = [v.to_dict() for v in all_vulns_orm]

    # Orphan assets
    orphan_orm = (
        db.query(Asset)
        .options(_jl(Asset.owner), _jl(Asset.vulnerabilities))
        .join(Owner)
        .filter(Owner.status == "orphan")
        .all()
    )
    orphans = [a.to_dict() for a in orphan_orm]

    # ── Generate PDF ──────────────────────────────────────────────────────────
    from datetime import datetime
    week_label = f"Week of {datetime.now().strftime('%Y-%m-%d')}"

    try:
        pdf_bytes = generate_report(
            stats=stats,
            top_assets=top_assets,
            vulnerabilities=vulnerabilities,
            orphans=orphans,
            week_label=week_label,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

    # ── Optionally fire "report ready" email ─────────────────────────────────
    email_alerts_mod = _get_email_alerts()
    if email_alerts_mod:
        try:
            email_alerts_mod.send_report_ready_alert(stats)
        except Exception as e:
            print(f"⚠️  Report ready email failed: {e}")

    filename = f"sentinel_report_{datetime.now().strftime('%Y-%m-%d')}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/alerts/send")
def send_alert(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    """
    Manually trigger an alert email. Admin only.

    Request body:
        {
            "alert_type": "weekly_report" | "critical_summary" | "orphan_summary",
            "recipient":  "override@email.com"  (optional)
        }
    """
    email_alerts_mod = _get_email_alerts()
    if email_alerts_mod is None:
        raise HTTPException(
            status_code=503,
            detail="email_alerts module not found — check email_alerts.py exists"
        )

    alert_type = payload.get("alert_type", "weekly_report")
    recipient  = payload.get("recipient", "").strip() or None

    # ── Gather stats for email content ───────────────────────────────────────
    stats = {
        "total_assets":    db.query(Asset).count(),
        "critical_count":  db.query(Asset).filter(Asset.risk_level == "Critical").count(),
        "exposed_count":   db.query(Asset).filter(Asset.internet_exposed == True).count(),
        "orphan_count":    db.query(Owner).filter(Owner.status == "orphan").count(),
        "high_risk_count": db.query(Asset).filter(Asset.risk_score >= 70).count(),
        "total_vulns":     db.query(Vulnerability).count(),
        "exploit_count":   db.query(Vulnerability).filter(Vulnerability.exploit_available == True).count(),
    }

    if alert_type == "weekly_report":
        result = email_alerts_mod.send_report_ready_alert(stats, recipient=recipient)

    elif alert_type == "critical_summary":
        # Find highest-risk asset and use it for the email
        from sqlalchemy.orm import joinedload as _jl
        top_asset_orm = (
            db.query(Asset)
            .filter(Asset.risk_level == "Critical")
            .options(_jl(Asset.owner), _jl(Asset.vulnerabilities))
            .order_by(Asset.risk_score.desc())
            .first()
        )
        if not top_asset_orm:
            raise HTTPException(
                status_code=404,
                detail="No Critical risk assets found to alert on"
            )
        result = email_alerts_mod.send_critical_asset_alert(
            top_asset_orm.to_dict(), recipient=recipient
        )

    elif alert_type == "orphan_summary":
        orphan_orm = (
            db.query(Asset)
            .join(Owner)
            .filter(Owner.status == "orphan")
            .order_by(Asset.risk_score.desc())
            .first()
        )
        if not orphan_orm:
            raise HTTPException(
                status_code=404,
                detail="No orphan assets found"
            )
        result = email_alerts_mod.send_orphan_alert(
            orphan_orm.asset_id,
            orphan_orm.risk_score or 0,
            orphan_orm.risk_level or "Unknown",
            recipient=recipient,
        )
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown alert_type '{alert_type}'. Use: weekly_report, critical_summary, orphan_summary"
        )

    if not result.get("success"):
        raise HTTPException(
            status_code=500,
            detail=f"Email failed: {result.get('error', 'unknown error')}"
        )

    return {"message": "Alert email sent", "recipient": result.get("recipient"), "alert_type": alert_type}


@app.get("/stats")
def get_stats(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_any_role),
):
    total_assets    = db.query(Asset).count()
    critical_count  = db.query(Asset).filter(Asset.risk_level == "Critical").count()
    exposed_count   = db.query(Asset).filter(Asset.internet_exposed == True).count()
    orphan_count    = db.query(Owner).filter(Owner.status == "orphan").count()
    high_risk_count = db.query(Asset).filter(Asset.risk_score >= 70).count()
    total_vulns     = db.query(Vulnerability).count()
    exploit_count   = db.query(Vulnerability).filter(Vulnerability.exploit_available == True).count()

    return {
        "total_assets":    total_assets,
        "critical_count":  critical_count,
        "exposed_count":   exposed_count,
        "orphan_count":    orphan_count,
        "high_risk_count": high_risk_count,
        "total_vulns":     total_vulns,
        "exploit_count":   exploit_count,
    }


# ─── PART 5: AI Q&A ENDPOINT ─────────────────────────────────────────────────

# ─── FIX: Changed from GET to POST to prevent browser/proxy caching
# GET requests with the same ?question= param can be served from cache,
# causing the frontend to silently receive a stale (or empty) response.
# POST is never cached, so every submission hits the backend fresh.
@app.post("/ask")
def ask(
    payload: dict,
    current_user: dict = Depends(require_analyst_or_above),
):
    question = payload.get("question", "").strip()
    if not question:
        raise HTTPException(status_code=422, detail="question field is required")

    rag = build_rag_context(question, collection, embed_model)

    print(
        f"🔍 RAG | intent={rag['intent']} | "
        f"retrieved={rag['n_retrieved']} | {rag['description']}"
    )

    # ─── AI inference: Groq (primary) → Ollama phi3 (fallback) ──────────────
    # Strategy:
    #   1. If groq_client was successfully initialised at startup, use Groq.
    #   2. If Groq raises ANY exception (rate limit, network error, bad key,
    #      quota exceeded), catch it, log it, and immediately retry with Ollama.
    #   3. If Ollama also fails, return a clear error — never silently blank.
    messages = [
        {"role": "system",  "content": rag["system_prompt"]},
        {"role": "user",    "content": f"Context:\n{rag['context']}\n\nQuestion: {question}"},
    ]

    answer      = None
    llm_backend = "unknown"

    # ── Attempt 1: Groq ───────────────────────────────────────────────────────
    if groq_client is not None:
        try:
            chat_response = groq_client.chat.completions.create(
                model=GROQ_MODEL,
                messages=messages,
                temperature=0.1,    # lower = less hallucination / training-data bleed
                max_tokens=1024,
                # Stop sequences prevent the model leaking into unrelated content
                # if the context window fills up unexpectedly
                stop=["<|end|>", "<|eot_id|>", "Human:", "User:"],
            )
            raw_answer  = chat_response.choices[0].message.content or ""
            # ── Sanity check: detect training-data bleed / garbled output ─────
            # If the model leaks unrelated content it tends to include tokens
            # like "you'reX/Y" patterns, JSON setup instructions, or prompt
            # injection artifacts. We detect these and re-route to Ollama.
            _bleed_signals = [
                "you'reX", "you'entertainment", "Prepare the JSON",
                "Apache Kafka", "Azure Active Directory (Amazon",
                "I am only interested in assets that are related",
                "explain it to a colleague who has no idea",
            ]
            if any(sig in raw_answer for sig in _bleed_signals) or len(raw_answer) < 10:
                raise ValueError(
                    f"Groq response appears garbled (length={len(raw_answer)}). "
                    "Falling back to Ollama."
                )
            answer      = raw_answer
            llm_backend = f"groq/{GROQ_MODEL}"
            print(f"✅ Answer via Groq ({GROQ_MODEL})")
        except Exception as groq_err:
            print(f"⚠️  Groq failed: {groq_err} — falling back to Ollama")

    # ── Attempt 2: Ollama fallback ────────────────────────────────────────────
    if answer is None:
        try:
            ollama_response = ollama.chat(
                model=OLLAMA_MODEL,
                messages=messages,
            )
            answer      = ollama_response["message"]["content"]
            llm_backend = f"ollama/{OLLAMA_MODEL}"
            print(f"✅ Answer via Ollama ({OLLAMA_MODEL})")
        except Exception as ollama_err:
            print(f"❌ Ollama also failed: {ollama_err}")
            raise HTTPException(
                status_code=502,
                detail=(
                    f"Both AI backends failed. "
                    f"Groq: check GROQ_API_KEY in .env. "
                    f"Ollama: make sure \'ollama serve\' is running with the {OLLAMA_MODEL} model. "
                    f"Ollama error: {str(ollama_err)}"
                ),
            )

    return {
        "response": answer,
        "rag_debug": {
            "intent":      rag["intent"],
            "description": rag["description"],
            "n_retrieved": rag["n_retrieved"],
            "llm_backend": llm_backend,   # shows "groq/llama3-70b-8192" or "ollama/phi3"
        },
    }


# ─── PART 6: ML ENDPOINTS ────────────────────────────────────────────────────

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ml"))

from predict import score_asset
from nvd_connector import get_cves_with_fallback
from ingest import ingest_single_asset
from pydantic import BaseModel
from typing import Optional, List
from datetime import date as DateType


class VulnerabilityInput(BaseModel):
    cve:               str
    severity:          str
    cvss_score:        Optional[float] = None
    exploit_available: bool = False
    patch_available:   bool = False
    description:       Optional[str] = ""


class OwnerInput(BaseModel):
    team:   Optional[str] = None
    email:  Optional[str] = None
    status: str = "assigned"


class AssetInput(BaseModel):
    asset_id:         str
    asset_type:       str
    environment:      str
    criticality:      str
    ip_address:       Optional[str] = None
    domain:           Optional[str] = None
    internet_exposed: bool = False
    os_name:          Optional[str] = None
    os_version:       Optional[str] = None
    software_name:    Optional[str] = None
    software_version: Optional[str] = None
    last_scan_date:   Optional[str] = None
    vulnerabilities:  List[VulnerabilityInput] = []
    owner:            Optional[OwnerInput] = None


@app.post("/assets")
def create_asset(
    asset_input: AssetInput,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    existing = db.query(Asset).filter(Asset.asset_id == asset_input.asset_id).first()
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Asset '{asset_input.asset_id}' already exists"
        )

    last_scan = None
    if asset_input.last_scan_date:
        try:
            from datetime import datetime
            last_scan = datetime.strptime(
                asset_input.last_scan_date[:10], "%Y-%m-%d"
            ).date()
        except ValueError:
            last_scan = None

    new_asset = Asset(
        asset_id         = asset_input.asset_id,
        asset_type       = asset_input.asset_type,
        environment      = asset_input.environment,
        criticality      = asset_input.criticality,
        ip_address       = asset_input.ip_address,
        domain           = asset_input.domain,
        internet_exposed = asset_input.internet_exposed,
        os_name          = asset_input.os_name,
        os_version       = asset_input.os_version,
        software_name    = asset_input.software_name,
        software_version = asset_input.software_version,
        last_scan_date   = last_scan,
        risk_score       = None,
        risk_level       = None,
    )
    db.add(new_asset)

    provided_cves = [
        {
            "cve":               v.cve,
            "severity":          v.severity,
            "cvss_score":        v.cvss_score,
            "exploit_available": v.exploit_available,
            "patch_available":   v.patch_available,
            "description":       v.description,
            "source":            "provided",
        }
        for v in asset_input.vulnerabilities
    ]

    final_cves, cve_source = get_cves_with_fallback(
        software_name    = asset_input.software_name or "",
        software_version = asset_input.software_version or "",
        mock_cves        = provided_cves,
    )

    for v in final_cves:
        vuln = Vulnerability(
            asset_id          = asset_input.asset_id,
            cve               = v.get("cve", "UNKNOWN"),
            severity          = v.get("severity", "Unknown"),
            cvss_score        = v.get("cvss_score"),
            exploit_available = v.get("exploit_available", False),
            patch_available   = v.get("patch_available", False),
            description       = v.get("description", ""),
        )
        db.add(vuln)

    if asset_input.owner:
        owner = Owner(
            asset_id = asset_input.asset_id,
            team     = asset_input.owner.team,
            email    = asset_input.owner.email,
            status   = asset_input.owner.status,
        )
    else:
        owner = Owner(
            asset_id = asset_input.asset_id,
            team     = None,
            email    = None,
            status   = "orphan",
        )
    db.add(owner)
    db.commit()

    asset_dict_for_ml = {
        "asset_id":         asset_input.asset_id,
        "asset_type":       asset_input.asset_type,
        "environment":      asset_input.environment,
        "criticality":      asset_input.criticality,
        "internet_exposed": asset_input.internet_exposed,
        "last_scan_date":   asset_input.last_scan_date,
        "vulnerabilities":  final_cves,
    }

    try:
        ml_result = score_asset(asset_dict_for_ml)
        new_asset.risk_score = ml_result["risk_score"]
        new_asset.risk_level = ml_result["risk_level"]
        db.commit()
    except Exception as e:
        print(f"⚠️  ML scoring failed for {asset_input.asset_id}: {e}")
        ml_result = None

    # ── AUTO EMAIL ALERT ──────────────────────────────────────────────────────
    # Fire alert emails automatically for high-risk new assets
    if ml_result and ml_result["risk_level"] in ("Critical", "High"):
        email_alerts_mod = _get_email_alerts()
        if email_alerts_mod:
            try:
                asset_alert_dict = {
                    "asset_id":         asset_input.asset_id,
                    "risk_level":       ml_result["risk_level"],
                    "risk_score":       ml_result["risk_score"],
                    "environment":      asset_input.environment,
                    "ip_address":       asset_input.ip_address,
                    "internet_exposed": asset_input.internet_exposed,
                    "vulnerabilities":  final_cves,
                }
                email_alerts_mod.send_critical_asset_alert(asset_alert_dict)

                # Also alert if there are dangerous unpatched exploits
                email_alerts_mod.send_exploit_cve_alert(
                    asset_input.asset_id, final_cves
                )

                # Orphan alert
                if not asset_input.owner or (asset_input.owner and not asset_input.owner.team):
                    email_alerts_mod.send_orphan_alert(
                        asset_input.asset_id,
                        ml_result["risk_score"],
                        ml_result["risk_level"],
                    )
            except Exception as alert_err:
                print(f"⚠️  Alert email failed (non-blocking): {alert_err}")

    db.refresh(new_asset)
    try:
        ingest_single_asset(new_asset.to_dict())
    except Exception as e:
        print(f"ChromaDB ingest failed for {asset_input.asset_id}: {e}")

    result = new_asset.to_dict()
    result["cve_source"] = cve_source

    if ml_result:
        result["ml_scoring"] = {
            "risk_score":   ml_result["risk_score"],
            "risk_level":   ml_result["risk_level"],
            "confidence":   ml_result["confidence"],
            "top_features": ml_result["top_features"],
        }

    return result


@app.get("/analyze/{asset_id}")
def analyze_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_analyst_or_above),
):
    asset = (
        db.query(Asset)
        .options(joinedload(Asset.owner), joinedload(Asset.vulnerabilities))
        .filter(Asset.asset_id == asset_id)
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")

    asset_dict = asset.to_dict()

    try:
        ml_result = score_asset(asset_dict)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ML scoring failed: {str(e)}")

    recommendations = []
    features = ml_result["features_used"]

    if features.get("exploit_unpatched_count", 0) > 0:
        recommendations.append({
            "priority": "CRITICAL",
            "action":   "Immediately isolate or take offline — active exploit with no patch available",
        })
    if features.get("has_critical_unpatched", 0) == 1:
        recommendations.append({
            "priority": "CRITICAL",
            "action":   "Apply emergency patch or workaround for Critical severity CVE",
        })
    if features.get("internet_exposed", 0) == 1:
        recommendations.append({
            "priority": "HIGH",
            "action":   "Review firewall rules — consider moving behind VPN or restricting public access",
        })
    if features.get("exploit_available", 0) == 1:
        recommendations.append({
            "priority": "HIGH",
            "action":   "Prioritise patching — known exploit exists in the wild",
        })
    if features.get("patch_available", 1) == 0:
        recommendations.append({
            "priority": "HIGH",
            "action":   "Monitor vendor advisories for patch release — apply immediately when available",
        })
    if features.get("days_since_scan", 0) > 30:
        recommendations.append({
            "priority": "MEDIUM",
            "action":   f"Schedule rescan — last scan was {int(features['days_since_scan'])} days ago",
        })
    if asset_dict.get("owner", {}) and asset_dict["owner"].get("status") == "orphan":
        recommendations.append({
            "priority": "MEDIUM",
            "action":   "Assign ownership — orphan assets are rarely monitored or patched",
        })
    if not recommendations:
        recommendations.append({
            "priority": "LOW",
            "action":   "Maintain regular scanning schedule and monitor for new CVEs",
        })

    return {
        "asset":           asset_dict,
        "ml_analysis": {
            "risk_score":     ml_result["risk_score"],
            "risk_level":     ml_result["risk_level"],
            "confidence":     ml_result["confidence"],
            "top_features":   ml_result["top_features"],
            "features_used":  ml_result["features_used"],
        },
        "recommendations": recommendations,
    }