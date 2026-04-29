from dotenv import load_dotenv
load_dotenv()  # MUST be before any os.environ.get() calls

"""
auth.py — Standalone auth helpers (optional import).

NOTE: The primary auth logic (get_current_user, require_admin, etc.) lives
directly in main.py to avoid circular import issues between main.py and auth.py.

This file is kept for reference and for any future modules that need to
call decode_jwt independently without importing from main.py.

If your page scripts or other modules need auth utilities, import from here.
"""

import os
import jwt
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session  # sync session — matches db.py and main.py

from db import get_db, UserRole

SUPABASE_JWT_SECRET = os.environ.get("SUPABASE_JWT_SECRET", "")
bearer_scheme = HTTPBearer()


def decode_jwt(token: str) -> dict:
    """
    Decode and validate a Supabase-issued JWT.
    verify_aud=False is required because Supabase does not set the 'aud' claim.
    """
    try:
        payload = jwt.decode(
            token,
            SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            options={"verify_aud": False},
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired — please log in again")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),          # sync Session, NOT AsyncSession
) -> dict:
    """
    FastAPI dependency. Decodes the JWT, fetches the user's role from
    user_roles table, and returns {"user_id": ..., "role": ..., "email": ...}.
    Attach this to any route that requires authentication.
    """
    payload = decode_jwt(credentials.credentials)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token has no user ID")

    # Sync query — consistent with how main.py and db.py work
    user_role = db.query(UserRole).filter(UserRole.user_id == user_id).first()

    if not user_role:
        raise HTTPException(status_code=403, detail="User has no role assigned")

    return {"user_id": user_id, "role": user_role.role, "email": payload.get("email")}


# ── Role-specific dependency shortcuts ────────────────────────────────────────

def require_admin(
    current_user: dict = Depends(get_current_user),
) -> dict:
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


def require_analyst_or_above(
    current_user: dict = Depends(get_current_user),
) -> dict:
    if current_user["role"] not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Analyst or admin access required")
    return current_user


def require_any_role(
    current_user: dict = Depends(get_current_user),
) -> dict:
    # All three roles pass — just proves the user is logged in
    return current_user