"""
ingest.py (Phase 5 Update)
─────────────────────────────────────────────────────────────────────────────
WHAT CHANGED FROM PHASE 1:
  Phase 1: Read from data/assets_v2.json
  Phase 5: Read from PostgreSQL via SQLAlchemy

WHY IT CHANGED:
  Phase 1 ChromaDB was loaded from JSON. PostgreSQL was loaded separately
  from the same JSON. They started identical but diverged whenever new
  assets were added via POST /assets — PostgreSQL got updated but
  ChromaDB did not. The AI assistant was answering questions about
  stale data.

  Now ChromaDB is always ingested FROM PostgreSQL, making it the
  single source of truth. Any asset added to PostgreSQL automatically
  gets reflected in ChromaDB after re-ingestion.

HOW TO USE:
  Full re-ingest (all assets):
      python ingest.py

  Single asset re-ingest (called by main.py after POST /assets):
      from ingest import ingest_single_asset
      ingest_single_asset(asset_dict)
"""

import os
import sys
import chromadb
from sentence_transformers import SentenceTransformer

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from db import SessionLocal, Asset

CHROMA_PATH = "chroma_db"
COLLECTION  = "cyber_assets"
EMBED_MODEL = "all-MiniLM-L6-v2"
BATCH_SIZE  = 50

print("Loading embedding model...")
model  = SentenceTransformer(EMBED_MODEL)
client = chromadb.PersistentClient(path=CHROMA_PATH)


def build_asset_text(asset_dict: dict) -> str:
    vulns  = asset_dict.get("vulnerabilities", []) or []
    owner  = asset_dict.get("owner") or {}
    os_d   = asset_dict.get("os") or {}
    sw     = asset_dict.get("software") or {}

    if vulns:
        vuln_lines = []
        for v in vulns:
            exploit_tag = "Exploit available" if v.get("exploit_available") else "No exploit"
            patch_tag   = "Patch available"   if v.get("patch_available")   else "No patch"
            source_tag  = f" [{v.get('source','mock')}]"
            vuln_lines.append(
                f"  - {v.get('cve','UNKNOWN')} | {v.get('severity','Unknown')} "
                f"| CVSS: {v.get('cvss_score','N/A')}{source_tag} "
                f"| {exploit_tag} | {patch_tag}\n"
                f"    {v.get('description','')[:200]}"
            )
        vuln_text = "\n".join(vuln_lines)
    else:
        vuln_text = "  No known vulnerabilities."

    if owner.get("status") == "orphan":
        owner_text = "UNOWNED - orphan asset, no responsible team assigned"
    else:
        owner_text = f"{owner.get('team','Unknown')} ({owner.get('email','N/A')})"

    return f"""Asset ID: {asset_dict.get('asset_id','')}
Asset Type: {asset_dict.get('asset_type','')}
Environment: {asset_dict.get('environment','')}
Criticality: {asset_dict.get('criticality','')}
IP Address: {asset_dict.get('ip_address','N/A')}
Domain: {asset_dict.get('domain','N/A')}
Internet Exposed: {'Yes' if asset_dict.get('internet_exposed') else 'No'}
Operating System: {os_d.get('name','Unknown')} {os_d.get('version','')}
Software: {sw.get('name','Unknown')} v{sw.get('version','Unknown')}
Owner: {owner_text}
Last Scan: {asset_dict.get('last_scan_date','Unknown')}
Risk Score: {asset_dict.get('risk_score','Not yet scored')} / 100
Risk Level: {asset_dict.get('risk_level','Not yet scored')}

Vulnerabilities:
{vuln_text}
"""


def build_asset_metadata(asset_dict: dict) -> dict:
    vulns   = asset_dict.get("vulnerabilities", []) or []
    owner   = asset_dict.get("owner") or {}
    max_cvss    = max((v.get("cvss_score") or 0 for v in vulns), default=0.0)
    has_exploit = any(v.get("exploit_available", False) for v in vulns)
    severities  = list({v.get("severity","Unknown") for v in vulns})
    has_nvd     = any(v.get("source") == "NVD" for v in vulns)

    return {
        "asset_id":         asset_dict.get("asset_id", ""),
        "asset_type":       asset_dict.get("asset_type", ""),
        "environment":      asset_dict.get("environment", ""),
        "criticality":      asset_dict.get("criticality", ""),
        "internet_exposed": str(asset_dict.get("internet_exposed", False)),
        "owner_status":     owner.get("status", "assigned"),
        "owner_team":       owner.get("team") or "orphan",
        "risk_score":       float(asset_dict.get("risk_score") or 0),
        "risk_level":       asset_dict.get("risk_level") or "Unknown",
        "max_cvss":         float(max_cvss),
        "has_exploit":      str(has_exploit),
        "vuln_count":       len(vulns),
        "severities":       ", ".join(severities),
        "has_nvd_cves":     str(has_nvd),
    }


def ingest_all():
    """Full re-ingest of all assets from PostgreSQL into ChromaDB."""
    print("\nLoading assets from PostgreSQL...")
    db = SessionLocal()
    try:
        assets = db.query(Asset).all()
        print(f"   Found {len(assets)} assets")
        asset_dicts = [a.to_dict() for a in assets]
    finally:
        db.close()

    if not asset_dicts:
        print("No assets found. Run migrate.py first.")
        return

    # Delete and recreate collection
    existing = [c.name for c in client.list_collections()]
    if COLLECTION in existing:
        client.delete_collection(name=COLLECTION)
        print(f"Deleted existing collection")

    collection = client.create_collection(name=COLLECTION)
    print(f"Created fresh collection '{COLLECTION}'")

    documents = [build_asset_text(a) for a in asset_dicts]
    metadatas = [build_asset_metadata(a) for a in asset_dicts]
    ids       = [a["asset_id"] for a in asset_dicts]

    print(f"\nGenerating embeddings for {len(documents)} assets...")
    embeddings = model.encode(documents, show_progress_bar=True).tolist()

    print(f"\nStoring in ChromaDB in batches of {BATCH_SIZE}...")
    for start in range(0, len(documents), BATCH_SIZE):
        end = start + BATCH_SIZE
        collection.add(
            documents  = documents[start:end],
            embeddings = embeddings[start:end],
            metadatas  = metadatas[start:end],
            ids        = ids[start:end],
        )
        print(f"   Stored batch ({start} to {min(end,len(documents))-1})")

    total     = collection.count()
    nvd_count = sum(1 for m in metadatas if m["has_nvd_cves"] == "True")
    print(f"\nChromaDB ingestion complete")
    print(f"   Total assets : {total}")
    print(f"   NVD CVEs     : {nvd_count}")


def ingest_single_asset(asset_dict: dict):
    """
    Add or update ONE asset in ChromaDB.
    Called by main.py after POST /assets saves a new asset.
    Keeps ChromaDB in sync without full re-ingest.
    """
    asset_id = asset_dict.get("asset_id")
    if not asset_id:
        return

    try:
        collection = client.get_or_create_collection(name=COLLECTION)

        # Remove old entry if exists
        try:
            collection.delete(ids=[asset_id])
        except Exception:
            pass

        text      = build_asset_text(asset_dict)
        metadata  = build_asset_metadata(asset_dict)
        embedding = model.encode([text]).tolist()

        collection.add(
            documents  = [text],
            embeddings = embedding,
            metadatas  = [metadata],
            ids        = [asset_id],
        )
        print(f"ChromaDB updated for {asset_id}")

    except Exception as e:
        print(f"ChromaDB single ingest failed for {asset_id}: {e}")


if __name__ == "__main__":
    print("Sentinel - ChromaDB Re-ingestion from PostgreSQL")
    print("=" * 50)
    ingest_all()