import re


# ─── INTENT CONSTANTS ────────────────────────────────────────────────────────
# Each intent maps to a different retrieval strategy.

INTENT_ORPHAN      = "orphan"        # unowned assets
INTENT_EXPOSED     = "exposed"       # internet-facing assets
INTENT_RISK_LEVEL  = "risk_level"    # filter by Critical/High/Medium/Low
INTENT_CVE         = "cve"           # vulnerability / CVE questions
INTENT_NVD         = "nvd"           # assets with real NVD CVE data
INTENT_ASSET_ID    = "asset_id"      # one specific asset
INTENT_ENVIRONMENT = "environment"   # filter by Production/Staging/Dev
INTENT_GENERAL     = "general"       # broad questions — semantic search


# ─── KEYWORD TABLES ──────────────────────────────────────────────────────────

ORPHAN_KEYWORDS = [
    "orphan", "unowned", "no owner", "without owner",
    "unassigned", "no team", "missing owner", "not assigned",
    "nobody owns", "no responsible",
]

EXPOSED_KEYWORDS = [
    "internet-exposed", "internet exposed", "exposed to internet",
    "publicly accessible", "public-facing", "publicly facing",
    "internet facing", "exposed asset", "open to internet",
    "reachable from internet", "accessible from internet",
    "facing the internet",
]

# ── FIX: HIGH_RISK_KEYWORDS must be checked BEFORE CVE_KEYWORDS in detect_intent
# so that "most dangerous CVEs" routes to high-risk intent, not plain CVE search.
HIGH_RISK_KEYWORDS = [
    "patch immediately", "patch first", "fix immediately",
    "most dangerous", "most vulnerable", "top risk", "riskiest",
    "urgent", "should i patch", "what to fix", "priority",
    "highest risk", "highest score", "highest risk score",
    "most at risk", "biggest risk", "greatest risk",
    "which assets", "what assets", "top assets",
    "should i fix", "need to fix", "fix first",
    "remediate", "remediation", "immediately patch",
    "critical assets", "dangerous assets", "risky assets",
    # ── FIX: added to catch "most dangerous CVEs / vulns" phrasing ────────────
    "most dangerous cve", "most dangerous vuln", "worst vulnerability",
    "worst cve", "critical vulnerability", "top vulnerability",
    "what should i fix", "what do i fix", "fix urgently",
]

CVE_KEYWORDS = [
    "cve", "vulnerability", "vulnerabilities", "exploit",
    "unpatched", "no patch", "missing patch", "cvss",
    "security flaw", "security issue", "weakness",
    "dangerous cve", "dangerous vulnerability", "dangerous vuln",
    "known exploit", "exploitable", "patch", "patching",
    "security hole", "attack surface", "attack vector", "exposure",
]

NVD_KEYWORDS = [
    "nvd", "real cve", "real vulnerability", "real data",
    "national vulnerability", "nvd data", "live cve",
]

# Maps user-facing words -> exact risk_level values stored in ChromaDB
# Checked BEFORE generic high-risk keywords so "critical" routes here
RISK_LEVEL_MAP = {
    "Critical": ["critical"],
    "High":     ["high risk", "high-risk", " high "],
    "Medium":   ["medium risk", "medium-risk", " medium "],
    "Low":      ["low risk", "low-risk"],
}

# Maps environment words -> exact environment values stored in ChromaDB
ENVIRONMENT_MAP = {
    "Production":  ["production", "prod environment", "live environment", "in production"],
    "Staging":     ["staging", "stage environment", "pre-prod"],
    "Development": ["development", "dev environment", "dev assets", "in development"],
}


# ─── INTENT DETECTION ────────────────────────────────────────────────────────

def detect_intent(question: str) -> dict:
    """
    Read the question and return a retrieval plan.

    Returns a dict:
      intent      — one of the INTENT_* constants
      filters     — dict passed to ChromaDB's `where` clause
                    (empty dict = no filter = pure semantic search)
      n_results   — how many documents to retrieve
      description — human-readable summary shown on the frontend

    ChromaDB filter syntax:
      Equality:         {"owner_status": "orphan"}
      Numeric compare:  {"risk_score": {"$gte": 60.0}}
      Compound AND:     {"$and": [{"owner_status": "orphan"},
                                   {"environment": "Production"}]}
      String booleans:  {"internet_exposed": "True"}
        Note: ingest.py stores booleans as "True"/"False" strings
              because ChromaDB metadata only supports str/int/float.

    ── FIX: Intent priority order (most specific → least specific) ──────────
      1. Specific asset ID   — completely unambiguous
      2. Environment only    — detected for use in compound filters below
      3. Risk level by name  — "critical assets", "high risk assets"
      4. Orphan assets       — "unowned", "no owner"
      5. Internet-exposed    — "publicly accessible", "internet facing"
      6. NVD data questions  — "real CVE data", "NVD"
      7. HIGH RISK / patch priority  ← MOVED ABOVE CVE (was below before)
         Catches "most dangerous", "patch first", "what should I fix"
         BEFORE the general CVE bucket swallows them.
      8. CVE / vulnerability — general vuln questions
      9. Environment summary — just "in production / staging / dev"
     10. General fallback    — semantic search
    """

    q = question.lower()

    # ── 1. Specific asset ID  ────────────────────────────────────────────────
    asset_id_match = re.search(r"ASSET-\d+", question, re.IGNORECASE)
    if asset_id_match:
        asset_id = asset_id_match.group(0).upper()
        return {
            "intent":      INTENT_ASSET_ID,
            "filters":     {"asset_id": asset_id},
            "n_results":   1,
            "description": f"Looking up asset {asset_id}",
        }

    # ── 2. Environment detection (reused in compound filters below) ──────────
    detected_env = None
    for env_value, keywords in ENVIRONMENT_MAP.items():
        if any(kw in q for kw in keywords):
            detected_env = env_value
            break

    # ── 3. Risk level detection ──────────────────────────────────────────────
    detected_risk_level = None
    for level, keywords in RISK_LEVEL_MAP.items():
        if any(kw in q for kw in keywords):
            detected_risk_level = level
            break

    if detected_risk_level:
        base    = {"risk_level": detected_risk_level}
        filters = _combine_env(base, detected_env)
        return {
            "intent":      INTENT_RISK_LEVEL,
            "filters":     filters,
            "n_results":   50,
            "description": f"Fetching {detected_risk_level} risk assets"
                           + (f" in {detected_env}" if detected_env else ""),
        }

    # ── 4. Orphan assets ──────────────────────────────────────────────────────
    if any(kw in q for kw in ORPHAN_KEYWORDS):
        base    = {"owner_status": "orphan"}
        filters = _combine_env(base, detected_env)
        return {
            "intent":      INTENT_ORPHAN,
            "filters":     filters,
            "n_results":   50,
            "description": "Fetching orphan assets"
                           + (f" in {detected_env}" if detected_env else ""),
        }

    # ── 5. Internet-exposed assets ────────────────────────────────────────────
    if any(kw in q for kw in EXPOSED_KEYWORDS):
        base    = {"internet_exposed": "True"}
        filters = _combine_env(base, detected_env)
        return {
            "intent":      INTENT_EXPOSED,
            "filters":     filters,
            "n_results":   50,
            "description": "Fetching internet-exposed assets"
                           + (f" in {detected_env}" if detected_env else ""),
        }

    # ── 6. NVD data questions ─────────────────────────────────────────────────
    if any(kw in q for kw in NVD_KEYWORDS):
        base    = {"has_nvd_cves": "True"}
        filters = _combine_env(base, detected_env)
        return {
            "intent":      INTENT_NVD,
            "filters":     filters,
            "n_results":   50,
            "description": "Fetching assets with real NVD CVE data",
        }

    # ── 7. High-risk / patch priority ─────────────────────────────────────────
    # ── FIX: This block is now ABOVE CVE intent (was below before).
    # "Most dangerous CVEs", "what should I patch first" etc. were incorrectly
    # falling into the generic CVE bucket with no risk filters applied, causing
    # the LLM to receive unranked context and give vague answers.
    # Now they correctly route here and fetch risk_score >= 60 assets.
    if any(kw in q for kw in HIGH_RISK_KEYWORDS):
        base    = {"risk_score": {"$gte": 60.0}}
        filters = _combine_env(base, detected_env)
        return {
            "intent":      INTENT_RISK_LEVEL,
            "filters":     filters,
            "n_results":   30,
            "description": "Fetching high+critical risk assets (score >= 60)"
                           + (f" in {detected_env}" if detected_env else ""),
        }

    # ── 8. CVE / vulnerability questions ─────────────────────────────────────
    if any(kw in q for kw in CVE_KEYWORDS):
        if "exploit" in q:
            # Narrow to assets that actually have a known exploit
            base    = {"has_exploit": "True"}
            filters = _combine_env(base, detected_env)
        elif detected_env:
            filters = {"environment": detected_env}
        else:
            filters = {}   # semantic search across all assets

        return {
            "intent":      INTENT_CVE,
            "filters":     filters,
            "n_results":   25,
            "description": "Fetching assets with vulnerability context"
                           + (" (exploits only)" if "exploit" in q else "")
                           + (f" in {detected_env}" if detected_env else ""),
        }

    # ── 9. Environment only ───────────────────────────────────────────────────
    if detected_env:
        return {
            "intent":      INTENT_ENVIRONMENT,
            "filters":     {"environment": detected_env},
            "n_results":   30,
            "description": f"Fetching all {detected_env} assets",
        }

    # ── 10. General fallback — pure semantic search ───────────────────────────
    return {
        "intent":      INTENT_GENERAL,
        "filters":     {},
        "n_results":   15,
        "description": "General semantic search",
    }


def _combine_env(base_filter: dict, env: str) -> dict:
    """
    Merge a base metadata filter with an optional environment filter.

    ChromaDB requires compound filters to use the $and operator.
    You cannot pass two separate `where` arguments.

    Example:
      base_filter = {"owner_status": "orphan"}
      env         = "Production"
      result      = {"$and": [{"owner_status": "orphan"},
                               {"environment": "Production"}]}
    """
    if not env:
        return base_filter
    return {"$and": [base_filter, {"environment": env}]}


# ─── SYSTEM PROMPT BUILDER ───────────────────────────────────────────────────

def build_system_prompt(intent: str) -> str:
    """
    Return a system prompt tuned for the detected intent.
    """

    base = (
        "You are Sentinel, a cybersecurity asset intelligence assistant. "
        "Answer ONLY using the information in the provided context below. "
        "Do not invent asset IDs, CVE identifiers, risk scores, team names, "
        "or any data not present in the context. "
        "If specific information is missing from the context, say so explicitly. "
        "When you have finished answering, STOP. "
        "Do not continue with unrelated questions, JSON examples, "
        "setup instructions, or any other content. "
    )

    hints = {
        INTENT_ORPHAN: (
            "The user is asking about orphan assets — assets with no assigned owner. "
            "List EVERY orphan asset found in the context. "
            "For each: Asset ID, Type, Environment, Risk Score, Risk Level. "
            "End with the total count. "
            "If there are no orphans in the context, say so clearly."
        ),
        INTENT_EXPOSED: (
            "The user is asking about internet-exposed assets. "
            "List EVERY exposed asset in the context. "
            "For each: Asset ID, Type, Environment, Risk Score, "
            "and its most critical CVE (ID + severity). "
            "End with the total count."
        ),
        INTENT_RISK_LEVEL: (
            "The user wants to see assets by risk level. "
            "List assets from highest to lowest risk score. "
            "For each: Asset ID, Risk Score, Risk Level, Environment, "
            "and the primary risk driver (exploit? exposure? criticality?). "
            "End with brief remediation advice."
        ),
        INTENT_CVE: (
            "The user is asking about vulnerabilities or CVEs. "
            "For each asset in context, list its CVEs: "
            "CVE ID, severity, CVSS score, exploit status, patch status. "
            "Note whether CVE data is sourced from NVD (real data) or manually provided. "
            "Highlight CVEs that have exploits AND no patch — these are the most dangerous."
        ),
        INTENT_NVD: (
            "The user is asking about assets with real CVE data from the NVD database. "
            "List these assets and their NVD-sourced CVEs. "
            "Highlight severity and any CVEs with active exploits. "
            "Contrast real NVD data against mock/provided CVEs where relevant."
        ),
        INTENT_ASSET_ID: (
            "The user is asking about one specific asset. "
            "Provide a complete security summary: "
            "asset type, environment, criticality, risk score, risk level, "
            "all CVEs with full details (including NVD source if applicable), "
            "owner information, and clear recommended remediation actions."
        ),
        INTENT_ENVIRONMENT: (
            "The user is asking about assets in a specific environment. "
            "Summarise the security posture: total assets shown, "
            "highest risk ones, most common vulnerabilities, "
            "any orphan or exposed assets worth flagging."
        ),
        INTENT_GENERAL: (
            "Provide a helpful, accurate security summary using only the context provided. "
            "Structure your answer: assets found, risk levels, key vulnerabilities, "
            "top recommended actions. "
            "If the context is insufficient to answer fully, say so."
        ),
    }

    task = hints.get(intent, hints[INTENT_GENERAL])
    return base + "\n\nYour task for this query: " + task


# ─── MAIN ENTRY POINT ────────────────────────────────────────────────────────

def build_rag_context(question: str, collection, embed_model) -> dict:
    """
    Called by the /ask endpoint. Returns everything needed to call the LLM.

    Steps:
      1. Detect intent from the question
      2. Embed the question (used for ranking even when filtering)
      3. Query ChromaDB with the right filters and n_results
      4. Format retrieved documents into a numbered context string
      5. Return context + system_prompt + metadata

    Args:
        question    — raw user question string
        collection  — connected ChromaDB collection object
        embed_model — loaded SentenceTransformer model

    Returns dict:
        context       — formatted string passed to LLM as context
        system_prompt — intent-tailored system prompt for the LLM
        intent        — detected intent constant
        description   — human-readable retrieval description
        n_retrieved   — actual number of documents returned
    """

    intent_info = detect_intent(question)
    intent      = intent_info["intent"]

    # Embed the question for similarity ranking
    query_embedding = embed_model.encode(question).tolist()

    # ── FIX: cap n_results at actual collection size to prevent ChromaDB errors
    # ChromaDB raises if you request more results than documents exist.
    total_docs = collection.count()
    if total_docs == 0:
        return {
            "context":       "[No assets found in the knowledge base. Run ingest.py first.]",
            "system_prompt": build_system_prompt(intent),
            "intent":        intent,
            "description":   intent_info["description"],
            "n_retrieved":   0,
        }

    n_results = min(intent_info["n_results"], total_docs)

    # Query ChromaDB
    # ChromaDB raises an exception when a `where` filter matches zero docs
    # rather than returning an empty result — we handle this explicitly.
    try:
        query_kwargs = {
            "query_embeddings": [query_embedding],
            "n_results":        n_results,
        }
        if intent_info["filters"]:
            query_kwargs["where"] = intent_info["filters"]

        results   = collection.query(**query_kwargs)
        documents = results["documents"][0]

        # ── FIX: if the filter matched docs but returned 0, still fall back
        if not documents:
            raise ValueError("Filter returned 0 documents")

    except Exception as e:
        # Filter matched zero documents — fall back to semantic search
        print(f"⚠️  ChromaDB filter failed: {e} — falling back to semantic search")
        fallback_n = min(15, total_docs)
        fallback   = collection.query(
            query_embeddings=[query_embedding],
            n_results=fallback_n,
        )
        documents = fallback["documents"][0]
        intent_info["description"] += " [no filter match — showing closest results]"

    # Build context string
    header = (
        f"[Context: {len(documents)} asset(s) retrieved. "
        f"Query type: {intent_info['description']}]\n\n"
    )
    # ── FIX: Truncate each document to 800 chars before passing to LLM ─────────
    # ChromaDB stores full asset text which can be 1500+ chars per asset.
    # When n_results=50, total context = 75,000+ chars — far beyond the model's
    # effective instruction-following window, causing it to "escape" the prompt
    # and bleed training-data content (the garbled response you saw in the UI).
    # 800 chars per doc keeps the full context under ~12k tokens for 50 docs,
    # well within the 8k–32k window depending on which Groq model is used.
    MAX_DOC_CHARS = 800
    sanitised = []
    for doc in documents:
        # Strip any null bytes or control chars that could confuse the tokeniser
        clean = doc.replace("\x00", "").strip()
        if len(clean) > MAX_DOC_CHARS:
            clean = clean[:MAX_DOC_CHARS] + "\n  [... truncated for context window]"
        sanitised.append(clean)

    numbered = "\n\n---\n\n".join(
        f"[Asset {i + 1}]\n{doc}"
        for i, doc in enumerate(sanitised)
    )

    return {
        "context":       header + numbered,
        "system_prompt": build_system_prompt(intent),
        "intent":        intent,
        "description":   intent_info["description"],
        "n_retrieved":   len(documents),
    }