"""
ml/features.py
─────────────────────────────────────────────────────────────────────────────
Feature extraction for Sentinel ML Risk Scoring.

Takes raw asset data (from PostgreSQL or a dict) and converts it into
a flat list of 13 numbers that the ML models can understand.

This is the most important file in the ML pipeline — if the features
are wrong, the model will be wrong no matter how good the algorithm is.

Usage:
    from ml.features import extract_features, FEATURE_NAMES
    features = extract_features(asset_dict)
─────────────────────────────────────────────────────────────────────────────
"""

from datetime import date, datetime
import numpy as np

# ─── FEATURE NAMES ────────────────────────────────────────────────────────────
# These must stay in this exact order — they match the columns
# the model was trained on. If you change the order, retrain the model.
FEATURE_NAMES = [
    "cvss_score",           # 1. max CVSS score across all CVEs
    "exploit_available",    # 2. 1 if any CVE has an exploit
    "patch_available",      # 3. 1 if ALL CVEs have patches (0 if any is unpatched)
    "internet_exposed",     # 4. 1 if asset is publicly reachable
    "criticality_encoded",  # 5. Low=1, Medium=2, High=3
    "environment_encoded",  # 6. Development=1, Staging=2, Production=3
    "vuln_count",           # 7. total number of CVEs
    "days_since_scan",      # 8. how old the last scan is (in days)
    "has_critical_unpatched",# 9. 1 if any Critical CVE has no patch
    "avg_cvss",             # 10. average CVSS across all CVEs
    "max_cvss",             # 11. highest single CVSS score
    "is_high_criticality",  # 12. 1 if criticality is High
    "exploit_unpatched_count",# 13. number of CVEs with exploit AND no patch
]

# ─── ENCODING MAPS ────────────────────────────────────────────────────────────
# Convert text values to numbers
# Higher number = higher risk contribution

CRITICALITY_MAP = {
    "low":    1,
    "medium": 2,
    "high":   3,
}

ENVIRONMENT_MAP = {
    "development": 1,
    "staging":     2,
    "production":  3,
}


# ─── MAIN FEATURE EXTRACTION FUNCTION ────────────────────────────────────────

def extract_features(asset: dict) -> list:
    """
    Convert one asset dict into a list of 13 numeric features.

    The asset dict can come from:
    - PostgreSQL via to_dict() — used during training
    - A new asset being scored in real time — used during prediction

    Args:
        asset: dict with keys like asset_id, criticality,
               internet_exposed, vulnerabilities, etc.

    Returns:
        List of 13 floats in the order defined by FEATURE_NAMES
    """

    vulns = asset.get("vulnerabilities", []) or []

    # ── Feature 1-3: CVE-based features ──────────────────────────────────────

    # Get all CVSS scores — filter out None values
    cvss_scores = [
        v.get("cvss_score") or 0.0
        for v in vulns
        if v.get("cvss_score") is not None
    ]

    # Feature 1: max CVSS score
    # The worst single CVE drives the most risk
    max_cvss = max(cvss_scores) if cvss_scores else 0.0

    # Feature 2: exploit_available
    # 1 if ANY vulnerability has a known exploit in the wild
    exploit_available = int(
        any(v.get("exploit_available", False) for v in vulns)
    )

    # Feature 3: patch_available
    # 0 if ANY vulnerability is missing a patch (more conservative)
    # An asset is only "fully patched" if ALL CVEs have patches
    patch_available = int(
        all(v.get("patch_available", True) for v in vulns)
    ) if vulns else 1   # no CVEs = consider it patched

    # ── Feature 4: Exposure ───────────────────────────────────────────────────

    # Feature 4: internet_exposed
    # Internet-facing assets are attacked by automated scanners constantly
    internet_exposed = int(asset.get("internet_exposed", False))

    # ── Feature 5-6: Encoded categorical features ─────────────────────────────

    # Feature 5: criticality_encoded
    # High criticality means bigger business impact if compromised
    criticality_raw = str(asset.get("criticality", "low")).lower().strip()
    criticality_encoded = CRITICALITY_MAP.get(criticality_raw, 1)

    # Feature 6: environment_encoded
    # Production systems carry higher risk than dev/staging
    environment_raw = str(asset.get("environment", "development")).lower().strip()
    environment_encoded = ENVIRONMENT_MAP.get(environment_raw, 1)

    # ── Feature 7: Vulnerability count ───────────────────────────────────────

    # Feature 7: vuln_count
    # More CVEs = wider attack surface = more ways to compromise the asset
    vuln_count = len(vulns)

    # ── Feature 8: Staleness ─────────────────────────────────────────────────

    # Feature 8: days_since_scan
    # If an asset hasn't been scanned recently, new vulnerabilities
    # might exist that we don't know about
    last_scan = asset.get("last_scan_date")
    if last_scan:
        try:
            # Handle both string dates and date objects
            if isinstance(last_scan, str):
                last_scan_date = datetime.strptime(
                    last_scan[:10], "%Y-%m-%d"
                ).date()
            elif isinstance(last_scan, datetime):
                last_scan_date = last_scan.date()
            else:
                last_scan_date = last_scan   # already a date object

            days_since_scan = (date.today() - last_scan_date).days
            # Cap at 365 days to avoid extreme outliers
            days_since_scan = min(days_since_scan, 365)
        except Exception:
            days_since_scan = 90  # default: assume 3 months if unknown
    else:
        days_since_scan = 90  # no scan date = treat as 3 months stale

    # ── Feature 9: Critical unpatched flag ───────────────────────────────────

    # Feature 9: has_critical_unpatched
    # An asset with a Critical-severity CVE that has no patch yet
    # is one of the highest-risk situations possible
    has_critical_unpatched = int(any(
        v.get("severity", "").lower() == "critical"
        and not v.get("patch_available", True)
        for v in vulns
    ))

    # ── Feature 10-11: CVSS aggregates ───────────────────────────────────────

    # Feature 10: avg_cvss
    # Average severity across all CVEs
    avg_cvss = float(np.mean(cvss_scores)) if cvss_scores else 0.0

    # Feature 11: max_cvss (same as Feature 1 but kept separate
    # because models can weight them differently in combination)
    # Already computed above as max_cvss

    # ── Feature 12: High criticality flag ────────────────────────────────────

    # Feature 12: is_high_criticality
    # Quick boolean flag — the model can use this alongside the
    # encoded version for better pattern matching
    is_high_criticality = int(criticality_raw == "high")

    # ── Feature 13: Exploit + unpatched count ────────────────────────────────

    # Feature 13: exploit_unpatched_count
    # The most dangerous CVEs: active exploit AND no fix available
    # More of these = exponentially higher risk
    exploit_unpatched_count = sum(
        1 for v in vulns
        if v.get("exploit_available", False)
        and not v.get("patch_available", True)
    )

    # ── Return in FEATURE_NAMES order ────────────────────────────────────────
    return [
        max_cvss,               # 1
        exploit_available,      # 2
        patch_available,        # 3
        internet_exposed,       # 4
        criticality_encoded,    # 5
        environment_encoded,    # 6
        vuln_count,             # 7
        days_since_scan,        # 8
        has_critical_unpatched, # 9
        avg_cvss,               # 10
        max_cvss,               # 11  (intentionally same as 1)
        is_high_criticality,    # 12
        exploit_unpatched_count,# 13
    ]


# ─── BATCH EXTRACTION ────────────────────────────────────────────────────────

def extract_features_batch(assets: list) -> np.ndarray:
    """
    Extract features for a list of assets.
    Returns a 2D numpy array — one row per asset, one column per feature.
    This is the format sklearn models expect.

    Args:
        assets: list of asset dicts

    Returns:
        numpy array of shape (n_assets, 13)
    """
    return np.array([extract_features(a) for a in assets])


# ─── QUICK TEST ───────────────────────────────────────────────────────────────
# Run: python ml/features.py to test feature extraction

if __name__ == "__main__":
    # Create a mock asset to test with
    test_asset = {
        "asset_id":        "ASSET-TEST",
        "asset_type":      "Web Server",
        "environment":     "Production",
        "criticality":     "High",
        "internet_exposed": True,
        "last_scan_date":  "2026-01-01",
        "vulnerabilities": [
            {
                "cve":               "CVE-2021-23017",
                "severity":          "Critical",
                "cvss_score":        9.4,
                "exploit_available": True,
                "patch_available":   False,
            },
            {
                "cve":               "CVE-2023-21980",
                "severity":          "High",
                "cvss_score":        7.2,
                "exploit_available": False,
                "patch_available":   True,
            },
        ]
    }

    features = extract_features(test_asset)

    print("Feature extraction test:")
    print("=" * 45)
    for name, value in zip(FEATURE_NAMES, features):
        print(f"  {name:<28} = {value}")
    print("=" * 45)
    print(f"Total features: {len(features)}")
    print(f"Expected:       {len(FEATURE_NAMES)}")
    assert len(features) == len(FEATURE_NAMES), "Feature count mismatch!"
    print("✅ All features extracted correctly!")