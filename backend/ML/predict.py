"""
ml/predict.py
─────────────────────────────────────────────────────────────────────────────
Sentinel ML Prediction Script

Loads trained models from .pkl files and scores any asset in real time.

Used by:
  - main.py POST /assets → score new asset immediately after creation
  - main.py GET /analyze/{id} → include ML score in AI analysis

Usage:
    from ml.predict import score_asset
    result = score_asset(asset_dict)
    # Returns: {"risk_score": 94.3, "risk_level": "Critical", "confidence": 0.91}

Run directly to test:
    cd backend
    python ml/predict.py
─────────────────────────────────────────────────────────────────────────────
"""

import os
import sys
import joblib
import numpy as np

# Add backend/ and ml/ to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from features import extract_features, FEATURE_NAMES

# ─── MODEL PATHS ─────────────────────────────────────────────────────────────
MODELS_DIR       = os.path.join(os.path.dirname(__file__), "models")
SCORE_MODEL_PATH = os.path.join(MODELS_DIR, "risk_score_model.pkl")
LEVEL_MODEL_PATH = os.path.join(MODELS_DIR, "risk_level_model.pkl")
ENCODER_PATH     = os.path.join(MODELS_DIR, "label_encoder.pkl")

# ─── LOAD MODELS ONCE ────────────────────────────────────────────────────────
# We load models at module level so they're only loaded once
# when the server starts — not on every single request
# Loading a .pkl file takes ~0.5s, predicting takes ~1ms

_score_model   = None
_level_model   = None
_label_encoder = None


def _load_models():
    """
    Load models from disk into memory.
    Called automatically on first prediction.
    Uses global variables so models stay in memory between calls.
    """
    global _score_model, _level_model, _label_encoder

    if _score_model is not None:
        return  # already loaded — skip

    if not os.path.exists(SCORE_MODEL_PATH):
        raise FileNotFoundError(
            f"Model not found: {SCORE_MODEL_PATH}\n"
            "Run train.py first to generate the model files."
        )

    print("🔄 Loading ML models from disk...")
    _score_model   = joblib.load(SCORE_MODEL_PATH)
    _level_model   = joblib.load(LEVEL_MODEL_PATH)
    _label_encoder = joblib.load(ENCODER_PATH)
    print("✅ Models loaded successfully")


# ─── MAIN SCORING FUNCTION ────────────────────────────────────────────────────

def score_asset(asset: dict) -> dict:
    """
    Score a single asset using the trained ML models.

    Args:
        asset: dict with keys matching our schema
               (asset_id, criticality, environment,
                internet_exposed, vulnerabilities, etc.)

    Returns:
        dict with:
          risk_score    → float 0.0 to 100.0
          risk_level    → "Critical" / "High" / "Medium" / "Low"
          confidence    → float 0.0 to 1.0 (how sure the classifier is)
          top_features  → list of (feature_name, value) sorted by importance
          features_used → all 13 feature values for debugging
    """
    # Load models if not already in memory
    _load_models()

    # ── Step 1: Extract 13 features from the asset ────────────────────────────
    features = extract_features(asset)

    # Reshape to 2D array — sklearn always expects (n_samples, n_features)
    # We have 1 sample with 13 features → shape (1, 13)
    X = np.array(features).reshape(1, -1)

    # ── Step 2: Predict risk score (regression) ───────────────────────────────
    # predict() returns an array — we take the first element [0]
    raw_score = float(_score_model.predict(X)[0])

    # Clamp to valid range [0, 100]
    # The model might occasionally predict slightly outside this range
    risk_score = max(0.0, min(100.0, raw_score))

    # ── Step 3: Predict risk level (classification) ───────────────────────────
    # predict() returns the encoded integer class
    level_encoded = _level_model.predict(X)[0]

    # Convert integer back to string using the label encoder
    risk_level = _label_encoder.inverse_transform([level_encoded])[0]

    # ── Step 4: Get confidence score ─────────────────────────────────────────
    # predict_proba() returns probability for each class
    # e.g. [0.05, 0.03, 0.02, 0.90] → 90% confident it's Critical
    # We take the probability of the predicted class as the confidence
    proba       = _level_model.predict_proba(X)[0]
    confidence  = float(proba[level_encoded])

    # ── Step 5: Top contributing features ────────────────────────────────────
    # Feature importances tell us which features the model relies on most
    # We combine importance weight × actual value to rank contribution
    importances = _score_model.feature_importances_

    feature_contributions = []
    for name, value, importance in zip(FEATURE_NAMES, features, importances):
        feature_contributions.append({
            "feature":    name,
            "value":      round(float(value), 3),
            "importance": round(float(importance), 4),
        })

    # Sort by importance — most impactful features first
    top_features = sorted(
        feature_contributions,
        key=lambda x: x["importance"],
        reverse=True
    )[:5]  # return top 5

    return {
        "risk_score":    round(risk_score, 2),
        "risk_level":    risk_level,
        "confidence":    round(confidence, 4),
        "top_features":  top_features,
        "features_used": {
            name: round(float(val), 3)
            for name, val in zip(FEATURE_NAMES, features)
        }
    }


def score_assets_batch(assets: list) -> list:
    """
    Score multiple assets at once — more efficient than calling
    score_asset() in a loop for large batches.

    Args:
        assets: list of asset dicts

    Returns:
        list of result dicts in the same order as input
    """
    _load_models()

    if not assets:
        return []

    # Extract features for all assets at once
    X = np.array([extract_features(a) for a in assets])

    # Batch predict — much faster than one at a time
    raw_scores     = _score_model.predict(X)
    level_encoded  = _level_model.predict(X)
    probas         = _level_model.predict_proba(X)
    importances    = _score_model.feature_importances_

    results = []
    for i, asset in enumerate(assets):
        risk_score = max(0.0, min(100.0, float(raw_scores[i])))
        risk_level = _label_encoder.inverse_transform([level_encoded[i]])[0]
        confidence = float(probas[i][level_encoded[i]])

        results.append({
            "asset_id":   asset.get("asset_id", "unknown"),
            "risk_score": round(risk_score, 2),
            "risk_level": risk_level,
            "confidence": round(confidence, 4),
        })

    return results


# ─── QUICK TEST ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("🚀 Sentinel — ML Prediction Test")
    print("=" * 50)

    # Test asset 1 — should score HIGH/CRITICAL
    high_risk_asset = {
        "asset_id":        "TEST-HIGH",
        "asset_type":      "Web Server",
        "environment":     "Production",
        "criticality":     "High",
        "internet_exposed": True,
        "last_scan_date":  "2025-12-01",
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
                "exploit_available": True,
                "patch_available":   False,
            },
        ]
    }

    # Test asset 2 — should score LOW
    low_risk_asset = {
        "asset_id":        "TEST-LOW",
        "asset_type":      "Internal Tool",
        "environment":     "Development",
        "criticality":     "Low",
        "internet_exposed": False,
        "last_scan_date":  "2026-03-01",
        "vulnerabilities": [
            {
                "cve":               "CVE-2022-00001",
                "severity":          "Low",
                "cvss_score":        2.1,
                "exploit_available": False,
                "patch_available":   True,
            }
        ]
    }

    for asset in [high_risk_asset, low_risk_asset]:
        print(f"\n📋 Scoring: {asset['asset_id']}")
        print(f"   Environment : {asset['environment']}")
        print(f"   Criticality : {asset['criticality']}")
        print(f"   Exposed     : {asset['internet_exposed']}")
        print(f"   CVEs        : {len(asset['vulnerabilities'])}")

        result = score_asset(asset)

        print(f"\n   🎯 Risk Score : {result['risk_score']}")
        print(f"   🏷️  Risk Level : {result['risk_level']}")
        print(f"   📊 Confidence : {result['confidence']*100:.1f}%")
        print(f"\n   Top contributing features:")
        for feat in result["top_features"]:
            bar = "█" * int(feat["importance"] * 60)
            print(f"   {feat['feature']:<28} {bar} ({feat['value']})")
        print()

    # Test batch scoring
    print("\n🔄 Batch scoring test...")
    batch_results = score_assets_batch([high_risk_asset, low_risk_asset])
    print(f"   Batch results:")
    for r in batch_results:
        print(f"   {r['asset_id']:<15} → {r['risk_score']:5.1f} ({r['risk_level']})"
              f"  confidence: {r['confidence']*100:.1f}%")

    print("\n✅ predict.py working correctly!")