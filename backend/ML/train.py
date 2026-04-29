import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
 
# Add backend folder to path so we can import db.py
# This is needed because train.py lives in backend/ml/
# but db.py lives in backend/
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
from sklearn.ensemble import RandomForestRegressor, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    mean_absolute_error,
    mean_squared_error,
    r2_score,
    accuracy_score,
    classification_report,
)
from sklearn.preprocessing import LabelEncoder
 
from db import SessionLocal, Asset, Vulnerability, Owner
from ML.features import extract_features, FEATURE_NAMES
 
# ─── PATHS ────────────────────────────────────────────────────────────────────
# Where to save trained models
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(MODELS_DIR, exist_ok=True)   # create models/ folder if it doesn't exist
 
SCORE_MODEL_PATH = os.path.join(MODELS_DIR, "risk_score_model.pkl")
LEVEL_MODEL_PATH = os.path.join(MODELS_DIR, "risk_level_model.pkl")
ENCODER_PATH     = os.path.join(MODELS_DIR, "label_encoder.pkl")
REPORT_PATH      = os.path.join(MODELS_DIR, "training_report.json")
 
 
# ─── STEP 1: LOAD DATA FROM POSTGRESQL ───────────────────────────────────────
 
def load_training_data():
    """
    Load all assets with their vulnerabilities and owners from PostgreSQL.
    Returns a list of asset dicts — same format as to_dict() in db.py.
    """
    print("📂 Loading training data from PostgreSQL...")
    db = SessionLocal()
 
    try:
        assets = db.query(Asset).all()
        print(f"   Found {len(assets)} assets in database")
 
        asset_dicts = []
        for asset in assets:
            # Skip assets with no risk_score — they can't be used as labels
            if asset.risk_score is None:
                print(f"   ⚠️  Skipping {asset.asset_id} — no risk_score")
                continue
            asset_dicts.append(asset.to_dict())
 
        print(f"   Using {len(asset_dicts)} assets for training")
        return asset_dicts
 
    finally:
        db.close()
 
 
# ─── STEP 2: PREPARE FEATURES AND LABELS ─────────────────────────────────────
 
def prepare_data(assets):
    """
    Convert asset dicts into:
      X → feature matrix (n_assets × 13)
      y_reg → risk score labels (floats)
      y_clf → risk level labels (strings → integers)
 
    Returns X, y_reg, y_clf, label_encoder
    """
    print("\n🔧 Preparing features and labels...")
 
    X      = []  # feature matrix
    y_reg  = []  # regression labels (risk_score floats)
    y_clf  = []  # classification labels (risk_level strings)
 
    for asset in assets:
        # Extract 13 numeric features for this asset
        features = extract_features(asset)
        X.append(features)
 
        # Regression label: the risk_score (0.0 to 100.0)
        y_reg.append(float(asset["risk_score"]))
 
        # Classification label: the risk_level string
        # We derive it from risk_score to stay consistent
        score = float(asset["risk_score"])
        if score >= 80:
            level = "Critical"
        elif score >= 60:
            level = "High"
        elif score >= 40:
            level = "Medium"
        else:
            level = "Low"
        y_clf.append(level)
 
    X     = np.array(X)
    y_reg = np.array(y_reg)
 
    # LabelEncoder converts string labels to integers
    # Critical→0, High→1, Low→2, Medium→3 (alphabetical by default)
    # The encoder remembers this mapping so we can reverse it later
    label_encoder = LabelEncoder()
    y_clf_encoded = label_encoder.fit_transform(y_clf)
 
    print(f"   Feature matrix shape : {X.shape}  (assets × features)")
    print(f"   Regression labels    : min={y_reg.min():.1f} max={y_reg.max():.1f} mean={y_reg.mean():.1f}")
    print(f"   Risk level counts    :")
    for level, count in zip(*np.unique(y_clf, return_counts=True)):
        print(f"      {level:<12}: {count} assets")
 
    return X, y_reg, y_clf_encoded, label_encoder
 
 
# ─── STEP 3: TRAIN BOTH MODELS ───────────────────────────────────────────────
 
def train_models(X, y_reg, y_clf):
    """
    Split data and train both models.
    Returns trained models and test splits for evaluation.
    """
    print("\n🔀 Splitting data: 80% train / 20% test...")
 
    # Split into train and test sets
    # random_state=42 means we get the same split every time
    # This makes results reproducible
    (X_train, X_test,
     y_reg_train, y_reg_test,
     y_clf_train, y_clf_test) = train_test_split(
        X, y_reg, y_clf,
        test_size=0.2,
        random_state=42
    )
 
    print(f"   Training set : {len(X_train)} assets")
    print(f"   Test set     : {len(X_test)} assets")
 
    # ── Model 1: Risk Score Regressor ─────────────────────────────────────────
    print("\n🌲 Training RandomForestRegressor (risk score)...")
 
    score_model = RandomForestRegressor(
        n_estimators=100,    # 100 decision trees
        max_depth=10,        # limit tree depth to prevent overfitting
        min_samples_split=2, # minimum samples to split a node
        min_samples_leaf=1,  # minimum samples at a leaf node
        random_state=42,     # reproducible results
        n_jobs=-1,           # use all CPU cores for speed
    )
 
    # fit() is where all the learning happens
    # The model reads X_train and y_reg_train and grows 100 trees
    score_model.fit(X_train, y_reg_train)
    print("   ✅ Regressor trained")
 
    # ── Model 2: Risk Level Classifier ────────────────────────────────────────
    print("\n🌲 Training RandomForestClassifier (risk level)...")
 
    level_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=2,
        min_samples_leaf=1,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",  # handle imbalanced classes
                                   # e.g. if we have 40 High but only 5 Critical
    )
 
    level_model.fit(X_train, y_clf_train)
    print("   ✅ Classifier trained")
 
    return (score_model, level_model,
            X_train, X_test,
            y_reg_train, y_reg_test,
            y_clf_train, y_clf_test)
 
 
# ─── STEP 4: EVALUATE BOTH MODELS ────────────────────────────────────────────
 
def evaluate_models(score_model, level_model, label_encoder,
                    X_test, y_reg_test, y_clf_test):
    """
    Evaluate both models on the test set.
    Returns a report dict with all metrics.
    """
    print("\n📊 Evaluating models on test set...")
 
    # ── Regression metrics ────────────────────────────────────────────────────
    y_reg_pred = score_model.predict(X_test)
 
    mae   = mean_absolute_error(y_reg_test, y_reg_pred)
    rmse  = np.sqrt(mean_squared_error(y_reg_test, y_reg_pred))
    r2    = r2_score(y_reg_test, y_reg_pred)
 
    print(f"\n   Regression (risk score):")
    print(f"   MAE   = {mae:.2f}   (avg prediction error in score points)")
    print(f"   RMSE  = {rmse:.2f}  (penalises large errors more)")
    print(f"   R²    = {r2:.4f} (1.0 = perfect, 0.0 = random)")
 
    # ── Classification metrics ────────────────────────────────────────────────
    y_clf_pred = level_model.predict(X_test)
    accuracy   = accuracy_score(y_clf_test, y_clf_pred)
 
    # Convert encoded labels back to strings for the report
    y_test_labels = label_encoder.inverse_transform(y_clf_test)
    y_pred_labels = label_encoder.inverse_transform(y_clf_pred)
 
    print(f"\n   Classification (risk level):")
    print(f"   Accuracy = {accuracy:.4f} ({accuracy*100:.1f}%)")
    print(f"\n   Per-class report:")
    print(classification_report(y_test_labels, y_pred_labels, zero_division=0))
 
    # ── Feature importance ────────────────────────────────────────────────────
    print("   Feature importance (from regressor):")
    importances = score_model.feature_importances_
    feat_importance = sorted(
        zip(FEATURE_NAMES, importances),
        key=lambda x: x[1],
        reverse=True
    )
    for feat, imp in feat_importance:
        bar = "█" * int(imp * 50)
        print(f"   {feat:<28} {bar} {imp:.4f}")
 
    # ── Sample predictions ────────────────────────────────────────────────────
    print(f"\n   Sample predictions vs actual:")
    print(f"   {'Actual Score':<15} {'Predicted Score':<18} {'Actual Level':<15} {'Predicted Level'}")
    print(f"   {'-'*70}")
    for i in range(min(5, len(X_test))):
        print(f"   {y_reg_test[i]:<15.1f} {y_reg_pred[i]:<18.1f} "
              f"{y_test_labels[i]:<15} {y_pred_labels[i]}")
 
    return {
        "trained_at":   datetime.now().isoformat(),
        "n_assets":     len(y_reg_test) + len(y_reg_test) * 4,
        "regression": {
            "mae":  round(float(mae),  4),
            "rmse": round(float(rmse), 4),
            "r2":   round(float(r2),   4),
        },
        "classification": {
            "accuracy": round(float(accuracy), 4),
        },
        "feature_importance": {
            feat: round(float(imp), 4)
            for feat, imp in feat_importance
        }
    }
 
 
# ─── STEP 5: SAVE MODELS ─────────────────────────────────────────────────────
 
def save_models(score_model, level_model, label_encoder, report):
    """Save trained models and report to disk."""
    print("\n💾 Saving models...")
 
    # joblib is better than pickle for sklearn models
    # It's faster and handles numpy arrays more efficiently
    joblib.dump(score_model,    SCORE_MODEL_PATH)
    joblib.dump(level_model,    LEVEL_MODEL_PATH)
    joblib.dump(label_encoder,  ENCODER_PATH)
 
    # Save the training report as JSON for reference
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)
 
    print(f"   ✅ Saved: {SCORE_MODEL_PATH}")
    print(f"   ✅ Saved: {LEVEL_MODEL_PATH}")
    print(f"   ✅ Saved: {ENCODER_PATH}")
    print(f"   ✅ Saved: {REPORT_PATH}")
 
 
# ─── MAIN ────────────────────────────────────────────────────────────────────
 
def main():
    print("🚀 Sentinel — ML Training Pipeline")
    print("=" * 50)
 
    # Step 1: Load data from PostgreSQL
    assets = load_training_data()
 
    if len(assets) < 10:
        print("❌ Not enough assets to train. Need at least 10.")
        return
 
    # Step 2: Prepare features and labels
    X, y_reg, y_clf, label_encoder = prepare_data(assets)
 
    # Step 3: Train both models
    (score_model, level_model,
     X_train, X_test,
     y_reg_train, y_reg_test,
     y_clf_train, y_clf_test) = train_models(X, y_reg, y_clf)
 
    # Step 4: Evaluate both models
    report = evaluate_models(
        score_model, level_model, label_encoder,
        X_test, y_reg_test, y_clf_test
    )
 
    # Step 5: Save models to disk
    save_models(score_model, level_model, label_encoder, report)
 
    print("\n" + "=" * 50)
    print("✅ Training complete!")
    print(f"   Risk Score MAE  : {report['regression']['mae']:.2f} points")
    print(f"   Risk Score R²   : {report['regression']['r2']:.4f}")
    print(f"   Level Accuracy  : {report['classification']['accuracy']*100:.1f}%")
    print("\nModels saved to backend/ml/models/")
    print("Run predict.py next to test scoring a new asset.")
 
 
if __name__ == "__main__":
    main()
 