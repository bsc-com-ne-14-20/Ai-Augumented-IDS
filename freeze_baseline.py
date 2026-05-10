"""
freeze_baseline.py
==================
Phase 1 — Freeze current CSIC-trained models as baseline.
Tag: baseline_csic_only
Never overwrite these files.
"""

import joblib
import json
import shutil
import hashlib
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
from sklearn.metrics import (
    classification_report, confusion_matrix,
    f1_score, roc_auc_score, accuracy_score
)

ROOT         = Path("/home/rashid/Documents/FYP/Ai-Augumented-IDS")
BASELINE_DIR = ROOT / "baseline_csic_only"
BASELINE_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 60)
print("  Phase 1 — Freezing CSIC Baseline")
print("=" * 60)

# ── 1. Copy model files ───────────────────────────────────────────
print("\n[1/5] Saving model files...")
shutil.copy(ROOT / "models/rf_model.pkl",           BASELINE_DIR / "rf_model.pkl")
shutil.copy(ROOT / "models/rf_feature_names.pkl",   BASELINE_DIR / "rf_feature_names.pkl")
shutil.copy(ROOT / "models/xgb_model.pkl",          BASELINE_DIR / "xgb_model.pkl")
shutil.copy(ROOT / "models/xgb_feature_names.pkl",  BASELINE_DIR / "xgb_feature_names.pkl")
shutil.copy(ROOT / "models/xgb_label_mapping.pkl",  BASELINE_DIR / "xgb_label_mapping.pkl")
shutil.copy(ROOT / "data/final/scaler.pkl",         BASELINE_DIR / "scaler.pkl")
print("  ✓ All model files copied")

# ── 2. Record train/test split hashes ────────────────────────────
print("\n[2/5] Recording dataset hashes...")
def file_hash(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()

hashes = {
    "train_csv": file_hash(ROOT / "data/final/train.csv"),
    "test_csv":  file_hash(ROOT / "data/final/test.csv"),
    "scaler":    file_hash(ROOT / "data/final/scaler.pkl"),
}
print(f"  ✓ train.csv  : {hashes['train_csv']}")
print(f"  ✓ test.csv   : {hashes['test_csv']}")
print(f"  ✓ scaler.pkl : {hashes['scaler']}")

# ── 3. Evaluate RF on test set ────────────────────────────────────
print("\n[3/5] Evaluating RF on CSIC test set...")
rf           = joblib.load(BASELINE_DIR / "rf_model.pkl")
rf_features  = joblib.load(BASELINE_DIR / "rf_feature_names.pkl")
test_df      = pd.read_csv(ROOT / "data/final/test.csv")

X_test_rf = test_df[rf_features]
y_test    = test_df["label"].astype(int)

rf_proba  = rf.predict_proba(X_test_rf)[:, 1]
rf_pred   = (rf_proba >= 0.5).astype(int)

rf_metrics = {
    "threshold":  0.5,
    "accuracy":   round(accuracy_score(y_test, rf_pred), 4),
    "f1":         round(f1_score(y_test, rf_pred), 4),
    "roc_auc":    round(roc_auc_score(y_test, rf_proba), 4),
    "report":     classification_report(y_test, rf_pred, output_dict=True),
    "confusion_matrix": confusion_matrix(y_test, rf_pred).tolist(),
}
print(f"  ✓ Accuracy : {rf_metrics['accuracy']}")
print(f"  ✓ F1       : {rf_metrics['f1']}")
print(f"  ✓ ROC-AUC  : {rf_metrics['roc_auc']}")
print(f"  ✓ Confusion matrix:")
cm = rf_metrics["confusion_matrix"]
print(f"      TN={cm[0][0]}  FP={cm[0][1]}")
print(f"      FN={cm[1][0]}  TP={cm[1][1]}")

# ── 4. Evaluate XGBoost on attacks-only test set ──────────────────
print("\n[4/5] Evaluating XGBoost on attacks-only test set...")
import xgboost as xgb

xgb_model      = joblib.load(BASELINE_DIR / "xgb_model.pkl")
xgb_features   = joblib.load(BASELINE_DIR / "xgb_feature_names.pkl")
label_mapping  = joblib.load(BASELINE_DIR / "xgb_label_mapping.pkl")
reverse_mapping = {v: k for k, v in label_mapping.items()}

attacks_test = pd.read_csv(ROOT / "test_attacks_only.csv")

def get_attack_type(row):
    if row.get("query_has_traversal", 0) > 0 or row.get("body_has_traversal", 0) > 0:
        return "PATH_TRAVERSAL"
    elif row.get("query_has_sqli", 0) > 0 or row.get("body_has_sqli", 0) > 0:
        return "SQLI"
    elif row.get("query_has_xss", 0) > 0 or row.get("body_has_xss", 0) > 0:
        return "XSS"
    return "OTHER"

attacks_test["attack_type"] = attacks_test.apply(get_attack_type, axis=1)

for col in xgb_features:
    if col not in attacks_test.columns:
        attacks_test[col] = 0.0

X_xgb    = attacks_test[xgb_features]
y_xgb    = attacks_test["attack_type"].map(label_mapping)
xgb_pred = xgb_model.predict(X_xgb)
xgb_pred_labels = [reverse_mapping[p] for p in xgb_pred]

xgb_metrics = {
    "accuracy": round(accuracy_score(y_xgb, xgb_pred), 4),
    "report":   classification_report(attacks_test["attack_type"], xgb_pred_labels, output_dict=True),
    "confusion_matrix": confusion_matrix(
        attacks_test["attack_type"], xgb_pred_labels,
        labels=list(label_mapping.keys())
    ).tolist(),
}
print(f"  ✓ Accuracy : {xgb_metrics['accuracy']}")
print(f"  ✓ Report saved to metadata")

# ── 5. Save metadata ──────────────────────────────────────────────
print("\n[5/5] Saving baseline metadata...")
metadata = {
    "tag":          "baseline_csic_only",
    "frozen_at":    datetime.now().isoformat(),
    "dataset":      "CSIC 2010",
    "train_samples": 48852,
    "test_samples":  12213,
    "normal_samples": 28800,
    "attack_samples": 20052,
    "features":      53,
    "dataset_hashes": hashes,
    "rf": {
        "model":      "RandomForestClassifier",
        "n_estimators": 300,
        "class_weight": "balanced",
        "metrics":    rf_metrics,
    },
    "xgb": {
        "model":      "XGBClassifier",
        "n_estimators": 400,
        "objective":  "multi:softprob",
        "num_class":  4,
        "metrics":    xgb_metrics,
    },
    "known_limitations": [
        "Trained on single e-commerce application (CSIC 2010)",
        "Requires JSESSIONID cookies and Connection:close headers for accurate normal classification",
        "cookie_length feature has zero variance — causes scaling issues at inference",
        "High false positive rate on out-of-domain traffic (general web apps)",
        "82% class imbalance in XGBoost (OTHER vs minority attack types)",
    ],
    "evaluation_domains": {
        "in_domain":   "CSIC-like traffic — expected high performance",
        "near_domain": "Similar web apps (DVWA, Mutillidae) — expect degradation",
        "out_of_domain": "Modern apps (Juice Shop, real traffic) — expect failure",
    }
}

with open(BASELINE_DIR / "metadata.json", "w") as f:
    json.dump(metadata, f, indent=2)

print(f"  ✓ metadata.json saved")

print("\n" + "=" * 60)
print("  ✓ Baseline frozen successfully!")
print(f"  ✓ Location: {BASELINE_DIR}")
print("  ⚠  DO NOT overwrite these files — comparison point only")
print("=" * 60)
