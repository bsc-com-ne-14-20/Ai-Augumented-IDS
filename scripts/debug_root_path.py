"""
scripts/debug_root_path.py
==========================
Diagnostic script for the GET / false-positive.
Exposes raw feature values, z-scores, and model verdict.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.pipeline.http_feature_extractor import HTTPFeatureExtractor
import joblib
import pandas as pd

extractor = HTTPFeatureExtractor()

root_request = {
    "method": "GET",
    "url": "/",
    "path": "/",
    "query_string": "",
    "headers": {},
    "body": "",
    "response_code": 200,
    "content_length": 0,
    "timestamp": "2026-05-28T10:00:00",
}

features = extractor.extract_features(root_request)

scaler = joblib.load("data/final/scaler.pkl")
model  = joblib.load("models/rf_model.joblib")

FEATURE_COLUMNS = Path("data/final/feature_names.txt").read_text().strip().splitlines()

df        = pd.DataFrame([features])[FEATURE_COLUMNS]
scaled    = scaler.transform(df)
scaled_df = pd.DataFrame(scaled, columns=FEATURE_COLUMNS)
proba     = model.predict_proba(scaled)[0]   # model fitted on numpy array

print("=== RAW FEATURE VALUES FOR GET / ===")
for col in FEATURE_COLUMNS:
    print(f"  {col:<35} {features[col]:.4f}")

print(f"\n=== SCALED VALUES (z-scores) ===")
for col, val in zip(FEATURE_COLUMNS, scaled[0]):
    if abs(val) > 1.5:
        print(f"  {col:<35} {val:+.4f}  ← OUTLIER")
    else:
        print(f"  {col:<35} {val:+.4f}")

print(f"\n=== MODEL VERDICT ===")
print(f"  P(CLEAN)  = {proba[0]:.4f}")
print(f"  P(ANOMALY)= {proba[1]:.4f}")
print(f"  Verdict   = {'ANOMALY' if proba[1] > 0.5 else 'CLEAN'}")

# Top features pushing toward ANOMALY
importances = dict(zip(FEATURE_COLUMNS, model.feature_importances_))
top = sorted(importances.items(), key=lambda x: -x[1])[:10]
print(f"\n=== TOP 10 FEATURE IMPORTANCES ===")
for name, imp in top:
    z   = scaled_df[name].values[0]
    raw = features[name]
    print(f"  {name:<35} importance={imp:.4f}  raw={raw:.2f}  z={z:+.4f}")

print(f"\n=== SCALER DISTRIBUTION FOR KEY URL FEATURES ===")
cols_of_interest = {"url_length", "url_entropy", "url_path_depth", "url_num_dots"}
for i, col in enumerate(scaler.feature_names_in_):
    if col in cols_of_interest:
        mean = scaler.mean_[i]
        std  = scaler.scale_[i]
        raw  = features.get(col, 0.0)
        z    = (raw - mean) / std
        print(f"  {col:<30} mean={mean:.2f}  std={std:.2f}  "
              f"GET/ raw={raw:.1f}  z={z:+.2f}")
