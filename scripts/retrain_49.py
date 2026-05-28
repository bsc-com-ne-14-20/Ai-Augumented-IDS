#!/usr/bin/env python3
"""
scripts/retrain_49.py
=====================
Retrain the RandomForestClassifier on 49 features, dropping the four
CSIC-specific bias features that cause false positives on real browser traffic.

DROPPED FEATURES (near-zero variance in production, constant in CSIC benign):
  - cookie_is_present    (CSIC always has JSESSIONID; real first-visit has none)
  - cookie_length        (always ~43 chars in CSIC benign; 0 in real first-visit)
  - connection_is_close  (CSIC always sends Connection: close; browsers use keep-alive)
  - connection_keep_alive (inverse of above; same domain-shift problem)

Usage:
    python scripts/retrain_49.py

Artefacts produced:
    data/final/scaler_49.pkl       — new StandardScaler fitted on 49 features
    models/rf_model_49.joblib      — new RandomForestClassifier (49 features)

Artefacts renamed (originals preserved):
    data/final/scaler.pkl          → data/final/scaler_53.pkl  (if not already renamed)

SRS Requirements: FE-001 (updated to 49), ML-007 (graceful degradation preserved)
"""

import sys
import logging
import shutil
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    roc_auc_score,
    accuracy_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# ── Repo root on sys.path ─────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
PROCESSED_DATA_PATH = REPO_ROOT / "data" / "processed" / "csic_cleaned.csv"
SCALER_ORIG_PATH    = REPO_ROOT / "data" / "final" / "scaler.pkl"
SCALER_53_PATH      = REPO_ROOT / "data" / "final" / "scaler_53.pkl"
SCALER_49_PATH      = REPO_ROOT / "data" / "final" / "scaler_49.pkl"
MODEL_49_PATH       = REPO_ROOT / "models" / "rf_model_49.joblib"
OLD_MODEL_PATH      = REPO_ROOT / "models" / "rf_model.joblib"

# ── Thresholds (SRS §7.3) ─────────────────────────────────────────────────────
MIN_ACCURACY   = 0.88
MIN_ROC_AUC    = 0.95
MIN_PRECISION_CLEAN = 0.85

# ── Features to drop ─────────────────────────────────────────────────────────
DROPPED = [
    "cookie_is_present",
    "cookie_length",
    "connection_is_close",
    "connection_keep_alive",
]

# ── Hyperparameters (identical to original train1.py) ─────────────────────────
RF_PARAMS = dict(
    n_estimators=300,
    max_depth=None,
    min_samples_split=2,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)

# Same split as original training script (train1.py: test_size=0.2, stratify=y, random_state=42)
SPLIT_PARAMS = dict(test_size=0.2, stratify=None, random_state=42)


def generate_synthetic_benign() -> pd.DataFrame:
    """
    Generate synthetic benign HTTP requests covering real browser traffic patterns
    that are absent from the CSIC 2010 dataset (short URLs, keep-alive connections,
    no cookies on first visit, etc.).

    These samples teach the model that simple/short requests are also benign,
    preventing false positives on real browser traffic. Short/root paths get
    more samples to overcome the CSIC distribution bias.

    Returns
    -------
    pd.DataFrame with 49 feature columns and a 'label' column (all 0 = benign).
    """
    from backend.pipeline.http_feature_extractor import HTTPFeatureExtractor
    import random

    rng = random.Random(42)
    extractor = HTTPFeatureExtractor(verbose=False)

    # URL templates covering common real-browser patterns
    # Short/simple URLs get more samples to overcome CSIC distribution bias
    url_templates_weighted = [
        # Root and very short paths — highest weight (most underrepresented in CSIC)
        ("/", 3000),
        ("/index.html", 2000),
        ("/home", 2000),
        ("/about", 1000),
        ("/contact", 1000),
        ("/login", 1000),
        ("/logout", 500),
        ("/register", 500),
        ("/dashboard", 500),
        ("/profile", 500),
        ("/settings", 500),
        ("/search", 500),
        ("/help", 500),
        ("/faq", 500),
        ("/terms", 500),
        ("/privacy", 500),
        # API paths
        ("/api/health", 500),
        ("/api/status", 500),
        ("/api/v1/users", 500),
        ("/api/v1/items", 500),
        # Static assets
        ("/static/main.css", 300),
        ("/static/app.js", 300),
        ("/static/logo.png", 300),
        ("/favicon.ico", 300),
        ("/robots.txt", 300),
        ("/sitemap.xml", 300),
        # App paths
        ("/products", 300),
        ("/products/list", 300),
        ("/cart", 300),
        ("/checkout", 300),
        ("/news", 300),
        ("/blog", 300),
        ("/articles", 300),
        ("/gallery", 300),
    ]

    methods_weights = [("GET", 0.75), ("POST", 0.20), ("PUT", 0.05)]
    content_types = ["application/json", "application/x-www-form-urlencoded", "none"]
    query_templates = [
        "", "page=1", "page=2&limit=20", "q=search+term", "id=42",
        "sort=name&order=asc", "filter=active", "lang=en",
    ]

    records = []
    for url, n_samples in url_templates_weighted:
        for _ in range(n_samples):
            method = rng.choices(
                [m for m, _ in methods_weights],
                weights=[w for _, w in methods_weights],
            )[0]
            query = rng.choice(query_templates)
            ct = rng.choice(content_types)
            body = ""
            if method == "POST":
                body = rng.choice(["name=test&value=1", "data=hello", ""])
            headers = {}
            if ct != "none":
                headers["content-type"] = ct

            http_request = {
                "url": url,
                "method": method,
                "query_string": query,
                "headers": headers,
                "body": body,
                "content_length": len(body),
            }
            try:
                features = extractor.extract_features(http_request)
                records.append(features)
            except Exception:
                pass

    df = pd.DataFrame(records)
    df["label"] = 0
    log.info(
        "Generated %d synthetic benign samples covering %d URL templates",
        len(df), len(url_templates_weighted),
    )
    return df


def build_feature_matrix_from_raw(df: pd.DataFrame) -> pd.DataFrame:
    """
    Run the HTTPFeatureExtractor over every row of the processed CSIC CSV
    to produce the feature matrix.

    The processed CSV (data/processed/csic_cleaned.csv) has columns:
      Method, cookie, content-type, connection, content_length, content,
      label, URL

    We map these to the dict format expected by extract_features().
    """
    from backend.pipeline.http_feature_extractor import HTTPFeatureExtractor

    extractor = HTTPFeatureExtractor(verbose=False)
    records = []

    log.info("Extracting features from %d rows …", len(df))

    for i, row in df.iterrows():
        url_raw = str(row.get("URL", "/") or "/")
        # Strip the HTTP version suffix if present (e.g. "http://host/path http/1.1")
        if " " in url_raw:
            url_raw = url_raw.split(" ")[0]

        # Parse path + query from full URL
        from urllib.parse import urlparse, urlunparse
        try:
            parsed = urlparse(url_raw)
            path = parsed.path or "/"
            query = parsed.query or ""
        except Exception:
            path = "/"
            query = ""

        method = str(row.get("Method", "GET") or "GET").upper()
        body = str(row.get("content", "") or "")
        if body == "nan":
            body = ""

        content_length_raw = row.get("content_length", 0)
        try:
            content_length = int(float(content_length_raw)) if not pd.isna(content_length_raw) else 0
        except (ValueError, TypeError):
            content_length = 0

        headers = {
            "cookie":       str(row.get("cookie", "") or ""),
            "content-type": str(row.get("content-type", "") or ""),
            "connection":   str(row.get("connection", "") or ""),
        }

        http_request = {
            "url":            path,
            "method":         method,
            "query_string":   query,
            "body":           body,
            "headers":        headers,
            "content_length": content_length,
        }

        try:
            features = extractor.extract_features(http_request)
            records.append(features)
        except Exception as exc:
            log.warning("Row %d: feature extraction failed (%s) — skipping", i, exc)

        if (i + 1) % 10000 == 0:
            log.info("  … processed %d / %d rows", i + 1, len(df))

    feature_df = pd.DataFrame(records)
    log.info("Feature matrix shape: %s", feature_df.shape)
    return feature_df


def main() -> None:
    log.info("=" * 70)
    log.info("AA-IDS 49-Feature Retraining Script")
    log.info("=" * 70)

    # ── STEP 2a: Load CSIC data ───────────────────────────────────────────────
    log.info("STEP 2a — Loading CSIC data from %s", PROCESSED_DATA_PATH)
    if not PROCESSED_DATA_PATH.exists():
        raise FileNotFoundError(f"Processed data not found: {PROCESSED_DATA_PATH}")

    raw_df = pd.read_csv(PROCESSED_DATA_PATH)
    log.info("Loaded %d rows, %d columns", *raw_df.shape)
    log.info("Label distribution:\n%s", raw_df["label"].value_counts().to_string())

    # ── STEP 2b: Define 49-feature list ──────────────────────────────────────
    log.info("STEP 2b — Defining 49-feature list")
    # The extractor may already be updated to 49 features (if this script is
    # re-run after Step 4). We derive the 49-feature list from the extractor
    # and verify the four dropped features are absent.
    from backend.pipeline.http_feature_extractor import HTTPFeatureExtractor
    extractor_cols = list(HTTPFeatureExtractor.FEATURE_COLUMNS)
    log.info("HTTPFeatureExtractor.FEATURE_COLUMNS has %d features", len(extractor_cols))

    if len(extractor_cols) == 53:
        # Extractor not yet updated — assert dropped features present, then remove
        for feat in DROPPED:
            assert feat in extractor_cols, (
                f"DROPPED feature '{feat}' not found in FEATURE_COLUMNS."
            )
        log.info("✓ All 4 dropped features confirmed present — removing them")
        features_49 = [f for f in extractor_cols if f not in DROPPED]
    elif len(extractor_cols) == 49:
        # Extractor already updated — verify dropped features are absent
        still_present = [f for f in DROPPED if f in extractor_cols]
        assert not still_present, (
            f"Dropped features still in FEATURE_COLUMNS: {still_present}"
        )
        log.info("✓ Extractor already updated to 49 features — dropped features absent")
        features_49 = extractor_cols
    else:
        raise ValueError(
            f"Unexpected FEATURE_COLUMNS length: {len(extractor_cols)} (expected 53 or 49)"
        )

    assert len(features_49) == 49, f"Expected 49 features, got {len(features_49)}"
    log.info("49-feature list confirmed: %s … (first 5)", features_49[:5])

    # ── Build feature matrix via HTTPFeatureExtractor ─────────────────────────
    log.info("Building feature matrix via HTTPFeatureExtractor …")
    X_all_53 = build_feature_matrix_from_raw(raw_df)
    y_csic = raw_df["label"].astype(int).values[: len(X_all_53)]

    # Verify all 49 columns are present (extractor already drops the 4 bias features)
    missing_cols = [c for c in features_49 if c not in X_all_53.columns]
    if missing_cols:
        raise ValueError(f"Feature matrix missing columns: {missing_cols}")

    # ── Augment with synthetic benign samples ─────────────────────────────────
    log.info("Augmenting with synthetic benign samples (real browser traffic patterns) …")
    synth_df = generate_synthetic_benign()
    synth_X = synth_df[features_49]
    synth_y = synth_df["label"].astype(int)

    log.info("CSIC samples: %d  |  Synthetic benign: %d", len(X_all_53), len(synth_X))

    # Combine CSIC + synthetic
    X_csic = X_all_53[features_49]
    X_combined = pd.concat([X_csic, synth_X], ignore_index=True)
    y_combined = pd.concat(
        [pd.Series(y_csic, name="label"), synth_y], ignore_index=True
    )

    log.info(
        "Combined dataset: %d rows  |  Attack ratio: %.4f",
        len(X_combined), y_combined.mean(),
    )

    # ── STEP 2c: Build X (49 cols) and y ─────────────────────────────────────
    log.info("STEP 2c — Building X (49 features) and y")
    X = X_combined
    y = y_combined

    log.info("X shape: %s  |  Attack ratio: %.4f", X.shape, y.mean())

    # Same split as original (train1.py: test_size=0.2, stratify=y, random_state=42)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        stratify=y,
        random_state=42,
    )
    log.info("Train: %s  |  Test: %s", X_train.shape, X_test.shape)
    log.info("Attack ratio — train: %.4f  test: %.4f", y_train.mean(), y_test.mean())

    # ── STEP 2d: Fit new scaler on X_train only ───────────────────────────────
    log.info("STEP 2d — Fitting StandardScaler on X_train (49 features)")
    scaler_49 = StandardScaler()
    scaler_49.fit(X_train)
    assert scaler_49.n_features_in_ == 49, (
        f"Scaler fitted on {scaler_49.n_features_in_} features, expected 49"
    )

    # Rename original scaler_53 if it hasn't been renamed yet
    if SCALER_ORIG_PATH.exists() and not SCALER_53_PATH.exists():
        shutil.copy2(SCALER_ORIG_PATH, SCALER_53_PATH)
        log.info("Original scaler backed up: %s → %s", SCALER_ORIG_PATH, SCALER_53_PATH)
    elif SCALER_53_PATH.exists():
        log.info("scaler_53.pkl already exists — skipping backup")

    # Save new scaler
    SCALER_49_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler_49, SCALER_49_PATH)
    log.info("New scaler saved → %s", SCALER_49_PATH)

    # ── STEP 2e: Scale features ───────────────────────────────────────────────
    log.info("STEP 2e — Scaling features")
    X_train_scaled = scaler_49.transform(X_train)
    X_test_scaled  = scaler_49.transform(X_test)

    # ── STEP 2f: Train RandomForest ───────────────────────────────────────────
    log.info("STEP 2f — Training RandomForestClassifier (same hyperparameters as original)")
    log.info("  Params: %s", RF_PARAMS)
    rf = RandomForestClassifier(**RF_PARAMS)
    rf.fit(X_train_scaled, y_train)
    log.info("Training complete. n_features_in_: %d", rf.n_features_in_)

    # ── STEP 2g: Evaluate and assert thresholds ───────────────────────────────
    log.info("STEP 2g — Evaluating on test set")
    y_pred = rf.predict(X_test_scaled)
    y_prob = rf.predict_proba(X_test_scaled)[:, 1]

    accuracy = accuracy_score(y_test, y_pred)
    roc_auc  = roc_auc_score(y_test, y_prob)

    report = classification_report(y_test, y_pred, target_names=["CLEAN", "ATTACK"], digits=4, output_dict=True)
    precision_clean = report["CLEAN"]["precision"]

    print("\n" + "=" * 70)
    print("EVALUATION RESULTS (49-feature model)")
    print("=" * 70)
    print(classification_report(y_test, y_pred, target_names=["CLEAN", "ATTACK"], digits=4))
    print(f"Accuracy:          {accuracy:.4f}  (threshold ≥ {MIN_ACCURACY})")
    print(f"ROC-AUC:           {roc_auc:.4f}  (threshold ≥ {MIN_ROC_AUC})")
    print(f"Precision (CLEAN): {precision_clean:.4f}  (threshold ≥ {MIN_PRECISION_CLEAN})")
    print("=" * 70)

    # Assert thresholds — do NOT save if any fail
    failed = False
    if accuracy < MIN_ACCURACY:
        log.error("FAIL: Accuracy %.4f < %.2f", accuracy, MIN_ACCURACY)
        failed = True
    if roc_auc < MIN_ROC_AUC:
        log.error("FAIL: ROC-AUC %.4f < %.2f", roc_auc, MIN_ROC_AUC)
        failed = True
    if precision_clean < MIN_PRECISION_CLEAN:
        log.error("FAIL: Precision(CLEAN) %.4f < %.2f", precision_clean, MIN_PRECISION_CLEAN)
        failed = True

    if failed:
        print("\n❌ THRESHOLD ASSERTIONS FAILED — artefacts NOT saved.")
        print("Full classification report printed above.")
        sys.exit(1)

    log.info("✓ All threshold assertions passed")

    # ── STEP 2h: Save new model ───────────────────────────────────────────────
    log.info("STEP 2h — Saving new model to %s", MODEL_49_PATH)
    MODEL_49_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(rf, MODEL_49_PATH)
    log.info("New model saved → %s", MODEL_49_PATH)

    # ── STEP 2i: Feature importance comparison ────────────────────────────────
    log.info("STEP 2i — Feature importance comparison (top 15)")

    # New model importances
    new_importances = pd.Series(rf.feature_importances_, index=features_49)
    top15_new = new_importances.nlargest(15)

    # Old model importances (if available)
    print("\n" + "=" * 70)
    print("FEATURE IMPORTANCE COMPARISON")
    print("=" * 70)

    if OLD_MODEL_PATH.exists():
        try:
            old_model = joblib.load(OLD_MODEL_PATH)
            old_feature_names_path = REPO_ROOT / "data" / "final" / "feature_names.txt"
            if old_feature_names_path.exists():
                old_features = old_feature_names_path.read_text().strip().splitlines()
            else:
                old_features = all_53
            old_importances = pd.Series(old_model.feature_importances_, index=old_features)
            top15_old = old_importances.nlargest(15)

            print(f"\n{'Rank':<5} {'53-feature model':<35} {'Importance':>10}  |  {'49-feature model':<35} {'Importance':>10}")
            print("-" * 100)
            for rank, ((old_feat, old_imp), (new_feat, new_imp)) in enumerate(
                zip(top15_old.items(), top15_new.items()), start=1
            ):
                print(f"{rank:<5} {old_feat:<35} {old_imp:>10.4f}  |  {new_feat:<35} {new_imp:>10.4f}")

            # Check dropped features were not top discriminators
            dropped_in_old_top15 = [f for f in DROPPED if f in top15_old.index]
            if dropped_in_old_top15:
                log.warning(
                    "Note: dropped features appeared in old top-15: %s "
                    "(this is expected — they were biased benign indicators)",
                    dropped_in_old_top15,
                )
            else:
                log.info("✓ None of the dropped features were in the old top-15 discriminators")
        except Exception as exc:
            log.warning("Could not load old model for comparison: %s", exc)
            print("\nNew model top-15 feature importances:")
            for feat, imp in top15_new.items():
                print(f"  {feat:<40} {imp:.4f}")
    else:
        print("\nNew model top-15 feature importances (old model not found for comparison):")
        for feat, imp in top15_new.items():
            print(f"  {feat:<40} {imp:.4f}")

    print("=" * 70)

    print("\n✅ Retraining complete.")
    print(f"   New scaler  → {SCALER_49_PATH}")
    print(f"   New model   → {MODEL_49_PATH}")
    print("\nNext: run  python scripts/promote_49.py  to promote artefacts to live paths.")


if __name__ == "__main__":
    main()
