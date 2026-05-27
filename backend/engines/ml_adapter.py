"""
==============================================================================
FILE: backend/engines/ml_adapter.py
COMPONENT: ML Detection Engine — Stacked Ensemble (RF + XGBoost)
SRS REQUIREMENTS: ML-001, ML-002, ML-003, ML-004, ML-005, ML-006, ML-007
OWNER: Rashid Sidreck
==============================================================================

WHAT THIS FILE DOES:
    Implements the stacked ensemble ML classifier for the AA-IDS pipeline.
    Loads pre-trained Random Forest (layer 1, binary gate) and XGBoost
    (layer 2, attack-type classifier) at module import time and exposes
    adapt_ml_model() used by the orchestrator.

PIPELINE POSITION:
    Stage 5 of 8 — invoked by orchestrator.run_pipeline() only when the
    rule engine returns no match (RE-004). Receives the 53-feature dict from
    HTTPFeatureExtractor.extract_features(). Returns a detection result dict
    consumed by sockets/events.py (persist_alert + emit_alert).

HOW IT IS IMPLEMENTED:
    Layer 1 — Random Forest (binary gate, SRS ML-002):
        Trained on 53 features from FEATURE_SCHEMA.json.
        classes_ = [0, 1] where 0 = normal, 1 = attack.
        Produces P(attack) as the primary confidence signal.
        If P(attack) < ML_CONFIDENCE_THRESHOLD → verdict CLEAN.
        If P(attack) >= threshold → XGBoost runs to classify attack type.

    Layer 2 — XGBoost (attack-type classifier, SRS ML-003):
        Trained on 58 features: the 53 base features PLUS 5 engineered
        ratio/flag features computed from the base features at runtime.
        classes_ = [0, 1, 2, 3] where:
            0 = OTHER          (generic/unknown attack)
            1 = SQLI           (SQL injection)
            2 = XSS            (cross-site scripting)
            3 = PATH_TRAVERSAL (directory traversal)
        XGBoost has NO normal class — it is only called when RF says attack.
        Its predicted class label is the authoritative attack_type (SRS ML-003).

    IMPORTANT: XGBoost was trained on attack samples only. Running it on
    clean traffic would always return an attack type, which is incorrect.
    RF is the authoritative is_attack decision maker. XGBoost is the
    authoritative attack_type decision maker.

INPUTS:
    feature_vector: dict — 53-key dict from HTTPFeatureExtractor.extract_features().
                    Keys must match FEATURE_SCHEMA.json exactly.

OUTPUTS:
    dict — detection result with keys:
        verdict        : "ANOMALY" | "CLEAN"
        is_attack      : bool
        detection_source: "ml_engine" | "ml_unavailable"
        attack_type    : str | None  — XGB class label or None
        confidence     : float       — RF P(attack)
        xgb_confidence : float | None — XGB predicted-class probability
        severity       : str | None
        matched_rule   : None        — always None for ML engine

DEPENDENCIES (internal):
    backend.config — ML_MODEL_PATH (RF), XGB_MODEL_PATH (XGB), ML_SCALER_PATH

INTEGRATION NOTES:
    - Models are loaded once at module import time (not per-request).
    - adapt_ml_model() is called only from backend/pipeline/orchestrator.py.
    - is_ml_model_loaded() is called from backend/api/routes.py (health endpoint).
    - The 5 engineered features for XGBoost are computed inside this module
      from the 53 base features — the feature extractor is NOT modified.
    - XGB_LABEL_MAP maps integer class indices to human-readable attack type strings.
==============================================================================
"""

import logging
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from backend.config import get_config

log = logging.getLogger(__name__)

# ── XGBoost label mapping ─────────────────────────────────────────────────────
# Maps XGBoost integer class index → attack type string used in API responses.
# Derived from the label_mapping in pipeline/ml_model/retrain_xgb.py:
#   {'OTHER': 0, 'SQLI': 1, 'XSS': 2, 'PATH_TRAVERSAL': 3}
# Stored here as the reverse mapping (index → label).
XGB_LABEL_MAP: dict[int, str] = {
    0: "OTHER",
    1: "SQLI",
    2: "XSS",
    3: "PATH_TRAVERSAL",
}

# ── Feature column order ──────────────────────────────────────────────────────
# FEATURE_SCHEMA.json defines the 53 base features in the exact order the RF
# model was trained on. XGBoost uses these 53 PLUS 5 engineered features.
config = get_config()
_feature_names_path = Path(config.ML_FEATURE_NAMES_PATH)
if not _feature_names_path.exists():
    raise RuntimeError(
        f"Feature names file not found: {_feature_names_path}. "
        "Ensure data/final/feature_names.txt exists in the repo."
    )
FEATURE_COLUMNS: list[str] = _feature_names_path.read_text().strip().splitlines()

# ── Scaler loading (once at import time) ──────────────────────────────────────
_scaler_path = Path(config.ML_SCALER_PATH)
SCALER = None  # noqa: N816

if not _scaler_path.exists():
    log.warning(
        "ML scaler not found at: %s - ML model will not be available. "
        "Ensure data/final/scaler.pkl exists in the repo.",
        _scaler_path
    )
else:
    try:
        SCALER = joblib.load(_scaler_path)
        log.info("ML scaler loaded from %s", _scaler_path)
    except Exception as exc:
        log.error("Failed to load ML scaler: %s", exc)
        SCALER = None

# ── Random Forest loading (layer 1, binary gate) ──────────────────────────────
_rf_path = Path(config.ML_MODEL_PATH)
MODEL = None  # noqa: N816  — kept as MODEL for backward compatibility

if not _rf_path.exists():
    log.warning(
        "RF model not found at: %s - running in rule-engine-only mode. "
        "Ensure models/rf_combined.pkl exists.",
        _rf_path
    )
else:
    try:
        MODEL = joblib.load(_rf_path)
        log.info(
            "RF model (layer 1) loaded from %s  |  estimators=%d  |  classes=%s",
            _rf_path,
            getattr(MODEL, "n_estimators", "?"),
            getattr(MODEL, "classes_", "?"),
        )
    except Exception as exc:
        log.error("Failed to load RF model: %s", exc)
        MODEL = None

# ── XGBoost loading (layer 2, attack-type classifier) ─────────────────────────
_xgb_path = Path(config.XGB_MODEL_PATH)
XGB_MODEL = None  # noqa: N816

if not _xgb_path.exists():
    log.warning(
        "XGBoost model not found at: %s - attack-type classification unavailable. "
        "Ensure models/xgb_model.pkl exists.",
        _xgb_path
    )
else:
    try:
        XGB_MODEL = joblib.load(_xgb_path)
        log.info(
            "XGBoost model (layer 2) loaded from %s  |  n_features=%d  |  classes=%s  |  objective=%s",
            _xgb_path,
            getattr(XGB_MODEL, "n_features_in_", "?"),
            getattr(XGB_MODEL, "classes_", "?"),
            getattr(XGB_MODEL, "objective", "?"),
        )
        # Validate XGB feature names match what we expect
        if hasattr(XGB_MODEL, "feature_names_in_"):
            xgb_feat_count = len(XGB_MODEL.feature_names_in_)
            log.info("XGBoost expects %d features (53 base + %d engineered)",
                     xgb_feat_count, xgb_feat_count - len(FEATURE_COLUMNS))
    except Exception as exc:
        log.error("Failed to load XGBoost model: %s", exc)
        XGB_MODEL = None

# Confidence threshold below which an ML flag is suppressed (RF P(attack))
_THRESHOLD: float = config.ML_CONFIDENCE_THRESHOLD


def _compute_xgb_features(raw_row: np.ndarray, feature_vector: dict[str, Any]) -> np.ndarray:
    """
    Compute the 5 engineered features XGBoost was trained on and append them
    to the 53-feature base vector.

    XGBoost was trained with these additional ratio/flag features derived from
    the base 53 features (see pipeline/ml_model/retrain_xgb.py):
        special_ratio_query = query_num_special / (query_length + 1e-5)
        special_ratio_body  = body_num_special  / (body_length  + 1e-5)
        percent_ratio_query = query_num_percent / (query_length + 1e-5)
        dots_ratio_url      = url_num_dots      / (url_length   + 1e-5)
        semicolon_ratio     = body_num_semicolons / (body_length + 1e-5)
        quotes_ratio        = body_num_quotes   / (body_length  + 1e-5)
        entropy_diff        = query_entropy - url_entropy
        high_query_entropy  = int(query_entropy > 4.0)
        high_body_entropy   = int(body_entropy  > 4.0)
        deep_path           = int(url_path_depth > 4)
        many_dots           = int(url_num_dots   > 3)

    The model's feature_names_in_ is the authoritative list. We compute all
    possible engineered features and select only those the model expects.

    Parameters
    ----------
    raw_row : np.ndarray, shape (1, 53)
        The unscaled base feature vector.
    feature_vector : dict
        The original feature dict for named access.

    Returns
    -------
    np.ndarray, shape (1, n_xgb_features)
        Feature vector ready for XGBoost prediction (unscaled — XGB does not
        use the StandardScaler; it was trained on raw feature values).
    """
    fv = feature_vector  # shorthand

    # Compute all possible engineered features
    engineered = {
        "special_ratio_query": fv.get("query_num_special", 0.0) / (fv.get("query_length", 0.0) + 1e-5),
        "special_ratio_body":  fv.get("body_num_special",  0.0) / (fv.get("body_length",  0.0) + 1e-5),
        "percent_ratio_query": fv.get("query_num_percent", 0.0) / (fv.get("query_length", 0.0) + 1e-5),
        "dots_ratio_url":      fv.get("url_num_dots",      0.0) / (fv.get("url_length",   0.0) + 1e-5),
        "semicolon_ratio":     fv.get("body_num_semicolons", 0.0) / (fv.get("body_length", 0.0) + 1e-5),
        "quotes_ratio":        fv.get("body_num_quotes",   0.0) / (fv.get("body_length",  0.0) + 1e-5),
        "entropy_diff":        fv.get("query_entropy", 0.0) - fv.get("url_entropy", 0.0),
        "high_query_entropy":  float(fv.get("query_entropy", 0.0) > 4.0),
        "high_body_entropy":   float(fv.get("body_entropy",  0.0) > 4.0),
        "deep_path":           float(fv.get("url_path_depth", 0.0) > 4),
        "many_dots":           float(fv.get("url_num_dots",   0.0) > 3),
    }

    if XGB_MODEL is not None and hasattr(XGB_MODEL, "feature_names_in_"):
        # Use the model's stored feature names as the authoritative order
        xgb_feature_names = [str(f) for f in XGB_MODEL.feature_names_in_]
        row_values = []
        for feat_name in xgb_feature_names:
            if feat_name in fv:
                row_values.append(float(fv[feat_name]))
            elif feat_name in engineered:
                row_values.append(float(engineered[feat_name]))
            else:
                log.warning("XGB feature '%s' not found in base or engineered features — using 0.0", feat_name)
                row_values.append(0.0)
        return np.array(row_values, dtype=np.float64).reshape(1, -1)
    else:
        # Fallback: append all engineered features to the base 53
        eng_values = np.array(list(engineered.values()), dtype=np.float64).reshape(1, -1)
        return np.hstack([raw_row, eng_values])


def adapt_ml_model(feature_vector: dict[str, Any]) -> dict[str, Any]:
    """
    Run the stacked ML ensemble on a 53-feature dict.

    Layer 1 — Random Forest (binary gate, SRS ML-002):
        Applies z-score normalisation using the saved scaler, then calls
        predict_proba(). If P(attack) < ML_CONFIDENCE_THRESHOLD, returns
        verdict=CLEAN immediately without calling XGBoost.

    Layer 2 — XGBoost (attack-type classifier, SRS ML-003):
        Called only when RF says attack. Computes 5 engineered ratio/flag
        features from the base 53, then calls predict_proba() on the 58-
        feature vector. Returns the predicted attack type label.

    Parameters
    ----------
    feature_vector : dict
        Raw features produced by HTTPFeatureExtractor.extract_features().
        Must contain all 53 keys listed in data/final/feature_names.txt.
        Missing keys are filled with 0.0 and logged as a warning.

    Returns
    -------
    dict with keys:
        verdict         : "ANOMALY" | "CLEAN"
        is_attack       : bool
        detection_source: "ml_engine" | "ml_unavailable"
        attack_type     : str | None  — XGB label (SQLI/XSS/PATH_TRAVERSAL/OTHER) or None
        confidence      : float       — RF P(attack) probability
        xgb_confidence  : float | None — XGB predicted-class probability (when attack)
        severity        : str | None
        matched_rule    : None        — always None for ML engine results

    SRS: ML-002, ML-003, ML-004, ML-005, ML-007
    """
    start_time = time.perf_counter()

    # ── ML-007: Graceful degradation if model or scaler unavailable ───────────
    if MODEL is None or SCALER is None:
        log.debug("ML model or scaler unavailable — returning CLEAN verdict (SRS ML-007)")
        return {
            "verdict":          "CLEAN",
            "is_attack":        False,
            "detection_source": "ml_unavailable",
            "attack_type":      None,
            "confidence":       0.0,
            "xgb_confidence":   None,
            "severity":         None,
            "matched_rule":     None,
            "ml_unavailable":   True,
        }

    # ── Assemble base feature vector (53 features, RF order) ─────────────────
    missing = [col for col in FEATURE_COLUMNS if col not in feature_vector]
    if missing:
        log.warning(
            "ML adapter: %d feature(s) missing, filling with 0.0: %s",
            len(missing), missing[:10]
        )

    raw_row = np.array(
        [float(feature_vector.get(col, 0.0)) for col in FEATURE_COLUMNS],
        dtype=np.float64,
    ).reshape(1, -1)

    # ── Layer 1: Random Forest (binary gate) ──────────────────────────────────
    try:
        # Pass as DataFrame with feature names to suppress sklearn warnings
        # (scaler and RF were fitted with named features)
        import pandas as pd
        raw_df = pd.DataFrame(raw_row, columns=FEATURE_COLUMNS)
        scaled_row = SCALER.transform(raw_df)
        # RF also expects named input
        scaled_df = pd.DataFrame(scaled_row, columns=FEATURE_COLUMNS)
    except ImportError:
        # pandas not available — fall back to plain numpy (triggers sklearn warning)
        scaled_row = SCALER.transform(raw_row)
        scaled_df = scaled_row
    except Exception as exc:
        log.error("Feature scaling failed: %s", exc)
        return {
            "verdict":          "CLEAN",
            "is_attack":        False,
            "detection_source": "ml_unavailable",
            "attack_type":      None,
            "confidence":       0.0,
            "xgb_confidence":   None,
            "severity":         None,
            "matched_rule":     None,
            "scaling_error":    True,
        }

    # predict_proba shape: (1, 2) → [P(normal), P(attack)]
    rf_proba    = MODEL.predict_proba(scaled_df)[0]
    rf_confidence = float(rf_proba[1])  # P(attack) — class index 1

    elapsed_rf_ms = (time.perf_counter() - start_time) * 1000
    log.debug("[ML-ENGINE] RF P(attack)=%.4f  (threshold=%.2f)  elapsed=%.1fms",
              rf_confidence, _THRESHOLD, elapsed_rf_ms)

    # ── Gate: RF below threshold → CLEAN ─────────────────────────────────────
    if rf_confidence < _THRESHOLD:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        log.debug("[ML-ENGINE] verdict=CLEAN  RF_confidence=%.4f  elapsed=%.1fms",
                  rf_confidence, elapsed_ms)
        return {
            "verdict":          "CLEAN",
            "is_attack":        False,
            "detection_source": "ml_engine",
            "attack_type":      None,
            "confidence":       rf_confidence,
            "xgb_confidence":   None,
            "severity":         None,
            "matched_rule":     None,
        }

    # ── Layer 2: XGBoost (attack-type classifier) ─────────────────────────────
    # RF says attack — now classify the attack type.
    attack_type    = "OTHER"   # default if XGB unavailable
    xgb_confidence = None

    if XGB_MODEL is not None:
        try:
            xgb_row    = _compute_xgb_features(raw_row, feature_vector)
            xgb_probas = XGB_MODEL.predict_proba(xgb_row)[0]  # shape: (4,)
            pred_idx   = int(xgb_probas.argmax())
            xgb_confidence = float(xgb_probas[pred_idx])

            # Map integer class index → label string using XGB_LABEL_MAP.
            # Fall back to the model's classes_ if the index is out of range.
            xgb_classes = list(getattr(XGB_MODEL, "classes_", []))
            if pred_idx < len(xgb_classes):
                raw_class = xgb_classes[pred_idx]
                attack_type = XGB_LABEL_MAP.get(int(raw_class), str(raw_class))
            else:
                attack_type = XGB_LABEL_MAP.get(pred_idx, "OTHER")

            log.debug(
                "[ML-ENGINE] XGB predicted_class=%s  xgb_confidence=%.4f  "
                "RF_confidence=%.4f",
                attack_type, xgb_confidence, rf_confidence,
            )
        except Exception as exc:
            log.warning(
                "[ML-ENGINE] XGBoost inference failed (non-fatal): %s. "
                "Falling back to attack_type='OTHER'.", exc
            )
            attack_type    = "OTHER"
            xgb_confidence = None
    else:
        log.warning(
            "[ML-ENGINE] XGBoost model not loaded — attack_type defaults to 'OTHER'. "
            "Ensure models/xgb_model.pkl exists (SRS ML-003)."
        )

    # ── Map RF confidence → severity ──────────────────────────────────────────
    if rf_confidence >= 0.90:
        severity = "critical"
    elif rf_confidence >= 0.80:
        severity = "high"
    elif rf_confidence >= 0.70:
        severity = "medium"
    else:
        severity = "low"

    elapsed_ms = (time.perf_counter() - start_time) * 1000
    if elapsed_ms > 100:
        log.warning(
            "[ML-ENGINE] Inference took %.1fms — exceeds 100ms target (SRS ML-005).",
            elapsed_ms
        )
    else:
        log.info(
            "[ML-ENGINE] verdict=ANOMALY  attack_type=%s  RF_confidence=%.4f  "
            "XGB_confidence=%s  severity=%s  elapsed=%.1fms",
            attack_type,
            rf_confidence,
            f"{xgb_confidence:.4f}" if xgb_confidence is not None else "N/A",
            severity,
            elapsed_ms,
        )

    return {
        "verdict":          "ANOMALY",
        "is_attack":        True,
        "detection_source": "ml_engine",
        "attack_type":      attack_type,
        "confidence":       rf_confidence,
        "xgb_confidence":   xgb_confidence,
        "severity":         severity,
        "matched_rule":     None,
    }


def is_ml_model_loaded() -> bool:
    """
    Return True if BOTH RF and XGBoost models are loaded and ready.

    Used by the health endpoint (GET /api/v1/health) to report models_loaded
    status (SRS FL-004). Returns True only when the full stacked ensemble is
    operational — False if either model failed to load.
    """
    return MODEL is not None and SCALER is not None and XGB_MODEL is not None
