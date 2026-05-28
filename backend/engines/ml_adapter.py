"""
engines/ml_adapter.py
=====================
Adapter wrapping the trained RandomForestClassifier ML anomaly detection model.

Original model
--------------
  RandomForestClassifier(n_estimators=300, class_weight='balanced', random_state=42)
  Trained in src/ml_model/train1.ipynb on the 49-column z-scored feature matrix
  from data/processed/csic_cleaned.csv (4 CSIC-bias features dropped).

  The model expects a 2-D array where columns match the order in:
    data/final/feature_names.txt  (49 features)

  Saved to disk by running:
    python scripts/retrain_49.py   (then promote_49.py)

Public API added by this adapter
---------------------------------
  adapt_ml_model(feature_vector: dict) -> dict
      Accepts a dict of raw features from HTTPFeatureExtractor, applies z-score
      normalization using the saved scaler, calls predict + predict_proba,
      and returns a normalised verdict dict for the orchestrator.

  MODEL : the loaded RandomForestClassifier instance (exposed for health checks)
  SCALER : the loaded StandardScaler instance (exposed for health checks)

# ADAPTER CHANGE: Added this module to bridge the dict-based Flask pipeline to
#   the numpy-array-based sklearn model — the original training notebook is NOT
#   modified.
# ADAPTER CHANGE: MODEL and SCALER are loaded once at module import time (not per-request)
#   to avoid repeated disk I/O on the critical request path.
# ADAPTER CHANGE: Now accepts raw features and applies z-scoring internally using
#   the saved scaler, making it compatible with HTTPFeatureExtractor output.
# ADAPTER CHANGE: Feature array is wrapped in a pandas DataFrame before calling
#   scaler.transform() and model.predict_proba() to silence sklearn UserWarning
#   about feature names and ensure correct column alignment.
"""

import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from backend.config import get_config

log = logging.getLogger(__name__)

# ── Feature column order ──────────────────────────────────────────────────────
# ADAPTER CHANGE: Load the saved column order so input dicts are assembled into
#   numpy arrays in the exact order the model was trained on.
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
        # Startup assertion: hard-fail if wrong artefact is loaded
        assert SCALER.n_features_in_ == 49, (
            f"Scaler expects {SCALER.n_features_in_} features, want 49. "
            "Re-run scripts/retrain_49.py and promote artefacts."
        )
    except AssertionError:
        raise
    except Exception as exc:
        log.error("Failed to load ML scaler: %s", exc)
        SCALER = None

# ── Model loading (once at import time) ───────────────────────────────────────
_model_path = Path(config.ML_MODEL_PATH)
MODEL = None  # noqa: N816

if not _model_path.exists():
    log.warning(
        "ML model not found at: %s - running in rule-engine-only mode. "
        "Run  python scripts/retrain_49.py  to train and save the model.",
        _model_path
    )
else:
    try:
        MODEL = joblib.load(_model_path)
        log.info("ML model loaded from %s  |  estimators=%d",
                 _model_path, MODEL.n_estimators)
        # Startup assertion: hard-fail if wrong artefact is loaded
        assert MODEL.n_features_in_ == 49, (
            f"Model expects {MODEL.n_features_in_} features, want 49. "
            "Re-run scripts/retrain_49.py and promote artefacts."
        )
    except AssertionError:
        raise
    except Exception as exc:
        log.error("Failed to load ML model: %s", exc)
        MODEL = None

# Confidence threshold below which an ML flag is suppressed
_THRESHOLD: float = config.ML_CONFIDENCE_THRESHOLD


def adapt_ml_model(feature_vector: dict[str, Any]) -> dict[str, Any]:
    """
    Run the RandomForestClassifier on a raw feature dict.
    
    SRS Requirement: ML-007 (Graceful degradation)

    Parameters
    ----------
    feature_vector : dict
        Raw features produced by pipeline.http_feature_extractor.HTTPFeatureExtractor.
        Must contain all 49 keys listed in data/final/feature_names.txt.
        Missing keys are filled with 0.0 and logged as a warning so the pipeline 
        does not crash on partial feature vectors.

    Returns
    -------
    dict with keys:
        verdict    : "ANOMALY" | "CLEAN"
        confidence : float  — predict_proba score for the attack class
        severity   : str | None
        attack_type: str
    """
    # ML-007: Graceful degradation if model or scaler unavailable
    if MODEL is None or SCALER is None:
        log.debug("ML model or scaler unavailable - returning CLEAN verdict")
        return {
            "verdict": "CLEAN",
            "confidence": 0.0,
            "severity": None,
            "attack_type": None,
            "ml_unavailable": True,
        }

    # ADAPTER CHANGE: Assemble values in the trained column order; fill missing
    #   features with 0.0 (neutral for raw features).
    missing = [col for col in FEATURE_COLUMNS if col not in feature_vector]
    if missing:
        log.warning("ML adapter: %d feature(s) missing, filling with 0.0: %s",
                    len(missing), missing[:10])

    # Assemble raw features in correct order as a DataFrame.
    # Passing a named DataFrame to scaler.transform() satisfies sklearn's
    # internal column-order validation (scaler was fitted with a DataFrame).
    raw_values = [float(feature_vector.get(col, 0.0)) for col in FEATURE_COLUMNS]
    df = pd.DataFrame([raw_values], columns=FEATURE_COLUMNS)

    # Apply z-score normalization using the scaler
    try:
        scaled = SCALER.transform(df)
    except Exception as exc:
        log.error("Feature scaling failed: %s", exc)
        return {
            "verdict": "CLEAN",
            "confidence": 0.0,
            "severity": None,
            "attack_type": None,
            "scaling_error": True,
        }

    # The model was trained on a plain numpy array (output of scaler.transform),
    # so pass the raw scaled ndarray — not a DataFrame — to predict_proba.
    # Passing a DataFrame here would trigger the inverse sklearn UserWarning
    # "fitted without feature names".
    proba = MODEL.predict_proba(scaled)[0]  # shape (2,): [P(clean), P(attack)]
    confidence = float(proba[1])

    if confidence < _THRESHOLD:
        return {
            "verdict":     "CLEAN",
            "confidence":  confidence,
            "severity":    None,
            "attack_type": None,
        }

    # Map confidence → severity
    if confidence >= 0.90:
        severity = "critical"
    elif confidence >= 0.80:
        severity = "high"
    elif confidence >= 0.70:
        severity = "medium"
    else:
        severity = "low"

    log.info("ML model ANOMALY: confidence=%.4f severity=%s", confidence, severity)

    return {
        "verdict":     "ANOMALY",
        "confidence":  confidence,
        "severity":    severity,
        "attack_type": "STATISTICAL_ANOMALY",
    }


def is_ml_model_loaded() -> bool:
    """Return True if MODEL and SCALER were loaded successfully at import time."""
    return MODEL is not None and SCALER is not None
