"""
engines/ml_adapter.py
=====================
Adapter wrapping the trained RandomForestClassifier ML anomaly detection model.

Original model
--------------
  RandomForestClassifier(n_estimators=300, class_weight='balanced', random_state=42)
  Trained in src/ml_model/train1.ipynb on the 53-column z-scored feature matrix
  from data/final/train.csv.

  The model expects a 2-D array where columns match the order in:
    data/final/feature_names.txt  (53 features)

  Saved to disk by running:
    python scripts/train_and_save_model.py

Public API added by this adapter
---------------------------------
  adapt_ml_model(feature_vector: dict) -> dict
      Accepts a dict of z-scored features, calls predict + predict_proba,
      and returns a normalised verdict dict for the orchestrator.

  MODEL : the loaded RandomForestClassifier instance (exposed for health checks)

# ADAPTER CHANGE: Added this module to bridge the dict-based Flask pipeline to
#   the numpy-array-based sklearn model — the original training notebook is NOT
#   modified.
# ADAPTER CHANGE: MODEL is loaded once at module import time (not per-request)
#   to avoid repeated disk I/O on the critical request path.
"""

import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np

import config  # noqa: E402

log = logging.getLogger(__name__)

# ── Feature column order ──────────────────────────────────────────────────────
# ADAPTER CHANGE: Load the saved column order so input dicts are assembled into
#   numpy arrays in the exact order the model was trained on.
_feature_names_path = Path(config.ML_FEATURE_NAMES_PATH)
if not _feature_names_path.exists():
    raise RuntimeError(
        f"Feature names file not found: {_feature_names_path}. "
        "Ensure data/final/feature_names.txt exists in the repo."
    )
FEATURE_COLUMNS: list[str] = _feature_names_path.read_text().strip().splitlines()

# ── Model loading (once at import time) ───────────────────────────────────────
_model_path = Path(config.ML_MODEL_PATH)
if not _model_path.exists():
    raise RuntimeError(
        f"ML model not found at: {_model_path}\n"
        "Run  python scripts/train_and_save_model.py  to train and save the model."
    )

MODEL = joblib.load(_model_path)  # noqa: N816 — exposed as public module attribute
log.info("ML model loaded from %s  |  estimators=%d",
         _model_path, MODEL.n_estimators)

# Confidence threshold below which an ML flag is suppressed
_THRESHOLD: float = config.ML_CONFIDENCE_THRESHOLD


def adapt_ml_model(feature_vector: dict[str, Any]) -> dict[str, Any]:
    """
    Run the RandomForestClassifier on a z-scored feature dict.

    Parameters
    ----------
    feature_vector : dict
        Z-scored features produced by pipeline.preprocessor.extract_features().
        Must contain all 53 keys listed in data/final/feature_names.txt.
        Missing keys are filled with 0.0 (neutral z-score) and logged as a
        warning so the pipeline does not crash on partial feature vectors.

    Returns
    -------
    dict with keys:
        verdict    : "ANOMALY" | "CLEAN"
        confidence : float  — predict_proba score for the attack class
        severity   : str | None
        attack_type: str
    """
    # ADAPTER CHANGE: Assemble values in the trained column order; fill missing
    #   features with 0.0 (the scaler mean, so neutral for z-scored data).
    missing = [col for col in FEATURE_COLUMNS if col not in feature_vector]
    if missing:
        log.warning("ML adapter: %d feature(s) missing, filling with 0.0: %s",
                    len(missing), missing[:10])

    row = np.array(
        [float(feature_vector.get(col, 0.0)) for col in FEATURE_COLUMNS],
        dtype=np.float64,
    ).reshape(1, -1)

    # ADAPTER CHANGE: predict_proba is called alongside predict so we can apply
    #   a configurable confidence threshold independently of the model's
    #   internal decision boundary.
    proba = MODEL.predict_proba(row)[0]  # shape (2,): [P(clean), P(attack)]
    confidence = float(proba[1])

    if confidence < _THRESHOLD:
        return {
            "verdict":     "CLEAN",
            "confidence":  confidence,
            "severity":    None,
            "attack_type": "UNKNOWN_ANOMALY",
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
        "attack_type": "UNKNOWN_ANOMALY",
    }


def is_ml_model_loaded() -> bool:
    """Return True if MODEL was loaded successfully at import time."""
    return MODEL is not None
