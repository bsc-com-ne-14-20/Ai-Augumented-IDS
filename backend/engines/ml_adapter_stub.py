"""
backend/engines/ml_adapter.py
==============================
ML detection engine adapter for AA-IDS.

SRS Requirements: Section 4.4 (Machine Learning Detection Engine)
- ML-001: Load pre-trained models at startup
- ML-002: Accept 53-feature vector
- ML-003: XGBoost as second layer (stacked ensemble)
- ML-004: Return verdict with confidence score
- ML-005: <100ms inference time
- ML-006: Configurable model paths
- ML-007: Graceful degradation if models unavailable

This is a STUB implementation that allows the system to start and the rule
engine to function fully even before the ML developer integrates the real model.

The ML developer must replace this file with the actual implementation that:
1. Loads RandomForest and XGBoost models from disk
2. Implements the stacked ensemble prediction
3. Returns confidence scores from XGBoost output
"""

import logging
from pathlib import Path
from typing import Any, Dict

import config

log = logging.getLogger(__name__)

# Check if model files exist
_model_path = Path(config.ML_MODEL_PATH)
_MODEL_AVAILABLE = _model_path.exists()

if _MODEL_AVAILABLE:
    log.info("ML model found at %s (stub mode - not loaded)", _model_path)
else:
    log.warning(
        "ML model not found at %s - running in rule-engine-only mode",
        _model_path
    )


def adapt_ml_model(features: Dict[str, float]) -> Dict[str, Any]:
    """
    ML detection stub.
    
    SRS Requirement: ML-007 (Graceful degradation)
    
    Parameters
    ----------
    features : dict
        53-element z-scored feature vector from preprocessor
    
    Returns
    -------
    dict
        {
            "verdict": "CLEAN",
            "confidence": 0.0,
            "severity": None,
            "attack_type": "UNKNOWN_ANOMALY",
            "ml_unavailable": True
        }
    """
    if not _MODEL_AVAILABLE:
        log.debug("ML model unavailable - returning CLEAN verdict")
    
    return {
        "verdict": "CLEAN",
        "confidence": 0.0,
        "severity": None,
        "attack_type": "UNKNOWN_ANOMALY",
        "ml_unavailable": True,
    }


def is_ml_model_loaded() -> bool:
    """
    Return True if ML model is available.
    
    SRS Requirement: FL-004 (Health endpoint)
    """
    return _MODEL_AVAILABLE


# ── Instructions for ML Developer ─────────────────────────────────────────────
"""
TO ML DEVELOPER:

Replace this stub with the actual implementation. Required interface:

def adapt_ml_model(features: Dict[str, float]) -> Dict[str, Any]:
    '''
    Run RandomForest + XGBoost stacked ensemble on feature vector.
    
    Parameters
    ----------
    features : dict
        53 z-scored features from preprocessor.extract_features()
        Keys must match data/final/feature_names.txt order
    
    Returns
    -------
    dict with keys:
        verdict: "ANOMALY" | "CLEAN"
        confidence: float (0.0-1.0) from XGBoost predict_proba
        severity: "critical" | "high" | "medium" | "low" | None
        attack_type: "UNKNOWN_ANOMALY"
    '''
    # 1. Load models at module import time (not per-request)
    # 2. Assemble feature vector in correct column order
    # 3. Run RandomForest.predict_proba() → first layer
    # 4. Run XGBoost.predict_proba() on RF output → final confidence
    # 5. Apply threshold (config.ML_CONFIDENCE_THRESHOLD)
    # 6. Map confidence to severity
    # 7. Return verdict dict
    
def is_ml_model_loaded() -> bool:
    '''Return True if models loaded successfully at import time.'''
    return MODEL is not None

Model loading example:
    import joblib
    MODEL = joblib.load(config.ML_MODEL_PATH)
    SCALER = joblib.load(config.ML_SCALER_PATH)
    FEATURE_COLUMNS = Path(config.ML_FEATURE_NAMES_PATH).read_text().splitlines()
"""
