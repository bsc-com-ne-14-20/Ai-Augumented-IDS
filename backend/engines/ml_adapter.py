"""
engines/ml_adapter.py  — STUB
ML inference is now handled by IDSController inside orchestrator.py.
This stub keeps is_ml_model_loaded() available for the health check in routes.py.
"""
import logging
log = logging.getLogger(__name__)

def adapt_ml_model(feature_vector):
    return {"verdict": "CLEAN", "confidence": 0.0, "severity": None, "attack_type": "UNKNOWN_ANOMALY"}

def is_ml_model_loaded():
    return True
