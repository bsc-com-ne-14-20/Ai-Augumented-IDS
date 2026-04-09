"""
pipeline/orchestrator.py
========================
Sequential detection pipeline: rule engine first, ML model only if clean.

Architecture
------------
  raw_log_entry  ──►  extract_features()
                           │
                     adapt_rule_engine()
                           │
                    ATTACK? YES ──► build_alert_payload(source="RULE")
                    ATTACK? NO  ──►
                           │
                       adapt_ml_model()
                           │
                   ANOMALY? YES ──► build_alert_payload(source="ML")
                   ANOMALY? NO  ──► build_clean_payload()

Design constraints
------------------
  • This module imports NOTHING from Flask or Flask-SocketIO.
  • It is a pure Python module testable without an application context.
  • Socket.IO events are emitted by route handlers, not here.
  • Engine failures on a single entry return an error verdict without crashing
    the entire batch.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from engines.rule_adapter import adapt_rule_engine
from engines.ml_adapter import adapt_ml_model
from pipeline.preprocessor import extract_features

log = logging.getLogger(__name__)


# ── Payload builders ──────────────────────────────────────────────────────────

def build_alert_payload(
    raw_log_entry: dict[str, Any],
    features: dict[str, Any],
    engine_result: dict[str, Any],
    source: str,
) -> dict[str, Any]:
    """
    Build the standardised alert result dict for ATTACK or ANOMALY verdicts.

    Parameters
    ----------
    raw_log_entry : dict  — original log entry from the frontend
    features      : dict  — z-scored feature vector (for future explainability)
    engine_result : dict  — normalised result from rule_adapter or ml_adapter
    source        : str   — "RULE" | "ML"

    Returns
    -------
    dict matching the /api/v1/analyze results[n] schema.
    """
    verdict = "ATTACK" if source == "RULE" else "ANOMALY"

    return {
        "alert_id":         str(uuid.uuid4()),
        "timestamp":        raw_log_entry.get("timestamp", _utc_now()),
        "verdict":          verdict,
        "detection_source": source,
        "severity":         engine_result.get("severity"),
        "attack_type":      engine_result.get("attack_type", "UNKNOWN_ANOMALY"),
        "rule_triggered":   engine_result.get("rule_triggered"),
        "confidence":       engine_result.get("confidence"),
        "affected_field":   engine_result.get("affected_field"),
        "request_summary": {
            "method":       raw_log_entry.get("method", ""),
            "path":         raw_log_entry.get("path", ""),
            "query_string": raw_log_entry.get("query_string", ""),
        },
    }


def build_clean_payload(raw_log_entry: dict[str, Any]) -> dict[str, Any]:
    """
    Build the standardised clean result dict when neither engine fires.

    Returns
    -------
    dict matching the /api/v1/analyze results[n] schema for a CLEAN verdict.
    """
    return {
        "alert_id":         str(uuid.uuid4()),
        "timestamp":        raw_log_entry.get("timestamp", _utc_now()),
        "verdict":          "CLEAN",
        "detection_source": None,
        "severity":         None,
        "attack_type":      None,
        "rule_triggered":   None,
        "confidence":       None,
        "affected_field":   None,
        "request_summary": {
            "method":       raw_log_entry.get("method", ""),
            "path":         raw_log_entry.get("path", ""),
            "query_string": raw_log_entry.get("query_string", ""),
        },
    }


def build_error_payload(
    raw_log_entry: dict[str, Any],
    error_message: str,
) -> dict[str, Any]:
    """
    Build an error verdict dict for a log entry that caused an engine failure.
    The pipeline continues processing remaining entries after returning this.
    """
    return {
        "alert_id":         str(uuid.uuid4()),
        "timestamp":        raw_log_entry.get("timestamp", _utc_now()),
        "verdict":          "ERROR",
        "detection_source": None,
        "severity":         None,
        "attack_type":      None,
        "rule_triggered":   None,
        "confidence":       None,
        "affected_field":   None,
        "error":            error_message,
        "request_summary": {
            "method":       raw_log_entry.get("method", ""),
            "path":         raw_log_entry.get("path", ""),
            "query_string": raw_log_entry.get("query_string", ""),
        },
    }


def _utc_now() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


# ── Main pipeline ─────────────────────────────────────────────────────────────

def run_pipeline(raw_log_entry: dict[str, Any]) -> dict[str, Any]:
    """
    Execute the full sequential detection pipeline on a single log entry.

    Returns a verdict dict (ATTACK, ANOMALY, CLEAN, or ERROR).
    Never raises — errors are wrapped in a build_error_payload so the batch
    route can continue processing remaining entries.

    Parameters
    ----------
    raw_log_entry : dict
        A single HTTP log entry from the /api/v1/analyze request body.
    """
    # ── Feature extraction ────────────────────────────────────────────────────
    try:
        features = extract_features(raw_log_entry)
    except (ValueError, Exception) as exc:
        log.error("Preprocessor failed: %s", exc)
        return build_error_payload(raw_log_entry, f"Feature extraction failed: {exc}")

    # ── Rule engine (runs first, always) ─────────────────────────────────────
    try:
        rule_result = adapt_rule_engine(features)
    except Exception as exc:
        log.error("Rule engine failed: %s", exc)
        return build_error_payload(raw_log_entry, f"Rule engine error: {exc}")

    if rule_result["verdict"] == "ATTACK":
        log.info(
            "PIPELINE verdict=ATTACK source=RULE attack=%s path=%s",
            rule_result.get("attack_type"), raw_log_entry.get("path"),
        )
        return build_alert_payload(raw_log_entry, features, rule_result, source="RULE")

    # ── ML model (only if rule engine returned CLEAN) ─────────────────────────
    try:
        ml_result = adapt_ml_model(features)
    except Exception as exc:
        log.error("ML model failed: %s", exc)
        return build_error_payload(raw_log_entry, f"ML model error: {exc}")

    if ml_result["verdict"] == "ANOMALY":
        log.info(
            "PIPELINE verdict=ANOMALY source=ML confidence=%.4f path=%s",
            ml_result.get("confidence", 0), raw_log_entry.get("path"),
        )
        return build_alert_payload(raw_log_entry, features, ml_result, source="ML")

    # ── Clean ─────────────────────────────────────────────────────────────────
    log.info("PIPELINE verdict=CLEAN path=%s", raw_log_entry.get("path"))
    return build_clean_payload(raw_log_entry)
