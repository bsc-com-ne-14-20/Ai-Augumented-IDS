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
                  _is_structurally_trivial()?
                    YES ──► build_clean_payload(source=None)
                    NO  ──►
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

from backend.engines.rule_engine import evaluate as rule_engine_evaluate
from backend.engines.ml_adapter import adapt_ml_model
from backend.pipeline.http_feature_extractor import HTTPFeatureExtractor

# Initialize feature extractor once at module level
_feature_extractor = HTTPFeatureExtractor(verbose=False)

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
        # Accept both 'rule_triggered' (CRS adapter) and 'matched_rule' (rule_engine)
        "rule_triggered":   engine_result.get("rule_triggered") or engine_result.get("matched_rule"),
        "confidence":       engine_result.get("confidence"),
        "affected_field":   engine_result.get("affected_field"),
        "request_summary": {
            "method":       raw_log_entry.get("method", ""),
            # Use 'url' (normalised by schema from 'path') with 'path' as fallback
            "path":         raw_log_entry.get("url", raw_log_entry.get("path", "")),
            "url":          raw_log_entry.get("url", raw_log_entry.get("path", "")),
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
            "path":         raw_log_entry.get("url", raw_log_entry.get("path", "")),
            "url":          raw_log_entry.get("url", raw_log_entry.get("path", "")),
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
            "path":         raw_log_entry.get("url", raw_log_entry.get("path", "")),
            "url":          raw_log_entry.get("url", raw_log_entry.get("path", "")),
            "query_string": raw_log_entry.get("query_string", ""),
        },
    }


def _utc_now() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


# ── Pre-filter ────────────────────────────────────────────────────────────────

# Attack flags checked by the pre-filter.  Any non-zero value means a pattern
# was detected and the request must go through the ML model.
_ATTACK_FLAG_FEATURES: tuple[str, ...] = (
    "query_has_sqli",       "query_has_xss",       "query_has_traversal",
    "body_has_sqli",        "body_has_xss",        "body_has_traversal",
    "cookie_has_sqli",      "cookie_has_xss",
    "url_has_double_encoding", "url_has_risky_ext",
)


def _is_structurally_trivial(features: dict[str, Any]) -> bool:
    """
    Return True if the request is structurally incapable of carrying an attack
    payload AND falls outside the CSIC 2010 URL distribution.

    Applied AFTER the rule engine (which always runs) and BEFORE ML inference.
    A request is trivial if ALL of the following hold:

      1. URL length ≤ 20 characters
         (CSIC benign mean ≈ 23 chars; GET / = 1 — deep outlier)
      2. No query string  (query_is_empty == 1.0)
      3. No body          (body_is_empty  == 1.0)
      4. No special characters in URL (url_num_special == 0)
      5. No percent-encoding in URL   (url_num_percent == 0)
      6. No attack flags set anywhere (all has_sqli / has_xss /
         has_traversal / has_double_encoding / has_risky_ext are 0.0)

    Root cause this addresses
    -------------------------
    The CSIC 2010 dataset only contains requests to /tienda1/... paths.
    url_entropy for "/" = 0.0 (z = −3.94 std below the scaler mean of 3.54).
    url_length = 1 (z = −2.08 std below the scaler mean of 23.2).
    url_num_dots = 0 (z = −1.71; CSIC benign paths always ended in .jsp).
    url_path_depth = 1 (z = −1.68; CSIC benign had 3–5 path segments).

    The model has never seen a benign request this short and classifies it as
    ANOMALY with high confidence.  This is not a model bug — it is a training
    coverage gap.  A structurally trivial request cannot carry the attack
    payloads the model was trained to detect, so skipping ML inference is safe.
    """
    # Condition 1: URL must be short
    if features.get("url_length", 999) > 20:
        return False

    # Condition 2: no query string
    if features.get("query_is_empty", 0.0) != 1.0:
        return False

    # Condition 3: no body
    if features.get("body_is_empty", 0.0) != 1.0:
        return False

    # Condition 4: no special characters in URL
    if features.get("url_num_special", 1.0) != 0.0:
        return False

    # Condition 5: no percent-encoding in URL
    if features.get("url_num_percent", 1.0) != 0.0:
        return False

    # Condition 6: no attack flags
    if any(features.get(f, 0.0) != 0.0 for f in _ATTACK_FLAG_FEATURES):
        return False
    return True


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
        # Convert raw_log_entry to the format expected by HTTPFeatureExtractor
        # Schema normalises 'path' → 'url', so always use 'url' with 'path' fallback
        http_request = {
            "method": raw_log_entry.get("method", "GET"),
            "url": raw_log_entry.get("url", raw_log_entry.get("path", "/")),
            "query_string": raw_log_entry.get("query_string", ""),
            "body": raw_log_entry.get("body", ""),
            "headers": raw_log_entry.get("headers", {}),
            "content_length": raw_log_entry.get("content_length", 0),
        }
        features = _feature_extractor.extract_features(http_request)
    except (ValueError, Exception) as exc:
        log.error("Feature extraction failed: %s", exc)
        return build_error_payload(raw_log_entry, f"Feature extraction failed: {exc}")

    # ── Rule engine (runs first, always) ─────────────────────────────────────
    try:
        rule_result = rule_engine_evaluate(raw_log_entry, features)
    except Exception as exc:
        log.error("Rule engine failed: %s", exc)
        return build_error_payload(raw_log_entry, f"Rule engine error: {exc}")

    if rule_result["is_attack"]:
        log.info(
            "PIPELINE verdict=ATTACK source=RULE attack=%s path=%s",
            rule_result.get("attack_type"), raw_log_entry.get("path"),
        )
        return build_alert_payload(raw_log_entry, features, rule_result, source="RULE")

    # ── Pre-filter: skip ML for structurally trivial requests ─────────────────
    # Requests with url_length ≤ 20, no query, no body, no special chars, and
    # no attack flags are outside the CSIC 2010 training distribution (all CSIC
    # benign URLs were /tienda1/... paths, ≥18 chars, with .jsp extensions).
    # Sending them through the ML model produces false positives because
    # url_entropy=0 and url_length=1 are extreme outliers (z ≈ −3.94 and −2.08).
    if _is_structurally_trivial(features):
        log.info(
            "PIPELINE verdict=CLEAN source=PRE_FILTER "
            "reason=structurally_trivial path=%s",
            raw_log_entry.get("url", raw_log_entry.get("path", "")),
        )
        return build_clean_payload(raw_log_entry)

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


