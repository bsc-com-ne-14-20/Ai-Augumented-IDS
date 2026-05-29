"""
pipeline/orchestrator.py
========================
Delegates to IDSController (CRS -> RF -> XGBoost).
Uses api.feature_extractor to extract features, then passes raw features to predict().
"""

import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from controller import IDSController
from api.feature_extractor import extract_features

log = logging.getLogger(__name__)

_controller = None
try:
    _controller = IDSController()
    log.info("IDSController loaded (CRS + RF + XGBoost ready)")
except Exception as _exc:
    log.error("Failed to load IDSController: %s", _exc)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_alert_payload(raw_log_entry, engine_result, source):
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
            "path":         raw_log_entry.get("url", raw_log_entry.get("path", "")),
            "url":          raw_log_entry.get("url", raw_log_entry.get("path", "")),
            "query_string": raw_log_entry.get("query_string", ""),
        },
    }


def build_clean_payload(raw_log_entry):
    return {
        "alert_id":         str(uuid.uuid4()),
        "timestamp":        raw_log_entry.get("timestamp", _utc_now()),
        "verdict":          "CLEAN",
        "detection_source": "ML",
        "severity":         "low",
        "attack_type":      "NORMAL",
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


def build_error_payload(raw_log_entry, error_message):
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


def _map_stage_to_source(stage):
    if stage and stage.upper() == "CRS":
        return "RULE"
    return "ML"


def _map_confidence_to_severity(confidence):
    if confidence is None:
        return None
    if confidence >= 0.90:
        return "critical"
    if confidence >= 0.80:
        return "high"
    if confidence >= 0.70:
        return "medium"
    return "low"


def run_pipeline(raw_log_entry):
    if _controller is None:
        return build_error_payload(raw_log_entry, "IDSController failed to initialise")

    request_dict = {
        "method":       raw_log_entry.get("method", "GET"),
        "url":          raw_log_entry.get("url", raw_log_entry.get("path", "/")),
        "query_string": raw_log_entry.get("query_string", ""),
        "body":         raw_log_entry.get("body", ""),
        "headers":      raw_log_entry.get("headers", {}),
        "source_ip":    raw_log_entry.get("source_ip", "unknown"),
    }

    # Step 1: extract features using your extractor
    try:
        _scaled, raw_df = extract_features(request_dict)
        # RF expects scaled features; XGBoost needs raw (passed under _raw key)
        features = _scaled.iloc[0].to_dict()
        features["_raw"] = raw_df.iloc[0].to_dict()
    except Exception as exc:
        log.error("Feature extraction failed: %s", exc)
        return build_error_payload(raw_log_entry, f"Feature extraction failed: {exc}")

    # Step 2: run through controller (CRS -> RF -> XGBoost)
    try:
        result = _controller.predict(features)
    except Exception as exc:
        log.error("IDSController.predict() failed: %s", exc)
        return build_error_payload(raw_log_entry, f"Pipeline error: {exc}")

    verdict     = result.get("verdict", "NORMAL")
    stage       = result.get("stage")
    confidence  = result.get("confidence")
    attack_type = result.get("attack_type")

    if verdict == "NORMAL":
        log.info("PIPELINE verdict=CLEAN stage=%s path=%s", stage, request_dict["url"])
        return build_clean_payload(raw_log_entry)

    source   = _map_stage_to_source(stage)
    severity = _map_confidence_to_severity(confidence)

    engine_result = {
        "attack_type":    attack_type or "UNKNOWN",
        "confidence":     confidence,
        "severity":       severity,
        "rule_triggered": result.get("rule_triggered"),
        "affected_field": result.get("affected_field"),
    }

    log.info("PIPELINE verdict=%s source=%s attack=%s confidence=%s path=%s",
             "ATTACK" if source == "RULE" else "ANOMALY",
             source, attack_type, confidence, request_dict["url"])
    return build_alert_payload(raw_log_entry, engine_result, source)
