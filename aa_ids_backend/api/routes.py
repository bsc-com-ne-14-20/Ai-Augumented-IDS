"""
api/routes.py
=============
All Flask route definitions for the AA-IDS REST API.

Blueprint : api
Prefix    : /api/v1

Endpoints
---------
  GET  /api/v1/health    — engine liveness check
  POST /api/v1/analyze   — submit log batch for detection
  GET  /api/v1/metrics   — session-scoped aggregate statistics
  GET  /api/v1/alerts    — paginated alert history with filtering
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any

from flask import Blueprint, jsonify, request, current_app
from marshmallow import ValidationError

from api.schemas import AnalyzeRequestSchema
from pipeline.orchestrator import run_pipeline
from sockets.events import emit_alert
from engines.rule_adapter import is_rule_engine_loaded
from engines.ml_adapter import is_ml_model_loaded, MODEL
import config

log = logging.getLogger(__name__)

api_bp = Blueprint("api", __name__)

# ── Validation schema (instantiated once) ─────────────────────────────────────
_analyze_schema = AnalyzeRequestSchema()

# ── Session-scoped in-memory state ────────────────────────────────────────────
# All counters reset on server restart — no database required for this prototype.

_START_TIME: float = time.time()

_metrics: dict[str, Any] = {
    "total_requests_analyzed": 0,
    "total_attacks_detected":  0,
    "total_anomalies_detected": 0,
    "total_clean":             0,
    "attack_type_breakdown":   {},
    "detection_source_breakdown": {"RULE": 0, "ML": 0},
    "severity_breakdown":      {"critical": 0, "high": 0, "medium": 0, "low": 0},
    "ml_confidence_scores":    [],   # raw list for distribution stats
}

# Full alert log for GET /alerts with pagination
_alert_log: list[dict[str, Any]] = []


def _uptime_seconds() -> int:
    """Return integer seconds since server start."""
    return int(time.time() - _START_TIME)


def _update_metrics(result: dict[str, Any]) -> None:
    """Update session metrics after a single pipeline result."""
    verdict = result.get("verdict")

    _metrics["total_requests_analyzed"] += 1

    if verdict == "ATTACK":
        _metrics["total_attacks_detected"] += 1
        attack_type = result.get("attack_type") or "UNKNOWN"
        _metrics["attack_type_breakdown"][attack_type] = (
            _metrics["attack_type_breakdown"].get(attack_type, 0) + 1
        )
        _metrics["detection_source_breakdown"]["RULE"] += 1
        severity = result.get("severity") or "low"
        if severity in _metrics["severity_breakdown"]:
            _metrics["severity_breakdown"][severity] += 1
        _alert_log.append(result)

    elif verdict == "ANOMALY":
        _metrics["total_anomalies_detected"] += 1
        attack_type = result.get("attack_type") or "UNKNOWN_ANOMALY"
        _metrics["attack_type_breakdown"][attack_type] = (
            _metrics["attack_type_breakdown"].get(attack_type, 0) + 1
        )
        _metrics["detection_source_breakdown"]["ML"] += 1
        severity = result.get("severity") or "low"
        if severity in _metrics["severity_breakdown"]:
            _metrics["severity_breakdown"][severity] += 1
        confidence = result.get("confidence")
        if confidence is not None:
            _metrics["ml_confidence_scores"].append(float(confidence))
        _alert_log.append(result)

    elif verdict == "CLEAN":
        _metrics["total_clean"] += 1


# ── Routes ────────────────────────────────────────────────────────────────────

@api_bp.route("/health", methods=["GET"])
def health() -> Any:
    """
    GET /api/v1/health

    Returns liveness status and engine readiness flags.
    Always returns 200 even if engines are partially degraded.
    """
    return jsonify({
        "status":             "ok",
        "rule_engine_loaded": is_rule_engine_loaded(),
        "ml_model_loaded":    is_ml_model_loaded(),
        "ml_model_path":      config.ML_MODEL_PATH,
        "uptime_seconds":     _uptime_seconds(),
    }), 200


@api_bp.route("/analyze", methods=["POST"])
def analyze() -> Any:
    """
    POST /api/v1/analyze

    Accept a batch of HTTP log entries, run the detection pipeline on each,
    emit Socket.IO alerts for any ATTACK/ANOMALY verdicts, and return the
    full result set with a summary.

    Request body : {"logs": [ {...}, ... ]}
    Response     : {"summary": {...}, "results": [...]}
    """
    body = request.get_json(silent=True)
    if body is None:
        return jsonify({
            "error":  "VALIDATION_ERROR",
            "detail": "Request body must be valid JSON.",
        }), 422

    # Schema validation
    try:
        validated = _analyze_schema.load(body)
    except ValidationError as err:
        # Surface the first human-readable error message
        first_msg = str(err.messages)
        log.warning("Validation error on /analyze: %s", first_msg)
        return jsonify({
            "error":  "VALIDATION_ERROR",
            "detail": first_msg,
        }), 422

    logs = validated["logs"]
    t_start = time.monotonic()
    results: list[dict[str, Any]] = []

    for idx, log_entry in enumerate(logs):
        try:
            result = run_pipeline(log_entry)
        except Exception as exc:
            log.error("Pipeline crashed on entry %d: %s", idx, exc)
            return jsonify({
                "error":  "PIPELINE_ERROR",
                "detail": f"Rule engine failed on entry {idx}: {exc}",
            }), 500

        _update_metrics(result)

        # Emit Socket.IO alert (route handler, not pipeline)
        if result.get("verdict") in ("ATTACK", "ANOMALY"):
            emit_alert(result)

        results.append(result)

    processing_ms = int((time.monotonic() - t_start) * 1000)

    total_attacks   = sum(1 for r in results if r["verdict"] == "ATTACK")
    total_anomalies = sum(1 for r in results if r["verdict"] == "ANOMALY")
    total_clean     = sum(1 for r in results if r["verdict"] == "CLEAN")

    return jsonify({
        "summary": {
            "total_processed":   len(results),
            "total_clean":       total_clean,
            "total_attacks":     total_attacks,
            "total_anomalies":   total_anomalies,
            "processing_time_ms": processing_ms,
        },
        "results": results,
    }), 200


@api_bp.route("/metrics", methods=["GET"])
def metrics() -> Any:
    """
    GET /api/v1/metrics

    Return session-scoped aggregate statistics.  All counters are in-memory
    and reset on server restart — no database required.
    """
    ml_scores = _metrics["ml_confidence_scores"]
    if ml_scores:
        import statistics
        ml_dist = {
            "mean": round(statistics.mean(ml_scores), 4),
            "min":  round(min(ml_scores), 4),
            "max":  round(max(ml_scores), 4),
        }
    else:
        ml_dist = {"mean": None, "min": None, "max": None}

    total_analyzed = _metrics["total_requests_analyzed"]
    total_detections = (
        _metrics["total_attacks_detected"] + _metrics["total_anomalies_detected"]
    )
    fpr_estimate = round(
        _metrics["total_clean"] / max(total_analyzed, 1) * 0.05, 4
    )  # rough heuristic for prototype

    return jsonify({
        "total_requests_analyzed":  total_analyzed,
        "total_attacks_detected":   _metrics["total_attacks_detected"],
        "total_anomalies_detected": _metrics["total_anomalies_detected"],
        "total_clean":              _metrics["total_clean"],
        "false_positive_rate_estimate": fpr_estimate,
        "attack_type_breakdown":    _metrics["attack_type_breakdown"],
        "detection_source_breakdown": _metrics["detection_source_breakdown"],
        "severity_breakdown":       _metrics["severity_breakdown"],
        "ml_confidence_distribution": ml_dist,
        "session_uptime_seconds":   _uptime_seconds(),
    }), 200


@api_bp.route("/alerts", methods=["GET"])
def alerts() -> Any:
    """
    GET /api/v1/alerts

    Return paginated, filterable alert history for the session.

    Query params
    ------------
    page       : int  (default 1)
    page_size  : int  (default 50, max 500)
    verdict    : str  — filter by verdict ("ATTACK" | "ANOMALY")
    severity   : str  — filter by severity ("critical" | "high" | "medium" | "low")
    """
    try:
        page      = max(1, int(request.args.get("page", 1)))
        page_size = min(500, max(1, int(request.args.get("page_size", config.DEFAULT_PAGE_SIZE))))
    except ValueError:
        return jsonify({
            "error":  "VALIDATION_ERROR",
            "detail": "page and page_size must be positive integers.",
        }), 422

    verdict_filter  = request.args.get("verdict", "").upper() or None
    severity_filter = request.args.get("severity", "").lower() or None

    # Filter
    filtered = _alert_log
    if verdict_filter:
        filtered = [a for a in filtered if a.get("verdict") == verdict_filter]
    if severity_filter:
        filtered = [a for a in filtered if a.get("severity") == severity_filter]

    total = len(filtered)
    start = (page - 1) * page_size
    page_data = filtered[start: start + page_size]

    return jsonify({
        "alerts":    page_data,
        "total":     total,
        "page":      page,
        "page_size": page_size,
    }), 200


# ── Error handlers (registered on the Blueprint) ─────────────────────────────

@api_bp.errorhandler(405)
def method_not_allowed(exc: Any) -> Any:
    """Return JSON for 405 instead of HTML."""
    return jsonify({"error": "METHOD_NOT_ALLOWED", "detail": str(exc)}), 405


@api_bp.errorhandler(404)
def not_found(exc: Any) -> Any:
    """Return JSON for 404 instead of HTML."""
    return jsonify({"error": "NOT_FOUND", "detail": str(exc)}), 404
