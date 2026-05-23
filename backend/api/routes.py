"""
api/routes.py
=============
Flask REST API routes for AA-IDS backend.

SRS Requirements: Section 4.6 (Flask IDS Backend)
- FL-001: POST /api/v1/analyse endpoint
- FL-002: Request validation
- FL-003: API key authentication
- FL-004: GET /api/v1/health endpoint
- AL-005: GET /api/v1/alerts with pagination and filtering
- Additional: GET /api/v1/alerts/<request_id> for single alert detail
- Additional: GET /api/v1/stats for aggregate statistics

Blueprint: api
Prefix: /api/v1
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any

from flask import Blueprint, jsonify, request
from marshmallow import ValidationError

from backend.api.schemas import AnalyzeRequestSchema
from backend.pipeline.orchestrator import run_pipeline
from backend.sockets.events import emit_alert
from backend.engines.rule_engine import is_rule_engine_loaded
from backend.engines.ml_adapter import is_ml_model_loaded
import config

log = logging.getLogger(__name__)

api_bp = Blueprint("api", __name__)

# Validation schema
_analyze_schema = AnalyzeRequestSchema()

# Session-scoped in-memory state (resets on server restart)
_START_TIME: float = time.time()

_metrics: dict[str, Any] = {
    "total_requests_analyzed": 0,
    "total_attacks_detected": 0,
    "total_anomalies_detected": 0,
    "total_clean": 0,
    "attack_type_breakdown": {},
    "detection_source_breakdown": {"RULE": 0, "ML": 0},
    "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    "ml_confidence_scores": [],
}

# Full alert log for GET /alerts
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
    
    SRS Requirement: FL-004
    
    Returns system health status and engine readiness.
    Always returns 200 even if engines are partially degraded.
    
    Response:
        {
            "status": "ok",
            "models_loaded": bool,
            "db_connected": bool,
            "rule_engine_loaded": bool,
            "ml_model_loaded": bool,
            "uptime_seconds": int
        }
    """
    # For prototype, db_connected is always true (in-memory state)
    return jsonify({
        "status": "ok",
        "models_loaded": is_ml_model_loaded(),
        "db_connected": True,
        "rule_engine_loaded": is_rule_engine_loaded(),
        "ml_model_loaded": is_ml_model_loaded(),
        "uptime_seconds": _uptime_seconds(),
    }), 200


@api_bp.route("/analyse", methods=["POST"])
def analyse() -> Any:
    """
    POST /api/v1/analyse
    
    SRS Requirements: FL-001, FL-002, FL-003
    
    Accept a batch of HTTP log entries, run the detection pipeline on each,
    emit Socket.IO alerts for ATTACK/ANOMALY verdicts, and return results.
    
    Request Headers:
        X-IDS-Key: Shared API key (required)
    
    Request Body:
        {
            "logs": [
                {
                    "method": "GET",
                    "url": "/path?query=value",
                    "path": "/path",
                    "query_string": "query=value",
                    "headers": {...},
                    "body": "",
                    "response_code": 200,
                    "content_length": 0,
                    "timestamp": "2026-05-23T10:00:00Z"
                },
                ...
            ]
        }
    
    Response:
        {
            "request_id": "uuid",
            "timestamp": "2026-05-23T10:00:00Z",
            "is_attack": bool,
            "detection_source": "rule_engine" | "ml_engine" | null,
            "attack_type": str | null,
            "confidence": float | null,
            "matched_rule": str | null,
            "features": {...}
        }
    """
    # FL-003: API key authentication
    api_key = request.headers.get("X-IDS-Key")
    expected_key = config.IDS_API_KEY
    
    if not api_key or api_key != expected_key:
        log.warning("Unauthorized access attempt to /analyse")
        return jsonify({
            "error": "UNAUTHORIZED",
            "detail": "Missing or invalid X-IDS-Key header",
        }), 403

    # FL-002: Request validation
    body = request.get_json(silent=True)
    if body is None:
        return jsonify({
            "error": "VALIDATION_ERROR",
            "detail": "Request body must be valid JSON.",
        }), 400

    try:
        validated = _analyze_schema.load(body)
    except ValidationError as err:
        first_msg = str(err.messages)
        log.warning("Validation error on /analyse: %s", first_msg)
        return jsonify({
            "error": "VALIDATION_ERROR",
            "detail": first_msg,
        }), 400

    logs = validated["logs"]
    t_start = time.monotonic()
    results: list[dict[str, Any]] = []

    # FL-001: Run detection pipeline
    for idx, log_entry in enumerate(logs):
        try:
            result = run_pipeline(log_entry)
        except Exception as exc:
            log.error("Pipeline crashed on entry %d: %s", idx, exc)
            return jsonify({
                "error": "PIPELINE_ERROR",
                "detail": f"Detection pipeline failed on entry {idx}: {exc}",
            }), 500

        _update_metrics(result)

        # Emit Socket.IO alert for ATTACK/ANOMALY
        if result.get("verdict") in ("ATTACK", "ANOMALY"):
            emit_alert(result)

        results.append(result)

    processing_ms = int((time.monotonic() - t_start) * 1000)

    total_attacks = sum(1 for r in results if r["verdict"] == "ATTACK")
    total_anomalies = sum(1 for r in results if r["verdict"] == "ANOMALY")
    total_clean = sum(1 for r in results if r["verdict"] == "CLEAN")

    return jsonify({
        "summary": {
            "total_processed": len(results),
            "total_clean": total_clean,
            "total_attacks": total_attacks,
            "total_anomalies": total_anomalies,
            "processing_time_ms": processing_ms,
        },
        "results": results,
    }), 200


@api_bp.route("/alerts", methods=["GET"])
def alerts() -> Any:
    """
    GET /api/v1/alerts
    
    SRS Requirement: AL-005
    
    Return paginated, filterable alert history.
    
    Query Parameters:
        page: int (default 1)
        limit: int (default 50, max 500)
        attack_type: str (filter by attack type)
        detection_source: str (filter by "RULE" or "ML")
        is_attack: bool (filter by attack status)
        from_date: ISO 8601 timestamp
        to_date: ISO 8601 timestamp
    
    Response:
        {
            "alerts": [...],
            "total": int,
            "page": int,
            "page_size": int
        }
    """
    try:
        page = max(1, int(request.args.get("page", 1)))
        limit = min(500, max(1, int(request.args.get("limit", 50))))
    except ValueError:
        return jsonify({
            "error": "VALIDATION_ERROR",
            "detail": "page and limit must be positive integers.",
        }), 400

    # Filters
    attack_type_filter = request.args.get("attack_type", "").strip() or None
    source_filter = request.args.get("source", "").upper() or None
    is_attack_filter = request.args.get("is_attack", "").lower()
    from_date = request.args.get("from_date", "").strip() or None
    to_date = request.args.get("to_date", "").strip() or None

    # Apply filters
    filtered = _alert_log
    
    if attack_type_filter:
        filtered = [a for a in filtered if a.get("attack_type") == attack_type_filter]
    
    if source_filter:
        filtered = [a for a in filtered if a.get("detection_source") == source_filter]
    
    if is_attack_filter in ("true", "false"):
        is_attack_bool = is_attack_filter == "true"
        filtered = [a for a in filtered if a.get("verdict") in ("ATTACK", "ANOMALY") == is_attack_bool]
    
    if from_date:
        try:
            from_dt = datetime.fromisoformat(from_date.replace('Z', '+00:00'))
            filtered = [a for a in filtered 
                       if datetime.fromisoformat(a.get("timestamp", "").replace('Z', '+00:00')) >= from_dt]
        except ValueError:
            pass
    
    if to_date:
        try:
            to_dt = datetime.fromisoformat(to_date.replace('Z', '+00:00'))
            filtered = [a for a in filtered 
                       if datetime.fromisoformat(a.get("timestamp", "").replace('Z', '+00:00')) <= to_dt]
        except ValueError:
            pass

    total = len(filtered)
    start = (page - 1) * limit
    page_data = filtered[start: start + limit]

    return jsonify({
        "alerts": page_data,
        "total": total,
        "page": page,
        "page_size": limit,
    }), 200


@api_bp.route("/alerts/<request_id>", methods=["GET"])
def alert_detail(request_id: str) -> Any:
    """
    GET /api/v1/alerts/<request_id>
    
    Return full detail of a single alert including all 53 extracted features.
    
    Response:
        {
            "alert_id": str,
            "timestamp": str,
            "verdict": str,
            "detection_source": str,
            "severity": str,
            "attack_type": str,
            "confidence": float | null,
            "matched_rule": str | null,
            "request_summary": {...},
            "features": {...}  # All 53 features
        }
    """
    for alert in _alert_log:
        if alert.get("alert_id") == request_id:
            return jsonify(alert), 200
    
    return jsonify({
        "error": "NOT_FOUND",
        "detail": f"Alert with ID {request_id} not found",
    }), 404


@api_bp.route("/stats", methods=["GET"])
def stats() -> Any:
    """
    GET /api/v1/stats
    
    Return aggregate statistics for the session.
    
    Response:
        {
            "total_requests": int,
            "total_attacks": int,
            "attack_type_breakdown": {...},
            "detection_source_split": {...}
        }
    """
    ml_scores = _metrics["ml_confidence_scores"]
    if ml_scores:
        import statistics
        ml_dist = {
            "mean": round(statistics.mean(ml_scores), 4),
            "min": round(min(ml_scores), 4),
            "max": round(max(ml_scores), 4),
        }
    else:
        ml_dist = {"mean": None, "min": None, "max": None}

    return jsonify({
        "total_requests": _metrics["total_requests_analyzed"],
        "total_attacks": _metrics["total_attacks_detected"],
        "total_anomalies": _metrics["total_anomalies_detected"],
        "total_clean": _metrics["total_clean"],
        "attack_type_breakdown": _metrics["attack_type_breakdown"],
        "detection_source_split": _metrics["detection_source_breakdown"],
        "severity_breakdown": _metrics["severity_breakdown"],
        "ml_confidence_distribution": ml_dist,
        "session_uptime_seconds": _uptime_seconds(),
    }), 200


# ── Error handlers ────────────────────────────────────────────────────────────

@api_bp.errorhandler(405)
def method_not_allowed(exc: Any) -> Any:
    """Return JSON for 405 instead of HTML."""
    return jsonify({"error": "METHOD_NOT_ALLOWED", "detail": str(exc)}), 405


@api_bp.errorhandler(404)
def not_found(exc: Any) -> Any:
    """Return JSON for 404 instead of HTML."""
    return jsonify({"error": "NOT_FOUND", "detail": str(exc)}), 404
