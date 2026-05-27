"""
==============================================================================
FILE: backend/api/routes.py
COMPONENT: Flask REST API Routes
SRS REQUIREMENTS: FL-001, FL-002, FL-003, FL-004, AL-005
OWNER: Backend Team
==============================================================================

WHAT THIS FILE DOES:
    Defines all REST API endpoints for the AA-IDS backend. Handles
    authentication, request validation, pipeline invocation, alert
    persistence, WebSocket broadcasting, and response formatting.

PIPELINE POSITION:
    Stage 1 of 8 — entry point. Authenticates the request, validates the
    payload, then hands off to orchestrator.run_pipeline(). Also calls
    persist_alert() and emit_alert() after each result.

HOW IT IS IMPLEMENTED:
    - require_api_key decorator checks X-IDS-Key OR X-IDS-API-Key headers
    - Accepts both flat middleware format and wrapped {"logs":[...]} format
    - sanitize_dict is NOT called before the pipeline (would destroy attack patterns)
    - persist_alert() called for EVERY request (attacks AND clean)
    - emit_alert() called for EVERY request (attacks AND clean)
    - /api/v1/analyze alias registered alongside /api/v1/analyse

INPUTS:
    HTTP requests from Django middleware (flat format) or dashboard (logs format)

OUTPUTS:
    JSON responses with detection results, alert history, stats, health

DEPENDENCIES (internal):
    backend.pipeline.orchestrator, backend.sockets.events,
    backend.engines.rule_engine, backend.engines.ml_adapter,
    backend.api.schemas, backend.config

INTEGRATION NOTES:
    The middleware sends X-IDS-API-Key (not X-IDS-Key). Both are accepted.
    The middleware sends a flat JSON object (not wrapped in logs array).
    The schema normalises both formats before the pipeline sees them.
    Do NOT sanitize request data before the pipeline — it destroys attack signals.
==============================================================================
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any
from functools import wraps

from flask import Blueprint, jsonify, request
from marshmallow import ValidationError

from backend.api.schemas import AnalyzeRequestSchema
from backend.api.validation import check_request_size, rate_limit
from backend.pipeline.orchestrator import run_pipeline
from backend.sockets.events import emit_alert, persist_alert
from backend.engines.rule_engine import is_rule_engine_loaded
from backend.engines.ml_adapter import is_ml_model_loaded
from backend.config import get_config
from backend.database import check_connection_health

log = logging.getLogger(__name__)

api_bp = Blueprint("api", __name__)

# Validation schema
_analyze_schema = AnalyzeRequestSchema()

# Session-scoped in-memory state (resets on server restart)
_START_TIME: float = time.time()


def require_api_key(f):
    """
    API key validation decorator.

    Accepts both 'X-IDS-Key' (SRS-defined) and 'X-IDS-API-Key' (middleware
    actual header name). Returns HTTP 403 on missing or invalid key.

    SRS Requirements: FL-003
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Accept both header names — middleware sends X-IDS-API-Key
        api_key = (
            request.headers.get("X-IDS-Key")
            or request.headers.get("X-IDS-API-Key")
            or request.headers.get("x-ids-key")
            or request.headers.get("x-ids-api-key")
        )

        if not api_key:
            log.warning("Missing API key header in request to %s", request.endpoint)
            return jsonify({"error": "Invalid or missing API key"}), 403

        config = get_config()
        expected_key = config.IDS_API_KEY

        if api_key != expected_key:
            log.warning("Invalid API key in request to %s", request.endpoint)
            return jsonify({"error": "Invalid or missing API key"}), 403

        return f(*args, **kwargs)

    return decorated_function


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
        _alert_log.append(result)


# ── Routes ────────────────────────────────────────────────────────────────────

@api_bp.route("/health", methods=["GET"])
def health() -> Any:
    """
    GET /api/v1/health

    SRS Requirement: FL-004

    Returns system health status. Always HTTP 200 — even if subsystems
    are degraded. The dashboard uses this to diagnose partial failures.

    Response:
        {
            "status": "ok",
            "models_loaded": bool,
            "db_connected": bool,
            "rule_engine_loaded": bool,
            "uptime_seconds": int
        }
    """
    return jsonify({
        "status": "ok",
        "models_loaded": is_ml_model_loaded(),
        "db_connected": check_connection_health(),
        "rule_engine_loaded": is_rule_engine_loaded(),
        "ml_model_loaded": is_ml_model_loaded(),
        "uptime_seconds": _uptime_seconds(),
    }), 200


def _run_analyse_pipeline(body: dict) -> tuple[Any, int]:
    """
    Core analysis logic shared by /analyse and /analyze routes.

    Accepts both flat middleware format and wrapped {"logs":[...]} format.
    Does NOT sanitize before the pipeline — sanitization destroys attack signals.

    Returns (response, status_code).
    """
    request_start_time = time.monotonic()

    # FL-002: Validate request body
    if body is None:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    try:
        validated = _analyze_schema.load(body)
    except ValidationError as err:
        # Extract a human-readable error message
        messages = err.messages
        # Find the first missing required field
        for field_name, field_errors in messages.items():
            if isinstance(field_errors, list):
                for msg in field_errors:
                    if "required" in str(msg).lower() or "missing" in str(msg).lower():
                        return jsonify({"error": f"Missing required field: {field_name}"}), 400
        return jsonify({"error": f"Validation error: {messages}"}), 400

    logs = validated.get("logs", [])

    if not logs:
        return jsonify({"error": "Missing required field: method"}), 400

    results: list[dict[str, Any]] = []
    individual_times: list[int] = []

    # FL-001: Run detection pipeline for each log entry
    for idx, log_entry in enumerate(logs):
        entry_start_time = time.monotonic()

        try:
            result = run_pipeline(log_entry)
        except Exception as exc:
            entry_ms = int((time.monotonic() - entry_start_time) * 1000)
            log.error("Pipeline crashed on entry %d: %s", idx, exc)
            return jsonify({
                "error": f"Detection pipeline failed on entry {idx}: {exc}",
            }), 500

        entry_ms = int((time.monotonic() - entry_start_time) * 1000)
        individual_times.append(entry_ms)

        log.info(
            "Request processed — entry=%d method=%s url=%s verdict=%s time=%dms",
            idx,
            log_entry.get("method", "?"),
            log_entry.get("url", "?"),
            result.get("verdict", "?"),
            entry_ms,
        )

        _update_metrics(result)

        # Persist to DB for ALL requests (attacks AND clean) — AL-002
        try:
            persist_alert(result, log_entry)
        except Exception as persist_exc:
            log.error("Alert persistence failed for entry %d: %s", idx, persist_exc)
            # Do not abort — persistence failure must not block the response

        # Emit WebSocket event for ALL requests — AL-003
        try:
            emit_alert(result)
        except Exception as emit_exc:
            log.warning("WebSocket emission failed for entry %d: %s", idx, emit_exc)

        results.append(result)

    total_ms = int((time.monotonic() - request_start_time) * 1000)

    # Count verdicts
    total_attacks = sum(1 for r in results if r.get("verdict") == "ATTACK")
    total_anomalies = sum(1 for r in results if r.get("verdict") == "ANOMALY")
    total_clean = sum(1 for r in results if r.get("verdict") == "CLEAN")

    # If single entry (middleware format), return the result directly
    # rather than wrapped in a batch response
    if len(results) == 1 and len(logs) == 1:
        return jsonify(results[0]), 200

    return jsonify({
        "summary": {
            "total_processed": len(results),
            "total_clean": total_clean,
            "total_attacks": total_attacks,
            "total_anomalies": total_anomalies,
            "processing_time_ms": total_ms,
            "individual_processing_times_ms": individual_times,
            "average_processing_time_ms": (
                int(sum(individual_times) / len(individual_times))
                if individual_times else 0
            ),
        },
        "results": results,
    }), 200


@api_bp.route("/analyse", methods=["POST"])
@require_api_key
@check_request_size()
@rate_limit()
def analyse() -> Any:
    """
    POST /api/v1/analyse

    SRS Requirements: FL-001, FL-002, FL-003

    Entry point for the detection pipeline. Accepts:
    - Flat format (Django middleware): {"method": "GET", "path": "/...", ...}
    - Wrapped format (batch): {"logs": [{...}, ...]}

    Authentication: X-IDS-Key OR X-IDS-API-Key header (FL-003)
    Validation: method and url/path required (FL-002)
    Pipeline: orchestrator.run_pipeline() for each entry (FL-001)
    """
    body = request.get_json(silent=True)
    return _run_analyse_pipeline(body)


@api_bp.route("/analyze", methods=["POST"])
@require_api_key
@check_request_size()
@rate_limit()
def analyze() -> Any:
    """
    POST /api/v1/analyze

    Alias for /api/v1/analyse — the Flutter dashboard calls this endpoint
    (American spelling). Identical behaviour.
    """
    body = request.get_json(silent=True)
    return _run_analyse_pipeline(body)


@api_bp.route("/alerts", methods=["GET"])
def alerts() -> Any:
    """
    GET /api/v1/alerts

    SRS Requirement: AL-005

    Return paginated, filterable alert history.

    Query Parameters:
        page: int (default 1)
        limit / page_size: int (default 50, max 500)
        verdict: str — filter by ATTACK, ANOMALY, CLEAN
        attack_type: str — filter by attack type
        detection_source: str — filter by RULE or ML
        severity: str — filter by severity
        is_attack: bool — filter by attack status
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
        # Accept both 'limit' and 'page_size' parameter names
        limit = min(500, max(1, int(
            request.args.get("limit", request.args.get("page_size", 50))
        )))
    except ValueError:
        return jsonify({"error": "page and limit must be positive integers"}), 400

    # Filters
    verdict_filter = request.args.get("verdict", "").strip() or None
    attack_type_filter = request.args.get("attack_type", "").strip() or None
    source_filter = request.args.get("detection_source", request.args.get("source", "")).upper() or None
    severity_filter = request.args.get("severity", "").strip() or None
    is_attack_filter = request.args.get("is_attack", "").lower()
    from_date = request.args.get("from_date", "").strip() or None
    to_date = request.args.get("to_date", "").strip() or None

    filtered = _alert_log

    if verdict_filter:
        filtered = [a for a in filtered if a.get("verdict") == verdict_filter.upper()]

    if attack_type_filter:
        filtered = [a for a in filtered if a.get("attack_type") == attack_type_filter]

    if source_filter:
        filtered = [a for a in filtered if a.get("detection_source") == source_filter]

    if severity_filter:
        filtered = [a for a in filtered if a.get("severity") == severity_filter.lower()]

    if is_attack_filter in ("true", "false"):
        is_attack_bool = is_attack_filter == "true"
        if is_attack_bool:
            filtered = [a for a in filtered if a.get("verdict") in ("ATTACK", "ANOMALY")]
        else:
            filtered = [a for a in filtered if a.get("verdict") == "CLEAN"]

    if from_date:
        try:
            from_dt = datetime.fromisoformat(from_date.replace("Z", "+00:00"))
            filtered = [
                a for a in filtered
                if datetime.fromisoformat(
                    (a.get("timestamp") or "").replace("Z", "+00:00")
                ) >= from_dt
            ]
        except ValueError:
            pass

    if to_date:
        try:
            to_dt = datetime.fromisoformat(to_date.replace("Z", "+00:00"))
            filtered = [
                a for a in filtered
                if datetime.fromisoformat(
                    (a.get("timestamp") or "").replace("Z", "+00:00")
                ) <= to_dt
            ]
        except ValueError:
            pass

    total = len(filtered)
    start = (page - 1) * limit
    page_data = filtered[start: start + limit]

    return jsonify({
        "alerts": page_data,
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit if total > 0 else 1,
        "page_size": limit,
        "limit": limit,
    }), 200


@api_bp.route("/alerts/<request_id>", methods=["GET"])
def alert_detail(request_id: str) -> Any:
    """
    GET /api/v1/alerts/<request_id>

    Return full detail of a single alert including all extracted features.
    """
    for alert in _alert_log:
        if alert.get("alert_id") == request_id:
            return jsonify(alert), 200

    return jsonify({"error": f"Alert not found: {request_id}"}), 404


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


@api_bp.route("/metrics", methods=["GET"])
def metrics() -> Any:
    """
    GET /api/v1/metrics

    Dashboard metrics endpoint — returns the same data as /stats but with
    field names matching what the Flutter MetricsData model expects.

    The Flutter dashboard calls this endpoint (not /stats).
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
        # Fields matching Flutter MetricsData.fromJson
        "total_requests_analyzed": _metrics["total_requests_analyzed"],
        "total_attacks_detected": _metrics["total_attacks_detected"],
        "total_anomalies_detected": _metrics["total_anomalies_detected"],
        "total_clean": _metrics["total_clean"],
        "attack_type_breakdown": _metrics["attack_type_breakdown"],
        "detection_source_breakdown": _metrics["detection_source_breakdown"],
        "severity_breakdown": _metrics["severity_breakdown"],
        "ml_confidence_distribution": ml_dist,
        # Also include /stats-compatible field names for cross-compatibility
        "total_requests": _metrics["total_requests_analyzed"],
        "total_attacks": _metrics["total_attacks_detected"],
        "detection_source_split": _metrics["detection_source_breakdown"],
        "session_uptime_seconds": _uptime_seconds(),
    }), 200


# ── Error handlers ────────────────────────────────────────────────────────────

@api_bp.errorhandler(405)
def method_not_allowed(exc: Any) -> Any:
    """Return JSON for 405 instead of HTML."""
    return jsonify({"error": "Method not allowed"}), 405


@api_bp.errorhandler(404)
def not_found(exc: Any) -> Any:
    """Return JSON for 404 instead of HTML."""
    return jsonify({"error": "Not found"}), 404
