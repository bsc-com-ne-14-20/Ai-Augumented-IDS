"""
sockets/events.py
=================
Flask-SocketIO event emitters for AA-IDS real-time alert delivery.

The emit functions in this module are called from route handlers ONLY —
never from inside the pipeline or engine modules, which must remain
framework-agnostic and independently testable.

Flutter dashboard listens with:
    socket.on('alert', handler)
"""

import logging
import time
from typing import Any
from datetime import datetime

from backend.database import SessionLocal, Alert, update_stats
from backend.api.validation import sanitize_string

log = logging.getLogger(__name__)

# socketio is injected at app startup via init_socketio() to avoid a circular
# import between app.py and routes.py.
_socketio = None


def init_socketio(socketio_instance: Any) -> None:
    """
    Bind the Flask-SocketIO instance to this module.

    Called once from app.py after the SocketIO object is created.
    Must be called before any emit_* function is used.
    """
    global _socketio
    _socketio = socketio_instance
    
    # Register connection and disconnection handlers
    _register_connection_handlers()
    
    log.info("Socket.IO emitter initialised.")


def _register_connection_handlers() -> None:
    """
    Register Socket.IO connection and disconnection event handlers.
    
    Implements requirements:
    - 9.2: Log client connections and emit welcome event
    - 9.7: Handle client disconnections gracefully without crashing
    """
    if _socketio is None:
        log.error("Cannot register connection handlers: Socket.IO not initialized")
        return
    
    @_socketio.on('connect')
    def handle_connect():
        """
        Handle client connection events.
        
        Logs the connection and emits a welcome event to the newly connected client.
        Requirement 9.2: WHEN a client connects, THE WebSocket_Server SHALL log 
        the connection and emit a welcome event.
        """
        try:
            # Get client session ID for logging
            from flask import request as flask_request
            client_id = getattr(flask_request, 'sid', 'unknown')
            client_ip = getattr(flask_request, 'environ', {}).get('REMOTE_ADDR', 'unknown')
            
            log.info("Socket.IO client connected: sid=%s ip=%s", client_id, client_ip)
            
            # Emit welcome event to the newly connected client
            welcome_data = {
                "event": "welcome",
                "data": {
                    "message": "Connected to AA-IDS real-time alerts",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "client_id": client_id
                }
            }
            
            # Add specific error handling for welcome event emission
            welcome_success = _safe_emit(
                'welcome', 
                welcome_data, 
                room=client_id, 
                context=f"client connection sid={client_id} ip={client_ip}"
            )
            
            if welcome_success:
                log.debug("Welcome event emitted to client: sid=%s", client_id)
            # Error already logged by _safe_emit if emission failed
            
        except Exception as exc:
            # Handle connection errors gracefully without crashing
            log.error("Error handling client connection: %s", exc)
    
    @_socketio.on('disconnect')
    def handle_disconnect():
        """
        Handle client disconnection events.
        
        Logs the disconnection gracefully without crashing the application.
        Requirement 9.7: THE WebSocket_Server SHALL handle client disconnections 
        gracefully without crashing.
        """
        try:
            # Get client session ID for logging
            from flask import request as flask_request
            client_id = getattr(flask_request, 'sid', 'unknown')
            client_ip = getattr(flask_request, 'environ', {}).get('REMOTE_ADDR', 'unknown')
            
            log.info("Socket.IO client disconnected: sid=%s ip=%s", client_id, client_ip)
            
        except Exception as exc:
            # Handle disconnection errors gracefully without crashing
            log.error("Error handling client disconnection: %s", exc)


def persist_alert(verdict_payload: dict[str, Any], raw_log_entry: dict[str, Any], db_session=None) -> None:
    """
    Persist detection result to database for all verdicts.

    Stores timestamp, method, URL, source IP, verdict, attack type, confidence,
    rule ID, and optional geolocation/VPN data. Commits transaction within 10ms.
    
    Implements robust error handling for database failures:
    - Logs database errors without crashing the application
    - Continues processing on persistence failure
    - Properly cleans up database sessions on errors

    Parameters
    ----------
    verdict_payload : dict
        The full result dict produced by pipeline.orchestrator.run_pipeline().
        Must contain: verdict, alert_id, timestamp, detection_source.
    raw_log_entry : dict
        The original HTTP log entry containing request details and optional
        geolocation/VPN data.
    db_session : Session, optional
        Database session to use. If None, creates a new session.
        Used for testing with in-memory databases.

    Requirements: 8.1, 8.2, 8.3, 8.4, 8.6, 8.7, 18.4
    """
    # Use provided session or create new one
    db = db_session if db_session is not None else SessionLocal()
    should_close = db_session is None  # Only close if we created the session
    start_time = time.perf_counter()
    alert_id = verdict_payload.get("alert_id", "unknown")
    
    try:
        # Extract request summary
        request_summary = verdict_payload.get("request_summary", {})
        
        # Build alert record with sanitized string fields (Requirement 19.5)
        alert = Alert(
            timestamp=_parse_timestamp(verdict_payload.get("timestamp")),
            method=sanitize_string(request_summary.get("method") or raw_log_entry.get("method", "GET"), 16),
            url=sanitize_string(raw_log_entry.get("url", "/"), 8192),
            source_ip=sanitize_string(raw_log_entry.get("source_ip", "unknown"), 45),  # IPv6 max length
            verdict=sanitize_string(verdict_payload.get("verdict", "ERROR"), 32),
            attack_type=sanitize_string(verdict_payload.get("attack_type"), 100),
            rule_id=sanitize_string(verdict_payload.get("rule_triggered"), 128),
            stage=sanitize_string(verdict_payload.get("detection_source"), 32),
            confidence=verdict_payload.get("confidence") or 0.0,  # Default to 0.0 if None
            crs_score=0,  # Not used in current implementation
            recommendation=None,  # Not used in current implementation
        )
        
        # Store geolocation data when available (sanitized)
        geolocation = raw_log_entry.get("geolocation", {})
        if geolocation:
            alert.country = sanitize_string(geolocation.get("country"), 64)
            alert.city = sanitize_string(geolocation.get("city"), 128)
            alert.latitude = geolocation.get("latitude")  # Numeric, no sanitization needed
            alert.longitude = geolocation.get("longitude")  # Numeric, no sanitization needed
            alert.isp = sanitize_string(geolocation.get("isp"), 256)
        
        # Store VPN/proxy/Tor detection flags when available
        alert.is_vpn = raw_log_entry.get("is_vpn", False)
        alert.is_proxy = raw_log_entry.get("is_proxy", False)
        alert.is_tor = raw_log_entry.get("is_tor", False)
        
        # Persist to database with enhanced error handling
        try:
            db.add(alert)
            db.commit()
            log.debug("Alert record persisted successfully (alert_id=%s)", alert_id)
        except Exception as db_exc:
            # Log database persistence error with detailed context
            log.error(
                "Failed to persist alert record to database (alert_id=%s, verdict=%s, source_ip=%s): %s",
                alert_id, alert.verdict, alert.source_ip, str(db_exc)
            )
            # Rollback the transaction to clean up
            try:
                db.rollback()
                log.debug("Database transaction rolled back successfully (alert_id=%s)", alert_id)
            except Exception as rollback_exc:
                log.error(
                    "Failed to rollback database transaction (alert_id=%s): %s",
                    alert_id, str(rollback_exc)
                )
            # Re-raise to be caught by outer exception handler
            raise db_exc
        
        # Update aggregate statistics with separate error handling
        try:
            update_stats(db, {
                "verdict": alert.verdict,
                "attack_type": alert.attack_type,
                "stage": alert.stage,
                "is_vpn": alert.is_vpn,
            })
            log.debug("Statistics updated successfully (alert_id=%s)", alert_id)
        except Exception as stats_exc:
            # Log statistics update error but don't fail the entire operation
            log.error(
                "Failed to update aggregate statistics (alert_id=%s): %s",
                alert_id, str(stats_exc)
            )
            # Rollback statistics transaction
            try:
                db.rollback()
                log.debug("Statistics transaction rolled back (alert_id=%s)", alert_id)
            except Exception as rollback_exc:
                log.error(
                    "Failed to rollback statistics transaction (alert_id=%s): %s",
                    alert_id, str(rollback_exc)
                )
        
        # Measure transaction time
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        if elapsed_ms > 10:
            log.warning(
                "Database persistence exceeded 10ms threshold: %.2fms (alert_id=%s)",
                elapsed_ms, alert_id
            )
        else:
            log.debug(
                "Alert persisted in %.2fms (alert_id=%s, verdict=%s)",
                elapsed_ms, alert_id, alert.verdict
            )
    
    except Exception as exc:
        # Enhanced error logging with more context for debugging
        log.error(
            "Database persistence failed for alert_id=%s (verdict=%s, source_ip=%s, url=%s): %s. "
            "Application will continue processing remaining requests.",
            alert_id,
            verdict_payload.get("verdict", "unknown"),
            raw_log_entry.get("source_ip", "unknown"),
            raw_log_entry.get("url", "unknown"),
            str(exc)
        )
        
        # Ensure database session is properly cleaned up on any error
        try:
            if db and db.is_active:
                db.rollback()
                log.debug("Final database rollback completed (alert_id=%s)", alert_id)
        except Exception as cleanup_exc:
            log.error(
                "Failed to clean up database session (alert_id=%s): %s",
                alert_id, str(cleanup_exc)
            )
    
    finally:
        # Ensure database session is always properly closed
        if should_close and db:
            try:
                db.close()
                log.debug("Database session closed successfully (alert_id=%s)", alert_id)
            except Exception as close_exc:
                log.error(
                    "Failed to close database session (alert_id=%s): %s",
                    alert_id, str(close_exc)
                )


def _parse_timestamp(timestamp_str: str) -> datetime:
    """
    Parse ISO 8601 timestamp string to datetime object.
    
    Falls back to current UTC time if parsing fails.
    """
    try:
        # Handle ISO 8601 format with timezone
        if timestamp_str:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    except (ValueError, AttributeError) as exc:
        log.warning("Failed to parse timestamp '%s': %s", timestamp_str, exc)
    
    # Fallback to current time
    return datetime.utcnow()


def _safe_emit(event_name: str, event_data: dict, room: str = None, context: str = "") -> bool:
    """
    Safely emit a WebSocket event with comprehensive error handling.
    
    This helper function centralizes WebSocket emission error handling to ensure
    consistent logging and graceful failure handling across all emission points.
    
    Parameters
    ----------
    event_name : str
        The name of the Socket.IO event to emit
    event_data : dict
        The event data payload to send
    room : str, optional
        Specific room/client to send to. If None, broadcasts to all clients.
    context : str, optional
        Additional context for error logging (e.g., "welcome", "alert", "clean_request")
        
    Returns
    -------
    bool
        True if emission succeeded, False if it failed
        
    Requirements: 9.7, 18.5 - Handle WebSocket failures gracefully with logging
    """
    if _socketio is None:
        log.warning(
            "Cannot emit %s event%s: Socket.IO not initialized. Event skipped.",
            event_name, f" ({context})" if context else ""
        )
        return False
    
    try:
        if room:
            _socketio.emit(event_name, event_data, room=room)
        else:
            _socketio.emit(event_name, event_data)
        
        log.debug(
            "Socket.IO %s event emitted successfully%s",
            event_name, f" ({context})" if context else ""
        )
        return True
        
    except Exception as exc:
        # Log WebSocket emission error with detailed context for debugging
        log.error(
            "Socket.IO %s event emission failed%s: %s. "
            "Application will continue processing remaining requests.",
            event_name, f" ({context})" if context else "", str(exc)
        )
        return False


def broadcast_alert(verdict_payload: dict[str, Any]) -> None:
    """
    Broadcast real-time events to ALL connected Socket.IO clients.
    
    This is the main entry point for alert broadcasting that ensures events
    are sent to all connected clients simultaneously. It delegates to emit_alert
    for the actual event emission logic with comprehensive error handling.
    
    Parameters
    ----------
    verdict_payload : dict
        The full result dict produced by pipeline.orchestrator.run_pipeline().
        Must contain at minimum: verdict, alert_id, timestamp, detection_source.
        
    Requirements: 9.6 - Broadcast to all connected clients
                  9.7 - Handle WebSocket failures gracefully without crashing
                  18.5 - Log WebSocket emission errors and continue processing
    """
    if _socketio is None:
        log.warning(
            "broadcast_alert called before Socket.IO was initialised — skipping alert broadcast for alert_id=%s.",
            verdict_payload.get("alert_id", "unknown")
        )
        return
    
    try:
        # Use emit_alert which already handles broadcasting to all clients via socketio.emit()
        emit_alert(verdict_payload)
    except Exception as exc:
        # Additional safety net for any unexpected errors in the broadcast process
        log.error(
            "Unexpected error during alert broadcast (alert_id=%s, verdict=%s): %s. "
            "Application will continue processing remaining requests.",
            verdict_payload.get("alert_id", "unknown"),
            verdict_payload.get("verdict", "unknown"),
            str(exc)
        )


def emit_alert(verdict_payload: dict[str, Any]) -> None:
    """
    Emit real-time events to all connected Socket.IO clients based on verdict type.

    Emits different event types based on the detection verdict:
    - ATTACK verdicts: emit 'alert' event with full detection details
    - ANOMALY verdicts: emit 'alert' event with full detection details  
    - CLEAN verdicts: emit 'clean_request' event
    - ERROR verdicts: silently ignored to avoid flooding the dashboard

    Parameters
    ----------
    verdict_payload : dict
        The full result dict produced by pipeline.orchestrator.run_pipeline().
        Must contain at minimum: verdict, alert_id, timestamp, detection_source.
        
    Requirements: 9.3, 9.4, 9.5, 9.6, 9.7, 18.5
    """
    if _socketio is None:
        log.warning(
            "emit_alert called before Socket.IO was initialised — skipping alert emission for alert_id=%s.",
            verdict_payload.get("alert_id", "unknown")
        )
        return

    # Validate required payload fields
    verdict = verdict_payload.get("verdict")
    alert_id = verdict_payload.get("alert_id", "unknown")
    
    if not verdict:
        log.error(
            "Cannot emit alert: missing verdict in payload (alert_id=%s). "
            "Skipping WebSocket emission.",
            alert_id
        )
        return
    
    # Build the unified 'alert' event payload for ALL verdicts (ATTACK, ANOMALY, CLEAN).
    # The dashboard listens exclusively to the 'alert' event and uses is_attack to
    # distinguish attacks from clean traffic. Emitting 'clean_request' separately
    # means clean traffic never appears in the live feed — fixed here.
    #
    # SRS §3.2.2: Events emitted for EVERY request (attacks AND clean).
    # is_attack: true  → ATTACK or ANOMALY
    # is_attack: false → CLEAN
    if verdict in ("ATTACK", "ANOMALY", "CLEAN"):
        is_attack = verdict in ("ATTACK", "ANOMALY")
        request_summary = verdict_payload.get("request_summary", {})

        event_data = {
            "event": "alert",
            "data": {
                "alert_id":         verdict_payload.get("alert_id"),
                "timestamp":        verdict_payload.get("timestamp"),
                "verdict":          verdict,
                "is_attack":        is_attack,
                "detection_source": verdict_payload.get("detection_source"),
                "severity":         verdict_payload.get("severity"),
                "attack_type":      verdict_payload.get("attack_type"),
                "confidence":       verdict_payload.get("confidence"),
                "matched_rule":     verdict_payload.get("rule_triggered"),
                "rule_triggered":   verdict_payload.get("rule_triggered"),
                "affected_field":   verdict_payload.get("affected_field"),
                "request_summary":  request_summary,
                # Flatten key fields to top level for SRS §3.2.2 compatibility
                "method":           request_summary.get("method", ""),
                "url":              request_summary.get("path", ""),
                "query_string":     request_summary.get("query_string", ""),
            },
        }

        context = (
            f"verdict={verdict} attack_type={verdict_payload.get('attack_type')} "
            f"alert_id={verdict_payload.get('alert_id')}"
        )
        emission_success = _safe_emit("alert", event_data, context=context)

        if emission_success:
            if is_attack:
                log.info(
                    "Socket.IO alert emitted: verdict=%s attack_type=%s confidence=%s alert_id=%s",
                    verdict, verdict_payload.get("attack_type"),
                    verdict_payload.get("confidence"), verdict_payload.get("alert_id"),
                )
            else:
                log.debug(
                    "Socket.IO clean alert emitted: alert_id=%s",
                    verdict_payload.get("alert_id"),
                )

        # Also emit the legacy 'clean_request' event for backward compatibility
        if not is_attack:
            clean_data = {
                "event": "clean_request",
                "data": {
                    "alert_id":        verdict_payload.get("alert_id"),
                    "timestamp":       verdict_payload.get("timestamp"),
                    "verdict":         verdict,
                    "detection_source": verdict_payload.get("detection_source"),
                    "request_summary": request_summary,
                },
            }
            _safe_emit("clean_request", clean_data,
                       context=f"alert_id={verdict_payload.get('alert_id')}")

    # ERROR verdicts are silently ignored to avoid flooding the dashboard
    elif verdict == "ERROR":
        log.debug("Skipping Socket.IO emission for ERROR verdict (alert_id=%s)",
                  verdict_payload.get("alert_id"))

    else:
        log.warning("Unknown verdict type for Socket.IO emission: %s (alert_id=%s)",
                    verdict, verdict_payload.get("alert_id"))
