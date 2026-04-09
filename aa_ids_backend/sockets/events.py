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
from typing import Any

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
    log.info("Socket.IO emitter initialised.")


def emit_alert(verdict_payload: dict[str, Any]) -> None:
    """
    Emit a real-time 'alert' event to all connected Socket.IO clients.

    Only fires for ATTACK or ANOMALY verdicts — CLEAN and ERROR verdicts
    are silently ignored to avoid flooding the dashboard.

    Parameters
    ----------
    verdict_payload : dict
        The full result dict produced by pipeline.orchestrator.run_pipeline().
        Must contain at minimum: verdict, alert_id, timestamp, detection_source.
    """
    if _socketio is None:
        log.warning("emit_alert called before Socket.IO was initialised — skipping.")
        return

    verdict = verdict_payload.get("verdict")
    if verdict not in ("ATTACK", "ANOMALY"):
        return

    event_data = {
        "event":      "alert",
        "data": {
            "alert_id":         verdict_payload.get("alert_id"),
            "timestamp":        verdict_payload.get("timestamp"),
            "verdict":          verdict,
            "detection_source": verdict_payload.get("detection_source"),
            "severity":         verdict_payload.get("severity"),
            "attack_type":      verdict_payload.get("attack_type"),
            "confidence":       verdict_payload.get("confidence"),
            "request_summary":  verdict_payload.get("request_summary", {}),
        },
    }

    try:
        _socketio.emit("alert", event_data)
        log.info(
            "Socket.IO alert emitted: verdict=%s attack_type=%s",
            verdict, verdict_payload.get("attack_type"),
        )
    except Exception as exc:
        log.error("Socket.IO emit failed: %s", exc)
