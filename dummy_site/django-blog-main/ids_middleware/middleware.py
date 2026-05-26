"""
IDS Traffic Interception Middleware.

This module defines the Django middleware that intercepts HTTP requests
and forwards metadata to the AI-Augmented IDS backend for analysis.

Architecture
------------
Request arrives
    → IDSMiddleware.__call__
        → payload_builder.build_payload()   # extract metadata (MW-002)
        → get_response(request)             # Django processes request normally
        → async_forwarder.forward_async()   # fire-and-forget to IDS (MW-004)
    → Response returned to client

Requirements satisfied
----------------------
MW-001  All HTTP methods intercepted (GET, POST, PUT, DELETE, HEAD)
MW-002  Metadata extracted: method, path, query, body, headers
MW-003  JSON POSTed to IDS_BACKEND_URL/api/v1/analyse
MW-004  Forwarding is asynchronous — response is never delayed
MW-005  All errors logged; middleware never raises to the caller
MW-006  IDS_BACKEND_URL and IDS_API_KEY read from environment variables
"""

from .payload_builder import build_payload
from .async_forwarder import forward_async
from .logger import logger
from .config import IDS_BACKEND_URL


class IDSMiddleware:
    """Intercepts every HTTP request and asynchronously forwards metadata to the IDS backend.

    Satisfies:
    - MW-001: intercepts all HTTP methods
    - MW-002: extracts method, path, query, body, headers via payload_builder
    - MW-003: forwards to IDS backend POST /api/v1/analyse
    - MW-004: forwarding is asynchronous via ThreadPoolExecutor
    - MW-005: errors are logged; middleware never crashes the application
    """

    def __init__(self, get_response):
        self.get_response = get_response
        if not IDS_BACKEND_URL:
            logger.warning(
                "IDS_BACKEND_URL is not configured — IDS traffic forwarding is DISABLED. "
                "Set IDS_BACKEND_URL in your environment or .env file."
            )
        logger.debug("IDSMiddleware initialised")

    def __call__(self, request):
        # Build the metadata payload before the view runs so we capture
        # the raw body (Django may consume it during view processing).
        try:
            payload = build_payload(request)
            logger.debug(
                "IDS intercepted %s %s",
                payload.get("method"),
                payload.get("path"),
            )
        except Exception as exc:  # noqa: BLE001 — MW-005
            logger.error("Failed to build IDS payload: %s", exc)
            payload = None

        # Let Django process the request normally — IDS must not block this.
        response = self.get_response(request)

        # Fire-and-forget: forward metadata to IDS backend after response is ready.
        if payload is not None:
            try:
                forward_async(payload)
                logger.debug(
                    "IDS forwarding submitted for %s %s (response %s)",
                    payload.get("method"),
                    payload.get("path"),
                    response.status_code,
                )
            except Exception as exc:  # noqa: BLE001 — MW-005
                logger.error("Failed to submit IDS forwarding task: %s", exc)

        return response
