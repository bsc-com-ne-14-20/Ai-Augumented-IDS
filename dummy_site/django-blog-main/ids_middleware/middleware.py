"""
IDS Traffic Interception Middleware.

This module defines the Django middleware that intercepts HTTP requests
and forwards metadata to the AI-Augmented IDS backend for analysis.
"""

from .payload_builder import build_payload
from .async_forwarder import forward_async
from .logger import logger


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
        logger.debug("IDSMiddleware initialised")

    def __call__(self, request):
        # Build the metadata payload before the view runs so we capture
        # the raw body (Django may consume it during view processing).
        try:
            payload = build_payload(request)
        except Exception as exc:  # noqa: BLE001 — MW-005
            logger.error("Failed to build IDS payload: %s", exc)
            payload = None

        # Let Django process the request normally — IDS must not block this.
        response = self.get_response(request)

        # Fire-and-forget: forward metadata to IDS backend after response is ready.
        if payload is not None:
            forward_async(payload)

        return response
