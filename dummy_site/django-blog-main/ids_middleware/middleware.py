"""
ids_middleware/middleware.py
============================
Django middleware that forwards every request to the IDS backend
asynchronously (fire-and-forget) so the user never sees added latency.
"""
import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

import requests

from ids_middleware.config import IDS_BACKEND_URL, IDS_API_KEY, IDS_TIMEOUT, IDS_MAX_WORKERS

log = logging.getLogger(__name__)
_pool = ThreadPoolExecutor(max_workers=IDS_MAX_WORKERS)


def _forward(payload: dict) -> None:
    """Send request data to IDS backend in a background thread."""
    if not IDS_BACKEND_URL or not IDS_API_KEY:
        return
    try:
        requests.post(
            IDS_BACKEND_URL,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-IDS-API-Key": IDS_API_KEY,
            },
            timeout=IDS_TIMEOUT,
        )
    except Exception as exc:
        log.debug("IDS forward failed: %s", exc)


class IDSMiddleware:
    """Fire-and-forget IDS forwarding middleware."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Read body before the view consumes it
        try:
            body = request.body.decode("utf-8", errors="replace")
        except Exception:
            body = ""

        payload = {
            "method":       request.method,
            "url":          request.path,
            "query_string": request.META.get("QUERY_STRING", ""),
            "body":         body,
            "headers": {
                "content-type": request.META.get("CONTENT_TYPE", ""),
                "user-agent":   request.META.get("HTTP_USER_AGENT", ""),
                "cookie":       request.META.get("HTTP_COOKIE", ""),
            },
            "source_ip": request.META.get("REMOTE_ADDR", "unknown"),
        }

        # Fire and forget — don't block the response
        _pool.submit(_forward, payload)

        return self.get_response(request)
