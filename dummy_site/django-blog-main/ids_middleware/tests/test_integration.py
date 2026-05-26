"""
Integration tests for the full IDS middleware pipeline.

These tests exercise the complete chain:
    Request → IDSMiddleware → payload_builder → async_forwarder → send_to_ids

The IDS backend HTTP call is mocked so no real network is needed.
Django is configured via conftest.py.
"""

import json
import threading
import time
from unittest.mock import patch, MagicMock

from django.test import RequestFactory
from django.http import HttpResponse

from ids_middleware.middleware import IDSMiddleware


factory = RequestFactory()


def _make_middleware():
    get_response = MagicMock(return_value=HttpResponse("OK", status=200))
    return IDSMiddleware(get_response), get_response


class TestFullPipeline:
    """End-to-end: request → middleware → IDS backend (mocked)."""

    def test_get_request_forwarded_to_ids(self):
        """A GET request should result in a JSON POST to the IDS backend."""
        mw, _ = _make_middleware()
        captured = []

        def fake_send(payload):
            captured.append(payload)

        with patch("ids_middleware.async_forwarder.send_to_ids", side_effect=fake_send):
            req = factory.get("/about/")
            resp = mw(req)

        # Give the background thread a moment to run.
        time.sleep(0.05)
        assert resp.status_code == 200
        assert len(captured) == 1
        assert captured[0]["method"] == "GET"
        assert captured[0]["path"] == "/about/"

    def test_post_request_body_captured(self):
        """A POST request body should appear in the forwarded payload."""
        mw, _ = _make_middleware()
        captured = []

        def fake_send(payload):
            captured.append(payload)

        with patch("ids_middleware.async_forwarder.send_to_ids", side_effect=fake_send):
            req = factory.post("/post/new/", data=b'{"title":"test"}', content_type="application/json")
            mw(req)

        time.sleep(0.05)
        assert len(captured) == 1
        assert "title" in captured[0]["body"]

    def test_response_not_delayed_by_ids_slow_backend(self):
        """Response must be returned before IDS backend finishes (MW-004)."""
        mw, _ = _make_middleware()

        def slow_send(payload):
            time.sleep(0.3)  # Simulate slow IDS backend

        with patch("ids_middleware.async_forwarder.send_to_ids", side_effect=slow_send):
            req = factory.get("/")
            start = time.monotonic()
            resp = mw(req)
            elapsed = time.monotonic() - start

        # Response should come back well under 100ms even though IDS takes 300ms
        assert elapsed < 0.1, f"Response took {elapsed:.3f}s — middleware is blocking"
        assert resp.status_code == 200

    def test_ids_backend_failure_does_not_affect_response(self):
        """MW-005: IDS backend failure must not affect the user response."""
        mw, _ = _make_middleware()

        def failing_send(payload):
            raise ConnectionError("IDS backend down")

        with patch("ids_middleware.async_forwarder.send_to_ids", side_effect=failing_send):
            req = factory.get("/")
            resp = mw(req)

        assert resp.status_code == 200

    def test_all_five_http_methods_forwarded(self):
        """MW-001: all five HTTP methods must be intercepted and forwarded."""
        methods_seen = []

        def capture_send(payload):
            methods_seen.append(payload["method"])

        requests = [
            factory.get("/"),
            factory.post("/", data={}),
            factory.put("/", data=b"x", content_type="application/json"),
            factory.delete("/"),
            factory.head("/"),
        ]

        with patch("ids_middleware.async_forwarder.send_to_ids", side_effect=capture_send):
            for req in requests:
                mw, _ = _make_middleware()
                mw(req)

        time.sleep(0.05)
        assert set(methods_seen) == {"GET", "POST", "PUT", "DELETE", "HEAD"}
