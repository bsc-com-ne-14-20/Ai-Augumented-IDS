"""
Unit tests for ids_middleware.middleware.IDSMiddleware.

Verifies that:
- The middleware calls get_response and returns the response unchanged.
- forward_async is called with the correct payload.
- Middleware does not crash when payload_builder raises.
- Middleware does not crash when forward_async raises.

Django is configured via conftest.py.
"""

from unittest.mock import patch, MagicMock

from django.test import RequestFactory
from django.http import HttpResponse
from ids_middleware.middleware import IDSMiddleware

factory = RequestFactory()


def _make_middleware(response=None):
    """Helper: return an IDSMiddleware instance with a trivial get_response."""
    if response is None:
        response = HttpResponse("OK")
    get_response = MagicMock(return_value=response)
    mw = IDSMiddleware(get_response)
    return mw, get_response


class TestIDSMiddlewareBasic:
    def test_returns_response_unchanged(self):
        """Middleware must pass the response through without modification."""
        mw, get_response = _make_middleware(HttpResponse("hello", status=200))
        req = factory.get("/")
        with patch("ids_middleware.middleware.forward_async"):
            resp = mw(req)
        assert resp.status_code == 200

    def test_get_response_called_once(self):
        """Middleware must call get_response exactly once."""
        mw, get_response = _make_middleware()
        req = factory.get("/about/")
        with patch("ids_middleware.middleware.forward_async"):
            mw(req)
        get_response.assert_called_once_with(req)

    def test_forward_async_called_with_payload(self):
        """forward_async must be called with a dict containing expected keys."""
        mw, _ = _make_middleware()
        req = factory.post("/post/new/", data=b'{"title":"hi"}', content_type="application/json")
        with patch("ids_middleware.middleware.forward_async") as mock_fwd:
            mw(req)
        mock_fwd.assert_called_once()
        payload = mock_fwd.call_args[0][0]
        assert payload["method"] == "POST"
        assert payload["path"] == "/post/new/"
        assert "headers" in payload


class TestIDSMiddlewareResilience:
    def test_does_not_crash_when_build_payload_raises(self):
        """MW-005: middleware must not crash even if payload_builder raises."""
        mw, get_response = _make_middleware()
        req = factory.get("/")
        with patch("ids_middleware.middleware.build_payload", side_effect=RuntimeError("oops")):
            with patch("ids_middleware.middleware.forward_async") as mock_fwd:
                resp = mw(req)
        assert resp.status_code == 200
        mock_fwd.assert_not_called()

    def test_does_not_crash_when_forward_async_raises(self):
        """MW-005: middleware must not crash even if forward_async raises."""
        mw, _ = _make_middleware()
        req = factory.get("/")
        with patch("ids_middleware.middleware.forward_async", side_effect=RuntimeError("thread pool dead")):
            resp = mw(req)
        assert resp.status_code == 200


class TestIDSMiddlewareHttpMethods:
    """MW-001: verify all required HTTP methods are intercepted."""

    def _run(self, req):
        mw, _ = _make_middleware()
        with patch("ids_middleware.middleware.forward_async") as mock_fwd:
            mw(req)
        return mock_fwd.call_args[0][0]["method"]

    def test_intercepts_get(self):
        assert self._run(factory.get("/")) == "GET"

    def test_intercepts_post(self):
        assert self._run(factory.post("/", data={})) == "POST"

    def test_intercepts_put(self):
        assert self._run(factory.put("/", data=b"x", content_type="application/json")) == "PUT"

    def test_intercepts_delete(self):
        assert self._run(factory.delete("/")) == "DELETE"

    def test_intercepts_head(self):
        assert self._run(factory.head("/")) == "HEAD"
