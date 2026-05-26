"""
Unit tests for ids_middleware.payload_builder.

These tests use Django's RequestFactory so they don't need a running server.
Django is configured via conftest.py.
"""

from django.test import RequestFactory

from ids_middleware.payload_builder import (
    extract_http_method,
    extract_path,
    extract_query_string,
    extract_body,
    extract_headers,
    build_payload,
)

factory = RequestFactory()


class TestExtractHttpMethod:
    def test_get(self):
        req = factory.get("/some/path/")
        assert extract_http_method(req) == "GET"

    def test_post(self):
        req = factory.post("/some/path/", data={})
        assert extract_http_method(req) == "POST"

    def test_put(self):
        req = factory.put("/some/path/", data=b"body", content_type="application/json")
        assert extract_http_method(req) == "PUT"

    def test_delete(self):
        req = factory.delete("/some/path/")
        assert extract_http_method(req) == "DELETE"

    def test_head(self):
        req = factory.head("/some/path/")
        assert extract_http_method(req) == "HEAD"


class TestExtractPath:
    def test_simple_path(self):
        req = factory.get("/post/3/update/")
        assert extract_path(req) == "/post/3/update/"

    def test_root_path(self):
        req = factory.get("/")
        assert extract_path(req) == "/"


class TestExtractQueryString:
    def test_with_query(self):
        req = factory.get("/", {"page": "2", "sort": "asc"})
        qs = extract_query_string(req)
        assert "page=2" in qs

    def test_no_query(self):
        req = factory.get("/about/")
        assert extract_query_string(req) == ""


class TestExtractBody:
    def test_json_body(self):
        req = factory.post("/api/", data=b'{"key":"val"}', content_type="application/json")
        body = extract_body(req)
        assert "key" in body

    def test_empty_body(self):
        req = factory.get("/")
        body = extract_body(req)
        assert body == ""


class TestExtractHeaders:
    def test_content_type_present(self):
        req = factory.post("/api/", data=b"{}", content_type="application/json")
        headers = extract_headers(req)
        assert "application/json" in headers["Content-Type"]

    def test_missing_headers_are_empty_string(self):
        req = factory.get("/")
        headers = extract_headers(req)
        # Connection header is not set by RequestFactory
        assert headers["Connection"] == ""


class TestBuildPayload:
    def test_all_keys_present(self):
        req = factory.post("/post/new/", data=b'{"title":"hi"}', content_type="application/json")
        payload = build_payload(req)
        assert set(payload.keys()) == {"method", "path", "query_string", "body", "headers"}

    def test_method_and_path(self):
        req = factory.get("/about/")
        payload = build_payload(req)
        assert payload["method"] == "GET"
        assert payload["path"] == "/about/"
