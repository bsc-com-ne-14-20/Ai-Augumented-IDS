"""
Unit tests for ids_middleware.ids_client.

We mock urllib.request.urlopen so no real network calls are made.
Django is configured via conftest.py.
"""

import json
from unittest.mock import patch, MagicMock

from ids_middleware.ids_client import send_to_ids


SAMPLE_PAYLOAD = {
    "method": "GET",
    "path": "/about/",
    "query_string": "",
    "body": "",
    "headers": {
        "Cookie": "",
        "Content-Type": "",
        "Content-Length": "",
        "Connection": "",
        "Accept": "text/html",
    },
}


class TestSendToIds:
    def test_skips_when_no_url(self, monkeypatch):
        """Should log a warning and return without making a network call."""
        monkeypatch.setattr("ids_middleware.ids_client.IDS_BACKEND_URL", "")
        with patch("ids_middleware.ids_client.urllib.request.urlopen") as mock_open:
            send_to_ids(SAMPLE_PAYLOAD)
            mock_open.assert_not_called()

    def test_posts_json_when_url_set(self, monkeypatch):
        """Should call urlopen with a POST request containing JSON body."""
        monkeypatch.setattr("ids_middleware.ids_client.IDS_BACKEND_URL", "http://fake-ids/api/v1/analyse")
        monkeypatch.setattr("ids_middleware.ids_client.IDS_API_KEY", "test-key")

        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.status = 200

        with patch("ids_middleware.ids_client.urllib.request.urlopen", return_value=mock_resp) as mock_open:
            send_to_ids(SAMPLE_PAYLOAD)
            mock_open.assert_called_once()
            req_arg = mock_open.call_args[0][0]
            # Verify the request body contains the method field
            body = json.loads(req_arg.data.decode())
            assert body["method"] == "GET"

    def test_handles_url_error_gracefully(self, monkeypatch):
        """Should log error and not raise when backend is unreachable."""
        import urllib.error
        monkeypatch.setattr("ids_middleware.ids_client.IDS_BACKEND_URL", "http://fake-ids/api/v1/analyse")
        with patch("ids_middleware.ids_client.urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
            # Must not raise
            send_to_ids(SAMPLE_PAYLOAD)

    def test_sends_api_key_header(self, monkeypatch):
        """Should include X-IDS-API-Key header in the request."""
        monkeypatch.setattr("ids_middleware.ids_client.IDS_BACKEND_URL", "http://fake-ids/api/v1/analyse")
        monkeypatch.setattr("ids_middleware.ids_client.IDS_API_KEY", "my-secret-key")

        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.status = 200

        with patch("ids_middleware.ids_client.urllib.request.urlopen", return_value=mock_resp) as mock_open:
            send_to_ids(SAMPLE_PAYLOAD)
            req_arg = mock_open.call_args[0][0]
            assert req_arg.get_header("X-ids-api-key") == "my-secret-key"

    def test_handles_unexpected_exception_gracefully(self, monkeypatch):
        """Should log error and not raise on any unexpected exception."""
        monkeypatch.setattr("ids_middleware.ids_client.IDS_BACKEND_URL", "http://fake-ids/api/v1/analyse")
        with patch("ids_middleware.ids_client.urllib.request.urlopen", side_effect=RuntimeError("boom")):
            send_to_ids(SAMPLE_PAYLOAD)

    def test_handles_timeout_gracefully(self, monkeypatch):
        """Should log timeout error and not raise when backend times out."""
        monkeypatch.setattr("ids_middleware.ids_client.IDS_BACKEND_URL", "http://fake-ids/api/v1/analyse")
        with patch("ids_middleware.ids_client.urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            send_to_ids(SAMPLE_PAYLOAD)
