"""
Unit tests for ids_middleware.async_forwarder.

Verifies that:
- forward_async submits send_to_ids to the executor.
- forward_async handles a shut-down executor gracefully.
"""

import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import django
from django.conf import settings

if not settings.configured:
    settings.configure(
        DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
        INSTALLED_APPS=["django.contrib.contenttypes", "django.contrib.auth"],
        SECRET_KEY="test-secret-key",
    )
    django.setup()

from ids_middleware.async_forwarder import forward_async  # noqa: E402

SAMPLE_PAYLOAD = {"method": "GET", "path": "/", "query_string": "", "body": "", "headers": {}}


class TestForwardAsync:
    def test_submits_to_executor(self):
        """forward_async should submit send_to_ids to the thread pool."""
        with patch("ids_middleware.async_forwarder._executor") as mock_exec:
            forward_async(SAMPLE_PAYLOAD)
            mock_exec.submit.assert_called_once()
            # First positional arg to submit should be send_to_ids
            from ids_middleware.ids_client import send_to_ids
            assert mock_exec.submit.call_args[0][0] is send_to_ids

    def test_handles_runtime_error_gracefully(self):
        """Should not raise when executor has been shut down."""
        with patch("ids_middleware.async_forwarder._executor") as mock_exec:
            mock_exec.submit.side_effect = RuntimeError("executor shut down")
            # Must not raise
            forward_async(SAMPLE_PAYLOAD)
