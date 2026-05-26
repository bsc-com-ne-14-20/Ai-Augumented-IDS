"""
IDS backend HTTP client.

Responsible for POSTing request metadata to the Flask IDS backend.
This module is intentionally kept separate from the middleware class
so it can be tested and replaced independently.

Built incrementally — timeout, auth header, and error handling
will be added in subsequent commits.
"""

import json

from .config import IDS_BACKEND_URL, IDS_API_KEY, IDS_TIMEOUT
from .logger import logger


def send_to_ids(payload: dict) -> None:
    """POST *payload* as JSON to the IDS backend analyse endpoint.

    This is a stub — actual HTTP call will be added in the next commit.
    """
    logger.debug("send_to_ids called with method=%s path=%s", payload.get("method"), payload.get("path"))
