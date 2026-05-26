"""
IDS backend HTTP client (MW-003, MW-004, MW-005, MW-006).

Responsible for POSTing request metadata to the Flask IDS backend.
This module is intentionally kept separate from the middleware class
so it can be tested and replaced independently.

Responsibilities
----------------
- Serialise the payload dict as JSON.
- Attach the X-IDS-API-Key authentication header (MW-006).
- Enforce the 500 ms timeout (MW-004).
- Log and swallow all errors so the middleware never crashes (MW-005).

No third-party HTTP library is used — stdlib urllib keeps the dependency
footprint minimal and avoids version conflicts with the host project.
"""

import json
import urllib.request
import urllib.error

from .config import IDS_BACKEND_URL, IDS_API_KEY, IDS_TIMEOUT
from .logger import logger


def _build_request(payload: dict) -> "urllib.request.Request":
    """Build the urllib Request object for the IDS backend POST call."""
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "X-IDS-API-Key": IDS_API_KEY,
    }
    return urllib.request.Request(
        url=IDS_BACKEND_URL,
        data=body,
        headers=headers,
        method="POST",
    )


def send_to_ids(payload: dict) -> None:
    """POST *payload* as JSON to the IDS backend analyse endpoint (MW-003).

    Uses the stdlib urllib so no extra dependency is required.
    Timeout is capped at IDS_TIMEOUT (500 ms) per MW-004.
    Errors are logged and swallowed per MW-005.
    """
    if not IDS_BACKEND_URL:
        logger.warning("IDS_BACKEND_URL is not set — skipping IDS forwarding")
        return

    req = _build_request(payload)

    try:
        with urllib.request.urlopen(req, timeout=IDS_TIMEOUT) as resp:
            logger.debug("IDS backend responded with status %s", resp.status)
    except urllib.error.URLError as exc:
        logger.error("IDS backend unreachable: %s", exc.reason)
    except TimeoutError:
        logger.error("IDS backend timed out after %.3fs — skipping", IDS_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected error forwarding to IDS backend: %s", exc)
