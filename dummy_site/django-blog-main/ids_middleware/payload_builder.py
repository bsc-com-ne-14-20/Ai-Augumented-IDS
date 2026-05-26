"""
Payload builder for the IDS middleware.

Extracts request metadata from a Django HttpRequest object and
returns a plain dict ready to be serialised as JSON.

Built incrementally — more fields will be added in later commits.
"""


def extract_http_method(request) -> str:
    """Return the HTTP method of the request (MW-001, MW-002)."""
    return request.method


def extract_path(request) -> str:
    """Return the full URL path (e.g. /post/3/update/)."""
    return request.path


def extract_query_string(request) -> str:
    """Return the raw query string (e.g. 'page=2&sort=asc'), empty string if none."""
    return request.META.get("QUERY_STRING", "")


def extract_body(request) -> str:
    """Safely decode the raw request body as a UTF-8 string (MW-002).

    Falls back to an empty string if the body is absent or cannot be decoded.
    Reading request.body on a streaming request can raise, so we guard with
    a broad except to satisfy MW-005 (middleware must never crash).
    """
    try:
        return request.body.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""


# Headers required by MW-002
_HEADER_MAP = {
    "Cookie": "HTTP_COOKIE",
    "Content-Type": "CONTENT_TYPE",
    "Content-Length": "CONTENT_LENGTH",
    "Connection": "HTTP_CONNECTION",
    "Accept": "HTTP_ACCEPT",
}


def extract_headers(request) -> dict:
    """Extract the MW-002 required headers from the Django META dict.

    Returns a dict with human-readable header names as keys.
    Missing headers are represented as empty strings.
    """
    return {
        header: request.META.get(meta_key, "")
        for header, meta_key in _HEADER_MAP.items()
    }


def build_payload(request) -> dict:
    """Assemble the complete JSON payload to send to the IDS backend (MW-002, MW-003).

    Returns a plain dict — the caller is responsible for JSON serialisation.
    """
    return {
        "method": extract_http_method(request),
        "path": extract_path(request),
        "query_string": extract_query_string(request),
        "body": extract_body(request),
        "headers": extract_headers(request),
    }
