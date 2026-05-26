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
