"""
Payload builder for the IDS middleware.

Extracts request metadata from a Django HttpRequest object and
returns a plain dict ready to be serialised as JSON.

Built incrementally — more fields will be added in later commits.
"""


def extract_http_method(request) -> str:
    """Return the HTTP method of the request (MW-001, MW-002)."""
    return request.method
