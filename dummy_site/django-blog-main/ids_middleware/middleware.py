"""
IDS Traffic Interception Middleware.

This module defines the Django middleware that intercepts HTTP requests
and forwards metadata to the AI-Augmented IDS backend for analysis.
"""


class IDSMiddleware:
    """Bare-bones pass-through middleware skeleton.

    Will be extended incrementally to extract request metadata and
    forward it asynchronously to the IDS backend.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Phase 1: pre-response hook (will add interception logic here)
        response = self.get_response(request)
        # Phase 2: post-response hook (will add async forwarding here)
        return response
