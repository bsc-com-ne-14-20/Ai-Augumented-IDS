"""
Asynchronous IDS forwarding utility (MW-004).

Uses a module-level ThreadPoolExecutor so that IDS forwarding never
blocks the Django response cycle.  The executor is shared across all
requests to avoid spawning a new thread per request.

Max workers is intentionally small — IDS calls are fire-and-forget
and we don't want to exhaust the thread pool under load.

Design notes
------------
- Module-level executor: created once at import time, reused for all requests.
- max_workers=4: enough concurrency for burst traffic without thread explosion.
- thread_name_prefix: makes IDS threads identifiable in stack traces / profilers.
- forward_async returns immediately; the caller (middleware) is never blocked.
- RuntimeError guard: handles the case where the executor is shut down during
  server teardown (e.g. gunicorn worker recycling).
"""

from concurrent.futures import ThreadPoolExecutor

from .ids_client import send_to_ids
from .logger import logger

# Shared executor — created once at import time.
# Reusing a single executor avoids the overhead of creating a new thread
# for every HTTP request that passes through the middleware.
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ids_fwd")


def forward_async(payload: dict) -> None:
    """Submit *payload* to the IDS backend in a background thread (MW-004).

    Returns immediately so the Django response is never delayed.
    Any exception raised inside the thread is caught by send_to_ids (MW-005).
    """
    try:
        _executor.submit(send_to_ids, payload)
    except RuntimeError:
        # Executor has been shut down (e.g. during server teardown).
        logger.warning("IDS forwarder executor is shut down — skipping forwarding")
