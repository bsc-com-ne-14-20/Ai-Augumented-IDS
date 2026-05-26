"""
Logging setup for the IDS middleware.

Uses Django's standard logging infrastructure so log output
is controlled by the LOGGING dict in settings.py.
"""

import logging

# Named logger — configure in settings.py LOGGING dict if needed.
logger = logging.getLogger("ids_middleware")
