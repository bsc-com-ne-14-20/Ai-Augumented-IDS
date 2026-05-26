"""
Environment variable configuration for the IDS middleware.

All secrets and URLs are read from environment variables.
Nothing is hardcoded here — see .env.example for required keys.
"""

import os

# URL of the Flask IDS backend's analyse endpoint.
# Example: https://your-droplet-ip/api/v1/analyse
IDS_BACKEND_URL: str = os.environ.get("IDS_BACKEND_URL", "")

# Shared secret sent as X-IDS-API-Key header to authenticate with the backend.
IDS_API_KEY: str = os.environ.get("IDS_API_KEY", "")

# Maximum time (seconds) to wait for the IDS backend before giving up.
# Can be overridden via IDS_TIMEOUT env var. Default is 500 ms (MW-004).
IDS_TIMEOUT: float = float(os.environ.get("IDS_TIMEOUT", "0.5"))
