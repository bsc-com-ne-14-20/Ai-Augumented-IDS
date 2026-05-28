"""
config.py
=========
Centralized configuration for the AA-IDS Flask backend.

SRS Requirements: Section 7.2 (Environment Variables)

All file paths and tunable parameters are read from environment variables.
A .env file in the project root is loaded automatically via python-dotenv.

Usage
-----
    import config
    path = config.ML_MODEL_PATH
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env if present
load_dotenv()

# Project root
_REPO_ROOT = Path(__file__).resolve().parent

# ── ML Model ──────────────────────────────────────────────────────────────────
ML_MODEL_PATH: str = os.environ.get(
    "ML_MODEL_PATH",
    str(_REPO_ROOT / "models" / "rf_model.joblib"),
)

ML_SCALER_PATH: str = os.environ.get(
    "ML_SCALER_PATH",
    str(_REPO_ROOT / "data" / "final" / "scaler.pkl"),
)

ML_FEATURE_NAMES_PATH: str = os.environ.get(
    "ML_FEATURE_NAMES_PATH",
    str(_REPO_ROOT / "data" / "final" / "feature_names.txt"),
)

ML_CONFIDENCE_THRESHOLD: float = float(
    os.environ.get("ML_CONFIDENCE_THRESHOLD", "0.65")
)

# Number of features the live model and scaler expect.
# Update this constant (and retrain) whenever the feature set changes.
ML_FEATURE_COUNT: int = 49

# ── Rule Engine ───────────────────────────────────────────────────────────────
RULE_ENGINE_THRESHOLD: int = int(os.environ.get("RULE_ENGINE_THRESHOLD", "5"))

# SRS RE-006: Brute force detection parameters
BF_REQUEST_THRESHOLD: int = int(os.environ.get("BF_REQUEST_THRESHOLD", "10"))
BF_TIME_WINDOW_SECONDS: int = int(os.environ.get("BF_TIME_WINDOW_SECONDS", "60"))

# ── Flask / Socket.IO ─────────────────────────────────────────────────────────
FLASK_SECRET_KEY: str = os.environ.get(
    "FLASK_SECRET_KEY", "aa-ids-dev-secret-change-in-production"
)

SOCKETIO_CORS_ORIGINS: str = os.environ.get("SOCKETIO_CORS_ORIGINS", "*")

# SRS FL-003: API key authentication
IDS_API_KEY: str = os.environ.get(
    "IDS_API_KEY", "dev-api-key-change-in-production"
)

# ── API Limits ────────────────────────────────────────────────────────────────
MAX_LOGS_PER_REQUEST: int = int(os.environ.get("MAX_LOGS_PER_REQUEST", "5000"))
DEFAULT_PAGE_SIZE: int = int(os.environ.get("DEFAULT_PAGE_SIZE", "50"))

# ── Database (for future PostgreSQL migration) ────────────────────────────────
DB_PATH: str = os.environ.get("DB_PATH", str(_REPO_ROOT / "ids.db"))
