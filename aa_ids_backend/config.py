"""
config.py
=========
Centralised configuration for the AA-IDS Flask backend.

All file paths and tunable parameters are read from environment variables so
that no values are ever hardcoded.  A .env file in the project root is loaded
automatically via python-dotenv when the app starts.

Usage
-----
    import config
    path = config.ML_MODEL_PATH
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# ── Load .env if present ─────────────────────────────────────────────────────
load_dotenv()

# ── Project root (two levels up from this file: aa_ids_backend/ → repo root) ─
_REPO_ROOT = Path(__file__).resolve().parent.parent

# ── ML model ─────────────────────────────────────────────────────────────────
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

# ── Rule engine ──────────────────────────────────────────────────────────────
RULE_ENGINE_THRESHOLD: int = int(os.environ.get("RULE_ENGINE_THRESHOLD", "5"))
RULE_ENGINE_SEVERITY_LEVELS: list[str] = ["low", "medium", "high", "critical"]

# ── Training data (used only by the model serialisation script) ───────────────
TRAIN_DATA_PATH: str = os.environ.get(
    "TRAIN_DATA_PATH",
    str(_REPO_ROOT / "data" / "final" / "train.csv"),
)

# ── Flask / Socket.IO ─────────────────────────────────────────────────────────
FLASK_SECRET_KEY: str = os.environ.get(
    "FLASK_SECRET_KEY", "aa-ids-dev-secret-change-in-production"
)

SOCKETIO_CORS_ORIGINS: str = os.environ.get("SOCKETIO_CORS_ORIGINS", "*")

# ── API limits ────────────────────────────────────────────────────────────────
MAX_LOGS_PER_REQUEST: int = int(os.environ.get("MAX_LOGS_PER_REQUEST", "5000"))
DEFAULT_PAGE_SIZE: int = int(os.environ.get("DEFAULT_PAGE_SIZE", "50"))
