"""
tests/test_milestone_1.py
=========================
Milestone 1 tests: adapter imports, model loading, and config key presence.

Run with:
    pytest tests/test_milestone_1.py -v
from the aa_ids_backend/ directory (or from project root with conftest on path).
"""

import pathlib
import sys

# Ensure aa_ids_backend is importable (conftest also handles this, but belt-and-braces)
_BACKEND_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))


def test_rule_adapter_import():
    """adapt_rule_engine must be importable and callable."""
    from engines.rule_adapter import adapt_rule_engine
    assert callable(adapt_rule_engine)


def test_rule_engine_singleton_loaded():
    """The CRSEngine instance must be created at import time (not None)."""
    from engines import rule_adapter
    assert rule_adapter._ENGINE is not None
    assert rule_adapter._ENGINE.threshold == 5  # default from config


def test_ml_adapter_import_and_model_loaded():
    """adapt_ml_model must be callable and MODEL must be non-None."""
    from engines.ml_adapter import adapt_ml_model, MODEL
    assert MODEL is not None
    assert callable(adapt_ml_model)


def test_ml_model_has_expected_estimators():
    """The loaded RF model must have 300 estimators (as trained)."""
    from engines.ml_adapter import MODEL
    assert MODEL.n_estimators == 300


def test_config_keys_present():
    """All mandatory config keys must exist as module-level attributes."""
    import config
    required_keys = [
        "ML_MODEL_PATH",
        "ML_CONFIDENCE_THRESHOLD",
        "FLASK_SECRET_KEY",
        "RULE_ENGINE_THRESHOLD",
        "SOCKETIO_CORS_ORIGINS",
        "ML_SCALER_PATH",
        "ML_FEATURE_NAMES_PATH",
    ]
    for key in required_keys:
        assert hasattr(config, key), f"config.{key} is missing"


def test_config_threshold_type():
    """ML_CONFIDENCE_THRESHOLD must be a float."""
    import config
    assert isinstance(config.ML_CONFIDENCE_THRESHOLD, float)


def test_config_severity_levels():
    """RULE_ENGINE_SEVERITY_LEVELS must contain the four standard levels."""
    import config
    for level in ["low", "medium", "high", "critical"]:
        assert level in config.RULE_ENGINE_SEVERITY_LEVELS
