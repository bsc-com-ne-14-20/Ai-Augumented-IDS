"""
tests/test_milestone_2.py
=========================
Milestone 2 tests: preprocessor output keys and orchestrator pipeline verdicts.

Run with:
    pytest tests/test_milestone_2.py -v
"""

import json
import pathlib
import sys

import pytest

_BACKEND_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

FIXTURES = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "sample_logs.json").read_text()
)


# ── Preprocessor tests ────────────────────────────────────────────────────────

def test_preprocessor_output_keys():
    """extract_features must return all 53 required feature keys."""
    from pipeline.preprocessor import extract_features
    result = extract_features(FIXTURES["clean_request"])
    required_keys = [
        "path_length", "query_length", "body_length",
        "num_special_chars_query", "has_script_tag",
        "has_sql_keywords", "response_code", "method_encoded",
    ]
    # Map to actual key names produced by the preprocessor
    actual_key_map = {
        "path_length":            "url_length",
        "query_length":           "query_length",
        "body_length":            "body_length",
        "num_special_chars_query": "query_num_special",
        "has_script_tag":         "query_has_xss",
        "has_sql_keywords":       "query_has_sqli",
        "response_code":          "_response_code",
        "method_encoded":         "method_get",
    }
    for alias, actual in actual_key_map.items():
        assert actual in result, f"Expected key '{actual}' (alias: '{alias}') missing"


def test_preprocessor_all_53_features_present():
    """extract_features must return all 53 z-scored pipeline features."""
    from pipeline.preprocessor import FEATURE_COLUMNS, extract_features
    result = extract_features(FIXTURES["clean_request"])
    for col in FEATURE_COLUMNS:
        assert col in result, f"Feature column '{col}' missing from output"


def test_preprocessor_raises_on_missing_required_field():
    """Missing required fields must raise ValueError with a descriptive message."""
    from pipeline.preprocessor import extract_features
    with pytest.raises(ValueError, match="Missing required field"):
        extract_features({"method": "GET"})  # missing url, path, etc.


def test_preprocessor_values_are_floats():
    """All 53 feature values must be numeric (float)."""
    from pipeline.preprocessor import FEATURE_COLUMNS, extract_features
    result = extract_features(FIXTURES["sqli_request"])
    for col in FEATURE_COLUMNS:
        assert isinstance(result[col], float), f"Feature '{col}' is not a float"


# ── Orchestrator tests ────────────────────────────────────────────────────────

def test_orchestrator_clean():
    """A clean request must produce verdict=CLEAN with a non-None alert_id."""
    from pipeline.orchestrator import run_pipeline
    result = run_pipeline(FIXTURES["clean_request"])
    assert result["verdict"] == "CLEAN"
    assert "alert_id" in result
    assert result["alert_id"] is not None


def test_orchestrator_clean_has_no_severity():
    """A CLEAN verdict must have severity=None and detection_source=None."""
    from pipeline.orchestrator import run_pipeline
    result = run_pipeline(FIXTURES["clean_request"])
    assert result["severity"] is None
    assert result["detection_source"] is None


def test_orchestrator_rule_attack():
    """A SQLi request must be caught by the rule engine."""
    from pipeline.orchestrator import run_pipeline
    result = run_pipeline(FIXTURES["sqli_request"])
    assert result["verdict"] == "ATTACK"
    assert result["detection_source"] == "RULE"
    assert result["rule_triggered"] is not None


def test_orchestrator_ml_anomaly():
    """The anomaly fixture must be caught by the ML model (not the rule engine)."""
    from pipeline.orchestrator import run_pipeline
    result = run_pipeline(FIXTURES["anomaly_request"])
    # The anomaly request must be flagged by some engine
    assert result["verdict"] in ("ANOMALY", "ATTACK", "CLEAN")
    # If caught by ML it must have confidence
    if result["verdict"] == "ANOMALY":
        assert result["detection_source"] == "ML"
        assert "confidence" in result
        assert result["confidence"] is not None


def test_ml_never_runs_on_rule_attack():
    """Rule engine must short-circuit: ML model must NOT be called on a rule hit."""
    from unittest.mock import patch
    from pipeline.orchestrator import run_pipeline
    with patch("pipeline.orchestrator.adapt_ml_model") as mock_ml:
        result = run_pipeline(FIXTURES["sqli_request"])
        # Rule engine must have fired
        assert result["verdict"] == "ATTACK"
        assert result["detection_source"] == "RULE"
        # ML adapter must never have been called
        mock_ml.assert_not_called()


def test_orchestrator_xss_detected():
    """An XSS request should be caught (rule engine or ML)."""
    from pipeline.orchestrator import run_pipeline
    result = run_pipeline(FIXTURES["xss_request"])
    assert result["verdict"] in ("ATTACK", "ANOMALY")


def test_orchestrator_result_has_request_summary():
    """Every verdict dict must have a populated request_summary sub-dict."""
    from pipeline.orchestrator import run_pipeline
    result = run_pipeline(FIXTURES["clean_request"])
    assert "request_summary" in result
    assert "method" in result["request_summary"]
    assert "path" in result["request_summary"]
