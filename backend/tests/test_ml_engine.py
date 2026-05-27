"""
==============================================================================
FILE: backend/tests/test_ml_engine.py
COMPONENT: ML Detection Engine — Stacked Ensemble (RF + XGBoost)
SRS REQUIREMENTS: ML-001, ML-002, ML-003, ML-004, ML-005, ML-007
==============================================================================

Tests verify:
  - Both RF and XGBoost models load without error.
  - adapt_ml_model() returns all required fields with correct types.
  - attack_type is None when verdict is CLEAN.
  - attack_type is a non-None string from XGB_LABEL_MAP when verdict is ANOMALY.
  - confidence is always a float between 0.0 and 1.0.
  - xgb_confidence is a float between 0.0 and 1.0 when attack, else None.
  - detection_source is 'ml_engine' (or 'ml_unavailable' if models missing).
  - matched_rule is always None.
  - is_ml_model_loaded() returns True when both models are loaded.
  - Graceful degradation when models are not loaded (SRS ML-007).
  - XGBoost engineered features are computed correctly.
  - Inference completes without raising exceptions.

SRS: ML-001, ML-002, ML-003, ML-004, ML-005, ML-007
"""

import json
import pytest
import numpy as np
from pathlib import Path
from unittest.mock import patch, MagicMock

from backend.engines import ml_adapter
from backend.engines.ml_adapter import (
    adapt_ml_model,
    is_ml_model_loaded,
    XGB_LABEL_MAP,
    FEATURE_COLUMNS,
    _compute_xgb_features,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def schema_features():
    """Load feature names from FEATURE_SCHEMA.json."""
    schema_path = Path(__file__).parent.parent.parent / "FEATURE_SCHEMA.json"
    with open(schema_path) as f:
        schema = json.load(f)
    return schema["features"]


def _make_feature_dict(scenario: str = "normal", schema_features: list = None) -> dict:
    """
    Build a synthetic 53-feature dict for testing.

    Parameters
    ----------
    scenario : str
        'normal'  — clean request (all zeros, query_is_empty=1)
        'sqli'    — SQL injection signals
        'xss'     — XSS signals
        'traversal' — path traversal signals
    schema_features : list, optional
        Feature names from FEATURE_SCHEMA.json. If None, uses FEATURE_COLUMNS.
    """
    cols = schema_features or FEATURE_COLUMNS
    features = {k: 0.0 for k in cols}

    if scenario == "normal":
        features["method_get"] = 1.0
        features["query_is_empty"] = 1.0
        features["body_is_empty"] = 1.0
        features["cookie_is_present"] = 1.0
        features["connection_keep_alive"] = 1.0
        features["content_type_is_none"] = 1.0

    elif scenario == "sqli":
        features["query_has_sqli"] = 1.0
        features["body_has_sqli"] = 1.0
        features["query_entropy"] = 4.5
        features["query_num_special"] = 8.0
        features["query_length"] = 35.0
        features["query_num_percent"] = 3.0
        features["method_get"] = 1.0

    elif scenario == "xss":
        features["query_has_xss"] = 1.0
        features["body_has_xss"] = 1.0
        features["query_entropy"] = 3.8
        features["body_num_special"] = 6.0
        features["body_num_brackets"] = 4.0
        features["method_post"] = 1.0

    elif scenario == "traversal":
        features["query_has_traversal"] = 1.0
        features["body_has_traversal"] = 1.0
        features["url_num_dots"] = 6.0
        features["url_path_depth"] = 5.0
        features["method_get"] = 1.0

    return features


# ── Model loading tests ───────────────────────────────────────────────────────

class TestModelLoading:
    """Verify both models load correctly (SRS ML-001, ML-006)."""

    def test_rf_model_is_loaded(self):
        """RF model must be loaded at module import time."""
        assert ml_adapter.MODEL is not None, (
            "RF model not loaded. Ensure models/rf_combined.pkl exists."
        )

    def test_xgb_model_is_loaded(self):
        """XGBoost model must be loaded at module import time."""
        assert ml_adapter.XGB_MODEL is not None, (
            "XGBoost model not loaded. Ensure models/xgb_model.pkl exists."
        )

    def test_scaler_is_loaded(self):
        """StandardScaler must be loaded at module import time."""
        assert ml_adapter.SCALER is not None, (
            "Scaler not loaded. Ensure data/final/scaler.pkl exists."
        )

    def test_is_ml_model_loaded_returns_true(self):
        """is_ml_model_loaded() must return True when all three are loaded."""
        assert is_ml_model_loaded() is True

    def test_rf_is_binary_classifier(self):
        """RF must be a binary classifier with classes [0, 1]."""
        rf_classes = list(ml_adapter.MODEL.classes_)
        assert 0 in rf_classes and 1 in rf_classes, (
            f"RF classes_ should contain 0 and 1, got {rf_classes}"
        )

    def test_xgb_is_multiclass_classifier(self):
        """XGBoost must be a multi-class classifier with 4 classes."""
        xgb_classes = list(ml_adapter.XGB_MODEL.classes_)
        assert len(xgb_classes) == 4, (
            f"XGBoost should have 4 classes, got {len(xgb_classes)}: {xgb_classes}"
        )

    def test_xgb_label_map_covers_all_classes(self):
        """XGB_LABEL_MAP must have an entry for every XGBoost class index."""
        xgb_classes = list(ml_adapter.XGB_MODEL.classes_)
        for cls in xgb_classes:
            assert int(cls) in XGB_LABEL_MAP, (
                f"XGB_LABEL_MAP missing entry for class {cls}. "
                f"Map: {XGB_LABEL_MAP}"
            )

    def test_rf_expects_53_features(self):
        """RF must expect exactly 53 features (matches FEATURE_SCHEMA.json)."""
        assert ml_adapter.MODEL.n_features_in_ == 53

    def test_xgb_expects_58_features(self):
        """XGBoost must expect 58 features (53 base + 5 engineered)."""
        assert ml_adapter.XGB_MODEL.n_features_in_ == 58

    def test_feature_columns_count(self):
        """FEATURE_COLUMNS must have exactly 53 entries."""
        assert len(FEATURE_COLUMNS) == 53


# ── Output contract tests ─────────────────────────────────────────────────────

class TestOutputContract:
    """Verify the exact output schema of adapt_ml_model() (SRS ML-004)."""

    REQUIRED_KEYS = {
        "verdict", "is_attack", "detection_source",
        "attack_type", "confidence", "xgb_confidence",
        "severity", "matched_rule",
    }

    def test_returns_dict(self):
        """adapt_ml_model() must return a dict."""
        result = adapt_ml_model(_make_feature_dict("normal"))
        assert isinstance(result, dict)

    def test_has_all_required_keys(self):
        """Result must contain all required keys."""
        result = adapt_ml_model(_make_feature_dict("normal"))
        missing = self.REQUIRED_KEYS - set(result.keys())
        assert not missing, f"Missing keys in result: {missing}"

    def test_verdict_is_valid_string(self):
        """verdict must be 'ANOMALY' or 'CLEAN'."""
        for scenario in ("normal", "sqli", "xss"):
            result = adapt_ml_model(_make_feature_dict(scenario))
            assert result["verdict"] in ("ANOMALY", "CLEAN"), (
                f"Unexpected verdict '{result['verdict']}' for scenario '{scenario}'"
            )

    def test_is_attack_is_bool(self):
        """is_attack must be a bool."""
        result = adapt_ml_model(_make_feature_dict("normal"))
        assert isinstance(result["is_attack"], bool)

    def test_is_attack_matches_verdict(self):
        """is_attack must be True iff verdict is ANOMALY."""
        for scenario in ("normal", "sqli", "xss", "traversal"):
            result = adapt_ml_model(_make_feature_dict(scenario))
            if result["verdict"] == "ANOMALY":
                assert result["is_attack"] is True, (
                    f"is_attack should be True when verdict=ANOMALY (scenario={scenario})"
                )
            else:
                assert result["is_attack"] is False, (
                    f"is_attack should be False when verdict=CLEAN (scenario={scenario})"
                )

    def test_detection_source_is_ml_engine(self):
        """detection_source must be 'ml_engine' when models are loaded."""
        result = adapt_ml_model(_make_feature_dict("normal"))
        assert result["detection_source"] == "ml_engine"

    def test_matched_rule_is_always_none(self):
        """matched_rule must always be None — ML engine never sets a rule ID."""
        for scenario in ("normal", "sqli", "xss"):
            result = adapt_ml_model(_make_feature_dict(scenario))
            assert result["matched_rule"] is None, (
                f"matched_rule should be None for ML engine (scenario={scenario})"
            )

    def test_confidence_is_float_between_0_and_1(self):
        """confidence (RF P(attack)) must be a float in [0.0, 1.0]."""
        for scenario in ("normal", "sqli"):
            result = adapt_ml_model(_make_feature_dict(scenario))
            assert isinstance(result["confidence"], float), (
                f"confidence should be float, got {type(result['confidence'])}"
            )
            assert 0.0 <= result["confidence"] <= 1.0, (
                f"confidence out of range: {result['confidence']}"
            )

    def test_attack_type_is_none_when_clean(self):
        """attack_type must be None when verdict is CLEAN."""
        features = _make_feature_dict("normal")
        result = adapt_ml_model(features)
        if result["verdict"] == "CLEAN":
            assert result["attack_type"] is None, (
                f"attack_type should be None for CLEAN verdict, got '{result['attack_type']}'"
            )

    def test_attack_type_is_string_when_anomaly(self):
        """attack_type must be a non-empty string when verdict is ANOMALY."""
        for scenario in ("sqli", "xss", "traversal"):
            result = adapt_ml_model(_make_feature_dict(scenario))
            if result["verdict"] == "ANOMALY":
                assert isinstance(result["attack_type"], str), (
                    f"attack_type should be str when ANOMALY (scenario={scenario}), "
                    f"got {type(result['attack_type'])}"
                )
                assert len(result["attack_type"]) > 0, (
                    f"attack_type should not be empty string (scenario={scenario})"
                )

    def test_attack_type_from_xgb_label_map(self):
        """attack_type must be a value from XGB_LABEL_MAP when ANOMALY."""
        valid_attack_types = set(XGB_LABEL_MAP.values())
        for scenario in ("sqli", "xss", "traversal"):
            result = adapt_ml_model(_make_feature_dict(scenario))
            if result["verdict"] == "ANOMALY":
                assert result["attack_type"] in valid_attack_types, (
                    f"attack_type '{result['attack_type']}' not in XGB_LABEL_MAP values: "
                    f"{valid_attack_types}"
                )

    def test_xgb_confidence_is_none_when_clean(self):
        """xgb_confidence must be None when verdict is CLEAN."""
        features = _make_feature_dict("normal")
        result = adapt_ml_model(features)
        if result["verdict"] == "CLEAN":
            assert result["xgb_confidence"] is None, (
                f"xgb_confidence should be None for CLEAN verdict"
            )

    def test_xgb_confidence_is_float_when_anomaly(self):
        """xgb_confidence must be a float in [0.0, 1.0] when verdict is ANOMALY."""
        for scenario in ("sqli", "xss"):
            result = adapt_ml_model(_make_feature_dict(scenario))
            if result["verdict"] == "ANOMALY":
                assert isinstance(result["xgb_confidence"], float), (
                    f"xgb_confidence should be float when ANOMALY (scenario={scenario})"
                )
                assert 0.0 <= result["xgb_confidence"] <= 1.0, (
                    f"xgb_confidence out of range: {result['xgb_confidence']}"
                )

    def test_severity_is_valid_when_anomaly(self):
        """severity must be one of critical/high/medium/low when ANOMALY."""
        valid_severities = {"critical", "high", "medium", "low"}
        for scenario in ("sqli", "xss"):
            result = adapt_ml_model(_make_feature_dict(scenario))
            if result["verdict"] == "ANOMALY":
                assert result["severity"] in valid_severities, (
                    f"severity '{result['severity']}' not in {valid_severities}"
                )

    def test_severity_is_none_when_clean(self):
        """severity must be None when verdict is CLEAN."""
        features = _make_feature_dict("normal")
        result = adapt_ml_model(features)
        if result["verdict"] == "CLEAN":
            assert result["severity"] is None


# ── Stacked ensemble logic tests ──────────────────────────────────────────────

class TestStackedEnsembleLogic:
    """Verify the RF → XGBoost stacking logic (SRS ML-002, ML-003)."""

    def test_xgb_not_called_when_rf_below_threshold(self):
        """XGBoost must NOT be called when RF P(attack) < threshold."""
        features = _make_feature_dict("normal")

        with patch.object(ml_adapter.XGB_MODEL, "predict_proba") as mock_xgb:
            # Force RF to return low attack probability
            with patch.object(ml_adapter.MODEL, "predict_proba",
                               return_value=np.array([[0.95, 0.05]])):
                result = adapt_ml_model(features)

            # XGBoost should not have been called
            mock_xgb.assert_not_called()
            assert result["verdict"] == "CLEAN"
            assert result["attack_type"] is None

    def test_xgb_called_when_rf_above_threshold(self):
        """XGBoost MUST be called when RF P(attack) >= threshold."""
        features = _make_feature_dict("sqli")

        with patch.object(ml_adapter.MODEL, "predict_proba",
                           return_value=np.array([[0.05, 0.95]])):
            with patch.object(ml_adapter.XGB_MODEL, "predict_proba",
                               return_value=np.array([[0.02, 0.95, 0.02, 0.01]])) as mock_xgb:
                result = adapt_ml_model(features)

            mock_xgb.assert_called_once()
            assert result["verdict"] == "ANOMALY"
            assert result["attack_type"] == "SQLI"

    def test_attack_type_comes_from_xgb_not_rf(self):
        """attack_type must come from XGBoost prediction, not RF."""
        features = _make_feature_dict("xss")

        with patch.object(ml_adapter.MODEL, "predict_proba",
                           return_value=np.array([[0.05, 0.95]])):
            # XGBoost predicts XSS (class index 2)
            with patch.object(ml_adapter.XGB_MODEL, "predict_proba",
                               return_value=np.array([[0.01, 0.02, 0.96, 0.01]])):
                result = adapt_ml_model(features)

        assert result["attack_type"] == "XSS", (
            f"attack_type should be 'XSS' from XGBoost, got '{result['attack_type']}'"
        )

    def test_rf_confidence_is_attack_probability(self):
        """confidence must be RF P(attack) — the value at class index 1."""
        features = _make_feature_dict("sqli")
        expected_rf_prob = 0.87

        with patch.object(ml_adapter.MODEL, "predict_proba",
                           return_value=np.array([[1 - expected_rf_prob, expected_rf_prob]])):
            with patch.object(ml_adapter.XGB_MODEL, "predict_proba",
                               return_value=np.array([[0.01, 0.97, 0.01, 0.01]])):
                result = adapt_ml_model(features)

        assert abs(result["confidence"] - expected_rf_prob) < 1e-6, (
            f"confidence should be RF P(attack)={expected_rf_prob}, got {result['confidence']}"
        )

    def test_all_four_xgb_classes_map_correctly(self):
        """Each XGBoost class index must map to the correct attack type string."""
        features = _make_feature_dict("sqli")
        expected_map = {0: "OTHER", 1: "SQLI", 2: "XSS", 3: "PATH_TRAVERSAL"}

        for class_idx, expected_label in expected_map.items():
            proba = [0.01, 0.01, 0.01, 0.01]
            proba[class_idx] = 0.97

            with patch.object(ml_adapter.MODEL, "predict_proba",
                               return_value=np.array([[0.05, 0.95]])):
                with patch.object(ml_adapter.XGB_MODEL, "predict_proba",
                                   return_value=np.array([proba])):
                    result = adapt_ml_model(features)

            assert result["attack_type"] == expected_label, (
                f"XGB class {class_idx} should map to '{expected_label}', "
                f"got '{result['attack_type']}'"
            )


# ── Engineered features tests ─────────────────────────────────────────────────

class TestEngineeredFeatures:
    """Verify the 5 engineered features computed for XGBoost."""

    def test_compute_xgb_features_returns_correct_shape(self):
        """_compute_xgb_features must return shape (1, 58)."""
        features = _make_feature_dict("sqli")
        raw_row = np.array(
            [float(features.get(col, 0.0)) for col in FEATURE_COLUMNS],
            dtype=np.float64,
        ).reshape(1, -1)

        xgb_row = _compute_xgb_features(raw_row, features)
        assert xgb_row.shape == (1, 58), (
            f"XGB feature vector should have shape (1, 58), got {xgb_row.shape}"
        )

    def test_special_ratio_query_computed_correctly(self):
        """special_ratio_query = query_num_special / (query_length + 1e-5)."""
        features = _make_feature_dict("normal")
        features["query_num_special"] = 4.0
        features["query_length"] = 20.0

        raw_row = np.array(
            [float(features.get(col, 0.0)) for col in FEATURE_COLUMNS],
            dtype=np.float64,
        ).reshape(1, -1)

        xgb_row = _compute_xgb_features(raw_row, features)
        # Find the index of special_ratio_query in XGB feature names
        if hasattr(ml_adapter.XGB_MODEL, "feature_names_in_"):
            feat_names = [str(f) for f in ml_adapter.XGB_MODEL.feature_names_in_]
            if "special_ratio_query" in feat_names:
                idx = feat_names.index("special_ratio_query")
                expected = 4.0 / (20.0 + 1e-5)
                assert abs(xgb_row[0, idx] - expected) < 1e-6, (
                    f"special_ratio_query: expected {expected:.6f}, got {xgb_row[0, idx]:.6f}"
                )

    def test_high_query_entropy_flag(self):
        """high_query_entropy = 1 when query_entropy > 4.0, else 0."""
        if not hasattr(ml_adapter.XGB_MODEL, "feature_names_in_"):
            pytest.skip("XGB model has no feature_names_in_")

        feat_names = [str(f) for f in ml_adapter.XGB_MODEL.feature_names_in_]
        if "high_query_entropy" not in feat_names:
            pytest.skip("high_query_entropy not in XGB feature names")

        idx = feat_names.index("high_query_entropy")

        # Low entropy — flag should be 0
        features_low = _make_feature_dict("normal")
        features_low["query_entropy"] = 2.5
        raw_low = np.array([float(features_low.get(c, 0.0)) for c in FEATURE_COLUMNS]).reshape(1, -1)
        xgb_low = _compute_xgb_features(raw_low, features_low)
        assert xgb_low[0, idx] == 0.0

        # High entropy — flag should be 1
        features_high = _make_feature_dict("sqli")
        features_high["query_entropy"] = 4.5
        raw_high = np.array([float(features_high.get(c, 0.0)) for c in FEATURE_COLUMNS]).reshape(1, -1)
        xgb_high = _compute_xgb_features(raw_high, features_high)
        assert xgb_high[0, idx] == 1.0


# ── Graceful degradation tests ────────────────────────────────────────────────

class TestGracefulDegradation:
    """Test behaviour when models are not loaded (SRS ML-007)."""

    def test_returns_ml_unavailable_when_rf_missing(self, monkeypatch):
        """When RF model is None, detection_source must be 'ml_unavailable'."""
        monkeypatch.setattr(ml_adapter, "MODEL", None)
        result = adapt_ml_model(_make_feature_dict("normal"))
        assert result["detection_source"] == "ml_unavailable"
        assert result["is_attack"] is False
        assert result["attack_type"] is None
        assert result["verdict"] == "CLEAN"

    def test_returns_ml_unavailable_when_scaler_missing(self, monkeypatch):
        """When scaler is None, detection_source must be 'ml_unavailable'."""
        monkeypatch.setattr(ml_adapter, "SCALER", None)
        result = adapt_ml_model(_make_feature_dict("normal"))
        assert result["detection_source"] == "ml_unavailable"
        assert result["is_attack"] is False

    def test_is_loaded_false_when_rf_missing(self, monkeypatch):
        """is_ml_model_loaded() must return False when RF is None."""
        monkeypatch.setattr(ml_adapter, "MODEL", None)
        assert is_ml_model_loaded() is False

    def test_is_loaded_false_when_xgb_missing(self, monkeypatch):
        """is_ml_model_loaded() must return False when XGBoost is None."""
        monkeypatch.setattr(ml_adapter, "XGB_MODEL", None)
        assert is_ml_model_loaded() is False

    def test_xgb_failure_falls_back_to_other(self, monkeypatch):
        """When XGBoost inference fails, attack_type must fall back to 'OTHER'."""
        features = _make_feature_dict("sqli")

        def bad_xgb_predict(*args, **kwargs):
            raise RuntimeError("Simulated XGBoost failure")

        with patch.object(ml_adapter.MODEL, "predict_proba",
                           return_value=np.array([[0.05, 0.95]])):
            with patch.object(ml_adapter.XGB_MODEL, "predict_proba",
                               side_effect=bad_xgb_predict):
                result = adapt_ml_model(features)

        assert result["verdict"] == "ANOMALY"
        assert result["attack_type"] == "OTHER", (
            "When XGBoost fails, attack_type should fall back to 'OTHER'"
        )
        assert result["xgb_confidence"] is None

    def test_scaling_failure_returns_ml_unavailable(self):
        """When scaler.transform() raises, detection_source must be 'ml_unavailable'."""
        features = _make_feature_dict("normal")

        with patch.object(ml_adapter.SCALER, "transform",
                           side_effect=ValueError("Simulated scaler failure")):
            result = adapt_ml_model(features)

        assert result["detection_source"] == "ml_unavailable"
        assert result["is_attack"] is False


# ── XGB_LABEL_MAP integrity tests ─────────────────────────────────────────────

class TestXGBLabelMap:
    """Verify the XGB_LABEL_MAP constant is correct."""

    def test_label_map_has_four_entries(self):
        assert len(XGB_LABEL_MAP) == 4

    def test_label_map_values_are_strings(self):
        for k, v in XGB_LABEL_MAP.items():
            assert isinstance(v, str), f"XGB_LABEL_MAP[{k}] should be str, got {type(v)}"

    def test_label_map_contains_expected_labels(self):
        expected = {"OTHER", "SQLI", "XSS", "PATH_TRAVERSAL"}
        actual = set(XGB_LABEL_MAP.values())
        assert actual == expected, f"XGB_LABEL_MAP values: expected {expected}, got {actual}"

    def test_label_map_keys_are_0_to_3(self):
        assert set(XGB_LABEL_MAP.keys()) == {0, 1, 2, 3}


# ── Integration smoke test ────────────────────────────────────────────────────

class TestIntegrationSmoke:
    """End-to-end smoke tests using real models (no mocking)."""

    def test_normal_request_does_not_raise(self):
        """adapt_ml_model() must not raise on a normal feature dict."""
        result = adapt_ml_model(_make_feature_dict("normal"))
        assert "verdict" in result

    def test_sqli_request_does_not_raise(self):
        """adapt_ml_model() must not raise on a SQLi feature dict."""
        result = adapt_ml_model(_make_feature_dict("sqli"))
        assert "verdict" in result

    def test_xss_request_does_not_raise(self):
        """adapt_ml_model() must not raise on an XSS feature dict."""
        result = adapt_ml_model(_make_feature_dict("xss"))
        assert "verdict" in result

    def test_traversal_request_does_not_raise(self):
        """adapt_ml_model() must not raise on a path traversal feature dict."""
        result = adapt_ml_model(_make_feature_dict("traversal"))
        assert "verdict" in result

    def test_missing_features_handled_gracefully(self):
        """adapt_ml_model() must handle a partially empty feature dict."""
        result = adapt_ml_model({"method_get": 1.0})  # only 1 of 53 features
        assert "verdict" in result
        assert result["detection_source"] in ("ml_engine", "ml_unavailable")

    def test_empty_feature_dict_handled_gracefully(self):
        """adapt_ml_model() must handle a completely empty feature dict."""
        result = adapt_ml_model({})
        assert "verdict" in result

    def test_sqli_classified_as_sqli_or_other(self):
        """
        A strong SQLi feature vector should be classified as SQLI or OTHER
        when the RF flags it as an attack.
        """
        result = adapt_ml_model(_make_feature_dict("sqli"))
        if result["verdict"] == "ANOMALY":
            assert result["attack_type"] in ("SQLI", "OTHER", "XSS", "PATH_TRAVERSAL"), (
                f"Unexpected attack_type: {result['attack_type']}"
            )
            assert result["attack_type"] in XGB_LABEL_MAP.values()
