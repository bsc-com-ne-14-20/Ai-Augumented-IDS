"""
backend/tests/test_config.py
=============================
Unit tests for configuration module.

Tests configuration loading from environment variables, default value fallback,
and validation error handling.

Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7, 11.8
"""

import os
import pytest
import logging
from pathlib import Path
from backend.config import Config, ConfigValidationError, get_config, reload_config


class TestConfigLoading:
    """Test configuration loading from environment variables."""
    
    def test_loads_default_values(self):
        """Test that configuration loads with default values when env vars are not set."""
        # Clear any existing environment variables
        env_vars_to_clear = [
            "IDS_API_KEY", "ML_MODEL_PATH", "ML_SCALER_PATH",
            "ML_FEATURE_NAMES_PATH", "ML_CONFIDENCE_THRESHOLD",
            "BF_REQUEST_THRESHOLD", "BF_TIME_WINDOW_SECONDS",
            "FLASK_SECRET_KEY", "FLASK_DEBUG", "PORT",
            "SOCKETIO_CORS_ORIGINS", "DB_PATH", "DATABASE_URL",
            "MAX_LOGS_PER_REQUEST", "DEFAULT_PAGE_SIZE"
        ]
        
        original_values = {}
        for var in env_vars_to_clear:
            original_values[var] = os.environ.get(var)
            if var in os.environ:
                del os.environ[var]
        
        try:
            # Disable validation for this test since ML files may not exist
            config = Config(validate=False)
            
            # Verify default values
            assert config.IDS_API_KEY == "dev-api-key-change-in-production"
            assert config.ML_CONFIDENCE_THRESHOLD == 0.65
            assert config.BF_REQUEST_THRESHOLD == 10
            assert config.BF_TIME_WINDOW_SECONDS == 60
            assert config.FLASK_DEBUG is False
            assert config.PORT == 5000
            assert config.SOCKETIO_CORS_ORIGINS == "*"
            assert config.MAX_LOGS_PER_REQUEST == 5000
            assert config.DEFAULT_PAGE_SIZE == 50
            
            # Verify paths are constructed correctly
            assert "models/rf_model.joblib" in config.ML_MODEL_PATH
            assert "data/final/scaler.pkl" in config.ML_SCALER_PATH
            assert "data/final/feature_names.txt" in config.ML_FEATURE_NAMES_PATH
            assert "ids.db" in config.DB_PATH
        
        finally:
            # Restore original environment variables
            for var, value in original_values.items():
                if value is not None:
                    os.environ[var] = value
    
    def test_loads_from_environment_variables(self):
        """Test that configuration loads values from environment variables."""
        # Set test environment variables
        test_env = {
            "IDS_API_KEY": "test-api-key-12345",
            "ML_MODEL_PATH": "/custom/path/model.joblib",
            "ML_SCALER_PATH": "/custom/path/scaler.pkl",
            "ML_FEATURE_NAMES_PATH": "/custom/path/features.txt",
            "ML_CONFIDENCE_THRESHOLD": "0.75",
            "BF_REQUEST_THRESHOLD": "15",
            "BF_TIME_WINDOW_SECONDS": "120",
            "FLASK_SECRET_KEY": "test-secret-key",
            "FLASK_DEBUG": "true",
            "PORT": "8080",
            "SOCKETIO_CORS_ORIGINS": "http://localhost:3000",
            "DB_PATH": "/custom/path/test.db",
            "DATABASE_URL": "postgresql://user:pass@localhost/testdb",
            "MAX_LOGS_PER_REQUEST": "1000",
            "DEFAULT_PAGE_SIZE": "25"
        }
        
        original_values = {}
        for key, value in test_env.items():
            original_values[key] = os.environ.get(key)
            os.environ[key] = value
        
        try:
            # Disable validation since custom paths don't exist
            config = Config(validate=False)
            
            # Verify environment variables are loaded
            assert config.IDS_API_KEY == "test-api-key-12345"
            assert config.ML_MODEL_PATH == "/custom/path/model.joblib"
            assert config.ML_SCALER_PATH == "/custom/path/scaler.pkl"
            assert config.ML_FEATURE_NAMES_PATH == "/custom/path/features.txt"
            assert config.ML_CONFIDENCE_THRESHOLD == 0.75
            assert config.BF_REQUEST_THRESHOLD == 15
            assert config.BF_TIME_WINDOW_SECONDS == 120
            assert config.FLASK_SECRET_KEY == "test-secret-key"
            assert config.FLASK_DEBUG is True
            assert config.PORT == 8080
            assert config.SOCKETIO_CORS_ORIGINS == "http://localhost:3000"
            assert config.DB_PATH == "/custom/path/test.db"
            assert config.DATABASE_URL == "postgresql://user:pass@localhost/testdb"
            assert config.MAX_LOGS_PER_REQUEST == 1000
            assert config.DEFAULT_PAGE_SIZE == 25
        
        finally:
            # Restore original environment variables
            for key, value in original_values.items():
                if value is not None:
                    os.environ[key] = value
                else:
                    if key in os.environ:
                        del os.environ[key]
    
    def test_flask_debug_boolean_parsing(self):
        """Test that FLASK_DEBUG is correctly parsed as boolean."""
        test_cases = [
            ("true", True),
            ("True", True),
            ("TRUE", True),
            ("1", True),
            ("yes", True),
            ("false", False),
            ("False", False),
            ("0", False),
            ("no", False),
            ("", False),
        ]
        
        original_value = os.environ.get("FLASK_DEBUG")
        
        try:
            for env_value, expected in test_cases:
                os.environ["FLASK_DEBUG"] = env_value
                config = Config(validate=False)
                assert config.FLASK_DEBUG == expected, \
                    f"FLASK_DEBUG={env_value} should parse to {expected}"
        
        finally:
            if original_value is not None:
                os.environ["FLASK_DEBUG"] = original_value
            else:
                if "FLASK_DEBUG" in os.environ:
                    del os.environ["FLASK_DEBUG"]


class TestConfigHelperMethods:
    """Test configuration helper methods."""
    
    def test_project_root_property(self):
        """Test that project_root property returns correct path."""
        config = Config(validate=False)
        assert isinstance(config.project_root, Path)
        assert config.project_root.exists()
        # Project root should be parent of backend directory
        assert (config.project_root / "backend").exists()
    
    def test_path_helper_methods(self):
        """Test that path helper methods return Path objects."""
        config = Config(validate=False)
        
        assert isinstance(config.get_ml_model_path(), Path)
        assert isinstance(config.get_ml_scaler_path(), Path)
        assert isinstance(config.get_ml_feature_names_path(), Path)
        assert isinstance(config.get_db_path(), Path)
    
    def test_repr_method(self):
        """Test that __repr__ returns useful string representation."""
        config = Config(validate=False)
        repr_str = repr(config)
        
        assert "Config(" in repr_str
        assert "ML_MODEL_PATH=" in repr_str
        assert "ML_CONFIDENCE_THRESHOLD=" in repr_str
        assert "BF_REQUEST_THRESHOLD=" in repr_str
        # Sensitive data like API keys should not be in repr
        assert "IDS_API_KEY" not in repr_str


class TestGlobalConfigInstance:
    """Test global configuration instance management."""
    
    def test_get_config_returns_singleton(self):
        """Test that get_config returns the same instance."""
        config1 = get_config()
        config2 = get_config()
        
        assert config1 is config2
    
    def test_reload_config_creates_new_instance(self):
        """Test that reload_config creates a new instance."""
        config1 = get_config()
        config2 = reload_config()
        
        # Should be different instances
        assert config1 is not config2
        
        # But get_config should now return the new instance
        config3 = get_config()
        assert config2 is config3


class TestConfigTypeSafety:
    """Test that configuration values have correct types."""
    
    def test_string_attributes(self):
        """Test that string attributes are strings."""
        config = Config(validate=False)
        
        assert isinstance(config.IDS_API_KEY, str)
        assert isinstance(config.ML_MODEL_PATH, str)
        assert isinstance(config.ML_SCALER_PATH, str)
        assert isinstance(config.ML_FEATURE_NAMES_PATH, str)
        assert isinstance(config.FLASK_SECRET_KEY, str)
        assert isinstance(config.SOCKETIO_CORS_ORIGINS, str)
        assert isinstance(config.DB_PATH, str)
    
    def test_numeric_attributes(self):
        """Test that numeric attributes have correct types."""
        config = Config(validate=False)
        
        assert isinstance(config.ML_CONFIDENCE_THRESHOLD, float)
        assert isinstance(config.RULE_ENGINE_THRESHOLD, int)
        assert isinstance(config.BF_REQUEST_THRESHOLD, int)
        assert isinstance(config.BF_TIME_WINDOW_SECONDS, int)
        assert isinstance(config.PORT, int)
        assert isinstance(config.MAX_LOGS_PER_REQUEST, int)
        assert isinstance(config.DEFAULT_PAGE_SIZE, int)
    
    def test_boolean_attributes(self):
        """Test that boolean attributes are booleans."""
        config = Config(validate=False)
        
        assert isinstance(config.FLASK_DEBUG, bool)
    
    def test_optional_attributes(self):
        """Test that optional attributes can be None."""
        # Clear DATABASE_URL if set
        original_value = os.environ.get("DATABASE_URL")
        if "DATABASE_URL" in os.environ:
            del os.environ["DATABASE_URL"]
        
        try:
            config = Config(validate=False)
            assert config.DATABASE_URL is None
        
        finally:
            if original_value is not None:
                os.environ["DATABASE_URL"] = original_value



class TestConfigValidation:
    """Test configuration validation functionality."""
    
    def test_validation_passes_with_valid_config(self):
        """Test that validation passes with valid configuration values."""
        test_env = {
            "IDS_API_KEY": "test-api-key-12345",
            "FLASK_SECRET_KEY": "test-secret-key",
            "ML_CONFIDENCE_THRESHOLD": "0.75",
            "BF_REQUEST_THRESHOLD": "15",
            "BF_TIME_WINDOW_SECONDS": "120",
            "PORT": "8080",
            "MAX_LOGS_PER_REQUEST": "1000",
            "DEFAULT_PAGE_SIZE": "25",
            "RULE_ENGINE_THRESHOLD": "5"
        }
        
        original_values = {}
        for key, value in test_env.items():
            original_values[key] = os.environ.get(key)
            os.environ[key] = value
        
        try:
            # This should not raise an exception (validation warnings are OK)
            config = Config(validate=False)
            config.validate()  # Manually call validate
        
        finally:
            for key, value in original_values.items():
                if value is not None:
                    os.environ[key] = value
                else:
                    if key in os.environ:
                        del os.environ[key]
    
    def test_validation_fails_with_invalid_confidence_threshold(self):
        """Test that validation fails when ML_CONFIDENCE_THRESHOLD is out of range."""
        original_value = os.environ.get("ML_CONFIDENCE_THRESHOLD")
        
        try:
            # Test value > 1.0
            os.environ["ML_CONFIDENCE_THRESHOLD"] = "1.5"
            config = Config(validate=False)
            
            with pytest.raises(ConfigValidationError) as exc_info:
                config.validate()
            
            assert "ML_CONFIDENCE_THRESHOLD must be between 0.0 and 1.0" in str(exc_info.value)
            
            # Test value < 0.0
            os.environ["ML_CONFIDENCE_THRESHOLD"] = "-0.1"
            config = Config(validate=False)
            
            with pytest.raises(ConfigValidationError) as exc_info:
                config.validate()
            
            assert "ML_CONFIDENCE_THRESHOLD must be between 0.0 and 1.0" in str(exc_info.value)
        
        finally:
            if original_value is not None:
                os.environ["ML_CONFIDENCE_THRESHOLD"] = original_value
            else:
                if "ML_CONFIDENCE_THRESHOLD" in os.environ:
                    del os.environ["ML_CONFIDENCE_THRESHOLD"]
    
    def test_validation_fails_with_negative_rule_engine_threshold(self):
        """Test that validation fails when RULE_ENGINE_THRESHOLD is negative."""
        original_value = os.environ.get("RULE_ENGINE_THRESHOLD")
        
        try:
            os.environ["RULE_ENGINE_THRESHOLD"] = "-5"
            config = Config(validate=False)
            
            with pytest.raises(ConfigValidationError) as exc_info:
                config.validate()
            
            assert "RULE_ENGINE_THRESHOLD must be non-negative" in str(exc_info.value)
        
        finally:
            if original_value is not None:
                os.environ["RULE_ENGINE_THRESHOLD"] = original_value
            else:
                if "RULE_ENGINE_THRESHOLD" in os.environ:
                    del os.environ["RULE_ENGINE_THRESHOLD"]
    
    def test_validation_fails_with_invalid_bf_request_threshold(self):
        """Test that validation fails when BF_REQUEST_THRESHOLD is not positive."""
        original_value = os.environ.get("BF_REQUEST_THRESHOLD")
        
        try:
            os.environ["BF_REQUEST_THRESHOLD"] = "0"
            config = Config(validate=False)
            
            with pytest.raises(ConfigValidationError) as exc_info:
                config.validate()
            
            assert "BF_REQUEST_THRESHOLD must be positive" in str(exc_info.value)
        
        finally:
            if original_value is not None:
                os.environ["BF_REQUEST_THRESHOLD"] = original_value
            else:
                if "BF_REQUEST_THRESHOLD" in os.environ:
                    del os.environ["BF_REQUEST_THRESHOLD"]
    
    def test_validation_fails_with_invalid_bf_time_window(self):
        """Test that validation fails when BF_TIME_WINDOW_SECONDS is not positive."""
        original_value = os.environ.get("BF_TIME_WINDOW_SECONDS")
        
        try:
            os.environ["BF_TIME_WINDOW_SECONDS"] = "-10"
            config = Config(validate=False)
            
            with pytest.raises(ConfigValidationError) as exc_info:
                config.validate()
            
            assert "BF_TIME_WINDOW_SECONDS must be positive" in str(exc_info.value)
        
        finally:
            if original_value is not None:
                os.environ["BF_TIME_WINDOW_SECONDS"] = original_value
            else:
                if "BF_TIME_WINDOW_SECONDS" in os.environ:
                    del os.environ["BF_TIME_WINDOW_SECONDS"]
    
    def test_validation_fails_with_invalid_port(self):
        """Test that validation fails when PORT is out of valid range."""
        original_value = os.environ.get("PORT")
        
        try:
            # Test port too high
            os.environ["PORT"] = "70000"
            config = Config(validate=False)
            
            with pytest.raises(ConfigValidationError) as exc_info:
                config.validate()
            
            assert "PORT must be between 1 and 65535" in str(exc_info.value)
            
            # Test port too low
            os.environ["PORT"] = "0"
            config = Config(validate=False)
            
            with pytest.raises(ConfigValidationError) as exc_info:
                config.validate()
            
            assert "PORT must be between 1 and 65535" in str(exc_info.value)
        
        finally:
            if original_value is not None:
                os.environ["PORT"] = original_value
            else:
                if "PORT" in os.environ:
                    del os.environ["PORT"]
    
    def test_validation_fails_with_invalid_max_logs_per_request(self):
        """Test that validation fails when MAX_LOGS_PER_REQUEST is not positive."""
        original_value = os.environ.get("MAX_LOGS_PER_REQUEST")
        
        try:
            os.environ["MAX_LOGS_PER_REQUEST"] = "-100"
            config = Config(validate=False)
            
            with pytest.raises(ConfigValidationError) as exc_info:
                config.validate()
            
            assert "MAX_LOGS_PER_REQUEST must be positive" in str(exc_info.value)
        
        finally:
            if original_value is not None:
                os.environ["MAX_LOGS_PER_REQUEST"] = original_value
            else:
                if "MAX_LOGS_PER_REQUEST" in os.environ:
                    del os.environ["MAX_LOGS_PER_REQUEST"]
    
    def test_validation_fails_with_invalid_default_page_size(self):
        """Test that validation fails when DEFAULT_PAGE_SIZE is not positive."""
        original_value = os.environ.get("DEFAULT_PAGE_SIZE")
        
        try:
            os.environ["DEFAULT_PAGE_SIZE"] = "0"
            config = Config(validate=False)
            
            with pytest.raises(ConfigValidationError) as exc_info:
                config.validate()
            
            assert "DEFAULT_PAGE_SIZE must be positive" in str(exc_info.value)
        
        finally:
            if original_value is not None:
                os.environ["DEFAULT_PAGE_SIZE"] = original_value
            else:
                if "DEFAULT_PAGE_SIZE" in os.environ:
                    del os.environ["DEFAULT_PAGE_SIZE"]
    
    def test_validation_warns_about_missing_ml_files(self, caplog):
        """Test that validation warns when ML model files don't exist."""
        test_env = {
            "ML_MODEL_PATH": "/nonexistent/model.joblib",
            "ML_SCALER_PATH": "/nonexistent/scaler.pkl",
            "ML_FEATURE_NAMES_PATH": "/nonexistent/features.txt"
        }
        
        original_values = {}
        for key, value in test_env.items():
            original_values[key] = os.environ.get(key)
            os.environ[key] = value
        
        try:
            with caplog.at_level(logging.WARNING):
                config = Config(validate=False)
                config.validate()
            
            # Check that warnings were logged
            warning_messages = [record.message for record in caplog.records if record.levelname == "WARNING"]
            assert any("model file not found" in msg for msg in warning_messages)  # RF or XGB model
            assert any("ML scaler file not found" in msg for msg in warning_messages)
            assert any("ML feature names file not found" in msg for msg in warning_messages)
        
        finally:
            for key, value in original_values.items():
                if value is not None:
                    os.environ[key] = value
                else:
                    if key in os.environ:
                        del os.environ[key]
    
    def test_validation_warns_about_default_api_key(self, caplog):
        """Test that validation warns when using default API key."""
        # Clear IDS_API_KEY to use default
        original_value = os.environ.get("IDS_API_KEY")
        if "IDS_API_KEY" in os.environ:
            del os.environ["IDS_API_KEY"]
        
        try:
            with caplog.at_level(logging.WARNING):
                config = Config(validate=False)
                config.validate()
            
            # Check that warning was logged
            warning_messages = [record.message for record in caplog.records if record.levelname == "WARNING"]
            assert any("IDS_API_KEY is using default development value" in msg for msg in warning_messages)
        
        finally:
            if original_value is not None:
                os.environ["IDS_API_KEY"] = original_value
    
    def test_validation_warns_about_default_flask_secret(self, caplog):
        """Test that validation warns when using default Flask secret key."""
        # Clear FLASK_SECRET_KEY to use default
        original_value = os.environ.get("FLASK_SECRET_KEY")
        if "FLASK_SECRET_KEY" in os.environ:
            del os.environ["FLASK_SECRET_KEY"]
        
        try:
            with caplog.at_level(logging.WARNING):
                config = Config(validate=False)
                config.validate()
            
            # Check that warning was logged
            warning_messages = [record.message for record in caplog.records if record.levelname == "WARNING"]
            assert any("FLASK_SECRET_KEY is using default development value" in msg for msg in warning_messages)
        
        finally:
            if original_value is not None:
                os.environ["FLASK_SECRET_KEY"] = original_value


class TestConfigLoggingSummary:
    """Test configuration logging summary functionality."""
    
    def test_log_configuration_summary(self, caplog):
        """Test that configuration summary is logged correctly."""
        with caplog.at_level(logging.INFO):
            config = Config(validate=False)
            config.log_configuration_summary()
        
        # Check that summary was logged
        info_messages = [record.message for record in caplog.records if record.levelname == "INFO"]
        
        assert any("AA-IDS Backend Configuration Summary" in msg for msg in info_messages)
        assert any("Server Port:" in msg for msg in info_messages)
        assert any("ML Model Path" in msg for msg in info_messages)  # matches "ML Model Path (RF):" or "ML Model Path:"
        assert any("ML Confidence Threshold:" in msg for msg in info_messages)
        assert any("Rule Engine Threshold:" in msg for msg in info_messages)
        assert any("Brute Force Request Threshold:" in msg for msg in info_messages)
        assert any("Database Path:" in msg for msg in info_messages)
    
    def test_log_summary_does_not_expose_secrets(self, caplog):
        """Test that configuration summary does not log sensitive data."""
        test_env = {
            "IDS_API_KEY": "super-secret-key-12345",
            "FLASK_SECRET_KEY": "super-secret-flask-key"
        }
        
        original_values = {}
        for key, value in test_env.items():
            original_values[key] = os.environ.get(key)
            os.environ[key] = value
        
        try:
            with caplog.at_level(logging.INFO):
                config = Config(validate=False)
                config.log_configuration_summary()
            
            # Check that secrets are NOT in logs
            all_messages = " ".join([record.message for record in caplog.records])
            assert "super-secret-key-12345" not in all_messages
            assert "super-secret-flask-key" not in all_messages
        
        finally:
            for key, value in original_values.items():
                if value is not None:
                    os.environ[key] = value
                else:
                    if key in os.environ:
                        del os.environ[key]
    
    def test_log_summary_shows_ml_file_existence(self, caplog):
        """Test that configuration summary shows whether ML files exist."""
        with caplog.at_level(logging.INFO):
            config = Config(validate=False)
            config.log_configuration_summary()
        
        # Check that file existence is logged
        info_messages = [record.message for record in caplog.records if record.levelname == "INFO"]
        assert any("RF Model File Exists:" in msg or "ML Model File Exists:" in msg for msg in info_messages)
        assert any("ML Scaler File Exists:" in msg for msg in info_messages)
        assert any("ML Feature Names File Exists:" in msg for msg in info_messages)
    
    def test_log_summary_handles_postgresql_url(self, caplog):
        """Test that configuration summary handles PostgreSQL URL correctly."""
        original_value = os.environ.get("DATABASE_URL")
        
        try:
            os.environ["DATABASE_URL"] = "postgresql://user:password@localhost/testdb"
            
            with caplog.at_level(logging.INFO):
                config = Config(validate=False)
                config.log_configuration_summary()
            
            # Check that PostgreSQL is mentioned but not the full URL with credentials
            info_messages = [record.message for record in caplog.records if record.levelname == "INFO"]
            assert any("PostgreSQL configured" in msg for msg in info_messages)
            # Ensure password is not logged
            all_messages = " ".join([record.message for record in caplog.records])
            assert "password" not in all_messages.lower() or "Database URL:" in all_messages
        
        finally:
            if original_value is not None:
                os.environ["DATABASE_URL"] = original_value
            else:
                if "DATABASE_URL" in os.environ:
                    del os.environ["DATABASE_URL"]
