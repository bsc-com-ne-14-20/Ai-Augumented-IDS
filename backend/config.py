"""
backend/config.py
=================
Configuration loader with environment variable support for AA-IDS Backend.

This module loads configuration from environment variables using python-dotenv,
provides typed configuration attributes, and implements default values for
optional settings.

This is the canonical configuration module for the backend package. It replaces
the root-level config.py as part of the directory structure consolidation.

Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7, 11.8

Usage:
    from backend.config import Config
    
    config = Config()
    api_key = config.IDS_API_KEY
    model_path = config.ML_MODEL_PATH
    
    # Or use the global instance
    from backend.config import get_config
    
    config = get_config()
"""

import os
import logging
from pathlib import Path
from typing import Optional, List
from dotenv import load_dotenv

# Configure logging
logger = logging.getLogger(__name__)


class ConfigValidationError(Exception):
    """Exception raised when configuration validation fails."""
    pass


class Config:
    """
    Configuration class with typed attributes for AA-IDS Backend.
    
    Loads configuration from environment variables with sensible defaults.
    All file paths are resolved relative to the project root.
    Validates configuration on initialization.
    """
    
    def __init__(self, env_file: Optional[str] = None, validate: bool = True):
        """
        Initialize configuration by loading environment variables.
        
        Args:
            env_file: Optional path to .env file. If None, searches for .env
                     in the project root directory.
            validate: Whether to validate configuration after loading (default: True).
        
        Raises:
            ConfigValidationError: If validation fails and validate=True.
        """
        # Determine project root (parent of backend directory)
        self._project_root = Path(__file__).resolve().parent.parent
        
        # Load .env file if present
        if env_file:
            load_dotenv(env_file)
        else:
            # Look for .env in project root
            env_path = self._project_root / ".env"
            load_dotenv(env_path)
        
        # Load all configuration attributes
        self._load_config()
        
        # Validate configuration if requested
        if validate:
            self.validate()
            self.log_configuration_summary()
    
    def _load_config(self) -> None:
        """Load all configuration from environment variables."""
        
        # ── API Authentication ────────────────────────────────────────────────
        self.IDS_API_KEY: str = os.environ.get(
            "IDS_API_KEY",
            "dev-api-key-change-in-production"
        )
        
        # ── ML Model Paths ────────────────────────────────────────────────────
        self.ML_MODEL_PATH: str = os.environ.get(
            "ML_MODEL_PATH",
            str(self._project_root / "models" / "rf_model.joblib")
        )
        
        self.ML_SCALER_PATH: str = os.environ.get(
            "ML_SCALER_PATH",
            str(self._project_root / "data" / "final" / "scaler.pkl")
        )
        
        self.ML_FEATURE_NAMES_PATH: str = os.environ.get(
            "ML_FEATURE_NAMES_PATH",
            str(self._project_root / "data" / "final" / "feature_names.txt")
        )
        
        self.ML_CONFIDENCE_THRESHOLD: float = float(
            os.environ.get("ML_CONFIDENCE_THRESHOLD", "0.65")
        )
        
        # ── Rule Engine Parameters ────────────────────────────────────────────
        self.RULE_ENGINE_THRESHOLD: int = int(
            os.environ.get("RULE_ENGINE_THRESHOLD", "5")
        )
        
        self.BF_REQUEST_THRESHOLD: int = int(
            os.environ.get("BF_REQUEST_THRESHOLD", "10")
        )
        
        self.BF_TIME_WINDOW_SECONDS: int = int(
            os.environ.get("BF_TIME_WINDOW_SECONDS", "60")
        )
        
        # ── Flask / SocketIO Settings ─────────────────────────────────────────
        self.FLASK_SECRET_KEY: str = os.environ.get(
            "FLASK_SECRET_KEY",
            "aa-ids-dev-secret-change-in-production"
        )
        
        self.FLASK_DEBUG: bool = os.environ.get(
            "FLASK_DEBUG",
            "false"
        ).lower() in ("true", "1", "yes")
        
        self.PORT: int = int(os.environ.get("PORT", "5000"))
        
        self.SOCKETIO_CORS_ORIGINS: str = os.environ.get(
            "SOCKETIO_CORS_ORIGINS",
            "*"
        )
        
        # ── Database Configuration ────────────────────────────────────────────
        self.DB_PATH: str = os.environ.get(
            "DB_PATH",
            str(self._project_root / "ids.db")
        )
        
        # Support for PostgreSQL in production
        self.DATABASE_URL: Optional[str] = os.environ.get("DATABASE_URL")
        
        # ── API Limits ────────────────────────────────────────────────────────
        self.MAX_LOGS_PER_REQUEST: int = int(
            os.environ.get("MAX_LOGS_PER_REQUEST", "5000")
        )
        
        self.DEFAULT_PAGE_SIZE: int = int(
            os.environ.get("DEFAULT_PAGE_SIZE", "50")
        )
    
    @property
    def project_root(self) -> Path:
        """Return the project root directory path."""
        return self._project_root
    
    def get_ml_model_path(self) -> Path:
        """Return ML model path as Path object."""
        return Path(self.ML_MODEL_PATH)
    
    def get_ml_scaler_path(self) -> Path:
        """Return ML scaler path as Path object."""
        return Path(self.ML_SCALER_PATH)
    
    def get_ml_feature_names_path(self) -> Path:
        """Return ML feature names path as Path object."""
        return Path(self.ML_FEATURE_NAMES_PATH)
    
    def get_db_path(self) -> Path:
        """Return database path as Path object."""
        return Path(self.DB_PATH)
    
    def validate(self) -> None:
        """
        Validate configuration values.
        
        Validates:
        - Required environment variables are present
        - File paths exist for ML models and data files (warns if missing)
        - Numeric thresholds are within valid ranges
        
        Raises:
            ConfigValidationError: If validation fails.
        
        Requirements: 11.3, 11.4, 11.5
        """
        errors: List[str] = []
        warnings: List[str] = []
        
        # Validate required environment variables (non-default values)
        # Note: We don't enforce non-default values in development, but we check types
        if not isinstance(self.IDS_API_KEY, str) or not self.IDS_API_KEY:
            errors.append("IDS_API_KEY must be a non-empty string")
        
        if self.IDS_API_KEY == "dev-api-key-change-in-production":
            warnings.append("IDS_API_KEY is using default development value - change in production")
        
        if not isinstance(self.FLASK_SECRET_KEY, str) or not self.FLASK_SECRET_KEY:
            errors.append("FLASK_SECRET_KEY must be a non-empty string")
        
        if self.FLASK_SECRET_KEY == "aa-ids-dev-secret-change-in-production":
            warnings.append("FLASK_SECRET_KEY is using default development value - change in production")
        
        # Validate file paths exist for ML models and data files
        ml_model_path = Path(self.ML_MODEL_PATH)
        if not ml_model_path.exists():
            warnings.append(f"ML model file not found: {self.ML_MODEL_PATH}")
        
        ml_scaler_path = Path(self.ML_SCALER_PATH)
        if not ml_scaler_path.exists():
            warnings.append(f"ML scaler file not found: {self.ML_SCALER_PATH}")
        
        ml_feature_names_path = Path(self.ML_FEATURE_NAMES_PATH)
        if not ml_feature_names_path.exists():
            warnings.append(f"ML feature names file not found: {self.ML_FEATURE_NAMES_PATH}")
        
        # Validate numeric thresholds are within valid ranges
        if not (0.0 <= self.ML_CONFIDENCE_THRESHOLD <= 1.0):
            errors.append(
                f"ML_CONFIDENCE_THRESHOLD must be between 0.0 and 1.0, got {self.ML_CONFIDENCE_THRESHOLD}"
            )
        
        if self.RULE_ENGINE_THRESHOLD < 0:
            errors.append(
                f"RULE_ENGINE_THRESHOLD must be non-negative, got {self.RULE_ENGINE_THRESHOLD}"
            )
        
        if self.BF_REQUEST_THRESHOLD <= 0:
            errors.append(
                f"BF_REQUEST_THRESHOLD must be positive, got {self.BF_REQUEST_THRESHOLD}"
            )
        
        if self.BF_TIME_WINDOW_SECONDS <= 0:
            errors.append(
                f"BF_TIME_WINDOW_SECONDS must be positive, got {self.BF_TIME_WINDOW_SECONDS}"
            )
        
        if not (1 <= self.PORT <= 65535):
            errors.append(
                f"PORT must be between 1 and 65535, got {self.PORT}"
            )
        
        if self.MAX_LOGS_PER_REQUEST <= 0:
            errors.append(
                f"MAX_LOGS_PER_REQUEST must be positive, got {self.MAX_LOGS_PER_REQUEST}"
            )
        
        if self.DEFAULT_PAGE_SIZE <= 0:
            errors.append(
                f"DEFAULT_PAGE_SIZE must be positive, got {self.DEFAULT_PAGE_SIZE}"
            )
        
        # Log warnings
        for warning in warnings:
            logger.warning(f"Configuration warning: {warning}")
        
        # Raise exception if there are errors
        if errors:
            error_message = "Configuration validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
            raise ConfigValidationError(error_message)
    
    def log_configuration_summary(self) -> None:
        """
        Log configuration summary at startup.
        
        Logs key configuration values (excluding sensitive data like API keys).
        
        Requirements: 11.6, 11.7
        """
        logger.info("=" * 60)
        logger.info("AA-IDS Backend Configuration Summary")
        logger.info("=" * 60)
        
        # Server configuration
        logger.info(f"Server Port: {self.PORT}")
        logger.info(f"Debug Mode: {self.FLASK_DEBUG}")
        logger.info(f"CORS Origins: {self.SOCKETIO_CORS_ORIGINS}")
        
        # ML configuration
        logger.info(f"ML Model Path: {self.ML_MODEL_PATH}")
        logger.info(f"ML Scaler Path: {self.ML_SCALER_PATH}")
        logger.info(f"ML Feature Names Path: {self.ML_FEATURE_NAMES_PATH}")
        logger.info(f"ML Confidence Threshold: {self.ML_CONFIDENCE_THRESHOLD}")
        
        # Check if ML files exist
        ml_model_exists = Path(self.ML_MODEL_PATH).exists()
        ml_scaler_exists = Path(self.ML_SCALER_PATH).exists()
        ml_features_exists = Path(self.ML_FEATURE_NAMES_PATH).exists()
        
        logger.info(f"ML Model File Exists: {ml_model_exists}")
        logger.info(f"ML Scaler File Exists: {ml_scaler_exists}")
        logger.info(f"ML Feature Names File Exists: {ml_features_exists}")
        
        # Rule engine configuration
        logger.info(f"Rule Engine Threshold: {self.RULE_ENGINE_THRESHOLD}")
        logger.info(f"Brute Force Request Threshold: {self.BF_REQUEST_THRESHOLD}")
        logger.info(f"Brute Force Time Window: {self.BF_TIME_WINDOW_SECONDS}s")
        
        # Database configuration
        logger.info(f"Database Path: {self.DB_PATH}")
        if self.DATABASE_URL:
            # Don't log the full URL as it may contain credentials
            logger.info("Database URL: [PostgreSQL configured]")
        else:
            logger.info("Database URL: [Using SQLite]")
        
        # API limits
        logger.info(f"Max Logs Per Request: {self.MAX_LOGS_PER_REQUEST}")
        logger.info(f"Default Page Size: {self.DEFAULT_PAGE_SIZE}")
        
        logger.info("=" * 60)
    
    def __repr__(self) -> str:
        """Return string representation of configuration (without sensitive data)."""
        return (
            f"Config("
            f"ML_MODEL_PATH={self.ML_MODEL_PATH}, "
            f"ML_CONFIDENCE_THRESHOLD={self.ML_CONFIDENCE_THRESHOLD}, "
            f"BF_REQUEST_THRESHOLD={self.BF_REQUEST_THRESHOLD}, "
            f"BF_TIME_WINDOW_SECONDS={self.BF_TIME_WINDOW_SECONDS}, "
            f"DB_PATH={self.DB_PATH}, "
            f"PORT={self.PORT}"
            f")"
        )


# Global configuration instance for convenience
_config_instance: Optional[Config] = None


def get_config() -> Config:
    """
    Get or create the global configuration instance.
    
    Returns:
        Config: The global configuration instance.
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
    return _config_instance


def reload_config(env_file: Optional[str] = None) -> Config:
    """
    Reload configuration from environment variables.
    
    Useful for testing or when environment variables change.
    
    Args:
        env_file: Optional path to .env file.
    
    Returns:
        Config: The newly loaded configuration instance.
    """
    global _config_instance
    _config_instance = Config(env_file=env_file)
    return _config_instance
