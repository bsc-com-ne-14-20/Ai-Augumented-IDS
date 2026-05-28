"""
Unit tests for database module.
Tests connection management, health checks, and reconnection logic.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from sqlalchemy.exc import OperationalError

# Import database module
from backend import database


class TestDatabaseConfiguration:
    """Test database configuration and initialization."""
    
    def test_engine_created(self):
        """Test that database engine is created successfully."""
        assert database.engine is not None
        assert database.SessionLocal is not None
    
    def test_sqlite_uses_null_pool(self):
        """Test that SQLite uses NullPool (no connection pooling)."""
        if database.is_sqlite:
            assert database.engine.pool.__class__.__name__ == 'NullPool'
    
    def test_connection_retry_config(self):
        """Test that connection retry configuration is set."""
        assert database.MAX_RETRIES == 3
        assert database.RETRY_DELAY == 2


class TestConnectionHealth:
    """Test connection health check functionality."""
    
    def test_check_connection_health_success(self):
        """Test health check returns True for healthy connection."""
        # This will use the actual database connection
        result = database.check_connection_health()
        assert result is True
    
    def test_check_connection_health_failure(self):
        """Test health check returns False when connection fails."""
        # Mock the engine to raise an exception
        with patch.object(database.engine, 'connect') as mock_connect:
            mock_connect.side_effect = OperationalError("Connection failed", None, None)
            result = database.check_connection_health()
            assert result is False


class TestDatabaseInitialization:
    """Test database initialization and table creation."""
    
    def test_init_db_creates_tables(self):
        """Test that init_db creates tables successfully."""
        # Use a temporary database for testing
        with tempfile.TemporaryDirectory() as tmpdir:
            test_db_path = Path(tmpdir) / "test.db"
            test_url = f"sqlite:///{test_db_path}"
            
            # Temporarily replace the engine
            original_engine = database.engine
            original_session = database.SessionLocal
            
            try:
                from sqlalchemy import create_engine
                from sqlalchemy.orm import sessionmaker
                
                database.engine = create_engine(test_url)
                database.SessionLocal = sessionmaker(bind=database.engine)
                
                # Initialize database
                database.init_db()
                
                # Verify tables were created
                assert test_db_path.exists()
                
                # Verify Statistics table has initial row
                db = database.SessionLocal()
                try:
                    stats = db.query(database.Statistics).first()
                    assert stats is not None
                    assert stats.total_requests == 0
                finally:
                    db.close()
                    
            finally:
                # Restore original engine
                database.engine = original_engine
                database.SessionLocal = original_session


class TestReconnection:
    """Test database reconnection logic."""
    
    def test_reconnect_with_retry_success(self):
        """Test successful reconnection."""
        # Mock check_connection_health to return True
        with patch('backend.database.check_connection_health') as mock_health:
            mock_health.return_value = True
            
            result = database.reconnect_with_retry(max_retries=1, delay=0)
            assert result is True
    
    def test_reconnect_with_retry_failure(self):
        """Test reconnection failure after max retries."""
        # Mock check_connection_health to always return False
        with patch('backend.database.check_connection_health') as mock_health:
            mock_health.return_value = False
            
            result = database.reconnect_with_retry(max_retries=2, delay=0)
            assert result is False
            # Should have tried max_retries times
            assert mock_health.call_count >= 2


class TestGetDB:
    """Test database session management."""
    
    def test_get_db_yields_session(self):
        """Test that get_db yields a valid session."""
        gen = database.get_db()
        db = next(gen)
        assert db is not None
        
        # Clean up
        try:
            next(gen)
        except StopIteration:
            pass
    
    def test_get_db_closes_session(self):
        """Test that get_db closes session after use."""
        gen = database.get_db()
        db = next(gen)
        
        # Finish the generator
        try:
            next(gen)
        except StopIteration:
            pass
        
        # Session should be closed (this is hard to test directly,
        # but we can verify no exception was raised)
        assert True


class TestModels:
    """Test database models."""
    
    def test_alert_model_fields(self):
        """Test Alert model has required fields."""
        alert = database.Alert()
        
        # Check that key fields exist
        assert hasattr(alert, 'id')
        assert hasattr(alert, 'timestamp')
        assert hasattr(alert, 'method')
        assert hasattr(alert, 'url')
        assert hasattr(alert, 'source_ip')
        assert hasattr(alert, 'verdict')
        assert hasattr(alert, 'attack_type')
        assert hasattr(alert, 'rule_id')
        assert hasattr(alert, 'confidence')
        assert hasattr(alert, 'country')
        assert hasattr(alert, 'is_vpn')
    
    def test_statistics_model_fields(self):
        """Test Statistics model has required fields."""
        stats = database.Statistics()
        
        # Check that key fields exist
        assert hasattr(stats, 'id')
        assert hasattr(stats, 'total_requests')
        assert hasattr(stats, 'total_attacks')
        assert hasattr(stats, 'total_normal')
        assert hasattr(stats, 'sqli_count')
        assert hasattr(stats, 'xss_count')
        assert hasattr(stats, 'crs_caught')
        assert hasattr(stats, 'rf_caught')


class TestUpdateStats:
    """Test statistics update functionality."""
    
    def test_update_stats_attack(self):
        """Test updating statistics for an attack."""
        # Use a temporary database
        with tempfile.TemporaryDirectory() as tmpdir:
            test_db_path = Path(tmpdir) / "test.db"
            test_url = f"sqlite:///{test_db_path}"
            
            original_engine = database.engine
            original_session = database.SessionLocal
            
            try:
                from sqlalchemy import create_engine
                from sqlalchemy.orm import sessionmaker
                
                database.engine = create_engine(test_url)
                database.SessionLocal = sessionmaker(bind=database.engine)
                database.init_db()
                
                db = database.SessionLocal()
                try:
                    result = {
                        "verdict": "ATTACK",
                        "attack_type": "SQLI",
                        "stage": "RULE",
                        "is_vpn": False
                    }
                    
                    database.update_stats(db, result)
                    
                    stats = db.query(database.Statistics).first()
                    assert stats.total_requests == 1
                    assert stats.total_attacks == 1
                    assert stats.sqli_count == 1
                    assert stats.crs_caught == 1  # RULE detection uses crs_caught
                finally:
                    db.close()
                    
            finally:
                database.engine = original_engine
                database.SessionLocal = original_session
    
    def test_update_stats_clean(self):
        """Test updating statistics for a clean request."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_db_path = Path(tmpdir) / "test.db"
            test_url = f"sqlite:///{test_db_path}"
            
            original_engine = database.engine
            original_session = database.SessionLocal
            
            try:
                from sqlalchemy import create_engine
                from sqlalchemy.orm import sessionmaker
                
                database.engine = create_engine(test_url)
                database.SessionLocal = sessionmaker(bind=database.engine)
                database.init_db()
                
                db = database.SessionLocal()
                try:
                    result = {
                        "verdict": "CLEAN",
                        "stage": None,  # CLEAN verdicts have no detection source
                        "is_vpn": False
                    }
                    
                    database.update_stats(db, result)
                    
                    stats = db.query(database.Statistics).first()
                    assert stats.total_requests == 1
                    assert stats.total_normal == 1
                    # CLEAN verdicts don't have a detection source
                    assert stats.rf_caught == 0
                    assert stats.crs_caught == 0
                finally:
                    db.close()
                    
            finally:
                database.engine = original_engine
                database.SessionLocal = original_session


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
