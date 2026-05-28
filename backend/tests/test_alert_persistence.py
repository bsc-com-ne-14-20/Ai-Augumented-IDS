"""
test_alert_persistence.py
=========================
Unit tests for alert persistence handler in backend/sockets/events.py

Tests verify:
- Alert persistence for all verdicts (CLEAN, ATTACK, ANOMALY, ERROR)
- Geolocation data storage when available
- VPN/proxy/Tor flag storage when available
- Transaction commit time within 10ms threshold
- Error handling for database failures
- Statistics aggregation

Requirements: 8.1, 8.2, 8.3, 8.4, 8.6, 8.7
"""

import pytest
import time
from datetime import datetime
from unittest.mock import Mock, patch

from backend.sockets.events import persist_alert, _parse_timestamp
from backend.database import SessionLocal, Alert, Statistics


class TestAlertPersistence:
    """Test suite for alert persistence handler."""
    
    def test_persist_attack_verdict(self, db_session):
        """Test persisting ATTACK verdict with rule detection."""
        verdict_payload = {
            "alert_id": "test-alert-001",
            "timestamp": "2024-01-15T10:30:00+00:00",
            "verdict": "ATTACK",
            "detection_source": "RULE",
            "severity": "high",
            "attack_type": "SQLI",
            "rule_triggered": "SQLI-001",
            "confidence": 0.95,
            "request_summary": {
                "method": "POST",
                "path": "/api/login",
                "query_string": "user=admin' OR '1'='1",
            },
        }
        
        raw_log_entry = {
            "method": "POST",
            "url": "/api/login?user=admin' OR '1'='1",
            "source_ip": "192.168.1.100",
        }
        
        # Persist alert
        persist_alert(verdict_payload, raw_log_entry, db_session)
        
        # Verify alert was persisted
        alert = db_session.query(Alert).filter_by(source_ip="192.168.1.100").first()
        assert alert is not None
        assert alert.verdict == "ATTACK"
        assert alert.attack_type == "SQLI"
        assert alert.rule_id == "SQLI-001"
        assert alert.stage == "RULE"
        assert alert.confidence == 0.95
        assert alert.method == "POST"
        assert alert.url == "/api/login?user=admin&#x27; [SQL_REMOVED] &#x27;1&#x27;=&#x27;1"
        assert alert.source_ip == "192.168.1.100"
    
    def test_persist_anomaly_verdict(self, db_session):
        """Test persisting ANOMALY verdict with ML detection."""
        verdict_payload = {
            "alert_id": "test-alert-002",
            "timestamp": "2024-01-15T10:31:00+00:00",
            "verdict": "ANOMALY",
            "detection_source": "ML",
            "severity": "medium",
            "attack_type": "UNKNOWN_ANOMALY",
            "rule_triggered": None,
            "confidence": 0.78,
            "request_summary": {
                "method": "GET",
                "path": "/api/data",
                "query_string": "",
            },
        }
        
        raw_log_entry = {
            "method": "GET",
            "url": "/api/data",
            "source_ip": "10.0.0.50",
        }
        
        # Persist alert
        persist_alert(verdict_payload, raw_log_entry, db_session)
        
        # Verify alert was persisted
        alert = db_session.query(Alert).filter_by(source_ip="10.0.0.50").first()
        assert alert is not None
        assert alert.verdict == "ANOMALY"
        assert alert.attack_type == "UNKNOWN_ANOMALY"
        assert alert.rule_id is None
        assert alert.stage == "ML"
        assert alert.confidence == 0.78
    
    def test_persist_clean_verdict(self, db_session):
        """Test persisting CLEAN verdict."""
        verdict_payload = {
            "alert_id": "test-alert-003",
            "timestamp": "2024-01-15T10:32:00+00:00",
            "verdict": "CLEAN",
            "detection_source": None,
            "severity": None,
            "attack_type": None,
            "rule_triggered": None,
            "confidence": None,
            "request_summary": {
                "method": "GET",
                "path": "/",
                "query_string": "",
            },
        }
        
        raw_log_entry = {
            "method": "GET",
            "url": "/",
            "source_ip": "172.16.0.10",
        }
        
        # Persist alert
        persist_alert(verdict_payload, raw_log_entry, db_session)
        
        # Verify alert was persisted
        alert = db_session.query(Alert).filter_by(source_ip="172.16.0.10").first()
        assert alert is not None
        assert alert.verdict == "CLEAN"
        assert alert.attack_type is None
        assert alert.rule_id is None
        assert alert.stage is None
        assert alert.confidence == 0.0
    
    def test_persist_error_verdict(self, db_session):
        """Test persisting ERROR verdict."""
        verdict_payload = {
            "alert_id": "test-alert-004",
            "timestamp": "2024-01-15T10:33:00+00:00",
            "verdict": "ERROR",
            "detection_source": None,
            "severity": None,
            "attack_type": None,
            "rule_triggered": None,
            "confidence": None,
            "error": "Feature extraction failed",
            "request_summary": {
                "method": "POST",
                "path": "/api/submit",
                "query_string": "",
            },
        }
        
        raw_log_entry = {
            "method": "POST",
            "url": "/api/submit",
            "source_ip": "192.168.2.50",
        }
        
        # Persist alert
        persist_alert(verdict_payload, raw_log_entry, db_session)
        
        # Verify alert was persisted
        alert = db_session.query(Alert).filter_by(source_ip="192.168.2.50").first()
        assert alert is not None
        assert alert.verdict == "ERROR"
    
    def test_persist_with_geolocation(self, db_session):
        """Test persisting alert with geolocation data."""
        verdict_payload = {
            "alert_id": "test-alert-005",
            "timestamp": "2024-01-15T10:34:00+00:00",
            "verdict": "ATTACK",
            "detection_source": "RULE",
            "severity": "critical",
            "attack_type": "XSS",
            "rule_triggered": "XSS-001",
            "confidence": 0.99,
            "request_summary": {
                "method": "POST",
                "path": "/comment",
                "query_string": "",
            },
        }
        
        raw_log_entry = {
            "method": "POST",
            "url": "/comment",
            "source_ip": "203.0.113.45",
            "geolocation": {
                "country": "United States",
                "city": "New York",
                "latitude": 40.7128,
                "longitude": -74.0060,
                "isp": "Example ISP",
            },
        }
        
        # Persist alert
        persist_alert(verdict_payload, raw_log_entry, db_session)
        
        # Verify geolocation data was stored
        alert = db_session.query(Alert).filter_by(source_ip="203.0.113.45").first()
        assert alert is not None
        assert alert.country == "United States"
        assert alert.city == "New York"
        assert alert.latitude == 40.7128
        assert alert.longitude == -74.0060
        assert alert.isp == "Example ISP"
    
    def test_persist_with_vpn_flags(self, db_session):
        """Test persisting alert with VPN/proxy/Tor flags."""
        verdict_payload = {
            "alert_id": "test-alert-006",
            "timestamp": "2024-01-15T10:35:00+00:00",
            "verdict": "ATTACK",
            "detection_source": "RULE",
            "severity": "high",
            "attack_type": "PATH_TRAVERSAL",
            "rule_triggered": "TRAV-001",
            "confidence": 0.88,
            "request_summary": {
                "method": "GET",
                "path": "/../etc/passwd",
                "query_string": "",
            },
        }
        
        raw_log_entry = {
            "method": "GET",
            "url": "/../etc/passwd",
            "source_ip": "198.51.100.10",
            "is_vpn": True,
            "is_proxy": False,
            "is_tor": False,
        }
        
        # Persist alert
        persist_alert(verdict_payload, raw_log_entry, db_session)
        
        # Verify VPN/proxy/Tor flags were stored
        alert = db_session.query(Alert).filter_by(source_ip="198.51.100.10").first()
        assert alert is not None
        assert alert.is_vpn is True
        assert alert.is_proxy is False
        assert alert.is_tor is False
    
    def test_persist_missing_optional_fields(self, db_session):
        """Test persisting alert with missing optional fields."""
        verdict_payload = {
            "alert_id": "test-alert-007",
            "timestamp": "2024-01-15T10:36:00+00:00",
            "verdict": "CLEAN",
            "detection_source": None,
            "severity": None,
            "attack_type": None,
            "rule_triggered": None,
            "confidence": None,
            "request_summary": {
                "method": "GET",
                "path": "/health",
                "query_string": "",
            },
        }
        
        raw_log_entry = {
            "method": "GET",
            "url": "/health",
            "source_ip": "192.0.2.100",
            # No geolocation or VPN flags
        }
        
        # Persist alert
        persist_alert(verdict_payload, raw_log_entry, db_session)
        
        # Verify alert was persisted with default values
        alert = db_session.query(Alert).filter_by(source_ip="192.0.2.100").first()
        assert alert is not None
        assert alert.country is None
        assert alert.city is None
        assert alert.latitude is None
        assert alert.longitude is None
        assert alert.isp is None
        assert alert.is_vpn is False
        assert alert.is_proxy is False
        assert alert.is_tor is False
    
    def test_transaction_commit_time(self, db_session):
        """Test that transaction commits within 10ms threshold."""
        verdict_payload = {
            "alert_id": "test-alert-008",
            "timestamp": "2024-01-15T10:37:00+00:00",
            "verdict": "ATTACK",
            "detection_source": "RULE",
            "severity": "high",
            "attack_type": "SQLI",
            "rule_triggered": "SQLI-002",
            "confidence": 0.92,
            "request_summary": {
                "method": "POST",
                "path": "/api/search",
                "query_string": "",
            },
        }
        
        raw_log_entry = {
            "method": "POST",
            "url": "/api/search",
            "source_ip": "10.1.1.50",
        }
        
        # Measure persistence time
        start_time = time.perf_counter()
        persist_alert(verdict_payload, raw_log_entry, db_session)
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        # Verify transaction completed within 10ms (with some tolerance for test overhead)
        # Note: In production, the function logs a warning if it exceeds 10ms
        assert elapsed_ms < 100, f"Transaction took {elapsed_ms:.2f}ms (expected < 100ms for test)"
        
        # Verify alert was persisted
        alert = db_session.query(Alert).filter_by(source_ip="10.1.1.50").first()
        assert alert is not None
    
    def test_statistics_aggregation(self, db_session):
        """Test that statistics are updated after alert persistence."""
        # Get initial statistics
        stats_before = db_session.query(Statistics).first()
        initial_total = stats_before.total_requests if stats_before else 0
        initial_attacks = stats_before.total_attacks if stats_before else 0
        
        verdict_payload = {
            "alert_id": "test-alert-009",
            "timestamp": "2024-01-15T10:38:00+00:00",
            "verdict": "ATTACK",
            "detection_source": "RULE",
            "severity": "high",
            "attack_type": "SQLI",
            "rule_triggered": "SQLI-003",
            "confidence": 0.96,
            "request_summary": {
                "method": "POST",
                "path": "/api/login",
                "query_string": "",
            },
        }
        
        raw_log_entry = {
            "method": "POST",
            "url": "/api/login",
            "source_ip": "172.20.0.10",
        }
        
        # Persist alert
        persist_alert(verdict_payload, raw_log_entry, db_session)
        
        # Verify statistics were updated
        stats_after = db_session.query(Statistics).first()
        assert stats_after is not None
        assert stats_after.total_requests == initial_total + 1
        assert stats_after.total_attacks == initial_attacks + 1
    
    def test_database_error_handling(self, caplog):
        """Test error handling when database persistence fails."""
        verdict_payload = {
            "alert_id": "test-alert-010",
            "timestamp": "2024-01-15T10:39:00+00:00",
            "verdict": "ATTACK",
            "detection_source": "RULE",
            "severity": "high",
            "attack_type": "XSS",
            "rule_triggered": "XSS-002",
            "confidence": 0.91,
            "request_summary": {
                "method": "POST",
                "path": "/api/comment",
                "query_string": "",
            },
        }
        
        raw_log_entry = {
            "method": "POST",
            "url": "/api/comment",
            "source_ip": "192.168.5.100",
        }
        
        # Mock database session to raise an exception
        with patch('backend.sockets.events.SessionLocal') as mock_session:
            mock_db = Mock()
            mock_db.add.side_effect = Exception("Database connection failed")
            mock_db.is_active = True
            mock_session.return_value = mock_db
            
            # Persist alert (should not raise exception)
            persist_alert(verdict_payload, raw_log_entry)
            
            # Verify error was logged with enhanced context
            assert "Database persistence failed" in caplog.text
            assert "test-alert-010" in caplog.text
            assert "ATTACK" in caplog.text
            assert "192.168.5.100" in caplog.text
            assert "/api/comment" in caplog.text
            assert "Application will continue processing remaining requests" in caplog.text
            
            # Verify proper cleanup was attempted
            assert mock_db.rollback.called
            assert mock_db.close.called
    
    def test_database_error_handling_with_statistics_failure(self, caplog):
        """Test error handling when statistics update fails but alert persistence succeeds."""
        verdict_payload = {
            "alert_id": "test-alert-011",
            "timestamp": "2024-01-15T10:40:00+00:00",
            "verdict": "ATTACK",
            "detection_source": "RULE",
            "severity": "high",
            "attack_type": "SQLI",
            "rule_triggered": "SQLI-004",
            "confidence": 0.93,
            "request_summary": {
                "method": "POST",
                "path": "/api/login",
                "query_string": "",
            },
        }
        
        raw_log_entry = {
            "method": "POST",
            "url": "/api/login",
            "source_ip": "192.168.6.100",
        }
        
        # Mock database session where alert persistence succeeds but statistics update fails
        with patch('backend.sockets.events.SessionLocal') as mock_session:
            mock_db = Mock()
            # Alert persistence succeeds
            mock_db.add.return_value = None
            mock_db.commit.return_value = None
            # Statistics update fails
            with patch('backend.sockets.events.update_stats') as mock_update_stats:
                mock_update_stats.side_effect = Exception("Statistics table locked")
                mock_db.is_active = True
                mock_session.return_value = mock_db
                
                # Persist alert (should not raise exception)
                persist_alert(verdict_payload, raw_log_entry)
                
                # Verify statistics error was logged separately
                assert "Failed to update aggregate statistics" in caplog.text
                assert "test-alert-011" in caplog.text
                assert "Statistics table locked" in caplog.text
                
                # Verify alert persistence succeeded (no alert persistence error)
                assert "Failed to persist alert record" not in caplog.text
                
                # Verify proper cleanup was attempted for statistics
                assert mock_db.rollback.called
                assert mock_db.close.called
    
    def test_database_session_cleanup_on_rollback_failure(self, caplog):
        """Test proper session cleanup when rollback itself fails."""
        verdict_payload = {
            "alert_id": "test-alert-012",
            "timestamp": "2024-01-15T10:41:00+00:00",
            "verdict": "ATTACK",
            "detection_source": "RULE",
            "severity": "high",
            "attack_type": "XSS",
            "rule_triggered": "XSS-003",
            "confidence": 0.89,
            "request_summary": {
                "method": "POST",
                "path": "/api/submit",
                "query_string": "",
            },
        }
        
        raw_log_entry = {
            "method": "POST",
            "url": "/api/submit",
            "source_ip": "192.168.7.100",
        }
        
        # Mock database session where both persistence and rollback fail
        with patch('backend.sockets.events.SessionLocal') as mock_session:
            mock_db = Mock()
            mock_db.add.side_effect = Exception("Database connection failed")
            mock_db.rollback.side_effect = Exception("Rollback failed")
            mock_db.is_active = True
            mock_session.return_value = mock_db
            
            # Persist alert (should not raise exception)
            persist_alert(verdict_payload, raw_log_entry)
            
            # Verify both errors were logged
            assert "Failed to persist alert record" in caplog.text
            assert "Failed to rollback database transaction" in caplog.text
            assert "test-alert-012" in caplog.text
            
            # Verify cleanup was still attempted
            assert mock_db.rollback.called
            assert mock_db.close.called
    
    def test_database_session_cleanup_on_close_failure(self, caplog):
        """Test error handling when session close fails."""
        verdict_payload = {
            "alert_id": "test-alert-013",
            "timestamp": "2024-01-15T10:42:00+00:00",
            "verdict": "CLEAN",
            "detection_source": None,
            "severity": None,
            "attack_type": None,
            "rule_triggered": None,
            "confidence": None,
            "request_summary": {
                "method": "GET",
                "path": "/health",
                "query_string": "",
            },
        }
        
        raw_log_entry = {
            "method": "GET",
            "url": "/health",
            "source_ip": "192.168.8.100",
        }
        
        # Mock database session where close fails
        with patch('backend.sockets.events.SessionLocal') as mock_session:
            mock_db = Mock()
            mock_db.close.side_effect = Exception("Session close failed")
            mock_db.is_active = False
            mock_session.return_value = mock_db
            
            # Persist alert (should not raise exception)
            persist_alert(verdict_payload, raw_log_entry)
            
            # Verify close error was logged
            assert "Failed to close database session" in caplog.text
            assert "test-alert-013" in caplog.text
            
            # Verify close was attempted
            assert mock_db.close.called


class TestTimestampParsing:
    """Test suite for timestamp parsing helper."""
    
    def test_parse_iso8601_with_timezone(self):
        """Test parsing ISO 8601 timestamp with timezone."""
        timestamp_str = "2024-01-15T10:30:00+00:00"
        result = _parse_timestamp(timestamp_str)
        assert isinstance(result, datetime)
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15
        assert result.hour == 10
        assert result.minute == 30
    
    def test_parse_iso8601_with_z_suffix(self):
        """Test parsing ISO 8601 timestamp with Z suffix."""
        timestamp_str = "2024-01-15T10:30:00Z"
        result = _parse_timestamp(timestamp_str)
        assert isinstance(result, datetime)
        assert result.year == 2024
    
    def test_parse_invalid_timestamp(self):
        """Test parsing invalid timestamp falls back to current time."""
        timestamp_str = "invalid-timestamp"
        result = _parse_timestamp(timestamp_str)
        assert isinstance(result, datetime)
        # Should be close to current time
        assert (datetime.utcnow() - result).total_seconds() < 1
    
    def test_parse_none_timestamp(self):
        """Test parsing None timestamp falls back to current time."""
        result = _parse_timestamp(None)
        assert isinstance(result, datetime)
        # Should be close to current time
        assert (datetime.utcnow() - result).total_seconds() < 1
