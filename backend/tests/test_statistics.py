"""
Unit tests for statistics aggregation functionality.

Tests Requirement 8.5: Statistics aggregation including total requests,
attack counts by type, and detection source breakdown.
"""

import pytest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import Base, Statistics, update_stats


@pytest.fixture
def db_session():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    # Initialize statistics row
    stats = Statistics()
    session.add(stats)
    session.commit()
    
    yield session
    session.close()


class TestStatisticsAggregation:
    """Test statistics aggregation for various detection scenarios."""
    
    def test_clean_request_increments_total_and_normal(self, db_session):
        """Test that CLEAN verdicts increment total_requests and total_normal."""
        result = {
            "verdict": "CLEAN",
            "attack_type": None,
            "stage": None,
            "is_vpn": False,
        }
        
        update_stats(db_session, result)
        
        stats = db_session.query(Statistics).first()
        assert stats.total_requests == 1
        assert stats.total_normal == 1
        assert stats.total_attacks == 0
    
    def test_attack_verdict_increments_total_and_attacks(self, db_session):
        """Test that ATTACK verdicts increment total_requests and total_attacks."""
        result = {
            "verdict": "ATTACK",
            "attack_type": "SQL_INJECTION",
            "stage": "RULE",
            "is_vpn": False,
        }
        
        update_stats(db_session, result)
        
        stats = db_session.query(Statistics).first()
        assert stats.total_requests == 1
        assert stats.total_attacks == 1
        assert stats.total_normal == 0
    
    def test_anomaly_verdict_increments_total_and_attacks(self, db_session):
        """Test that ANOMALY verdicts increment total_requests and total_attacks."""
        result = {
            "verdict": "ANOMALY",
            "attack_type": "UNKNOWN_ANOMALY",
            "stage": "ML",
            "is_vpn": False,
        }
        
        update_stats(db_session, result)
        
        stats = db_session.query(Statistics).first()
        assert stats.total_requests == 1
        assert stats.total_attacks == 1
        assert stats.total_normal == 0
    
    def test_error_verdict_increments_total_and_normal(self, db_session):
        """Test that ERROR verdicts increment total_requests and total_normal."""
        result = {
            "verdict": "ERROR",
            "attack_type": None,
            "stage": None,
            "is_vpn": False,
        }
        
        update_stats(db_session, result)
        
        stats = db_session.query(Statistics).first()
        assert stats.total_requests == 1
        assert stats.total_normal == 1
        assert stats.total_attacks == 0
    
    def test_sql_injection_attack_type_count(self, db_session):
        """Test that SQL_INJECTION attack type increments sqli_count."""
        result = {
            "verdict": "ATTACK",
            "attack_type": "SQL_INJECTION",
            "stage": "RULE",
            "is_vpn": False,
        }
        
        update_stats(db_session, result)
        
        stats = db_session.query(Statistics).first()
        assert stats.sqli_count == 1
        assert stats.xss_count == 0
        assert stats.traversal_count == 0
        assert stats.other_count == 0
    
    def test_sqli_legacy_attack_type_count(self, db_session):
        """Test that SQLI (legacy) attack type increments sqli_count."""
        result = {
            "verdict": "ATTACK",
            "attack_type": "SQLI",
            "stage": "RULE",
            "is_vpn": False,
        }
        
        update_stats(db_session, result)
        
        stats = db_session.query(Statistics).first()
        assert stats.sqli_count == 1
    
    def test_xss_attack_type_count(self, db_session):
        """Test that XSS attack type increments xss_count."""
        result = {
            "verdict": "ATTACK",
            "attack_type": "XSS",
            "stage": "RULE",
            "is_vpn": False,
        }
        
        update_stats(db_session, result)
        
        stats = db_session.query(Statistics).first()
        assert stats.xss_count == 1
        assert stats.sqli_count == 0
        assert stats.traversal_count == 0
        assert stats.other_count == 0
    
    def test_path_traversal_attack_type_count(self, db_session):
        """Test that PATH_TRAVERSAL attack type increments traversal_count."""
        result = {
            "verdict": "ATTACK",
            "attack_type": "PATH_TRAVERSAL",
            "stage": "RULE",
            "is_vpn": False,
        }
        
        update_stats(db_session, result)
        
        stats = db_session.query(Statistics).first()
        assert stats.traversal_count == 1
        assert stats.sqli_count == 0
        assert stats.xss_count == 0
        assert stats.other_count == 0
    
    def test_crlf_injection_attack_type_count(self, db_session):
        """Test that CRLF_INJECTION attack type increments other_count."""
        result = {
            "verdict": "ATTACK",
            "attack_type": "CRLF_INJECTION",
            "stage": "RULE",
            "is_vpn": False,
        }
        
        update_stats(db_session, result)
        
        stats = db_session.query(Statistics).first()
        assert stats.other_count == 1
        assert stats.sqli_count == 0
        assert stats.xss_count == 0
        assert stats.traversal_count == 0
    
    def test_brute_force_attack_type_count(self, db_session):
        """Test that BRUTE_FORCE attack type increments other_count."""
        result = {
            "verdict": "ATTACK",
            "attack_type": "BRUTE_FORCE",
            "stage": "RULE",
            "is_vpn": False,
        }
        
        update_stats(db_session, result)
        
        stats = db_session.query(Statistics).first()
        assert stats.other_count == 1
    
    def test_unknown_anomaly_attack_type_count(self, db_session):
        """Test that UNKNOWN_ANOMALY attack type increments other_count."""
        result = {
            "verdict": "ANOMALY",
            "attack_type": "UNKNOWN_ANOMALY",
            "stage": "ML",
            "is_vpn": False,
        }
        
        update_stats(db_session, result)
        
        stats = db_session.query(Statistics).first()
        assert stats.other_count == 1
    
    def test_rule_detection_source_count(self, db_session):
        """Test that RULE detection source increments crs_caught."""
        result = {
            "verdict": "ATTACK",
            "attack_type": "SQL_INJECTION",
            "stage": "RULE",
            "is_vpn": False,
        }
        
        update_stats(db_session, result)
        
        stats = db_session.query(Statistics).first()
        assert stats.crs_caught == 1
        assert stats.rf_caught == 0
    
    def test_ml_detection_source_count(self, db_session):
        """Test that ML detection source increments rf_caught."""
        result = {
            "verdict": "ANOMALY",
            "attack_type": "UNKNOWN_ANOMALY",
            "stage": "ML",
            "is_vpn": False,
        }
        
        update_stats(db_session, result)
        
        stats = db_session.query(Statistics).first()
        assert stats.rf_caught == 1
        assert stats.crs_caught == 0
    
    def test_vpn_flag_increments_vpn_count(self, db_session):
        """Test that is_vpn flag increments vpn_count."""
        result = {
            "verdict": "ATTACK",
            "attack_type": "SQL_INJECTION",
            "stage": "RULE",
            "is_vpn": True,
        }
        
        update_stats(db_session, result)
        
        stats = db_session.query(Statistics).first()
        assert stats.vpn_count == 1
    
    def test_non_vpn_does_not_increment_vpn_count(self, db_session):
        """Test that is_vpn=False does not increment vpn_count."""
        result = {
            "verdict": "ATTACK",
            "attack_type": "SQL_INJECTION",
            "stage": "RULE",
            "is_vpn": False,
        }
        
        update_stats(db_session, result)
        
        stats = db_session.query(Statistics).first()
        assert stats.vpn_count == 0
    
    def test_multiple_requests_aggregate_correctly(self, db_session):
        """Test that multiple requests aggregate statistics correctly."""
        # Clean request
        update_stats(db_session, {
            "verdict": "CLEAN",
            "attack_type": None,
            "stage": None,
            "is_vpn": False,
        })
        
        # SQL injection attack via rule engine
        update_stats(db_session, {
            "verdict": "ATTACK",
            "attack_type": "SQL_INJECTION",
            "stage": "RULE",
            "is_vpn": False,
        })
        
        # XSS attack via rule engine
        update_stats(db_session, {
            "verdict": "ATTACK",
            "attack_type": "XSS",
            "stage": "RULE",
            "is_vpn": True,
        })
        
        # ML anomaly
        update_stats(db_session, {
            "verdict": "ANOMALY",
            "attack_type": "UNKNOWN_ANOMALY",
            "stage": "ML",
            "is_vpn": False,
        })
        
        stats = db_session.query(Statistics).first()
        assert stats.total_requests == 4
        assert stats.total_attacks == 3
        assert stats.total_normal == 1
        assert stats.sqli_count == 1
        assert stats.xss_count == 1
        assert stats.other_count == 1
        assert stats.crs_caught == 2
        assert stats.rf_caught == 1
        assert stats.vpn_count == 1
    
    def test_last_updated_timestamp_is_set(self, db_session):
        """Test that last_updated timestamp is updated."""
        result = {
            "verdict": "CLEAN",
            "attack_type": None,
            "stage": None,
            "is_vpn": False,
        }
        
        before = datetime.utcnow()
        update_stats(db_session, result)
        after = datetime.utcnow()
        
        stats = db_session.query(Statistics).first()
        assert stats.last_updated is not None
        assert before <= stats.last_updated <= after
    
    def test_statistics_row_created_if_missing(self, db_session):
        """Test that statistics row is created if it doesn't exist."""
        # Delete the existing statistics row
        db_session.query(Statistics).delete()
        db_session.commit()
        
        result = {
            "verdict": "CLEAN",
            "attack_type": None,
            "stage": None,
            "is_vpn": False,
        }
        
        update_stats(db_session, result)
        
        stats = db_session.query(Statistics).first()
        assert stats is not None
        assert stats.total_requests == 1
