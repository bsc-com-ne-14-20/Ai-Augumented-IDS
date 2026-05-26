"""
test_rate_limiting.py
====================
Unit tests for API rate limiting functionality.

Tests the rate limiting decorator to ensure it properly limits requests
to 100 per minute per IP address and returns HTTP 429 when exceeded.

Requirements: 19.7
"""

import time
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask, jsonify

from backend.api.validation import rate_limit, _rate_limit_storage


@pytest.fixture
def app():
    """Create a test Flask app with rate limiting."""
    app = Flask(__name__)
    
    @app.route("/test", methods=["POST"])
    @rate_limit(max_requests=5, window_seconds=10)  # Lower limits for testing
    def test_endpoint():
        return jsonify({"message": "success"}), 200
    
    return app


@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()


def test_rate_limit_allows_requests_within_limit(client):
    """Test that requests within the rate limit are allowed."""
    # Clear any existing rate limit data
    _rate_limit_storage.clear()
    
    # Make 5 requests (within limit)
    for i in range(5):
        response = client.post("/test", json={"test": f"request_{i}"})
        assert response.status_code == 200
        data = response.get_json()
        assert data["message"] == "success"


def test_rate_limit_blocks_requests_over_limit(client):
    """Test that requests over the rate limit are blocked with HTTP 429."""
    # Clear any existing rate limit data
    _rate_limit_storage.clear()
    
    # Make 5 requests (at limit)
    for i in range(5):
        response = client.post("/test", json={"test": f"request_{i}"})
        assert response.status_code == 200
    
    # 6th request should be blocked
    response = client.post("/test", json={"test": "request_6"})
    assert response.status_code == 429
    
    data = response.get_json()
    assert data["error"] == "RATE_LIMIT_EXCEEDED"
    assert "Rate limit exceeded" in data["detail"]


def test_rate_limit_resets_after_time_window(client):
    """Test that rate limit resets after the time window expires."""
    # Clear any existing rate limit data
    _rate_limit_storage.clear()
    
    # Make 5 requests (at limit)
    for i in range(5):
        response = client.post("/test", json={"test": f"request_{i}"})
        assert response.status_code == 200
    
    # 6th request should be blocked
    response = client.post("/test", json={"test": "request_6"})
    assert response.status_code == 429
    
    # Mock time to simulate window expiration
    future_time = time.time() + 11
    with patch('backend.api.validation.time.time') as mock_time:
        # Set time to 11 seconds later (past the 10-second window)
        mock_time.return_value = future_time
        
        # Request should now be allowed
        response = client.post("/test", json={"test": "request_after_reset"})
        assert response.status_code == 200


def test_rate_limit_per_ip_isolation():
    """Test that rate limiting is isolated per IP address."""
    # Clear any existing rate limit data
    _rate_limit_storage.clear()
    
    app = Flask(__name__)
    
    @app.route("/test", methods=["POST"])
    @rate_limit(max_requests=2, window_seconds=10)
    def test_endpoint():
        return jsonify({"message": "success"}), 200
    
    client = app.test_client()
    
    # Simulate requests from IP 1
    # Make 2 requests from IP 1 (at limit)
    for i in range(2):
        response = client.post("/test", json={"test": f"ip1_request_{i}"}, environ_base={'REMOTE_ADDR': '192.168.1.1'})
        assert response.status_code == 200
        
    # 3rd request from IP 1 should be blocked
    response = client.post("/test", json={"test": "ip1_request_3"}, environ_base={'REMOTE_ADDR': '192.168.1.1'})
    assert response.status_code == 429
    
    # Simulate requests from IP 2 (should still be allowed)
    response = client.post("/test", json={"test": "ip2_request_1"}, environ_base={'REMOTE_ADDR': '192.168.1.2'})
    assert response.status_code == 200


def test_rate_limit_handles_forwarded_headers():
    """Test that rate limiting correctly handles X-Forwarded-For headers."""
    # Clear any existing rate limit data
    _rate_limit_storage.clear()
    
    app = Flask(__name__)
    
    @app.route("/test", methods=["POST"])
    @rate_limit(max_requests=1, window_seconds=10)
    def test_endpoint():
        return jsonify({"message": "success"}), 200
    
    client = app.test_client()
    
    # Test with X-Forwarded-For header
    headers = {'X-Forwarded-For': '203.0.113.1, 198.51.100.1'}
    
    # First request should succeed
    response = client.post("/test", json={"test": "data"}, headers=headers)
    assert response.status_code == 200
    
    # Second request from same forwarded IP should be blocked
    response = client.post("/test", json={"test": "data"}, headers=headers)
    assert response.status_code == 429


def test_rate_limit_default_parameters():
    """Test that rate limiting uses correct default parameters."""
    app = Flask(__name__)
    
    @app.route("/test", methods=["POST"])
    @rate_limit()  # Use defaults: 100 requests per 60 seconds
    def test_endpoint():
        return jsonify({"message": "success"}), 200
    
    client = app.test_client()
    
    # Clear any existing rate limit data
    _rate_limit_storage.clear()
    
    # Make 100 requests (should all succeed)
    for i in range(100):
        response = client.post("/test", json={"test": f"request_{i}"})
        assert response.status_code == 200
    
    # 101st request should be blocked
    response = client.post("/test", json={"test": "request_101"})
    assert response.status_code == 429


def test_rate_limit_cleanup_old_entries():
    """Test that old rate limit entries are cleaned up properly."""
    # Clear any existing rate limit data
    _rate_limit_storage.clear()
    
    app = Flask(__name__)
    
    @app.route("/test", methods=["POST"])
    @rate_limit(max_requests=3, window_seconds=5)
    def test_endpoint():
        return jsonify({"message": "success"}), 200
    
    client = app.test_client()
    
    # Make 3 requests
    for i in range(3):
        response = client.post("/test", json={"test": f"request_{i}"})
        assert response.status_code == 200
    
    # 4th request should be blocked
    response = client.post("/test", json={"test": "request_4"})
    assert response.status_code == 429
    
    # Wait for window to expire and make another request
    future_time = time.time() + 6
    with patch('backend.api.validation.time.time') as mock_time:
        mock_time.return_value = future_time  # Past the 5-second window
        
        # This should clean up old entries and allow the request
        response = client.post("/test", json={"test": "request_after_cleanup"})
        assert response.status_code == 200
        
        # Verify that old entries were cleaned up
        # The storage should only contain the most recent request
        client_ip = '127.0.0.1'  # Default test client IP
        assert len(_rate_limit_storage[client_ip]) == 1


def test_rate_limit_error_response_format():
    """Test that rate limit error responses have the correct format."""
    # Clear any existing rate limit data
    _rate_limit_storage.clear()
    
    app = Flask(__name__)
    
    @app.route("/test", methods=["POST"])
    @rate_limit(max_requests=1, window_seconds=10)
    def test_endpoint():
        return jsonify({"message": "success"}), 200
    
    client = app.test_client()
    
    # First request succeeds
    response = client.post("/test", json={"test": "data"})
    assert response.status_code == 200
    
    # Second request should be rate limited
    response = client.post("/test", json={"test": "data"})
    assert response.status_code == 429
    
    data = response.get_json()
    assert "error" in data
    assert data["error"] == "RATE_LIMIT_EXCEEDED"
    assert "detail" in data
    assert "Rate limit exceeded" in data["detail"]
    assert "1 requests per 10 seconds" in data["detail"]


if __name__ == "__main__":
    pytest.main([__file__])