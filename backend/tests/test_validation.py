"""
test_validation.py
==================
Unit tests for request validation utilities.

Tests for:
- String sanitization
- Request size limiting
- Dictionary sanitization
- Rate limiting
- JSON schema validation
- Comprehensive validation

Requirements: 19.3, 19.4, 19.5, 19.6, 19.7
"""

import pytest
import time
from unittest.mock import Mock, patch
from flask import Flask
from marshmallow import Schema, fields

from backend.api.validation import (
    sanitize_string,
    sanitize_dict,
    check_request_size,
    rate_limit,
    validate_json_schema,
    validate_request_data,
    get_validation_errors,
    is_suspicious_request,
    MAX_REQUEST_SIZE,
    _rate_limit_storage
)


class TestSchema(Schema):
    """Test schema for validation tests."""
    name = fields.Str(required=True)
    age = fields.Int(required=True)


class TestStringSanitization:
    """Test string sanitization functionality."""
    
    def test_sanitize_none_value(self):
        """Test that None values return None."""
        result = sanitize_string(None)
        assert result is None
    
    def test_sanitize_normal_string(self):
        """Test that normal strings are preserved."""
        result = sanitize_string("normal string")
        assert result == "normal string"
    
    def test_sanitize_html_characters(self):
        """Test that HTML characters are escaped."""
        # Test with a string that has HTML but no attack patterns
        result = sanitize_string("<div>normal content</div>")
        assert "&lt;" in result
        assert "&gt;" in result
        assert "div" in result  # Content should still be there, just escaped
    
    def test_sanitize_sql_injection(self):
        """Test that SQL injection patterns are removed."""
        result = sanitize_string("SELECT * FROM users WHERE id=1 OR 1=1")
        assert "[SQL_REMOVED]" in result
        assert "SELECT" not in result
        assert "OR" not in result
    
    def test_sanitize_xss_patterns(self):
        """Test that XSS patterns are removed."""
        result = sanitize_string("javascript:alert('xss')")
        assert "[XSS_REMOVED]" in result
        assert "javascript:" not in result
    
    def test_sanitize_path_traversal(self):
        """Test that path traversal patterns are removed."""
        result = sanitize_string("../../../etc/passwd")
        assert "[PATH_REMOVED]" in result
        assert "../" not in result
    
    def test_sanitize_max_length(self):
        """Test that strings are truncated to maximum length."""
        long_string = "a" * 10000
        result = sanitize_string(long_string, max_length=100)
        assert len(result) == 100
    
    def test_sanitize_non_string_input(self):
        """Test that non-string inputs are converted to strings."""
        result = sanitize_string(12345)
        assert result == "12345"


class TestDictionarySanitization:
    """Test dictionary sanitization functionality."""
    
    def test_sanitize_simple_dict(self):
        """Test sanitization of simple dictionary."""
        data = {
            "normal": "value",
            "sql": "SELECT * FROM users",
            "xss": "<script>alert('xss')</script>",
            "html": "<div>safe content</div>"
        }
        result = sanitize_dict(data)
        
        assert result["normal"] == "value"
        assert "[SQL_REMOVED]" in result["sql"]
        assert result["xss"] == "[XSS_REMOVED]"  # XSS patterns completely removed
        assert "&lt;" in result["html"] and "div" in result["html"]  # HTML escaped
    
    def test_sanitize_nested_dict(self):
        """Test sanitization of nested dictionary."""
        data = {
            "outer": {
                "inner": "SELECT * FROM users",
                "safe": "normal value"
            }
        }
        result = sanitize_dict(data)
        
        assert "[SQL_REMOVED]" in result["outer"]["inner"]
        assert result["outer"]["safe"] == "normal value"
    
    def test_sanitize_dict_with_list(self):
        """Test sanitization of dictionary containing lists."""
        data = {
            "items": [
                "normal string",
                "SELECT * FROM users",
                {"nested": "<script>alert('xss')</script>"},
                {"safe_html": "<div>content</div>"}
            ]
        }
        result = sanitize_dict(data)
        
        assert result["items"][0] == "normal string"
        assert "[SQL_REMOVED]" in result["items"][1]
        assert result["items"][2]["nested"] == "[XSS_REMOVED]"
        assert "&lt;" in result["items"][3]["safe_html"]
    
    def test_sanitize_dict_keys(self):
        """Test that dictionary keys are also sanitized."""
        data = {
            "SELECT * FROM users": "value",
            "normal_key": "value"
        }
        result = sanitize_dict(data)
        
        # Keys should be sanitized
        keys = list(result.keys())
        assert any("[SQL_REMOVED]" in key for key in keys)
        assert "normal_key" in keys


class TestRequestSizeValidation:
    """Test request size validation decorator."""
    
    def test_request_size_within_limit(self):
        """Test that requests within size limit are allowed."""
        app = Flask(__name__)
        
        with app.test_request_context('/', method='POST', 
                                    headers={'Content-Length': '1000'}):
            @check_request_size()
            def test_function():
                return "success"
            
            result = test_function()
            assert result == "success"
    
    def test_request_size_exceeds_limit(self):
        """Test that requests exceeding size limit are rejected."""
        app = Flask(__name__)
        
        # Use environ_base to properly set Content-Length
        with app.test_request_context('/', method='POST', 
                                    environ_base={'CONTENT_LENGTH': str(MAX_REQUEST_SIZE + 1)}):
            @check_request_size()
            def test_function():
                return "success"
            
            result = test_function()
            
            # Should return tuple (response, status_code)
            assert isinstance(result, tuple)
            assert result[1] == 413  # HTTP 413 Request Entity Too Large
    
    def test_request_size_no_content_length(self):
        """Test handling of requests without Content-Length header."""
        app = Flask(__name__)
        
        with app.test_request_context('/', method='POST', data=b"small data"):
            @check_request_size()
            def test_function():
                return "success"
            
            result = test_function()
            assert result == "success"
    
    def test_request_data_exceeds_limit(self):
        """Test that request data exceeding limit is rejected."""
        app = Flask(__name__)
        large_data = b"x" * (MAX_REQUEST_SIZE + 1)
        
        with app.test_request_context('/', method='POST', data=large_data):
            @check_request_size()
            def test_function():
                return "success"
            
            result = test_function()
            
            assert isinstance(result, tuple)
            assert result[1] == 413


class TestRateLimiting:
    """Test rate limiting functionality."""
    
    def setup_method(self):
        """Clear rate limit storage before each test."""
        _rate_limit_storage.clear()
    
    def test_rate_limit_within_limit(self):
        """Test that requests within rate limit are allowed."""
        app = Flask(__name__)
        
        with app.test_request_context('/', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
            @rate_limit(max_requests=5, window_seconds=60)
            def test_function():
                return "success"
            
            # Make 5 requests (within limit)
            for i in range(5):
                result = test_function()
                assert result == "success"
    
    def test_rate_limit_exceeds_limit(self):
        """Test that requests exceeding rate limit are rejected."""
        app = Flask(__name__)
        
        with app.test_request_context('/', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
            @rate_limit(max_requests=3, window_seconds=60)
            def test_function():
                return "success"
            
            # Make 3 requests (at limit)
            for i in range(3):
                result = test_function()
                assert result == "success"
            
            # 4th request should be rejected
            result = test_function()
            assert isinstance(result, tuple)
            assert result[1] == 429  # HTTP 429 Too Many Requests
    
    def test_rate_limit_different_ips(self):
        """Test that rate limiting is per-IP."""
        app = Flask(__name__)
        
        @rate_limit(max_requests=2, window_seconds=60)
        def test_function():
            return "success"
        
        # IP 1 makes 2 requests
        with app.test_request_context('/', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
            for i in range(2):
                result = test_function()
                assert result == "success"
        
        # IP 2 should still be able to make requests
        with app.test_request_context('/', environ_base={'REMOTE_ADDR': '192.168.1.1'}):
            result = test_function()
            assert result == "success"
    
    def test_rate_limit_window_expiry(self):
        """Test that rate limit window expires correctly."""
        app = Flask(__name__)
        
        with app.test_request_context('/', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
            @rate_limit(max_requests=2, window_seconds=1)  # 1 second window
            def test_function():
                return "success"
            
            # Make 2 requests (at limit)
            for i in range(2):
                result = test_function()
                assert result == "success"
            
            # 3rd request should be rejected
            result = test_function()
            assert isinstance(result, tuple)
            assert result[1] == 429
            
            # Wait for window to expire
            time.sleep(1.1)
            
            # Should be able to make requests again
            result = test_function()
            assert result == "success"


class TestJSONSchemaValidation:
    """Test JSON schema validation functionality."""
    
    def test_valid_json_schema(self):
        """Test that valid JSON passes schema validation."""
        app = Flask(__name__)
        
        with app.test_request_context('/', method='POST', json={"name": "John", "age": 30}):
            @validate_json_schema(TestSchema)
            def test_function():
                return "success"
            
            result = test_function()
            assert result == "success"
    
    def test_invalid_json_schema(self):
        """Test that invalid JSON fails schema validation."""
        app = Flask(__name__)
        
        with app.test_request_context('/', method='POST', json={"name": "John"}):  # Missing age
            @validate_json_schema(TestSchema)
            def test_function():
                return "success"
            
            result = test_function()
            assert isinstance(result, tuple)
            assert result[1] == 400  # HTTP 400 Bad Request
    
    def test_non_json_request(self):
        """Test that non-JSON requests fail validation."""
        app = Flask(__name__)
        
        with app.test_request_context('/', method='POST', data="not json"):
            @validate_json_schema(TestSchema)
            def test_function():
                return "success"
            
            result = test_function()
            assert isinstance(result, tuple)
            assert result[1] == 400


class TestSuspiciousRequestDetection:
    """Test suspicious request detection."""
    
    def test_normal_request_not_suspicious(self):
        """Test that normal requests are not flagged as suspicious."""
        data = {
            "name": "John Doe",
            "email": "john@example.com",
            "message": "Hello world"
        }
        assert not is_suspicious_request(data)
    
    def test_single_attack_pattern_not_suspicious(self):
        """Test that single attack patterns are not flagged as suspicious."""
        data = {
            "query": "SELECT * FROM users"  # Only SQL injection
        }
        assert not is_suspicious_request(data)
    
    def test_multiple_attack_patterns_suspicious(self):
        """Test that multiple attack patterns are flagged as suspicious."""
        data = {
            "query": "SELECT * FROM users; <script>alert('xss')</script>"  # SQL + XSS
        }
        assert is_suspicious_request(data)
    
    def test_nested_suspicious_data(self):
        """Test detection in nested data structures."""
        data = {
            "user": {
                "profile": {
                    "bio": "SELECT * FROM users; ../../../etc/passwd"  # SQL + Path traversal
                }
            }
        }
        assert is_suspicious_request(data)


class TestValidationHelpers:
    """Test validation helper functions."""
    
    def test_get_validation_errors_valid(self):
        """Test validation error helper with valid data."""
        data = {"name": "John", "age": 30}
        errors = get_validation_errors(data, TestSchema)
        assert errors is None
    
    def test_get_validation_errors_invalid(self):
        """Test validation error helper with invalid data."""
        data = {"name": "John"}  # Missing age
        errors = get_validation_errors(data, TestSchema)
        assert errors is not None
        assert "age" in errors


if __name__ == "__main__":
    pytest.main([__file__])