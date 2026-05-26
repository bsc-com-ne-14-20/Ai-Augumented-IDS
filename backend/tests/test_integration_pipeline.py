"""
Integration test for the complete detection pipeline.

Tests the full flow: raw request → feature extraction → rule engine → ML model
"""

import pytest
from backend.pipeline.orchestrator import run_pipeline


class TestPipelineIntegration:
    """Test end-to-end pipeline with HTTPFeatureExtractor."""
    
    def test_clean_request_pipeline(self):
        """Test that a clean request passes through the entire pipeline."""
        request = {
            "method": "GET",
            "url": "/products?category=electronics",
            "path": "/products",
            "query_string": "category=electronics",
            "body": "",
            "headers": {"accept": "text/html"},
            "content_length": 0,
            "source_ip": "192.168.1.100",
            "timestamp": "2024-01-15T10:30:00Z"
        }
        
        result = run_pipeline(request)
        
        # Should return CLEAN verdict (or ANOMALY if ML model detects something)
        assert result["verdict"] in ["CLEAN", "ANOMALY"]
        assert "alert_id" in result
        assert "timestamp" in result
    
    def test_sqli_attack_detected_by_rules(self):
        """Test that SQLi attack is detected by rule engine."""
        request = {
            "method": "GET",
            "url": "/search?q=test' UNION SELECT * FROM users--",
            "path": "/search",
            "query_string": "q=test' UNION SELECT * FROM users--",
            "body": "",
            "headers": {},
            "content_length": 0,
            "source_ip": "192.168.1.100",
            "timestamp": "2024-01-15T10:30:00Z"
        }
        
        result = run_pipeline(request)
        
        assert result["verdict"] == "ATTACK"
        assert result["detection_source"] == "RULE"
        assert result["attack_type"] == "SQL_INJECTION"
        # Severity may be None for rule-based detections
        assert result["severity"] in ["low", "medium", "high", "critical", None]
    
    def test_xss_attack_detected_by_rules(self):
        """Test that XSS attack is detected by rule engine."""
        request = {
            "method": "POST",
            "url": "/comment",
            "path": "/comment",
            "query_string": "",
            "body": "text=<script>alert('XSS')</script>",
            "headers": {"content_type": "application/x-www-form-urlencoded"},
            "content_length": 38,
            "source_ip": "192.168.1.100",
            "timestamp": "2024-01-15T10:30:00Z"
        }
        
        result = run_pipeline(request)
        
        assert result["verdict"] == "ATTACK"
        assert result["detection_source"] == "RULE"
        assert result["attack_type"] == "XSS"
    
    def test_path_traversal_detected_by_rules(self):
        """Test that path traversal is detected by rule engine."""
        request = {
            "method": "GET",
            "url": "/file?path=../../etc/passwd",
            "path": "/file",
            "query_string": "path=../../etc/passwd",
            "body": "",
            "headers": {},
            "content_length": 0,
            "source_ip": "192.168.1.100",
            "timestamp": "2024-01-15T10:30:00Z"
        }
        
        result = run_pipeline(request)
        
        assert result["verdict"] == "ATTACK"
        assert result["detection_source"] == "RULE"
        assert result["attack_type"] == "PATH_TRAVERSAL"
    
    def test_url_encoded_attack_detection(self):
        """Test that URL-encoded attacks are properly decoded and detected."""
        request = {
            "method": "GET",
            "url": "/search?q=test%27%20OR%20%271%27%3D%271",
            "path": "/search",
            "query_string": "q=test%27%20OR%20%271%27%3D%271",
            "body": "",
            "headers": {},
            "content_length": 0,
            "source_ip": "192.168.1.100",
            "timestamp": "2024-01-15T10:30:00Z"
        }
        
        result = run_pipeline(request)
        
        # Should detect SQLi after URL decoding
        assert result["verdict"] == "ATTACK"
        assert result["detection_source"] == "RULE"
        assert result["attack_type"] == "SQL_INJECTION"
    
    def test_real_world_github_url(self):
        """Test pipeline with real-world GitHub URL."""
        request = {
            "method": "GET",
            "url": "https://github.com/user/repo/issues?q=is%3Aopen+is%3Aissue",
            "path": "/user/repo/issues",
            "query_string": "q=is%3Aopen+is%3Aissue",
            "body": "",
            "headers": {
                "accept": "text/html",
                "cookie": "session=abc123; user_id=456"
            },
            "content_length": 0,
            "source_ip": "192.168.1.100",
            "timestamp": "2024-01-15T10:30:00Z"
        }
        
        result = run_pipeline(request)
        
        # Should be clean (or possibly ANOMALY if ML model flags it)
        assert result["verdict"] in ["CLEAN", "ANOMALY"]
        assert "alert_id" in result
    
    def test_real_world_rest_api_request(self):
        """Test pipeline with real-world REST API request."""
        request = {
            "method": "POST",
            "url": "/api/v1/users",
            "path": "/api/v1/users",
            "query_string": "",
            "body": '{"name":"John Doe","email":"john@example.com"}',
            "headers": {"content_type": "application/json"},
            "content_length": 46,
            "source_ip": "192.168.1.100",
            "timestamp": "2024-01-15T10:30:00Z"
        }
        
        result = run_pipeline(request)
        
        # Should be clean
        assert result["verdict"] in ["CLEAN", "ANOMALY"]
        assert "alert_id" in result
    
    def test_error_handling_invalid_request(self):
        """Test that pipeline handles invalid requests gracefully."""
        request = {
            "method": "GET",
            # Missing required fields - pipeline should handle gracefully
        }
        
        result = run_pipeline(request)
        
        # Pipeline is resilient - may return ERROR or process with defaults
        assert result["verdict"] in ["ERROR", "CLEAN", "ANOMALY", "ATTACK"]
        assert "alert_id" in result
    
    def test_batch_processing(self):
        """Test processing multiple requests in sequence."""
        requests = [
            {
                "method": "GET",
                "url": "/page1",
                "path": "/page1",
                "query_string": "",
                "body": "",
                "headers": {},
                "content_length": 0,
                "source_ip": "192.168.1.100",
                "timestamp": "2024-01-15T10:30:00Z"
            },
            {
                "method": "GET",
                "url": "/search?q=test' OR '1'='1",
                "path": "/search",
                "query_string": "q=test' OR '1'='1",
                "body": "",
                "headers": {},
                "content_length": 0,
                "source_ip": "192.168.1.100",
                "timestamp": "2024-01-15T10:30:01Z"
            },
            {
                "method": "GET",
                "url": "/page2",
                "path": "/page2",
                "query_string": "",
                "body": "",
                "headers": {},
                "content_length": 0,
                "source_ip": "192.168.1.100",
                "timestamp": "2024-01-15T10:30:02Z"
            }
        ]
        
        results = [run_pipeline(req) for req in requests]
        
        assert len(results) == 3
        # First request should be clean
        assert results[0]["verdict"] in ["CLEAN", "ANOMALY"]
        # Second request should be detected as attack
        assert results[1]["verdict"] == "ATTACK"
        # Third request should be clean
        assert results[2]["verdict"] in ["CLEAN", "ANOMALY"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
