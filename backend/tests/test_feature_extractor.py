"""
Test suite for HTTP feature extraction with real-world URLs.

SRS Requirements: Section 4.2 (Feature Extraction Pipeline)
- FE-001: Exactly 49 numeric features
- FE-002: URL decoding for attack detection
- FE-003: Shannon entropy computation
- FE-004: Semantic handling of missing fields
- FE-005: Reproducible, JSON-serializable output
- FE-006: <50ms per request performance
"""

import pytest
import time
from backend.pipeline.http_feature_extractor import HTTPFeatureExtractor


@pytest.fixture
def extractor():
    """Create feature extractor instance."""
    return HTTPFeatureExtractor(verbose=True)


class TestFeatureCount:
    """Test that exactly 49 features are extracted."""

    def test_feature_count_normal_request(self, extractor):
        """SRS FE-001: Verify 49 features for normal request."""
        request = {
            "method": "GET",
            "url": "/products?category=electronics",
            "query_string": "category=electronics",
            "body": "",
            "headers": {"accept": "text/html"},
            "content_length": 0,
        }

        features = extractor.extract_features(request)

        assert len(features) == 49, f"Expected 49 features, got {len(features)}"
        assert all(isinstance(v, (int, float)) for v in features.values())

    def test_feature_count_attack_request(self, extractor):
        """SRS FE-001: Verify 49 features for attack request."""
        request = {
            "method": "POST",
            "url": "/login",
            "query_string": "",
            "body": "username=admin' OR '1'='1&password=test",
            "headers": {"content-type": "application/x-www-form-urlencoded"},
            "content_length": 42,
        }

        features = extractor.extract_features(request)

        assert len(features) == 49


class TestRealWorldURLs:
    """Test feature extraction with real-world URLs."""
    
    def test_github_url(self, extractor):
        """Extract features from GitHub URL."""
        request = {
            "method": "GET",
            "url": "https://github.com/user/repo/issues?q=is%3Aopen+is%3Aissue",
            "query_string": "q=is%3Aopen+is%3Aissue",
            "body": "",
            "headers": {
                "accept": "text/html",
                "cookie": "session=abc123; user_id=456"
            },
            "content_length": 0,
        }

        features = extractor.extract_features(request)

        assert features["url_length"] > 0
        assert features["query_has_encoding"] == 1.0  # %3A encoding
        assert features["method_get"] == 1.0
    
    def test_amazon_product_url(self, extractor):
        """Extract features from Amazon product URL."""
        request = {
            "method": "GET",
            "url": "/dp/B08N5WRWNW?ref=nav_signin&psc=1",
            "query_string": "ref=nav_signin&psc=1",
            "body": "",
            "headers": {"accept": "text/html"},
            "content_length": 0,
        }
        
        features = extractor.extract_features(request)
        
        assert features["query_num_params"] == 2
        assert features["url_num_ampersand"] == 1  # Ampersand is in URL features
        assert features["url_num_underscores"] > 0
    
    def test_google_search_url(self, extractor):
        """Extract features from Google search URL."""
        request = {
            "method": "GET",
            "url": "/search?q=machine+learning&hl=en&start=10",
            "query_string": "q=machine+learning&hl=en&start=10",
            "body": "",
            "headers": {"accept": "text/html"},
            "content_length": 0,
        }
        
        features = extractor.extract_features(request)
        
        assert features["query_num_params"] == 3
        assert features["query_num_equals"] == 3
        assert features["query_is_empty"] == 0.0
    
    def test_rest_api_url(self, extractor):
        """Extract features from REST API URL."""
        request = {
            "method": "POST",
            "url": "/api/v1/users",
            "query_string": "",
            "body": '{"name":"John Doe","email":"john@example.com"}',
            "headers": {"content_type": "application/json"},  # Use underscore, not hyphen
            "content_length": 46,
        }
        
        features = extractor.extract_features(request)
        
        assert features["method_post"] == 1.0
        assert features["content_type_is_json"] == 1.0
        assert features["body_length"] == 46
        assert features["body_is_empty"] == 0.0
    
    def test_wordpress_admin_url(self, extractor):
        """Extract features from WordPress admin URL."""
        request = {
            "method": "GET",
            "url": "/wp-admin/admin.php?page=settings",
            "query_string": "page=settings",
            "body": "",
            "headers": {
                "cookie": "wordpress_logged_in=user123; wp-settings-1=editor%3Dtinymce"
            },
            "content_length": 0,
        }

        features = extractor.extract_features(request)

        assert features["url_num_hyphens"] > 0
        assert features["cookie_has_sqli"] == 0.0  # no SQLi in cookie


class TestAttackDetection:
    """Test feature extraction for attack patterns."""
    
    def test_sql_injection_detection(self, extractor):
        """SRS FE-002: Detect SQLi patterns in features."""
        request = {
            "method": "GET",
            "url": "/search?q=test' UNION SELECT * FROM users--",
            "query_string": "q=test' UNION SELECT * FROM users--",
            "body": "",
            "headers": {},
            "content_length": 0,
        }
        
        features = extractor.extract_features(request)
        
        assert features["query_has_sqli"] == 1.0
        assert features["query_num_special"] > 0
    
    def test_xss_detection(self, extractor):
        """SRS FE-002: Detect XSS patterns in features."""
        request = {
            "method": "POST",
            "url": "/comment",
            "query_string": "",
            "body": "text=<script>alert('XSS')</script>",
            "headers": {},
            "content_length": 38,
        }
        
        features = extractor.extract_features(request)
        
        assert features["body_has_xss"] == 1.0
        assert features["body_num_special"] > 0
    
    def test_path_traversal_detection(self, extractor):
        """SRS FE-002: Detect path traversal patterns."""
        request = {
            "method": "GET",
            "url": "/file?path=../../etc/passwd",
            "query_string": "path=../../etc/passwd",
            "body": "",
            "headers": {},
            "content_length": 0,
        }
        
        features = extractor.extract_features(request)
        
        assert features["query_has_traversal"] == 1.0
        assert features["url_num_dots"] > 0
    
    def test_encoded_sqli_detection(self, extractor):
        """SRS FE-002: Detect URL-encoded SQLi."""
        request = {
            "method": "GET",
            "url": "/search?q=test%27%20OR%20%271%27%3D%271",
            "query_string": "q=test%27%20OR%20%271%27%3D%271",
            "body": "",
            "headers": {},
            "content_length": 0,
        }
        
        features = extractor.extract_features(request)
        
        # Should detect SQLi after URL decoding
        assert features["query_has_sqli"] == 1.0
        assert features["query_has_encoding"] == 1.0
        assert features["query_num_percent"] > 0


class TestEntropyCalculation:
    """Test Shannon entropy calculation."""
    
    def test_low_entropy_url(self, extractor):
        """SRS FE-003: Low entropy for simple URLs."""
        request = {
            "method": "GET",
            "url": "/home",
            "query_string": "",
            "body": "",
            "headers": {},
            "content_length": 0,
        }
        
        features = extractor.extract_features(request)
        
        # Simple URL should have low entropy
        assert features["url_entropy"] < 3.0
    
    def test_high_entropy_url(self, extractor):
        """SRS FE-003: High entropy for complex URLs."""
        request = {
            "method": "GET",
            "url": "/api/v1/users/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "query_string": "",
            "body": "",
            "headers": {},
            "content_length": 0,
        }
        
        features = extractor.extract_features(request)
        
        # UUID in URL should have higher entropy
        assert features["url_entropy"] > 3.0
    
    def test_random_query_entropy(self, extractor):
        """SRS FE-003: High entropy for random query strings."""
        request = {
            "method": "GET",
            "url": "/search?token=aB3dE5fG7hI9jK1lM2nO4pQ6rS8tU0vW",
            "query_string": "token=aB3dE5fG7hI9jK1lM2nO4pQ6rS8tU0vW",
            "body": "",
            "headers": {},
            "content_length": 0,
        }
        
        features = extractor.extract_features(request)
        
        assert features["query_entropy"] > 3.0


class TestMissingFields:
    """Test semantic handling of missing fields."""
    
    def test_missing_query_string(self, extractor):
        """SRS FE-004: Handle missing query string."""
        request = {
            "method": "GET",
            "url": "/home",
            "query_string": "",
            "body": "",
            "headers": {},
            "content_length": 0,
        }
        
        features = extractor.extract_features(request)
        
        assert features["query_is_empty"] == 1.0
        assert features["query_length"] == 0
        assert features["query_num_params"] == 0
    
    def test_missing_body(self, extractor):
        """SRS FE-004: Handle missing body."""
        request = {
            "method": "GET",
            "url": "/api/data",
            "query_string": "",
            "body": "",
            "headers": {},
            "content_length": 0,
        }
        
        features = extractor.extract_features(request)
        
        assert features["body_is_empty"] == 1.0
        assert features["body_length"] == 0
    
    def test_missing_cookie(self, extractor):
        """SRS FE-004: Handle missing cookie — dropped features no longer present."""
        request = {
            "method": "GET",
            "url": "/page",
            "query_string": "",
            "body": "",
            "headers": {},
            "content_length": 0,
        }

        features = extractor.extract_features(request)

        # cookie_is_present and cookie_length were dropped (CSIC bias)
        assert "cookie_is_present" not in features
        assert "cookie_length" not in features
        # Security-pattern features are still present
        assert features["cookie_has_sqli"] == 0.0
        assert features["cookie_has_xss"] == 0.0
    
    def test_missing_content_type(self, extractor):
        """SRS FE-004: Handle missing content-type."""
        request = {
            "method": "POST",
            "url": "/submit",
            "query_string": "",
            "body": "data=test",
            "headers": {},
            "content_length": 9,
        }
        
        features = extractor.extract_features(request)
        
        assert features["content_type_is_none"] == 1.0
        assert features["post_no_content_type"] == 1.0


class TestReproducibility:
    """Test that feature extraction is reproducible."""
    
    def test_same_input_same_output(self, extractor):
        """SRS FE-005: Identical inputs produce identical outputs."""
        request = {
            "method": "GET",
            "url": "/test?param=value",
            "query_string": "param=value",
            "body": "",
            "headers": {"accept": "text/html"},
            "content_length": 0,
        }
        
        features1 = extractor.extract_features(request)
        features2 = extractor.extract_features(request)
        
        assert features1 == features2
    
    def test_no_nan_values(self, extractor):
        """SRS FE-005: No NaN or Inf values in output."""
        request = {
            "method": "GET",
            "url": "/test",
            "query_string": "",
            "body": "",
            "headers": {},
            "content_length": 0,
        }
        
        features = extractor.extract_features(request)
        
        import math
        for key, value in features.items():
            assert not math.isnan(value), f"NaN value in {key}"
            assert not math.isinf(value), f"Inf value in {key}"


class TestPerformance:
    """Test feature extraction performance."""
    
    def test_extraction_speed(self, extractor):
        """SRS FE-006: Feature extraction completes in <50ms."""
        request = {
            "method": "POST",
            "url": "/api/v1/users?filter=active&sort=name",
            "query_string": "filter=active&sort=name",
            "body": '{"name":"John","email":"john@example.com","age":30}',
            "headers": {
                "content-type": "application/json",
                "cookie": "session=abc123; user_id=456"
            },
            "content_length": 55,
        }
        
        start = time.time()
        features = extractor.extract_features(request)
        elapsed_ms = (time.time() - start) * 1000
        
        assert elapsed_ms < 50, f"Extraction took {elapsed_ms:.2f}ms (target: <50ms)"
    
    def test_batch_performance(self, extractor):
        """Test performance with multiple requests."""
        requests = [
            {
                "method": "GET",
                "url": f"/page{i}?id={i}",
                "query_string": f"id={i}",
                "body": "",
                "headers": {},
                "content_length": 0,
            }
            for i in range(100)
        ]
        
        start = time.time()
        for req in requests:
            extractor.extract_features(req)
        elapsed_ms = (time.time() - start) * 1000
        
        avg_ms = elapsed_ms / 100
        assert avg_ms < 50, f"Average extraction: {avg_ms:.2f}ms (target: <50ms)"


class TestEdgeCases:
    """Test edge cases and unusual inputs."""
    
    def test_very_long_url(self, extractor):
        """Handle very long URLs."""
        long_query = "param=" + "A" * 5000
        request = {
            "method": "GET",
            "url": f"/search?{long_query}",
            "query_string": long_query,
            "body": "",
            "headers": {},
            "content_length": 0,
        }
        
        features = extractor.extract_features(request)
        
        assert features["url_length"] > 5000
        assert features["query_length"] > 5000
    
    def test_unicode_characters(self, extractor):
        """Handle Unicode characters in URL."""
        request = {
            "method": "GET",
            "url": "/search?q=café+naïve",
            "query_string": "q=café+naïve",
            "body": "",
            "headers": {},
            "content_length": 0,
        }

        features = extractor.extract_features(request)

        assert len(features) == 49

    def test_empty_request(self, extractor):
        """Handle minimal request."""
        request = {
            "method": "GET",
            "url": "/",
            "query_string": "",
            "body": "",
            "headers": {},
            "content_length": 0,
        }

        features = extractor.extract_features(request)

        assert len(features) == 49
        assert features["url_length"] == 1
        assert features["query_is_empty"] == 1.0
        assert features["body_is_empty"] == 1.0


class TestFeatureSchema:
    """Test that features match FEATURE_SCHEMA.json."""

    def test_feature_names_match_schema(self, extractor):
        """Verify feature names match FEATURE_SCHEMA.json (49 features)."""
        import json
        from pathlib import Path

        schema_path = Path(__file__).parent.parent.parent / "FEATURE_SCHEMA.json"
        with open(schema_path) as f:
            schema = json.load(f)

        expected_features = schema["features"]

        request = {
            "method": "GET",
            "url": "/test",
            "query_string": "",
            "body": "",
            "headers": {},
            "content_length": 0,
        }

        features = extractor.extract_features(request)
        actual_features = list(features.keys())

        assert actual_features == expected_features, \
            f"Feature mismatch:\nExpected: {expected_features}\nActual: {actual_features}"


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "--tb=short"])
