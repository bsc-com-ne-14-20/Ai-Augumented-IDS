"""
Test suite for Flask REST API endpoints.

SRS Requirements: Section 8.1 (Unit Testing - Flask REST API)
- Test /api/v1/analyse with valid payload
- Test missing method field returns 400
- Test wrong API key returns 403
- Test /api/v1/health returns correct schema
- Test API key validator decorator (Task 17.1)
"""

import pytest
from app import create_app
from backend.config import get_config


@pytest.fixture
def client():
    """Create test client."""
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def valid_headers():
    """Valid API headers with correct key."""
    config = get_config()
    return {
        "Content-Type": "application/json",
        "X-IDS-Key": config.IDS_API_KEY
    }


class TestAPIKeyValidator:
    """Test API key validator decorator (Task 17.1)."""
    
    def test_missing_api_key_header(self, client):
        """Test that missing X-IDS-Key header returns HTTP 403."""
        payload = {
            "logs": [
                {
                    "method": "GET",
                    "url": "/test",
                    "path": "/test", 
                    "query_string": "",
                    "headers": {},
                    "body": "",
                    "response_code": 200,
                    "content_length": 0,
                    "timestamp": "2026-05-23T10:00:00Z"
                }
            ]
        }
        
        response = client.post(
            "/api/v1/analyse",
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 403
        data = response.get_json()
        assert data["error"] == "Invalid or missing API key"
    
    def test_invalid_api_key_header(self, client):
        """Test that invalid X-IDS-Key header returns HTTP 403."""
        payload = {
            "logs": [
                {
                    "method": "GET",
                    "url": "/test",
                    "path": "/test",
                    "query_string": "",
                    "headers": {},
                    "body": "",
                    "response_code": 200,
                    "content_length": 0,
                    "timestamp": "2026-05-23T10:00:00Z"
                }
            ]
        }
        
        response = client.post(
            "/api/v1/analyse",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-IDS-Key": "invalid-api-key-12345"
            }
        )
        
        assert response.status_code == 403
        data = response.get_json()
        assert data["error"] == "Invalid or missing API key"
    
    def test_valid_api_key_allows_access(self, client, valid_headers):
        """Test that valid X-IDS-Key header allows access to protected endpoint."""
        payload = {
            "logs": [
                {
                    "method": "GET",
                    "url": "/test",
                    "path": "/test",
                    "query_string": "",
                    "headers": {},
                    "body": "",
                    "response_code": 200,
                    "content_length": 0,
                    "timestamp": "2026-05-23T10:00:00Z"
                }
            ]
        }
        
        response = client.post(
            "/api/v1/analyse",
            json=payload,
            headers=valid_headers
        )
        
        # Should not return 403 (may return other status codes for validation errors)
        assert response.status_code != 403
    
    def test_empty_api_key_header(self, client):
        """Test that empty X-IDS-Key header returns HTTP 403."""
        payload = {
            "logs": [
                {
                    "method": "GET",
                    "url": "/test",
                    "path": "/test",
                    "query_string": "",
                    "headers": {},
                    "body": "",
                    "response_code": 200,
                    "content_length": 0,
                    "timestamp": "2026-05-23T10:00:00Z"
                }
            ]
        }
        
        response = client.post(
            "/api/v1/analyse",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-IDS-Key": ""
            }
        )
        
        assert response.status_code == 403
        data = response.get_json()
        assert data["error"] == "Invalid or missing API key"
    
    def test_api_key_not_logged_in_response(self, client):
        """Test that API key is never exposed in error responses (Requirement 19.8)."""
        config = get_config()
        
        # Test with wrong API key
        response = client.post(
            "/api/v1/analyse",
            json={"logs": []},
            headers={
                "Content-Type": "application/json",
                "X-IDS-Key": "wrong-key"
            }
        )
        
        response_text = response.get_data(as_text=True)
        
        # Ensure the actual API key is never exposed in the response
        assert config.IDS_API_KEY not in response_text
        assert "wrong-key" not in response_text  # Even the wrong key shouldn't be echoed back


class TestHealthEndpoint:
    """Test GET /api/v1/health endpoint."""
    
    def test_health_returns_200(self, client):
        """SRS FL-004: Health endpoint returns 200."""
        response = client.get("/api/v1/health")
        assert response.status_code == 200
    
    def test_health_schema(self, client):
        """SRS FL-004: Health endpoint returns correct schema."""
        response = client.get("/api/v1/health")
        data = response.get_json()
        
        assert "status" in data
        assert "models_loaded" in data
        assert "db_connected" in data
        assert "rule_engine_loaded" in data
        assert "ml_model_loaded" in data
        assert "uptime_seconds" in data
        
        assert data["status"] == "ok"
        assert isinstance(data["models_loaded"], bool)
        assert isinstance(data["db_connected"], bool)
        assert isinstance(data["uptime_seconds"], int)


class TestAnalyseEndpoint:
    """Test POST /api/v1/analyse endpoint."""
    
    def test_analyse_requires_api_key(self, client):
        """SRS FL-003: Missing API key returns 403."""
        payload = {
            "logs": [
                {
                    "method": "GET",
                    "url": "/test",
                    "path": "/test",
                    "query_string": "",
                    "headers": {},
                    "body": "",
                    "response_code": 200,
                    "content_length": 0,
                    "timestamp": "2026-05-23T10:00:00Z"
                }
            ]
        }
        
        response = client.post(
            "/api/v1/analyse",
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 403
        data = response.get_json()
        assert data["error"] == "Invalid or missing API key"
    
    def test_analyse_wrong_api_key(self, client):
        """SRS FL-003: Wrong API key returns 403."""
        payload = {
            "logs": [
                {
                    "method": "GET",
                    "url": "/test",
                    "path": "/test",
                    "query_string": "",
                    "headers": {},
                    "body": "",
                    "response_code": 200,
                    "content_length": 0,
                    "timestamp": "2026-05-23T10:00:00Z"
                }
            ]
        }
        
        response = client.post(
            "/api/v1/analyse",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-IDS-Key": "wrong-key"
            }
        )
        
        assert response.status_code == 403
    
    def test_analyse_missing_method_field(self, client, valid_headers):
        """SRS FL-002: Missing required field returns 400."""
        payload = {
            "logs": [
                {
                    # Missing "method" field
                    "url": "/test",
                    "path": "/test",
                    "query_string": "",
                    "headers": {},
                    "body": "",
                    "response_code": 200,
                    "content_length": 0,
                    "timestamp": "2026-05-23T10:00:00Z"
                }
            ]
        }
        
        response = client.post(
            "/api/v1/analyse",
            json=payload,
            headers=valid_headers
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data  # Returns validation error message
    
    def test_analyse_invalid_json(self, client, valid_headers):
        """SRS FL-002: Invalid JSON returns 400."""
        response = client.post(
            "/api/v1/analyse",
            data="not json",
            headers=valid_headers
        )
        
        assert response.status_code == 400
    
    def test_analyse_clean_request(self, client, valid_headers):
        """SRS FL-001: Clean request returns correct response."""
        payload = {
            "logs": [
                {
                    "method": "GET",
                    "url": "/products?category=electronics",
                    "path": "/products",
                    "query_string": "category=electronics",
                    "headers": {},
                    "body": "",
                    "response_code": 200,
                    "content_length": 0,
                    "timestamp": "2026-05-23T10:00:00Z"
                },
                {
                    "method": "GET",
                    "url": "/home",
                    "path": "/home",
                    "query_string": "",
                    "headers": {},
                    "body": "",
                    "response_code": 200,
                    "content_length": 0,
                    "timestamp": "2026-05-23T10:00:01Z"
                }
            ]
        }
        
        response = client.post(
            "/api/v1/analyse",
            json=payload,
            headers=valid_headers
        )
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert "summary" in data
        assert "results" in data
        assert data["summary"]["total_processed"] == 2
        assert len(data["results"]) == 2
        
        result = data["results"][0]
        assert "verdict" in result
        assert "detection_source" in result
    
    def test_analyse_sqli_attack(self, client, valid_headers):
        """SRS FL-001: SQLi attack detected correctly."""
        payload = {
            "logs": [
                {
                    "method": "GET",
                    "url": "/search?q=test' OR '1'='1",
                    "path": "/search",
                    "query_string": "q=test' OR '1'='1",
                    "headers": {},
                    "body": "",
                    "response_code": 200,
                    "content_length": 0,
                    "timestamp": "2026-05-23T10:00:00Z"
                }
            ]
        }
        
        response = client.post(
            "/api/v1/analyse",
            json=payload,
            headers=valid_headers
        )
        
        assert response.status_code == 200
        data = response.get_json()
        
        # Single-entry requests return the result directly (not wrapped)
        result = data if "verdict" in data else data.get("results", [data])[0]
        assert result["verdict"] == "ATTACK"
        assert result["detection_source"] == "RULE"
        assert result["attack_type"] == "SQL_INJECTION"


class TestAlertsEndpoint:
    """Test GET /api/v1/alerts endpoint."""
    
    def test_alerts_returns_200(self, client):
        """SRS AL-005: Alerts endpoint returns 200."""
        response = client.get("/api/v1/alerts")
        assert response.status_code == 200
    
    def test_alerts_pagination(self, client):
        """SRS AL-005: Alerts endpoint supports pagination."""
        response = client.get("/api/v1/alerts?page=1&limit=10")
        assert response.status_code == 200
        
        data = response.get_json()
        assert "alerts" in data
        assert "total" in data
        assert "page" in data
        assert "page_size" in data
        
        assert data["page"] == 1
        assert data["page_size"] == 10
    
    def test_alerts_invalid_page(self, client):
        """SRS AL-005: Invalid page parameter returns 400."""
        response = client.get("/api/v1/alerts?page=invalid")
        assert response.status_code == 400


class TestStatsEndpoint:
    """Test GET /api/v1/stats endpoint."""
    
    def test_stats_returns_200(self, client):
        """Stats endpoint returns 200."""
        response = client.get("/api/v1/stats")
        assert response.status_code == 200
    
    def test_stats_schema(self, client):
        """Stats endpoint returns correct schema."""
        response = client.get("/api/v1/stats")
        data = response.get_json()
        
        assert "total_requests" in data
        assert "total_attacks" in data
        assert "attack_type_breakdown" in data
        assert "detection_source_split" in data
