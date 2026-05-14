"""
tests/test_milestone_3.py
=========================
Milestone 3 tests: Flask API endpoints, request validation, and metrics.

Run with:
    pytest tests/test_milestone_3.py -v
"""
import json
import pathlib
import sys

import pytest

_BACKEND_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

_FIXTURES = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "sample_logs.json").read_text()
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def sample_logs():
    return _FIXTURES


@pytest.fixture(scope="module")
def app_instance():
    from app import create_app
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture(scope="module")
def client(app_instance):
    with app_instance.test_client() as c:
        yield c


# ── Health endpoint ───────────────────────────────────────────────────────────

def test_health_endpoint(client):
    """GET /api/v1/health must return 200 with required keys."""
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    data = r.get_json()
    assert data["status"] == "ok"
    assert "rule_engine_loaded" in data
    assert "ml_model_loaded" in data
    assert data["rule_engine_loaded"] is True
    assert data["ml_model_loaded"] is True
    assert "uptime_seconds" in data
    assert "ml_model_path" in data


# ── Analyze endpoint ──────────────────────────────────────────────────────────

def test_analyze_single_clean(client, sample_logs):
    """A single clean log must return 200 with total_clean=1 and total_attacks=0."""
    r = client.post(
        "/api/v1/analyze",
        json={"logs": [sample_logs["clean_request"]]},
    )
    assert r.status_code == 200
    data = r.get_json()
    assert data["summary"]["total_processed"] == 1
    assert data["summary"]["total_clean"] == 1
    assert data["summary"]["total_attacks"] == 0
    assert len(data["results"]) == 1
    assert data["results"][0]["verdict"] == "CLEAN"


def test_analyze_batch_mixed(client, sample_logs):
    """A batch with one clean and one SQLi must report total_attacks=1."""
    logs = [sample_logs["clean_request"], sample_logs["sqli_request"]]
    r = client.post("/api/v1/analyze", json={"logs": logs})
    assert r.status_code == 200
    data = r.get_json()
    assert data["summary"]["total_processed"] == 2
    assert data["summary"]["total_attacks"] == 1


def test_analyze_sqli_verdict(client, sample_logs):
    """SQLi request must produce verdict=ATTACK and detection_source=RULE."""
    r = client.post(
        "/api/v1/analyze",
        json={"logs": [sample_logs["sqli_request"]]},
    )
    assert r.status_code == 200
    result = r.get_json()["results"][0]
    assert result["verdict"] == "ATTACK"
    assert result["detection_source"] == "RULE"
    assert result["rule_triggered"] is not None


def test_analyze_response_has_summary_keys(client, sample_logs):
    """Response summary must contain all required keys."""
    r = client.post(
        "/api/v1/analyze",
        json={"logs": [sample_logs["clean_request"]]},
    )
    summary = r.get_json()["summary"]
    for key in ["total_processed", "total_clean", "total_attacks",
                "total_anomalies", "processing_time_ms"]:
        assert key in summary, f"summary missing key: {key}"


def test_analyze_malformed_request(client):
    """logs must be a list — if it's a string, expect 422."""
    r = client.post("/api/v1/analyze", json={"logs": "not_a_list"})
    assert r.status_code == 422
    data = r.get_json()
    assert data["error"] == "VALIDATION_ERROR"


def test_analyze_missing_required_field(client):
    """An entry with only method= (missing url, path, etc.) must return 422."""
    r = client.post(
        "/api/v1/analyze",
        json={"logs": [{"method": "GET"}]},
    )
    assert r.status_code == 422
    data = r.get_json()
    assert data["error"] == "VALIDATION_ERROR"


def test_analyze_empty_logs_list(client):
    """An empty logs list must return 422 (min length = 1)."""
    r = client.post("/api/v1/analyze", json={"logs": []})
    assert r.status_code == 422


def test_analyze_no_body(client):
    """No JSON body at all must return 422."""
    r = client.post("/api/v1/analyze", content_type="application/json", data="")
    assert r.status_code == 422


# ── Metrics endpoint ──────────────────────────────────────────────────────────

def test_metrics_endpoint(client, sample_logs):
    """After an analyze call, /metrics must reflect updated counters."""
    # Seed at least one attack
    client.post("/api/v1/analyze", json={"logs": [sample_logs["sqli_request"]]})
    r = client.get("/api/v1/metrics")
    assert r.status_code == 200
    data = r.get_json()
    assert data["total_requests_analyzed"] >= 1
    assert "attack_type_breakdown" in data
    assert "detection_source_breakdown" in data
    assert "severity_breakdown" in data
    assert "ml_confidence_distribution" in data
    assert "session_uptime_seconds" in data


# ── Alerts endpoint ───────────────────────────────────────────────────────────

def test_alerts_endpoint_returns_list(client, sample_logs):
    """GET /api/v1/alerts must return a JSON object with an 'alerts' list."""
    client.post("/api/v1/analyze", json={"logs": [sample_logs["sqli_request"]]})
    r = client.get("/api/v1/alerts")
    assert r.status_code == 200
    data = r.get_json()
    assert "alerts" in data
    assert isinstance(data["alerts"], list)
    assert "total" in data
    assert "page" in data
    assert "page_size" in data


def test_alerts_pagination(client, sample_logs):
    """page_size param must limit the number of alerts returned."""
    r = client.get("/api/v1/alerts?page_size=1&page=1")
    assert r.status_code == 200
    data = r.get_json()
    assert len(data["alerts"]) <= 1
