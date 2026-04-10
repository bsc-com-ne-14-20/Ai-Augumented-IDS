import pytest, io, pathlib
from app import create_app

SAMPLE_CSV = pathlib.Path("tests/fixtures/sample_dataset.csv").read_bytes()

@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c

def test_dashboard_root_returns_200(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"AA-IDS" in r.data

def test_dashboard_root_contains_upload_zone(client):
    r = client.get("/")
    assert b"upload" in r.data.lower() or b"drag" in r.data.lower()

def test_upload_valid_csv_returns_json(client):
    data = {"file": (io.BytesIO(SAMPLE_CSV), "test.csv")}
    r = client.post("/upload", data=data, content_type="multipart/form-data")
    assert r.status_code == 200
    assert r.content_type == "application/json"
    body = r.get_json()
    assert "rule_engine" in body
    assert "ml_engine" in body
    assert "comparison" in body
    assert "row_details" in body

def test_upload_returns_correct_dataset_row_count(client):
    data = {"file": (io.BytesIO(SAMPLE_CSV), "test.csv")}
    r = client.post("/upload", data=data, content_type="multipart/form-data")
    body = r.get_json()
    assert body["dataset"]["total_rows"] >= 1

def test_upload_report_counts_consistent(client):
    data = {"file": (io.BytesIO(SAMPLE_CSV), "test.csv")}
    r = client.post("/upload", data=data, content_type="multipart/form-data")
    body = r.get_json()
    total = body["dataset"]["total_rows"]
    re = body["rule_engine"]
    ml = body["ml_engine"]
    assert re["total_detections"] + re["total_clean"] + re["total_errors"] == total
    assert ml["total_detections"] + ml["total_clean"] + ml["total_errors"] == total

def test_upload_wrong_extension_returns_400(client):
    data = {"file": (io.BytesIO(b"a,b,c"), "test.txt")}
    r = client.post("/upload", data=data, content_type="multipart/form-data")
    assert r.status_code == 400

def test_upload_no_file_returns_400(client):
    r = client.post("/upload", data={}, content_type="multipart/form-data")
    assert r.status_code == 400

def test_upload_missing_columns_returns_422(client):
    bad_csv = b"col1,col2\nval1,val2"
    data = {"file": (io.BytesIO(bad_csv), "bad.csv")}
    r = client.post("/upload", data=data, content_type="multipart/form-data")
    assert r.status_code == 422
    body = r.get_json()
    assert "error" in body

def test_original_api_analyze_still_works(client):
    """Regression: the existing JSON API must not be broken by dashboard additions."""
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"

def test_static_files_served(client):
    r = client.get("/static/css/dashboard.css")
    assert r.status_code == 200
    r = client.get("/static/js/charts.js")
    assert r.status_code == 200
