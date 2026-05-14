import io, pathlib, pytest
from dashboard.csv_parser import parse_csv, validate_csv_columns

SAMPLE_CSV = pathlib.Path("tests/fixtures/sample_dataset.csv").read_text()

def test_parse_valid_csv():
    rows, warnings = parse_csv(io.StringIO(SAMPLE_CSV))
    assert len(rows) >= 20
    for row in rows:
        assert "method" in row
        assert "url" in row
        assert "body" in row
        assert isinstance(row["response_code"], int)
        assert isinstance(row["content_length"], int)

def test_method_uppercased():
    csv_data = "method,url,path,query_string,body,response_code,content_length\nget,http://x.com/,/,,, 200,0"
    rows, _ = parse_csv(io.StringIO(csv_data))
    assert rows[0]["method"] == "GET"

def test_missing_required_columns_raises():
    """Test that CSV with truly missing all critical columns still raises error"""
    csv_data = "body\ntest"
    with pytest.raises(ValueError, match="Missing required columns"):
        parse_csv(io.StringIO(csv_data))

def test_url_only_generates_path():
    """Test that when only url column is provided, path is auto-generated"""
    csv_data = "method,url,body,response_code,content_length,query_string\nGET,http://example.com/api/users,test_body,200,42,"
    rows, _ = parse_csv(io.StringIO(csv_data))
    assert len(rows) == 1
    assert rows[0]["url"] == "http://example.com/api/users"
    assert rows[0]["path"] == "/api/users"
    assert rows[0]["method"] == "GET"
    assert rows[0]["body"] == "test_body"

def test_path_only_creates_url():
    """Test that when only path column is provided, url is created from it"""
    csv_data = "method,path,body,response_code,content_length,query_string\nPOST,/api/endpoint,request_data,201,100,"
    rows, _ = parse_csv(io.StringIO(csv_data))
    assert len(rows) == 1
    assert rows[0]["path"] == "/api/endpoint"
    assert rows[0]["url"] == "/api/endpoint"
    assert rows[0]["method"] == "POST"

def test_url_with_query_string_extracts_path():
    """Test that path is extracted correctly when URL has query string"""
    csv_data = "method,url,body,response_code,content_length,query_string\nGET,http://example.com/search?q=test&limit=10,results,200,500,"
    rows, _ = parse_csv(io.StringIO(csv_data))
    assert len(rows) == 1
    assert rows[0]["path"] == "/search"
    assert rows[0]["url"] == "http://example.com/search?q=test&limit=10"

def test_nan_body_becomes_empty_string():
    csv_data = "method,url,path,query_string,body,response_code,content_length\nGET,http://x.com/,/,,,200,0"
    rows, _ = parse_csv(io.StringIO(csv_data))
    assert rows[0]["body"] == ""

def test_max_rows_exceeded_truncates():
    import os
    # Temporarily set a lower limit for testing
    old_limit = os.environ.get("MAX_CSV_ROWS")
    os.environ["MAX_CSV_ROWS"] = "100"
    
    try:
        # Reload config to pick up the new limit
        import importlib
        import config
        importlib.reload(config)
        
        header = "method,url,path,query_string,body,response_code,content_length\n"
        rows_data = "GET,http://x.com/,/,,,200,0\n" * 150
        rows, warnings = parse_csv(io.StringIO(header + rows_data))
        
        assert len(rows) == config.MAX_CSV_ROWS
        assert len(warnings) >= 1
        assert "Truncating" in warnings[0]
    finally:
        # Restore original limit
        if old_limit:
            os.environ["MAX_CSV_ROWS"] = old_limit
        else:
            os.environ.pop("MAX_CSV_ROWS", None)
        importlib.reload(config)

def test_invalid_response_code_row_skipped_with_warning():
    csv_data = "method,url,path,query_string,body,response_code,content_length\nGET,http://x.com/,/,,,999,0\nGET,http://x.com/home,/home,,,200,0"
    rows, warnings = parse_csv(io.StringIO(csv_data))
    assert len(rows) == 1
    assert len(warnings) >= 1
