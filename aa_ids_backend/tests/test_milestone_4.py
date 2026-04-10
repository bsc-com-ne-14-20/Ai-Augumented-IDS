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
    csv_data = "url,body\nhttp://x.com/,test"
    with pytest.raises(ValueError, match="Missing required columns"):
        parse_csv(io.StringIO(csv_data))

def test_nan_body_becomes_empty_string():
    csv_data = "method,url,path,query_string,body,response_code,content_length\nGET,http://x.com/,/,,,200,0"
    rows, _ = parse_csv(io.StringIO(csv_data))
    assert rows[0]["body"] == ""

def test_max_rows_exceeded_raises():
    header = "method,url,path,query_string,body,response_code,content_length\n"
    rows_data = "GET,http://x.com/,/,,,200,0\n" * 10001
    with pytest.raises(ValueError, match="exceeds maximum"):
        parse_csv(io.StringIO(header + rows_data))

def test_invalid_response_code_row_skipped_with_warning():
    csv_data = "method,url,path,query_string,body,response_code,content_length\nGET,http://x.com/,/,,,999,0\nGET,http://x.com/home,/home,,,200,0"
    rows, warnings = parse_csv(io.StringIO(csv_data))
    assert len(rows) == 1
    assert len(warnings) >= 1
