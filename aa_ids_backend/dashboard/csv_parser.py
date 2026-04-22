import io
import json
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

import pandas as pd
import chardet
from dateutil.parser import parse as parse_date

import config

log = logging.getLogger(__name__)

REQUIRED_COLUMNS = {
    "method", "url", "path", "query_string", "body", "response_code", "content_length"
}

VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}

def validate_csv_columns(df_columns: list[str]) -> None:
    missing = REQUIRED_COLUMNS - set(df_columns)
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(missing)}")

def _parse_timestamp(ts_val) -> str:
    if pd.isna(ts_val) or ts_val == "" or str(ts_val).strip() == "":
        return datetime.now(timezone.utc).isoformat()
    try:
        dt = parse_date(str(ts_val))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()

def _parse_headers(hdrs_val) -> dict:
    if pd.isna(hdrs_val) or not hdrs_val:
        return {}
    try:
        return json.loads(str(hdrs_val))
    except Exception:
        return {}

def parse_csv(file_stream) -> tuple[list[dict], list[str]]:
    warnings = []
    
    # file_stream might be text (StringIO) or bytes (BytesIO/FileStorage)
    content = file_stream.read()
    if isinstance(content, bytes):
        try:
            content_str = content.decode("utf-8")
        except UnicodeDecodeError:
            encoding_info = chardet.detect(content)
            encoding = encoding_info.get("encoding", "utf-8") or "utf-8"
            try:
                content_str = content.decode(encoding)
            except Exception:
                content_str = content.decode("utf-8", errors="replace")
    else:
        content_str = content
        
    try:
        df = pd.read_csv(io.StringIO(content_str), dtype=str)
    except pd.errors.EmptyDataError:
        raise ValueError("Invalid CSV format: File is empty")
    except Exception as e:
        raise ValueError(f"Invalid CSV format: {e}")

    # ── Column normalisation (before validation) ─────────────────────────────
    cols = df.columns.tolist()

    # 1. url_path → derive both url and path
    if 'url_path' in cols:
        if 'url' not in cols:
            df['url'] = df['url_path']
        if 'path' not in cols:
            # Extract just the path component (strip query string)
            df['path'] = df['url_path'].apply(
                lambda v: urlparse(str(v)).path if str(v).strip() else '/'
            )

    # 2. status → response_code alias
    if 'status' in cols and 'response_code' not in df.columns:
        df.rename(columns={'status': 'response_code'}, inplace=True)

    # 3. url / path cross-derivation (when only one is present)
    if 'url' not in df.columns and 'path' in df.columns:
        df['url'] = df['path']
    elif 'path' not in df.columns and 'url' in df.columns:
        df['path'] = df['url'].apply(
            lambda u: urlparse(str(u)).path if str(u).strip() else '/'
        )

    # 4. Inject safe defaults for other optional-but-required columns
    if 'response_code' not in df.columns:
        df['response_code'] = '200'
    if 'content_length' not in df.columns:
        df['content_length'] = '0'
    if 'query_string' not in df.columns:
        df['query_string'] = ''
    if 'body' not in df.columns:
        df['body'] = ''
    if 'method' not in df.columns:
        df['method'] = 'GET'

    validate_csv_columns(df.columns.tolist())
    
    max_rows = config.MAX_CSV_ROWS
    if len(df) > max_rows:
        warnings.append(f"Dataset size ({len(df)} rows) exceeded max allowed ({max_rows}). Truncating to {max_rows} rows.")
        df = df.head(max_rows)

    rows = []
    for idx, row in df.iterrows():
        r_dict = row.to_dict()
        
        # Method
        method = str(r_dict.get("method", "")).upper()
        if method not in VALID_METHODS:
            method = "OTHER"
        r_dict["method"] = method
        
        # Body
        b = r_dict.get("body")
        if pd.isna(b):
            r_dict["body"] = ""
        else:
            r_dict["body"] = str(b)
            
        # Response code
        try:
            rc = int(float(r_dict.get("response_code", 0)))
            if not (100 <= rc <= 599):
                warnings.append(f"Row {idx+1}: Invalid response code {rc}. Skipped.")
                continue
        except (ValueError, TypeError):
            warnings.append(f"Row {idx+1}: Invalid response code '{r_dict.get('response_code')}'. Skipped.")
            continue
        r_dict["response_code"] = rc
        
        # Content length
        try:
            cl = int(float(r_dict.get("content_length", 0)))
        except (ValueError, TypeError):
            cl = 0
        r_dict["content_length"] = cl
        
        # Timestamp
        r_dict["timestamp"] = _parse_timestamp(r_dict.get("timestamp"))
        
        # Headers
        r_dict["headers"] = _parse_headers(r_dict.get("headers"))
        
        # User Agent is just a string
        ua = r_dict.get("user_agent")
        r_dict["user_agent"] = "" if pd.isna(ua) else str(ua)

        # String fields
        for field in ["url", "path", "query_string"]:
            v = r_dict.get(field)
            r_dict[field] = "" if pd.isna(v) else str(v)

        rows.append(r_dict)
        
    return rows, warnings
