"""
pipeline/preprocessor.py
========================
Feature extraction and z-score normalisation for raw HTTP log entries.

Pipeline position
-----------------
  raw HTTP log dict  ──►  extract_features()  ──►  z-scored feature dict
                                                      │
                                          ┌───────────┴───────────┐
                                     rule_adapter           ml_adapter

The 53 feature columns output by this module exactly match the column order
in data/final/feature_names.txt, which is the order the RandomForest model
and CRS engine were trained on.

Feature groups
--------------
  URL features        (url_*)         12 columns
  Query features      (query_*)       10 columns
  Body features       (body_*)        13 columns
  Method features     (method_*)       4 columns
  Cookie features     (cookie_*)       4 columns
  Content-type flags  (content_type_*) 3 columns
  Connection flags    (connection_*)   2 columns
  Protocol anomalies                   5 columns
"""

import logging
import math
import re
import urllib.parse
from collections import Counter
from typing import Any

import joblib
import numpy as np

import config  # noqa: E402

log = logging.getLogger(__name__)

# ── Load scaler once at import time ──────────────────────────────────────────
from pathlib import Path as _Path
_scaler_path = _Path(config.ML_SCALER_PATH)
if not _scaler_path.exists():
    raise RuntimeError(
        f"Scaler not found at: {_scaler_path}. "
        "Ensure data/final/scaler.pkl exists in the repo."
    )
_SCALER = joblib.load(_scaler_path)
log.info("Scaler loaded from %s", _scaler_path)

# ── Feature column order (must match model training order) ────────────────────
_feature_names_path = _Path(config.ML_FEATURE_NAMES_PATH)
FEATURE_COLUMNS: list[str] = _feature_names_path.read_text().strip().splitlines()

# ── Constants for feature extraction ─────────────────────────────────────────
_RISKY_EXTENSIONS = re.compile(
    r"\.(php|asp|aspx|jsp|cgi|pl|py|rb|sh|bak|swp|env|git|htaccess|htpasswd|cfg|conf|ini|log|sql|sqlite|db)$",
    re.IGNORECASE,
)
_SQLI_KEYWORDS = re.compile(
    r"(\bselect\b|\bunion\b|\bdrop\b|\binsert\b|\bor\s+1=1\b|\bdelete\b|\bupdate\b"
    r"|\bexec\b|\bdeclare\b|\bcast\b|\bconvert\b|\bhaving\b|\bgroup\s+by\b)",
    re.IGNORECASE,
)
_SQLI_CHARS = re.compile(r"['\"\-\-;#]|(\b--\b)|(\/\*)")
_XSS_PATTERNS = re.compile(
    r"(<script|javascript:|<img[^>]+onerror|<svg|<iframe|<body|<input"
    r"|\son\w+=|\balert\s*\(|\bprompt\s*\(|\bconfirm\s*\()",
    re.IGNORECASE,
)
_TRAVERSAL_PATTERNS = re.compile(r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f", re.IGNORECASE)
_ENCODING_PATTERNS = re.compile(r"%[0-9a-fA-F]{2}[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}", re.IGNORECASE)
_DOUBLE_ENCODING = re.compile(r"%25[0-9a-fA-F]{2}", re.IGNORECASE)

_REQUIRED_FIELDS = {"method", "url", "path", "query_string", "headers", "body",
                    "response_code", "content_length", "timestamp"}


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _count_percent_encoded(s: str) -> int:
    """Count percent-encoded sequences like %2F in a string."""
    return len(re.findall(r"%[0-9a-fA-F]{2}", s))


def _count_special_chars(s: str) -> int:
    """Count security-relevant special characters."""
    return sum(s.count(c) for c in ["'", '"', "<", ">", ";", "(", ")", "{", "}", "|", "\\"])


def _extract_raw_features(log_entry: dict[str, Any]) -> dict[str, float]:
    """
    Extract raw (unscaled) numeric features from a single HTTP log entry dict.

    All 53 feature columns from data/final/feature_names.txt are produced here.
    """
    method: str = str(log_entry.get("method", "GET")).upper()
    url: str = str(log_entry.get("url", ""))
    path: str = str(log_entry.get("path", ""))
    query_string: str = str(log_entry.get("query_string", ""))
    headers: dict = log_entry.get("headers", {}) or {}
    body: str = str(log_entry.get("body", "") or "")
    content_length: int = int(log_entry.get("content_length", 0) or 0)

    # ── Decode for evasion detection ──────────────────────────────────────────
    try:
        query_decoded = urllib.parse.unquote(query_string)
    except Exception:
        query_decoded = query_string
    try:
        body_decoded = urllib.parse.unquote(body)
    except Exception:
        body_decoded = body

    # ── Cookie ────────────────────────────────────────────────────────────────
    cookie_header: str = ""
    for k, v in headers.items():
        if k.lower() == "cookie":
            cookie_header = str(v)
            break

    content_type: str = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            content_type = str(v).lower()
            break

    connection_header: str = ""
    for k, v in headers.items():
        if k.lower() == "connection":
            connection_header = str(v).lower()
            break

    # ── URL features ──────────────────────────────────────────────────────────
    url_length = len(url)
    url_path_depth = path.count("/")
    url_num_dots = url.count(".")
    url_num_special = _count_special_chars(url)
    url_num_hyphens = url.count("-")
    url_num_underscores = url.count("_")
    url_num_percent = _count_percent_encoded(url)
    url_num_equal = url.count("=")
    url_num_ampersand = url.count("&")
    url_entropy = _shannon_entropy(url)
    url_has_risky_ext = 1.0 if _RISKY_EXTENSIONS.search(path) else 0.0
    url_has_double_encoding = 1.0 if _DOUBLE_ENCODING.search(url) else 0.0

    # ── Query features ────────────────────────────────────────────────────────
    query_length = len(query_string)
    query_params = urllib.parse.parse_qs(query_string, keep_blank_values=True)
    query_num_params = len(query_params)
    query_num_equals = query_string.count("=")
    query_num_special = _count_special_chars(query_decoded)
    query_num_percent = _count_percent_encoded(query_string)
    query_entropy = _shannon_entropy(query_string)
    query_has_sqli = 1.0 if (_SQLI_KEYWORDS.search(query_decoded) or _SQLI_CHARS.search(query_decoded)) else 0.0
    query_has_xss = 1.0 if _XSS_PATTERNS.search(query_decoded) else 0.0
    query_has_traversal = 1.0 if _TRAVERSAL_PATTERNS.search(query_decoded) else 0.0
    query_has_encoding = 1.0 if _ENCODING_PATTERNS.search(query_string) else 0.0
    query_is_empty = 1.0 if not query_string.strip() else 0.0

    # ── Body features ─────────────────────────────────────────────────────────
    body_length = len(body)
    body_entropy = _shannon_entropy(body)
    body_params = urllib.parse.parse_qs(body, keep_blank_values=True)
    body_num_params = len(body_params)
    body_num_special = _count_special_chars(body_decoded)
    body_num_percent = _count_percent_encoded(body)
    body_num_quotes = body.count("'") + body.count('"')
    body_num_semicolons = body.count(";")
    body_num_brackets = body.count("(") + body.count(")")
    body_has_sqli = 1.0 if (_SQLI_KEYWORDS.search(body_decoded) or _SQLI_CHARS.search(body_decoded)) else 0.0
    body_has_xss = 1.0 if _XSS_PATTERNS.search(body_decoded) else 0.0
    body_has_traversal = 1.0 if _TRAVERSAL_PATTERNS.search(body_decoded) else 0.0
    body_has_encoding = 1.0 if _ENCODING_PATTERNS.search(body) else 0.0
    body_is_empty = 1.0 if not body.strip() else 0.0

    # ── Method features ───────────────────────────────────────────────────────
    method_get = 1.0 if method == "GET" else 0.0
    method_post = 1.0 if method == "POST" else 0.0
    method_put = 1.0 if method == "PUT" else 0.0
    method_suspicious = 1.0 if method in {"TRACE", "CONNECT", "PROPFIND", "OPTIONS", "PATCH"} else 0.0

    # ── Cookie features ───────────────────────────────────────────────────────
    cookie_length = len(cookie_header)
    cookie_has_sqli = 1.0 if (_SQLI_KEYWORDS.search(cookie_header) or _SQLI_CHARS.search(cookie_header)) else 0.0
    cookie_has_xss = 1.0 if _XSS_PATTERNS.search(cookie_header) else 0.0
    cookie_is_present = 1.0 if cookie_header else 0.0

    # ── Content-type features ─────────────────────────────────────────────────
    content_type_is_form = 1.0 if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type else 0.0
    content_type_is_json = 1.0 if "application/json" in content_type else 0.0
    content_type_is_none = 1.0 if not content_type else 0.0

    # ── Connection features ───────────────────────────────────────────────────
    connection_is_close = 1.0 if "close" in connection_header else 0.0
    connection_keep_alive = 1.0 if "keep-alive" in connection_header else 0.0

    # ── Protocol anomaly features ─────────────────────────────────────────────
    post_no_content_type = 1.0 if method == "POST" and not content_type else 0.0
    get_with_body = 1.0 if method == "GET" and body.strip() else 0.0
    post_empty_body = 1.0 if method == "POST" and not body.strip() else 0.0
    actual_body_length = len(body.encode("utf-8", errors="replace"))
    content_length_mismatch = 1.0 if content_length > 0 and abs(content_length - actual_body_length) > 10 else 0.0

    return {
        "url_length":              float(url_length),
        "url_path_depth":          float(url_path_depth),
        "url_num_dots":            float(url_num_dots),
        "url_num_special":         float(url_num_special),
        "url_num_hyphens":         float(url_num_hyphens),
        "url_num_underscores":     float(url_num_underscores),
        "url_num_percent":         float(url_num_percent),
        "url_num_equal":           float(url_num_equal),
        "url_num_ampersand":       float(url_num_ampersand),
        "url_entropy":             url_entropy,
        "url_has_risky_ext":       url_has_risky_ext,
        "url_has_double_encoding": url_has_double_encoding,
        "query_length":            float(query_length),
        "query_num_params":        float(query_num_params),
        "query_num_equals":        float(query_num_equals),
        "query_num_special":       float(query_num_special),
        "query_num_percent":       float(query_num_percent),
        "query_entropy":           query_entropy,
        "query_has_sqli":          query_has_sqli,
        "query_has_xss":           query_has_xss,
        "query_has_traversal":     query_has_traversal,
        "query_has_encoding":      query_has_encoding,
        "query_is_empty":          query_is_empty,
        "body_length":             float(body_length),
        "body_entropy":            body_entropy,
        "body_num_params":         float(body_num_params),
        "body_num_special":        float(body_num_special),
        "body_num_percent":        float(body_num_percent),
        "body_num_quotes":         float(body_num_quotes),
        "body_num_semicolons":     float(body_num_semicolons),
        "body_num_brackets":       float(body_num_brackets),
        "body_has_sqli":           body_has_sqli,
        "body_has_xss":            body_has_xss,
        "body_has_traversal":      body_has_traversal,
        "body_has_encoding":       body_has_encoding,
        "body_is_empty":           body_is_empty,
        "method_get":              method_get,
        "method_post":             method_post,
        "method_put":              method_put,
        "method_suspicious":       method_suspicious,
        "cookie_length":           float(cookie_length),
        "cookie_has_sqli":         cookie_has_sqli,
        "cookie_has_xss":          cookie_has_xss,
        "cookie_is_present":       cookie_is_present,
        "content_type_is_form":    content_type_is_form,
        "content_type_is_json":    content_type_is_json,
        "content_type_is_none":    content_type_is_none,
        "connection_is_close":     connection_is_close,
        "connection_keep_alive":   connection_keep_alive,
        "post_no_content_type":    post_no_content_type,
        "get_with_body":           get_with_body,
        "post_empty_body":         post_empty_body,
        "content_length_mismatch": content_length_mismatch,
    }


def extract_features(raw_log_entry: dict[str, Any]) -> dict[str, float]:
    """
    Accept a raw HTTP log dict from the frontend, extract features, and
    return a z-scored feature dict ready for both the rule engine and ML model.

    Parameters
    ----------
    raw_log_entry : dict
        Must contain: method, url, path, query_string, headers, body,
                      response_code, content_length, timestamp.

    Returns
    -------
    dict[str, float]
        53 z-scored features keyed by the names in data/final/feature_names.txt.

    Raises
    ------
    ValueError
        If any required field is missing from raw_log_entry.
    """
    # Validate required fields
    missing_fields = _REQUIRED_FIELDS - set(raw_log_entry.keys())
    if missing_fields:
        raise ValueError(
            f"Missing required field(s) in log entry: {sorted(missing_fields)}"
        )

    raw = _extract_raw_features(raw_log_entry)

    # Assemble in the exact trained column order and scale
    raw_array = np.array(
        [raw[col] for col in FEATURE_COLUMNS], dtype=np.float64
    ).reshape(1, -1)

    scaled_array = _SCALER.transform(raw_array)[0]

    scaled_dict: dict[str, float] = {
        col: float(scaled_array[i]) for i, col in enumerate(FEATURE_COLUMNS)
    }

    # Also store the passthrough fields needed by the orchestrator's payloads
    # (not consumed by engines but carried through for alert context)
    scaled_dict["_response_code"] = int(raw_log_entry.get("response_code", 0))
    scaled_dict["_content_length"] = int(raw_log_entry.get("content_length", 0))

    return scaled_dict
