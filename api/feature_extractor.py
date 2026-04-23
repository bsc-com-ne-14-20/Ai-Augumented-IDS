import re, math, joblib, pandas as pd
from pathlib import Path
from urllib.parse import unquote

ROOT        = Path(__file__).parent.parent
scaler      = joblib.load(ROOT / "data/final/scaler.pkl")

SQLI_PATTERN = re.compile(
    r"(\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bDELETE\b|"
    r"\bUPDATE\b|\bSLEEP\b|\bBENCHMARK\b|1=1|'--|\bEXEC\b|--|;--)", re.IGNORECASE)
XSS_PATTERN = re.compile(
    r"(<script|javascript:|onerror=|onload=|alert\(|document\.cookie|"
    r"<img|<iframe|<svg|eval\(|expression\(|vbscript:)", re.IGNORECASE)
TRAVERSAL_PATTERN = re.compile(
    r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|cmd\.exe|/proc/self|"
    r"/windows/system32|%2e%2e)", re.IGNORECASE)
RISKY_EXT     = re.compile(r"\.(php|asp|aspx|jsp|cgi|sh|pl|py|rb|exe|bat|cmd)(\?|$|#)", re.IGNORECASE)
SPECIAL_CHARS = re.compile(r"[<>\"';()\[\]{}|\\^`]")

def shannon_entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in freq.values())

def extract_features(request: dict) -> pd.DataFrame:
    method       = request.get("method", "GET").upper().strip()
    url          = request.get("url", "/") or "/"
    query_string = request.get("query_string", "") or ""
    body         = request.get("body", "") or ""
    headers      = {k.lower(): v for k, v in (request.get("headers", {}) or {}).items()}
    content_type = headers.get("content-type", "none") or "none"
    cookie       = headers.get("cookie", "none") or "none"
    connection   = headers.get("connection", "") or ""
    content_length = int(headers.get("content-length", 0) or 0)
    cookie_val   = "" if cookie == "none" else cookie
    qd = unquote(query_string); bd = unquote(body); cd = unquote(cookie_val)

    f = {}
    f["url_length"]              = len(url)
    f["url_path_depth"]          = url.count("/")
    f["url_num_dots"]            = url.count(".")
    f["url_num_special"]         = len(SPECIAL_CHARS.findall(url))
    f["url_num_hyphens"]         = url.count("-")
    f["url_num_underscores"]     = url.count("_")
    f["url_num_percent"]         = url.count("%")
    f["url_num_equal"]           = url.count("=")
    f["url_num_ampersand"]       = url.count("&")
    f["url_entropy"]             = shannon_entropy(url)
    f["url_has_risky_ext"]       = 1 if RISKY_EXT.search(url) else 0
    f["url_has_double_encoding"] = 1 if "%25" in url.lower() else 0
    f["query_length"]            = len(query_string)
    f["query_num_params"]        = query_string.count("&")+1 if query_string else 0
    f["query_num_equals"]        = query_string.count("=")
    f["query_num_special"]       = len(SPECIAL_CHARS.findall(qd))
    f["query_num_percent"]       = query_string.count("%")
    f["query_entropy"]           = shannon_entropy(query_string)
    f["query_has_sqli"]          = 1 if SQLI_PATTERN.search(qd) else 0
    f["query_has_xss"]           = 1 if XSS_PATTERN.search(qd) else 0
    f["query_has_traversal"]     = 1 if TRAVERSAL_PATTERN.search(qd) else 0
    f["query_has_encoding"]      = 1 if "%" in query_string else 0
    f["query_is_empty"]          = 1 if not query_string else 0
    f["body_length"]             = len(body)
    f["body_entropy"]            = shannon_entropy(body)
    f["body_num_params"]         = body.count("&")+1 if body else 0
    f["body_num_special"]        = len(SPECIAL_CHARS.findall(bd))
    f["body_num_percent"]        = body.count("%")
    f["body_num_quotes"]         = body.count("'")+body.count('"')
    f["body_num_semicolons"]     = body.count(";")
    f["body_num_brackets"]       = body.count("(")+body.count(")")
    f["body_has_sqli"]           = 1 if SQLI_PATTERN.search(bd) else 0
    f["body_has_xss"]            = 1 if XSS_PATTERN.search(bd) else 0
    f["body_has_traversal"]      = 1 if TRAVERSAL_PATTERN.search(bd) else 0
    f["body_has_encoding"]       = 1 if "%" in body else 0
    f["body_is_empty"]           = 1 if not body else 0
    f["method_get"]              = 1 if method=="GET" else 0
    f["method_post"]             = 1 if method=="POST" else 0
    f["method_put"]              = 1 if method=="PUT" else 0
    f["method_suspicious"]       = 1 if method in {"DELETE","TRACE","CONNECT","PROPFIND"} else 0
    f["cookie_length"]           = len(cookie_val)
    f["cookie_has_sqli"]         = 1 if SQLI_PATTERN.search(cd) else 0
    f["cookie_has_xss"]          = 1 if XSS_PATTERN.search(cd) else 0
    f["cookie_is_present"]       = 1 if cookie_val else 0
    f["content_type_is_form"]    = 1 if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type else 0
    f["content_type_is_json"]    = 1 if "application/json" in content_type else 0
    f["content_type_is_none"]    = 1 if content_type in ("none","") else 0
    f["connection_is_close"]     = 1 if "close" in connection.lower() else 0
    f["connection_keep_alive"]   = 1 if "keep-alive" in connection.lower() else 0
    f["post_no_content_type"]    = 1 if method=="POST" and f["content_type_is_none"] else 0
    f["get_with_body"]           = 1 if method=="GET" and len(body)>0 else 0
    f["post_empty_body"]         = 1 if method=="POST" and len(body)==0 else 0
    f["content_length_mismatch"] = 1 if content_length==0 and len(body)>0 else 0

    df     = pd.DataFrame([f])
    scaled = scaler.transform(df)
    return pd.DataFrame(scaled, columns=df.columns)