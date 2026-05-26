import re, math, joblib, pandas as pd
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).parent.parent
scaler = joblib.load(ROOT / "data/augmented/scaler_augmented.pkl")

SQLI_PATTERN = re.compile(r"(\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|1=1|'--|--|;--)", re.IGNORECASE)
XSS_PATTERN = re.compile(r"(<script|javascript:|onerror=|alert\(|document\.cookie)", re.IGNORECASE)
TRAVERSAL_PATTERN = re.compile(r"(\.\./|/etc/passwd|cmd\.exe)", re.IGNORECASE)
RISKY_EXT = re.compile(r"\.(php|asp|jsp|cgi|sh|exe|bat|cmd)(\?|$|#)", re.IGNORECASE)
SPECIAL_CHARS = re.compile(r"[<>\"';()\[\]{}|\\\^`]")

def shannon_entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in freq.values())

def extract_features(request: dict) -> pd.DataFrame:
    method = request.get("method", "GET").upper().strip()
    url = request.get("url", "/") or "/"
    query_string = request.get("query_string", "") or ""
    body = request.get("body", "") or ""
    headers = {k.lower(): v for k, v in (request.get("headers", {}) or {}).items()}
    content_type = headers.get("content-type", "none") or "none"
    qd = unquote(query_string)
    bd = unquote(body)
    ud = unquote(url)
    
    f = {}
    f["url_length"] = len(url)
    f["url_path_depth"] = url.count("/")
    f["url_num_dots"] = url.count(".")
    f["url_num_special"] = len(SPECIAL_CHARS.findall(url))
    f["url_num_hyphens"] = url.count("-")
    f["url_num_underscores"] = url.count("_")
    f["url_num_percent"] = url.count("%")
    f["url_num_equal"] = url.count("=")
    f["url_num_ampersand"] = url.count("&")
    f["url_entropy"] = shannon_entropy(url)
    f["url_has_risky_ext"] = 1 if RISKY_EXT.search(url) else 0
    f["url_has_double_encoding"] = 1 if "%25" in url.lower() else 0
    # Check URL path itself for attack patterns (catches path-based attacks)
    # URL path attack patterns — used below, NOT added as features
    _url_has_sqli     = 1 if SQLI_PATTERN.search(ud) else 0
    _url_has_xss      = 1 if XSS_PATTERN.search(ud)  else 0
    _url_has_traversal= 1 if TRAVERSAL_PATTERN.search(ud) else 0
    f["query_length"] = len(query_string)
    f["query_num_params"] = query_string.count("&")+1 if query_string else 0
    f["query_num_equals"] = query_string.count("=")
    f["query_num_special"] = len(SPECIAL_CHARS.findall(qd))
    f["query_num_percent"] = query_string.count("%")
    f["query_entropy"] = shannon_entropy(query_string)
    f["query_has_sqli"]     = 1 if (SQLI_PATTERN.search(qd)     or _url_has_sqli)      else 0
    f["query_has_xss"]      = 1 if (XSS_PATTERN.search(qd)      or _url_has_xss)       else 0
    f["query_has_traversal"]= 1 if (TRAVERSAL_PATTERN.search(qd) or _url_has_traversal) else 0
    f["query_has_encoding"] = 1 if "%" in query_string else 0
    f["query_is_empty"] = 1 if not query_string else 0
    f["body_length"] = len(body)
    f["body_entropy"] = shannon_entropy(body)
    f["body_num_params"] = body.count("&")+1 if body else 0
    f["body_num_special"] = len(SPECIAL_CHARS.findall(bd))
    f["body_num_percent"] = body.count("%")
    f["body_num_quotes"] = body.count("'")+body.count('\"')
    f["body_num_semicolons"] = body.count(";")
    f["body_num_brackets"] = body.count("(")+body.count(")")
    f["body_has_sqli"] = 1 if SQLI_PATTERN.search(bd) else 0
    f["body_has_xss"] = 1 if XSS_PATTERN.search(bd) else 0
    f["body_has_traversal"] = 1 if TRAVERSAL_PATTERN.search(bd) else 0
    f["body_has_encoding"] = 1 if "%" in body else 0
    f["body_is_empty"] = 1 if not body else 0
    f["method_get"] = 1 if method=="GET" else 0
    f["method_post"] = 1 if method=="POST" else 0
    f["method_put"] = 1 if method=="PUT" else 0
    f["method_suspicious"] = 1 if method in {"DELETE","TRACE","CONNECT"} else 0
    f["cookie_length"] = 0.1
    f["cookie_has_sqli"] = 0
    f["cookie_has_xss"] = 0
    f["cookie_is_present"] = 0
    f["content_type_is_form"] = 1 if "form" in content_type else 0
    f["content_type_is_json"] = 1 if "json" in content_type else 0
    f["content_type_is_none"] = 1 if content_type=="none" else 0
    f["connection_is_close"] = 0
    f["connection_keep_alive"] = 0
    f["post_no_content_type"] = 0
    f["get_with_body"] = 0
    f["post_empty_body"] = 0
    f["content_length_mismatch"] = 0
    
    df = pd.DataFrame([f])
    scaled = scaler.transform(df)
    result = pd.DataFrame(scaled, columns=df.columns)
    # Clip extreme outliers caused by zero-variance features in training data
    result = result.clip(lower=-5, upper=5)
    return result, df  # (scaled, unscaled)
