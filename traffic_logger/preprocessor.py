"""
preprocessor.py
===============
Phase 2 — Convert raw JSONL traffic logs to 53-feature CSV.
Merges Juice Shop data with existing CSIC 2010 training data.

Output:
    data/augmented/train_augmented.csv
    data/augmented/test_augmented.csv
    data/augmented/scaler_augmented.pkl
"""

import json
import re
import math
import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from urllib.parse import unquote
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

ROOT       = Path(__file__).parent.parent
RAW_DIR    = ROOT / "traffic_data" / "raw"
OUT_DIR    = ROOT / "data" / "augmented"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Attack pattern regexes ────────────────────────────────────────
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

def extract_features(record: dict) -> dict:
    """Extract 53 features from a raw JSONL record."""
    method       = record.get("method", "GET").upper().strip()
    path         = record.get("path", "/") or "/"
    query_string = record.get("query_string", "") or ""
    body         = record.get("body", "") or ""
    headers      = record.get("headers", {}) or {}
    if isinstance(headers, str):
        headers = {}
    headers      = {k.lower(): v for k, v in headers.items()}
    content_type = headers.get("content-type", "none") or "none"
    cookie       = headers.get("cookie", "none") or "none"
    connection   = headers.get("connection", "") or ""
    content_length = int(headers.get("content-length", 0) or 0)
    cookie_val   = "" if cookie == "none" else cookie

    qd = unquote(query_string)
    bd = unquote(body)
    cd = unquote(cookie_val)

    f = {}
    # Group 1 — URL
    f["url_length"]              = len(path)
    f["url_path_depth"]          = path.count("/")
    f["url_num_dots"]            = path.count(".")
    f["url_num_special"]         = len(SPECIAL_CHARS.findall(path))
    f["url_num_hyphens"]         = path.count("-")
    f["url_num_underscores"]     = path.count("_")
    f["url_num_percent"]         = path.count("%")
    f["url_num_equal"]           = path.count("=")
    f["url_num_ampersand"]       = path.count("&")
    f["url_entropy"]             = shannon_entropy(path)
    f["url_has_risky_ext"]       = 1 if RISKY_EXT.search(path) else 0
    f["url_has_double_encoding"] = 1 if "%25" in path.lower() else 0
    # Group 2 — Query
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
    # Group 3 — Body
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
    # Group 4 — Method
    f["method_get"]              = 1 if method=="GET" else 0
    f["method_post"]             = 1 if method=="POST" else 0
    f["method_put"]              = 1 if method=="PUT" else 0
    f["method_suspicious"]       = 1 if method in {"DELETE","TRACE","CONNECT","PROPFIND"} else 0
    # Group 5 — Headers
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

    # Label
    label_str = record.get("label", "NORMAL")
    f["label"] = 0 if label_str == "NORMAL" else 1

    return f


def load_jsonl_files() -> pd.DataFrame:
    """Load all JSONL files and extract features."""
    records = []
    files   = list(RAW_DIR.glob("*.jsonl"))
    print(f"  Found {len(files)} JSONL files")

    for fpath in files:
        print(f"  Processing {fpath.name}...")
        with open(fpath) as f:
            for line in f:
                try:
                    record  = json.loads(line.strip())
                    features = extract_features(record)
                    records.append(features)
                except Exception as e:
                    continue

    df = pd.DataFrame(records)
    print(f"  ✓ Extracted {len(df)} records from JSONL files")
    return df


def main():
    print("\n" + "="*60)
    print("  Phase 2 — Preprocessor")
    print("="*60)

    # ── 1. Load Juice Shop JSONL data ─────────────────────────────
    print("\n[1/5] Loading Juice Shop traffic logs...")
    juice_df = load_jsonl_files()

    print("\n  Juice Shop label distribution:")
    print(juice_df['label'].value_counts().to_string())

    # ── 2. Load existing CSIC training data ───────────────────────
    print("\n[2/5] Loading CSIC 2010 training data...")
    csic_train = pd.read_csv(ROOT / "data/final/train.csv")
    csic_test  = pd.read_csv(ROOT / "data/final/test.csv")

    # Load original scaler to inverse transform CSIC data
    old_scaler = joblib.load(ROOT / "data/final/scaler.pkl")

    # Inverse transform CSIC data back to raw feature space
    feature_cols = [c for c in csic_train.columns if c != 'label']
    csic_train_raw = pd.DataFrame(
        old_scaler.inverse_transform(csic_train[feature_cols]),
        columns=feature_cols
    )
    csic_train_raw['label'] = csic_train['label'].values

    csic_test_raw = pd.DataFrame(
        old_scaler.inverse_transform(csic_test[feature_cols]),
        columns=feature_cols
    )
    csic_test_raw['label'] = csic_test['label'].values

    print(f"  ✓ CSIC train: {len(csic_train_raw)} rows")
    print(f"  ✓ CSIC test:  {len(csic_test_raw)} rows")

    # ── 3. Align and merge ────────────────────────────────────────
    print("\n[3/5] Merging datasets...")

    # Ensure juice_df has same columns as CSIC
    for col in feature_cols:
        if col not in juice_df.columns:
            juice_df[col] = 0.0

    juice_df = juice_df[feature_cols + ['label']]

    # Split juice shop data into train/test
    juice_train, juice_test = train_test_split(
        juice_df, test_size=0.2, stratify=juice_df['label'], random_state=42
    )

    # Merge
    train_merged = pd.concat([csic_train_raw, juice_train], ignore_index=True)
    test_merged  = pd.concat([csic_test_raw,  juice_test],  ignore_index=True)

    # Shuffle
    train_merged = train_merged.sample(frac=1, random_state=42).reset_index(drop=True)
    test_merged  = test_merged.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"  ✓ Merged train : {len(train_merged)} rows")
    print(f"  ✓ Merged test  : {len(test_merged)} rows")
    print(f"\n  Label distribution (train):")
    print(f"    Normal : {(train_merged['label']==0).sum()}")
    print(f"    Attack : {(train_merged['label']==1).sum()}")

    # ── 4. Fit new scaler on merged training data ─────────────────
    print("\n[4/5] Fitting new scaler on merged training data...")
    X_train = train_merged[feature_cols]
    X_test  = test_merged[feature_cols]

    new_scaler = StandardScaler()
    X_train_scaled = new_scaler.fit_transform(X_train)
    X_test_scaled  = new_scaler.transform(X_test)

    train_scaled = pd.DataFrame(X_train_scaled, columns=feature_cols)
    train_scaled['label'] = train_merged['label'].values

    test_scaled = pd.DataFrame(X_test_scaled, columns=feature_cols)
    test_scaled['label'] = test_merged['label'].values

    # ── 5. Save outputs ───────────────────────────────────────────
    print("\n[5/5] Saving outputs...")
    train_scaled.to_csv(OUT_DIR / "train_augmented.csv", index=False)
    test_scaled.to_csv(OUT_DIR  / "test_augmented.csv",  index=False)
    joblib.dump(new_scaler, OUT_DIR / "scaler_augmented.pkl")

    print(f"  ✓ train_augmented.csv → {len(train_scaled)} rows")
    print(f"  ✓ test_augmented.csv  → {len(test_scaled)} rows")
    print(f"  ✓ scaler_augmented.pkl saved")

    print("\n" + "="*60)
    print("  ✓ Preprocessing complete!")
    print("  Next: retrain RF + XGBoost on augmented data")
    print("="*60)


if __name__ == "__main__":
    main()
