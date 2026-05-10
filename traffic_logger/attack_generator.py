"""
attack_generator.py
===================
Fires SecLists payloads at Juice Shop through the traffic logger proxy.
Automatically labels each request with the correct attack type.

Usage:
    python traffic_logger/attack_generator.py
"""

import requests
import time
import json
from pathlib import Path
from datetime import datetime, timezone
import hashlib

ROOT       = Path(__file__).parent.parent
SECLISTS   = ROOT / "SecLists"
LOG_DIR    = ROOT / "traffic_data" / "raw"
LOG_DIR.mkdir(parents=True, exist_ok=True)

TARGET     = "http://localhost:3000"
DELAY      = 0.1  # seconds between requests

# ── Payload files ─────────────────────────────────────────────────
PAYLOAD_FILES = {
    "SQLI": [
        SECLISTS / "Fuzzing/Databases/SQLi/Generic-SQLi.txt",
        SECLISTS / "Fuzzing/Databases/SQLi/quick-SQLi.txt",
        SECLISTS / "Fuzzing/Databases/SQLi/MySQL-SQLi-Login-Bypass.fuzzdb.txt",
        SECLISTS / "Fuzzing/Databases/SQLi/sqli.auth.bypass.txt",
    ],
    "XSS": [
        SECLISTS / "Fuzzing/XSS/human-friendly/XSS-RSNAKE.txt",
        SECLISTS / "Fuzzing/XSS/human-friendly/XSS-Jhaddix.txt",
        SECLISTS / "Fuzzing/XSS/human-friendly/XSS-Somdev.txt",
    ],
    "PATH_TRAVERSAL": [
        SECLISTS / "Fuzzing/LFI/LFI-Jhaddix.txt",
        SECLISTS / "Fuzzing/LFI/LFI-LFISuite-pathtotest.txt",
    ],
}

# ── Target endpoints ──────────────────────────────────────────────
ENDPOINTS = {
    "SQLI": [
        {"method": "GET",  "path": "/rest/products/search", "param": "q"},
        {"method": "POST", "path": "/rest/user/login",      "param": "email", "body_key": "email"},
        {"method": "GET",  "path": "/api/Products",         "param": "q"},
    ],
    "XSS": [
        {"method": "GET",  "path": "/rest/products/search", "param": "q"},
        {"method": "GET",  "path": "/api/Challenges",       "param": "name"},
    ],
    "PATH_TRAVERSAL": [
        {"method": "GET", "path": "/assets/public/images/uploads/", "param": None, "as_path": True},
        {"method": "GET", "path": "/ftp/",                          "param": None, "as_path": True},
    ],
}


def get_log_file(label: str) -> Path:
    date = datetime.now(timezone.utc).strftime("%Y%m%d")
    return LOG_DIR / f"juice_shop_{date}.jsonl"


def log_record(record: dict, label: str):
    with open(get_log_file(label), "a") as f:
        f.write(json.dumps(record) + "\n")


def load_payloads(files: list, max_per_file: int = 200) -> list:
    payloads = []
    for path in files:
        if not path.exists():
            print(f"  ⚠ Not found: {path.name}")
            continue
        with open(path, "r", errors="ignore") as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            payloads.extend(lines[:max_per_file])
    return payloads


def fire_payload(label: str, endpoint: dict, payload: str, session: requests.Session):
    method   = endpoint["method"]
    path     = endpoint["path"]
    param    = endpoint.get("param")
    as_path  = endpoint.get("as_path", False)

    try:
        if as_path:
            url = f"{TARGET}{path}{payload}"
            r   = session.get(url, timeout=5)
            query_string = ""
            body = ""
        elif method == "GET":
            url  = f"{TARGET}{path}"
            r    = session.get(url, params={param: payload}, timeout=5)
            query_string = f"{param}={payload}"
            body = ""
        elif method == "POST":
            url  = f"{TARGET}{path}"
            body_key = endpoint.get("body_key", param)
            post_data = {body_key: payload, "password": "test"}
            r    = session.post(url, json=post_data, timeout=5)
            query_string = ""
            body = json.dumps(post_data)

        record = {
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "source_app":   "juice_shop",
            "label":        label,
            "method":       method,
            "path":         path,
            "query_string": query_string,
            "full_path":    path + (f"?{query_string}" if query_string else ""),
            "headers":      dict(r.request.headers),
            "cookie":       r.request.headers.get("Cookie", ""),
            "body":         body,
            "body_length":  len(body),
            "status_code":  r.status_code,
            "payload":      payload,
            "request_id":   hashlib.md5(f"{path}{payload}".encode()).hexdigest()[:12],
        }
        log_record(record, label)
        return r.status_code

    except Exception as e:
        return f"ERR: {e}"


def run():
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Accept":     "application/json, text/plain, */*",
    })

    total = 0
    print("\n" + "=" * 60)
    print("  AA-IDS Attack Generator — SecLists Payloads")
    print("=" * 60)

    for label, files in PAYLOAD_FILES.items():
        payloads  = load_payloads(files, max_per_file=300)
        endpoints = ENDPOINTS[label]

        print(f"\n[{label}] {len(payloads)} payloads × {len(endpoints)} endpoints")

        count = 0
        for payload in payloads:
            for endpoint in endpoints:
                status = fire_payload(label, endpoint, payload, session)
                count += 1
                total += 1
                if count % 50 == 0:
                    print(f"  → {count} requests sent | last status: {status}")
                time.sleep(DELAY)

        print(f"  ✓ {label} complete — {count} requests logged")

    print(f"\n{'=' * 60}")
    print(f"  ✓ Total: {total} attack requests logged")
    print(f"  ✓ Log  : {get_log_file('attack')}")
    print("=" * 60)


if __name__ == "__main__":
    run()
