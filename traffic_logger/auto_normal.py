"""
auto_normal.py
==============
Automatically generates realistic normal traffic against Juice Shop.
No browser needed — runs in background while you study.

Usage:
    python traffic_logger/auto_normal.py
"""

import requests
import time
import json
import random
import hashlib
from datetime import datetime, timezone
from pathlib import Path

ROOT    = Path(__file__).parent.parent
LOG_DIR = ROOT / "traffic_data" / "raw"
LOG_DIR.mkdir(parents=True, exist_ok=True)
TARGET  = "http://localhost:3000"

# ── Realistic normal endpoints ────────────────────────────────────
NORMAL_REQUESTS = [
    # Product browsing
    {"method": "GET",  "path": "/rest/products/search",        "params": {"q": ""}},
    {"method": "GET",  "path": "/rest/products/search",        "params": {"q": "apple"}},
    {"method": "GET",  "path": "/rest/products/search",        "params": {"q": "juice"}},
    {"method": "GET",  "path": "/rest/products/search",        "params": {"q": "banana"}},
    {"method": "GET",  "path": "/rest/products/search",        "params": {"q": "lemon"}},
    {"method": "GET",  "path": "/api/Products/1",              "params": {}},
    {"method": "GET",  "path": "/api/Products/2",              "params": {}},
    {"method": "GET",  "path": "/api/Products/3",              "params": {}},
    {"method": "GET",  "path": "/api/Products/4",              "params": {}},
    {"method": "GET",  "path": "/api/Products/5",              "params": {}},
    {"method": "GET",  "path": "/api/Quantitys/",              "params": {}},
    # Auth endpoints
    {"method": "GET",  "path": "/rest/user/whoami",            "params": {}},
    {"method": "GET",  "path": "/rest/user/whoami",            "params": {"fields": "email"}},
    {"method": "GET",  "path": "/api/SecurityQuestions/",      "params": {}},
    # App config
    {"method": "GET",  "path": "/rest/admin/application-configuration", "params": {}},
    {"method": "GET",  "path": "/rest/admin/application-version",       "params": {}},
    {"method": "GET",  "path": "/rest/languages",              "params": {}},
    # Reviews
    {"method": "GET",  "path": "/rest/products/1/reviews",    "params": {}},
    {"method": "GET",  "path": "/rest/products/2/reviews",    "params": {}},
    {"method": "GET",  "path": "/rest/products/3/reviews",    "params": {}},
    # Challenges / score board
    {"method": "GET",  "path": "/api/Challenges/",            "params": {"name": "Score Board"}},
    {"method": "GET",  "path": "/api/Challenges/",            "params": {"sort": "name"}},
    # Memories
    {"method": "GET",  "path": "/rest/memories/",             "params": {}},
    # Basket
    {"method": "GET",  "path": "/rest/basket/1",              "params": {}},
    # POST login (valid credentials)
    {"method": "POST", "path": "/rest/user/login",
     "json": {"email": "customer@juice-sh.op", "password": "customer"}},
    {"method": "POST", "path": "/rest/user/login",
     "json": {"email": "admin@juice-sh.op", "password": "admin123"}},
    # Registration
    {"method": "GET",  "path": "/api/SecurityQuestions/",     "params": {}},
    # Deluxe membership
    {"method": "GET",  "path": "/rest/deluxe-membership",     "params": {}},
    # Cards
    {"method": "GET",  "path": "/api/Cards",                  "params": {}},
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15",
]


def get_log_file() -> Path:
    date = datetime.now(timezone.utc).strftime("%Y%m%d")
    return LOG_DIR / f"juice_shop_{date}.jsonl"


def log_record(record: dict):
    with open(get_log_file(), "a") as f:
        f.write(json.dumps(record) + "\n")


def fire(session, req):
    method  = req["method"]
    path    = req["path"]
    params  = req.get("params", {})
    body    = req.get("json", None)

    try:
        if method == "GET":
            r = session.get(f"{TARGET}{path}", params=params, timeout=5)
            query_string = "&".join(f"{k}={v}" for k, v in params.items())
            body_str     = ""
        else:
            r = session.post(f"{TARGET}{path}", json=body, timeout=5)
            query_string = ""
            body_str     = json.dumps(body) if body else ""

        record = {
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "source_app":   "juice_shop",
            "label":        "NORMAL",
            "method":       method,
            "path":         path,
            "query_string": query_string,
            "full_path":    path + (f"?{query_string}" if query_string else ""),
            "headers":      dict(r.request.headers),
            "cookie":       r.request.headers.get("Cookie", ""),
            "body":         body_str,
            "body_length":  len(body_str),
            "status_code":  r.status_code,
            "request_id":   hashlib.md5(
                f"{path}{query_string}{body_str}".encode()
            ).hexdigest()[:12],
        }
        log_record(record)
        return r.status_code

    except Exception as e:
        return f"ERR: {e}"


def run(target_count: int = 15000):
    session = requests.Session()
    count   = 0

    print(f"""
╔══════════════════════════════════════════════════════╗
  AA-IDS Auto Normal Traffic Generator
  Target : {target_count} normal requests
  Log    : {get_log_file()}
╚══════════════════════════════════════════════════════╝
Running in background — go study! Ctrl+C to stop.
""")

    while count < target_count:
        # Rotate user agents
        session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept":     "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
        })

        # Pick a random request
        req    = random.choice(NORMAL_REQUESTS)
        status = fire(session, req)
        count += 1

        if count % 100 == 0:
            print(f"  ✓ {count}/{target_count} normal requests logged")

        # Random delay to simulate real browsing
        time.sleep(random.uniform(0.05, 0.3))

    print(f"\n✓ Done! {count} normal requests logged to {get_log_file()}")


if __name__ == "__main__":
    run(target_count=5000)
