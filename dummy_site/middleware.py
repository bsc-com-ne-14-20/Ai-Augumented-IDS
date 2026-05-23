
import json, time, csv, os
from datetime import datetime
from flask import request, g

LOG_FILE = "http_traffic.jsonl"   # one JSON object per line

def register_logger(app):
    @app.before_request
    def start_timer():
        g.start_time = time.time()

    @app.after_request
    def log_request(response):
        duration_ms = round((time.time() - g.start_time) * 1000, 2)

        # Parse URL the same way your feature pipeline expects
        url_path   = request.path
        query_str  = request.query_string.decode("utf-8", errors="replace")
        body       = request.get_data(as_text=True)

        record = {
            "timestamp":      datetime.utcnow().isoformat(),
            "method":         request.method.upper().strip(),
            "url_path":       url_path,
            "query_string":   query_str,
            "body":           body,
            "content_length": len(body),
            "content_type":   request.content_type or "none",
            "accept":         request.headers.get("Accept", "unknown"),
            "cookie":         request.headers.get("Cookie", "none"),
            "user_agent":     request.headers.get("User-Agent", "unknown"),
            "status_code":    response.status_code,
            "duration_ms":    duration_ms,
            "remote_addr":    request.remote_addr,
        }

        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")

        return response