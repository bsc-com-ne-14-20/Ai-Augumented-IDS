"""
logger.py
=========
HTTP Traffic Logger — Phase 2
Captures full raw HTTP requests and stores them to JSONL.
Acts as a transparent proxy between the browser/tool and the target app.

Usage:
    python logger.py --target http://localhost:3000 --port 8080 --source juice_shop --label NORMAL

Then point your browser/tool to http://localhost:8080
"""

import json
import argparse
from datetime import datetime, timezone
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
import urllib.error

# ── Label taxonomy ─────────────────────────────────────────────────────────────
LABELS = ["NORMAL", "SQLI", "XSS", "PATH_TRAVERSAL", "SCANNER", "OTHER"]

# ── Output directory ───────────────────────────────────────────────────────────
ROOT    = Path(__file__).parent.parent
LOG_DIR = ROOT / "traffic_data" / "raw"
LOG_DIR.mkdir(parents=True, exist_ok=True)


def get_log_file(source_app: str) -> Path:
    date = datetime.now(timezone.utc).strftime("%Y%m%d")
    return LOG_DIR / f"{source_app}_{date}.jsonl"


def log_request(record: dict, source_app: str):
    """Append one record to the JSONL log."""
    log_file = get_log_file(source_app)
    with open(log_file, "a") as fh:
        fh.write(json.dumps(record) + "\n")


class ProxyHandler(BaseHTTPRequestHandler):
    # Injected by run() via subclass
    target_url: str = "http://localhost:3000"
    source_app: str = "juice_shop"
    label:      str = "NORMAL"

    # ── Silence default request logging (we do our own) ───────────────────────
    def log_message(self, fmt, *args):
        pass

    # ── Route all methods through do_request ──────────────────────────────────
    def do_GET(self):    self.do_request("GET")
    def do_POST(self):   self.do_request("POST")
    def do_PUT(self):    self.do_request("PUT")
    def do_DELETE(self): self.do_request("DELETE")
    def do_PATCH(self):  self.do_request("PATCH")
    def do_HEAD(self):   self.do_request("HEAD")
    def do_OPTIONS(self):self.do_request("OPTIONS")

    def do_request(self, method: str):
        # ── 1. Read incoming body ──────────────────────────────────────────────
        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b""
        body_str   = body_bytes.decode("utf-8", errors="replace")

        # ── 2. Parse path and query string ────────────────────────────────────
        parts        = self.path.split("?", 1)
        url_path     = parts[0]
        query_string = parts[1] if len(parts) > 1 else ""

        # ── 3. Build the log record ───────────────────────────────────────────
        record = {
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "source_app":    self.source_app,
            "label":         self.label,
            "method":        method,
            "path":          url_path,
            "query_string":  query_string,
            "headers":       dict(self.headers),
            "body":          body_str,
            "body_length":   content_length,
        }

        # ── 4. Forward request to real target ─────────────────────────────────
        target = f"{self.target_url}{self.path}"
        req = urllib.request.Request(
            url=target,
            data=body_bytes if body_bytes else None,
            method=method,
        )
        # Forward original headers (skip hop-by-hop)
        skip_headers = {"host", "content-length", "transfer-encoding", "connection"}
        for key, value in self.headers.items():
            if key.lower() not in skip_headers:
                req.add_header(key, value)

        status_code = 502
        response_body = b""
        response_headers = {}

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status_code     = resp.status
                response_body   = resp.read()
                response_headers = dict(resp.headers)
        except urllib.error.HTTPError as e:
            status_code   = e.code
            response_body = e.read()
        except Exception as exc:
            status_code = 502
            response_body = str(exc).encode()

        # ── 5. Add response info and persist ──────────────────────────────────
        record["response_status"] = status_code
        log_request(record, self.source_app)

        # Print concise console summary
        label_pad = f"[{self.label}]".ljust(15)
        print(f"{label_pad} {method:7s} {status_code}  {self.path[:80]}")

        # ── 6. Relay response back to caller ──────────────────────────────────
        self.send_response(status_code)
        skip_resp = {"transfer-encoding", "connection", "keep-alive"}
        for key, value in response_headers.items():
            if key.lower() not in skip_resp:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)


def make_handler(target_url: str, source_app: str, label: str):
    """Return a ProxyHandler subclass with injected config."""
    class ConfiguredHandler(ProxyHandler):
        pass
    ConfiguredHandler.target_url = target_url
    ConfiguredHandler.source_app = source_app
    ConfiguredHandler.label      = label
    return ConfiguredHandler


def run(target_url: str, port: int, source_app: str, label: str):
    handler = make_handler(target_url, source_app, label)
    server  = HTTPServer(("0.0.0.0", port), handler)
    log_file = get_log_file(source_app)

    print("=" * 60)
    print("  HTTP Traffic Logger — Phase 2")
    print("=" * 60)
    print(f"  Proxy port : {port}")
    print(f"  Target     : {target_url}")
    print(f"  Source app : {source_app}")
    print(f"  Label      : {label}")
    print(f"  Log file   : {log_file}")
    print("=" * 60)
    print("  Point browser/tool to  http://localhost:{port}")
    print("  Ctrl-C to stop\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[logger] Stopped.")
    finally:
        server.server_close()


# ── CLI ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="HTTP Traffic Logger — forwards traffic and logs to JSONL"
    )
    parser.add_argument(
        "--target", default="http://localhost:3000",
        help="Target app base URL (default: http://localhost:3000)"
    )
    parser.add_argument(
        "--port", type=int, default=8080,
        help="Local proxy port to listen on (default: 8080)"
    )
    parser.add_argument(
        "--source", default="juice_shop",
        help="Source app tag written into every log record (default: juice_shop)"
    )
    parser.add_argument(
        "--label", default="NORMAL", choices=LABELS,
        help=f"Traffic label for all captured requests. One of: {LABELS}"
    )
    args = parser.parse_args()
    run(args.target, args.port, args.source, args.label)