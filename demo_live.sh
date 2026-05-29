#!/bin/bash
BASE="https://ai-augumented-ids.onrender.com"
API="http://localhost:5000/api/v1/analyse"
KEY="ids-demo-key-2024"

echo ""
echo "══════════════════════════════════════════════"
echo "  AA-IDS LIVE DEMO — ai-augumented-ids.onrender.com"
echo "══════════════════════════════════════════════"

# Helper — hit the dummy site directly (middleware forwards to IDS)
hit() {
    local label=$1; shift
    echo -n "  $label → "
    curl -s -o /dev/null -w "%{http_code}" "$@"
    echo " (check dashboard)"
    sleep 0.5
}

echo ""
echo "─── RULE ENGINE ATTACKS ───"

echo "[1] SQLi UNION SELECT"
curl -s -o /dev/null -g "$BASE/?search=1+UNION+SELECT+username,password+FROM+users--"
echo "  → check dashboard"

echo "[2] SQLi OR 1=1"
curl -s -o /dev/null -g "$BASE/?q=admin'+OR+'1'='1"
echo "  → check dashboard"

echo "[3] SQLi login injection"
curl -s -o /dev/null -X POST "$BASE/auth/login/" \
  -d "username=admin'--&password=anything" \
  -H "Content-Type: application/x-www-form-urlencoded"
echo "  → check dashboard"

echo "[4] SQLi register injection"
curl -s -o /dev/null -X POST "$BASE/auth/register/" \
  -d "username=hacker'/*&email=x@x.com&password1=test&password2=test" \
  -H "Content-Type: application/x-www-form-urlencoded"
echo "  → check dashboard"

echo "[5] XSS script tag"
curl -s -o /dev/null -g "$BASE/?q=<script>alert('xss')</script>"
echo "  → check dashboard"

echo "[6] XSS event handler"
curl -s -o /dev/null -g "$BASE/?q=<img+src=x+onerror=alert(1)>"
echo "  → check dashboard"

echo "[7] XSS in POST body"
curl -s -o /dev/null -X POST "$BASE/post/new/" \
  -d "title=Hello&content=<script>document.cookie</script>" \
  -H "Content-Type: application/x-www-form-urlencoded"
echo "  → check dashboard"

echo "[8] Path traversal query"
curl -s -o /dev/null -g "$BASE/?file=../../etc/passwd"
echo "  → check dashboard"

echo "[9] Sensitive file access"
curl -s -o /dev/null -g "$BASE/?page=/etc/passwd"
echo "  → check dashboard"

echo "[10] Brute force (15 attempts)..."
for i in {1..15}; do
  curl -s -o /dev/null -X POST "$BASE/auth/login/" \
    -d "username=admin&password=wrong$i" \
    -H "Content-Type: application/x-www-form-urlencoded"
  echo -n "  attempt $i "
  sleep 0.3
done
echo ""
echo "  → check dashboard for BF alert"

echo ""
echo "─── ML ENGINE ATTACKS ───"

echo "[11] GET with body (protocol anomaly)"
curl -s -o /dev/null -X GET "$BASE/" \
  -d "hidden=SELECT * FROM users WHERE 1=1" \
  -H "Content-Type: application/x-www-form-urlencoded"
echo "  → check dashboard"

echo "[12] POST no Content-Type + traversal"
curl -s -o /dev/null -X POST "$BASE/auth/login/" \
  -d "username=admin&password=test&redirect=../../../../etc/shadow" \
  -H "Content-Type:"
echo "  → check dashboard"

echo "[13] High-entropy fuzzer query"
curl -s -o /dev/null -g "$BASE/?a=xK9mP2&b=Lq7nR4&c=Wz3vT8&d=Hy6uE1&e=Jf5sA0&f=Cb4dN9&g=Ot2wM6&h=Vu8kI3&i=Rp1lG7&j=Dx0yF5&k=Qn3bH2&l=Sm9cJ4"
echo "  → check dashboard"

echo "[14a] DELETE method anomaly"
curl -s -o /dev/null -X DELETE "$BASE/post/1/"
echo "  → check dashboard"

echo "[14b] TRACE method anomaly"
curl -s -o /dev/null -X TRACE "$BASE/"
echo "  → check dashboard"

echo "[15] Double-encoded SQLi"
curl -s -o /dev/null -g "$BASE/?id=%2527%2520OR%25201%253D1%2520--"
echo "  → check dashboard"

echo ""
echo "─── NORMAL TRAFFIC ───"
for url in "/" "/about/" "/auth/login/" "/auth/register/"; do
  curl -s -o /dev/null "$BASE$url"
  echo "  Normal GET $url → check dashboard (should be CLEAN)"
  sleep 0.3
done

echo ""
echo "══════════════════════════════════════════════"
echo "  Done. Dashboard → http://localhost:3000"
echo "  Stats → curl -s http://localhost:5000/api/v1/metrics -H 'X-IDS-API-Key: ids-demo-key-2024' | python3 -m json.tool"
echo "══════════════════════════════════════════════"
