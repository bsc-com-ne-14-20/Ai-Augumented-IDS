#!/bin/bash
API_KEY="ids-demo-key-2024"
BASE="http://localhost:5000/api/v1/analyse"

run() {
    local label=$1; local data=$2
    echo -n "  $label → "
    curl -s -X POST $BASE \
        -H "Content-Type: application/json" \
        -H "X-IDS-API-Key: $API_KEY" \
        --data-raw "$data" | python3 -m json.tool | \
        grep -E '"verdict"|"attack_type"|"detection_source"' | tr '\n' ' '
    echo
}

echo ""
echo "══════════════════════════════════════════"
echo "  AA-IDS DEMO — Attack Detection Tests"
echo "══════════════════════════════════════════"
echo ""
echo "─── STAGE 1: CRS Rule Engine ───"
run "[1] SQLI UNION SELECT   " '{"method":"GET","url":"/search","query_string":"q=1 UNION SELECT username,password FROM users--","body":"","headers":{},"source_ip":"10.1.0.1"}'
run "[2] SQLI OR 1=1         " '{"method":"GET","url":"/search","query_string":"q=admin OR 1=1--","body":"","headers":{},"source_ip":"10.1.0.2"}'
run "[3] SQLI Login injection" '{"method":"POST","url":"/login","query_string":"","body":"username=admin'\''--&password=x","headers":{"content-type":"application/x-www-form-urlencoded"},"source_ip":"10.1.0.3"}'

echo ""
echo "─── STAGE 2+3: ML Model (RF + XGBoost) ───"
run "[4] XSS script tag      " '{"method":"GET","url":"/search","query_string":"q=<script>alert(1)</script>","body":"","headers":{},"source_ip":"10.1.0.4"}'
run "[5] Path traversal URL  " '{"method":"GET","url":"/download/../../etc/passwd","query_string":"","body":"","headers":{},"source_ip":"10.1.0.5"}'
run "[6] Encoded traversal   " '{"method":"GET","url":"/files/%2e%2e%2f%2e%2e%2fetc%2fpasswd","query_string":"","body":"","headers":{},"source_ip":"10.1.0.6"}'
run "[7] Evasive XSS         " '{"method":"POST","url":"/comment","query_string":"","body":"comment=test&ref=javascript:void(document.cookie)","headers":{"content-type":"application/x-www-form-urlencoded"},"source_ip":"10.1.0.7"}'

echo ""
echo "─── NORMAL TRAFFIC ───"
run "[8] Normal GET          " '{"method":"GET","url":"/products","query_string":"category=electronics","body":"","headers":{},"source_ip":"192.168.1.10"}'
run "[9] Normal POST login   " '{"method":"POST","url":"/login","query_string":"","body":"username=john&password=pass123","headers":{"content-type":"application/x-www-form-urlencoded"},"source_ip":"192.168.1.11"}'

echo ""
echo "══════════════════════════════════════════"
echo "  Check dashboard → http://localhost:3000"
echo "══════════════════════════════════════════"
