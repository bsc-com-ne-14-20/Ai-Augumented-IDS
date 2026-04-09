"""
crs_rules.py
============
OWASP CRS — Feature-Based Rule Definitions
-------------------------------------------
Maps pre-engineered, z-scored dataset features to OWASP CRS rule groups.

Because the dataset contains scaled binary indicators (e.g. query_has_sqli)
and scaled continuous anomaly signals (e.g. url_entropy), each CRS "rule"
is defined as a named feature threshold rather than a raw regex pattern.
The engine accumulates an anomaly score exactly as CRS does, and flags
a request when the score meets or exceeds the configured threshold.

Rule fields
-----------
  rule_id   : CRS-style ID  (e.g. "942100")
  feature   : column name in the dataset DataFrame
  threshold : scaled value above which the rule fires
  severity  : CRITICAL | HIGH | MEDIUM | LOW
  category  : attack family name (for output labelling)
  message   : human-readable explanation

Threshold derivation
--------------------
  Binary indicators   → midpoint between the two z-scored values
    e.g. query_has_sqli  neg = -0.1925, pos = 5.1957  → threshold = 2.50
  Continuous features → 95th-percentile of the *normal* class (no leakage
    because this is a fixed statistical property of the scaler, not the
    test labels).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class CRSRule:
    rule_id:   str
    feature:   str
    threshold: float
    severity:  str        # CRITICAL | HIGH | MEDIUM | LOW
    category:  str
    message:   str


# ──────────────────────────────────────────────────────────────────
# 942xxx — SQL Injection
# Threshold source: midpoint of z-scored binary pos/neg values
# ──────────────────────────────────────────────────────────────────
SQL_INJECTION_RULES = [
    CRSRule(
        rule_id="942100", feature="query_has_sqli", threshold=2.50,
        severity="CRITICAL", category="SQL Injection",
        message="SQL Injection pattern detected in query string"
    ),
    CRSRule(
        rule_id="942200", feature="body_has_sqli", threshold=2.50,
        severity="CRITICAL", category="SQL Injection",
        message="SQL Injection pattern detected in request body"
    ),
    CRSRule(
        rule_id="942300", feature="cookie_has_sqli", threshold=0.5,
        severity="CRITICAL", category="SQL Injection",
        message="SQL Injection pattern detected in cookie"
    ),
    CRSRule(
        rule_id="942400", feature="query_num_special", threshold=0.50,
        severity="HIGH", category="SQL Injection",
        message="High density of special characters in query (SQLi evasion)"
    ),
]

# ──────────────────────────────────────────────────────────────────
# 941xxx — Cross-Site Scripting (XSS)
# ──────────────────────────────────────────────────────────────────
XSS_RULES = [
    CRSRule(
        rule_id="941100", feature="query_has_xss", threshold=6.41,
        severity="CRITICAL", category="XSS",
        message="XSS pattern detected in query string"
    ),
    CRSRule(
        rule_id="941200", feature="body_has_xss", threshold=6.44,
        severity="CRITICAL", category="XSS",
        message="XSS pattern detected in request body"
    ),
    CRSRule(
        rule_id="941300", feature="cookie_has_xss", threshold=0.5,
        severity="CRITICAL", category="XSS",
        message="XSS pattern detected in cookie"
    ),
]

# ──────────────────────────────────────────────────────────────────
# 930xxx — Path Traversal / LFI
# ──────────────────────────────────────────────────────────────────
PATH_TRAVERSAL_RULES = [
    CRSRule(
        rule_id="930100", feature="query_has_traversal", threshold=12.33,
        severity="CRITICAL", category="Path Traversal",
        message="Directory traversal sequence detected in query string"
    ),
    CRSRule(
        rule_id="930200", feature="body_has_traversal", threshold=12.82,
        severity="CRITICAL", category="Path Traversal",
        message="Directory traversal sequence detected in request body"
    ),
]

# ──────────────────────────────────────────────────────────────────
# 920xxx — Protocol Anomalies & Encoding Evasion
# ──────────────────────────────────────────────────────────────────
PROTOCOL_ANOMALY_RULES = [
    CRSRule(
        rule_id="920100", feature="query_has_encoding", threshold=0.86,
        severity="HIGH", category="Encoding Evasion",
        message="Suspicious encoding detected in query string"
    ),
    CRSRule(
        rule_id="920200", feature="body_has_encoding", threshold=0.85,
        severity="HIGH", category="Encoding Evasion",
        message="Suspicious encoding detected in request body"
    ),
    CRSRule(
        rule_id="920300", feature="url_has_double_encoding", threshold=2.998,
        severity="HIGH", category="Encoding Evasion",
        message="Double URL-encoding detected (evasion attempt)"
    ),
    CRSRule(
        rule_id="920400", feature="url_num_percent", threshold=0.44,
        severity="MEDIUM", category="Encoding Evasion",
        message="Elevated percent-encoded characters in URL"
    ),
    CRSRule(
        rule_id="920500", feature="query_num_percent", threshold=0.44,
        severity="MEDIUM", category="Encoding Evasion",
        message="Elevated percent-encoded characters in query"
    ),
    CRSRule(
        rule_id="920600", feature="body_num_percent", threshold=0.44,
        severity="MEDIUM", category="Encoding Evasion",
        message="Elevated percent-encoded characters in body"
    ),
    CRSRule(
        rule_id="920700", feature="content_length_mismatch", threshold=0.5,
        severity="HIGH", category="Protocol Anomaly",
        message="Content-Length header does not match actual body length"
    ),
    CRSRule(
        rule_id="920800", feature="post_no_content_type", threshold=0.5,
        severity="MEDIUM", category="Protocol Anomaly",
        message="POST request missing Content-Type header"
    ),
    CRSRule(
        rule_id="920900", feature="get_with_body", threshold=0.5,
        severity="MEDIUM", category="Protocol Anomaly",
        message="GET request contains a non-empty body (protocol violation)"
    ),
]

# ──────────────────────────────────────────────────────────────────
# 913xxx — Scanner / Brute Force
# ──────────────────────────────────────────────────────────────────
SCANNER_RULES = [
    CRSRule(
        rule_id="913100", feature="url_has_risky_ext", threshold=0.07,
        severity="HIGH", category="Scanner",
        message="Risky file extension in URL (e.g. .php, .asp, .bak)"
    ),
    CRSRule(
        rule_id="913200", feature="method_suspicious", threshold=0.5,
        severity="HIGH", category="Scanner",
        message="Suspicious HTTP method (TRACE, CONNECT, PROPFIND, etc.)"
    ),
]

# ──────────────────────────────────────────────────────────────────
# 980xxx — Entropy / Statistical Anomaly (custom CRS extension)
# High entropy indicates obfuscated or encrypted payloads
# Threshold = 95th-percentile of normal class (no label leakage)
# ──────────────────────────────────────────────────────────────────
ENTROPY_ANOMALY_RULES = [
    CRSRule(
        rule_id="980100", feature="url_entropy", threshold=1.704,
        severity="MEDIUM", category="Entropy Anomaly",
        message="URL entropy exceeds normal 95th-percentile (obfuscation signal)"
    ),
    CRSRule(
        rule_id="980200", feature="query_entropy", threshold=1.900,
        severity="MEDIUM", category="Entropy Anomaly",
        message="Query entropy exceeds normal 95th-percentile (obfuscation signal)"
    ),
    CRSRule(
        rule_id="980300", feature="body_entropy", threshold=1.876,
        severity="MEDIUM", category="Entropy Anomaly",
        message="Body entropy exceeds normal 95th-percentile (obfuscation signal)"
    ),
]

# ──────────────────────────────────────────────────────────────────
# Master registry
# ──────────────────────────────────────────────────────────────────
ALL_RULE_GROUPS: dict = {
    "SQL Injection":    SQL_INJECTION_RULES,
    "XSS":              XSS_RULES,
    "Path Traversal":   PATH_TRAVERSAL_RULES,
    "Encoding Evasion": PROTOCOL_ANOMALY_RULES,
    "Scanner":          SCANNER_RULES,
    "Entropy Anomaly":  ENTROPY_ANOMALY_RULES,
}

ALL_RULES: list = [r for rules in ALL_RULE_GROUPS.values() for r in rules]

# Severity → anomaly score weight  (mirrors CRS default weights)
SEVERITY_WEIGHT: dict = {
    "CRITICAL": 5,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
}
