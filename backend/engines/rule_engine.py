"""
backend/engines/rule_engine.py
===============================
Rule-based detection engine for AA-IDS.

SRS Requirements: Section 4.3 (Rule-Based Detection Engine)
- RE-001: Attack coverage (SQLi, XSS, Path Traversal, CRLF, Brute Force)
- RE-002: Rule identifiers and metadata
- RE-003: Short-circuit on first match
- RE-004: Clean pass-through when no match
- RE-005: External rule definitions (rules.json)
- RE-006: Brute force per-IP counter

Architecture
------------
The rule engine evaluates HTTP requests against signature-based rules.
It operates on raw request fields (not feature vectors) and uses URL decoding
to detect encoded attack payloads (SRS FE-002).

Rules are loaded from backend/engines/rules.json at module import time.
Brute force detection uses an in-memory per-source-IP counter.
"""

import json
import logging
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import unquote

from backend.config import get_config

log = logging.getLogger(__name__)

# ── Load rules from JSON ──────────────────────────────────────────────────────
_RULES_PATH = Path(__file__).parent / "rules.json"

if not _RULES_PATH.exists():
    raise RuntimeError(f"Rules file not found: {_RULES_PATH}")

with open(_RULES_PATH, "r") as f:
    _RULES_DATA = json.load(f)

_RULES: List[Dict[str, Any]] = _RULES_DATA["rules"]

# Compile regex patterns at load time
for rule in _RULES:
    if "pattern" in rule:
        rule["_compiled_pattern"] = re.compile(rule["pattern"])

log.info("Rule engine loaded %d rules from %s", len(_RULES), _RULES_PATH)

# ── Brute force counter (RE-006) ──────────────────────────────────────────────
# Structure: {source_ip: [(timestamp, path), ...]}
_brute_force_counter: Dict[str, List[tuple]] = defaultdict(list)

# Thresholds from config
config = get_config()
_BF_THRESHOLD = config.BF_REQUEST_THRESHOLD
_BF_WINDOW = config.BF_TIME_WINDOW_SECONDS

log.info(
    "Brute force detection: %d requests to /login within %d seconds",
    _BF_THRESHOLD,
    _BF_WINDOW,
)


def _url_decode(text: str) -> str:
    """
    Safely URL-decode a string, handling multiple encoding layers.
    
    SRS Requirement: FE-002 (URL decoding for attack detection)
    """
    if not text:
        return ""
    
    try:
        decoded = text
        # Decode up to 3 layers to catch double/triple encoding
        for _ in range(3):
            try:
                decoded_new = unquote(decoded)
                if decoded_new == decoded:
                    break
                decoded = decoded_new
            except:
                break
        return decoded
    except:
        return text


def _check_brute_force(source_ip: str, method: str, path: str) -> bool:
    """
    Check if source IP has exceeded brute force threshold.
    
    SRS Requirement: RE-006
    
    Parameters
    ----------
    source_ip : str
        Source IP address from request
    method : str
        HTTP method
    path : str
        Request path
    
    Returns
    -------
    bool
        True if brute force threshold exceeded
    """
    # Only track POST requests to login paths
    if method.upper() != "POST":
        return False
    
    if "/login" not in path.lower():
        return False
    
    now = time.time()
    
    # Add current request
    _brute_force_counter[source_ip].append((now, path))
    
    # Remove old entries outside the time window
    _brute_force_counter[source_ip] = [
        (ts, p) for ts, p in _brute_force_counter[source_ip]
        if now - ts <= _BF_WINDOW
    ]
    
    # Check threshold
    count = len(_brute_force_counter[source_ip])
    
    if count >= _BF_THRESHOLD:
        log.warning(
            "Brute force detected: IP=%s count=%d window=%ds",
            source_ip, count, _BF_WINDOW
        )
        return True
    
    return False


def evaluate(request_data: Dict[str, Any], features: Dict[str, float]) -> Dict[str, Any]:
    """
    Evaluate HTTP request against all rules.
    
    SRS Requirements: RE-001 through RE-006
    
    Parameters
    ----------
    request_data : dict
        Raw HTTP request fields:
        - method: str
        - url: str
        - path: str (optional, extracted from url if missing)
        - query_string: str
        - body: str
        - headers: dict
        - source_ip: str (optional, for brute force detection)
    
    features : dict
        53-element feature vector (not used by rule engine, but kept
        for interface compatibility with orchestrator)
    
    Returns
    -------
    dict
        SRS-compliant result:
        {
            "is_attack": bool,
            "detection_source": "rule_engine",
            "attack_type": str | None,
            "matched_rule": str | None,
            "confidence": None
        }
    """
    # Extract fields
    method = str(request_data.get("method", "GET")).upper()
    url = str(request_data.get("url", ""))
    path = str(request_data.get("path", url.split("?")[0]))
    query_string = str(request_data.get("query_string", ""))
    body = str(request_data.get("body", ""))
    headers = request_data.get("headers", {}) or {}
    source_ip = str(request_data.get("source_ip", "unknown"))
    
    # Extract cookie from headers
    cookie = ""
    for k, v in headers.items():
        if k.lower() == "cookie":
            cookie = str(v)
            break
    
    # RE-002: URL decode for evasion detection (FE-002)
    url_decoded = _url_decode(url)
    query_decoded = _url_decode(query_string)
    body_decoded = _url_decode(body)
    cookie_decoded = _url_decode(cookie)
    
    # Build field map for rule evaluation
    field_map = {
        "url": (url, url_decoded),
        "query_string": (query_string, query_decoded),
        "body": (body, body_decoded),
        "cookie": (cookie, cookie_decoded),
        "headers": (str(headers), str(headers)),  # Headers not decoded
    }
    
    # RE-006: Check brute force first
    if _check_brute_force(source_ip, method, path):
        return {
            "is_attack": True,
            "detection_source": "rule_engine",
            "attack_type": "BRUTE_FORCE",
            "matched_rule": "BF-001",
            "confidence": None,
        }
    
    # RE-003: Evaluate rules in order, short-circuit on first match
    for rule in _RULES:
        rule_id = rule["id"]
        
        # Skip brute force rule (already checked above)
        if rule_id == "BF-001":
            continue
        
        # Skip rules without patterns
        if "_compiled_pattern" not in rule:
            continue
        
        pattern = rule["_compiled_pattern"]
        fields_to_check = rule.get("fields", [])
        
        # Check each field specified by the rule
        for field_name in fields_to_check:
            if field_name not in field_map:
                continue
            
            raw_value, decoded_value = field_map[field_name]
            
            # Check both raw and decoded values
            if pattern.search(raw_value) or pattern.search(decoded_value):
                log.info(
                    "Rule match: rule=%s field=%s attack=%s",
                    rule_id, field_name, rule["category"]
                )
                
                # RE-003: Return immediately on first match
                return {
                    "is_attack": True,
                    "detection_source": "rule_engine",
                    "attack_type": rule["category"],
                    "matched_rule": rule_id,
                    "confidence": None,
                }
    
    # RE-004: No match, return clean
    return {
        "is_attack": False,
        "detection_source": "rule_engine",
        "attack_type": None,
        "matched_rule": None,
        "confidence": None,
    }


def is_rule_engine_loaded() -> bool:
    """Return True if rules were loaded successfully."""
    return len(_RULES) > 0
