"""
Test suite for rule-based detection engine.

SRS Requirements: Section 8.1 (Unit Testing - Rule Engine)
- Test each rule type independently with known attack payloads
- Test clean requests return is_attack=False
- Verify correct attack_type and matched_rule ID
"""

import pytest
from backend.engines.rule_engine import evaluate, is_rule_engine_loaded


class TestRuleEngineLoading:
    """Test rule engine initialization."""
    
    def test_rules_loaded(self):
        """Verify rules were loaded successfully."""
        assert is_rule_engine_loaded() is True


class TestSQLInjectionDetection:
    """Test SQL injection rule detection."""
    
    def test_sqli_union_select_in_query(self):
        """SRS RE-001: Detect UNION SELECT in query string."""
        request = {
            "method": "GET",
            "url": "/search?q=test' UNION SELECT * FROM users--",
            "path": "/search",
            "query_string": "q=test' UNION SELECT * FROM users--",
            "body": "",
            "headers": {},
            "source_ip": "192.168.1.100"
        }
        features = {}
        
        result = evaluate(request, features)
        
        assert result["is_attack"] is True
        assert result["detection_source"] == "rule_engine"
        assert result["attack_type"] == "SQL_INJECTION"
        assert result["matched_rule"] == "SQLI-001"
        assert result["confidence"] is None
    
    def test_sqli_or_1_equals_1(self):
        """SRS RE-001: Detect OR 1=1 pattern."""
        request = {
            "method": "POST",
            "url": "/login",
            "path": "/login",
            "query_string": "",
            "body": "username=admin' OR '1'='1&password=test",
            "headers": {},
            "source_ip": "192.168.1.100"
        }
        features = {}
        
        result = evaluate(request, features)
        
        assert result["is_attack"] is True
        assert result["attack_type"] == "SQL_INJECTION"
        assert result["matched_rule"] == "SQLI-002"
    
    def test_sqli_comment_injection(self):
        """SRS RE-001: Detect SQL comment injection."""
        request = {
            "method": "GET",
            "url": "/user?id=1--",
            "path": "/user",
            "query_string": "id=1--",
            "body": "",
            "headers": {},
            "source_ip": "192.168.1.100"
        }
        features = {}
        
        result = evaluate(request, features)
        
        assert result["is_attack"] is True
        assert result["attack_type"] == "SQL_INJECTION"
        assert result["matched_rule"] == "SQLI-003"
    
    def test_sqli_in_cookie(self):
        """SRS RE-001: Detect SQLi in cookie header."""
        request = {
            "method": "GET",
            "url": "/dashboard",
            "path": "/dashboard",
            "query_string": "",
            "body": "",
            "headers": {"cookie": "session=abc' OR 1=1--"},
            "source_ip": "192.168.1.100"
        }
        features = {}
        
        result = evaluate(request, features)
        
        assert result["is_attack"] is True
        assert result["attack_type"] == "SQL_INJECTION"
    
    def test_sqli_url_encoded(self):
        """SRS FE-002: Detect URL-encoded SQLi payload."""
        request = {
            "method": "GET",
            "url": "/search?q=test%27%20OR%20%271%27%3D%271",
            "path": "/search",
            "query_string": "q=test%27%20OR%20%271%27%3D%271",
            "body": "",
            "headers": {},
            "source_ip": "192.168.1.100"
        }
        features = {}
        
        result = evaluate(request, features)
        
        assert result["is_attack"] is True
        assert result["attack_type"] == "SQL_INJECTION"


class TestXSSDetection:
    """Test cross-site scripting rule detection."""
    
    def test_xss_script_tag(self):
        """SRS RE-001: Detect <script> tag."""
        request = {
            "method": "POST",
            "url": "/comment",
            "path": "/comment",
            "query_string": "",
            "body": "text=<script>alert('XSS')</script>",
            "headers": {},
            "source_ip": "192.168.1.100"
        }
        features = {}
        
        result = evaluate(request, features)
        
        assert result["is_attack"] is True
        assert result["attack_type"] == "XSS"
        assert result["matched_rule"] == "XSS-001"
    
    def test_xss_event_handler(self):
        """SRS RE-001: Detect event handler injection."""
        request = {
            "method": "GET",
            "url": "/profile?name=<img src=x onerror=alert(1)>",
            "path": "/profile",
            "query_string": "name=<img src=x onerror=alert(1)>",
            "body": "",
            "headers": {},
            "source_ip": "192.168.1.100"
        }
        features = {}
        
        result = evaluate(request, features)
        
        assert result["is_attack"] is True
        assert result["attack_type"] == "XSS"
        assert result["matched_rule"] == "XSS-002"


class TestPathTraversalDetection:
    """Test path traversal rule detection."""
    
    def test_path_traversal_dot_dot_slash(self):
        """SRS RE-001: Detect ../ pattern."""
        request = {
            "method": "GET",
            "url": "/file?path=../../etc/passwd",
            "path": "/file",
            "query_string": "path=../../etc/passwd",
            "body": "",
            "headers": {},
            "source_ip": "192.168.1.100"
        }
        features = {}
        
        result = evaluate(request, features)
        
        assert result["is_attack"] is True
        assert result["attack_type"] == "PATH_TRAVERSAL"
        assert result["matched_rule"] == "PT-001"
    
    def test_path_traversal_sensitive_file(self):
        """SRS RE-001: Detect access to sensitive files."""
        request = {
            "method": "GET",
            "url": "/download?file=/etc/passwd",
            "path": "/download",
            "query_string": "file=/etc/passwd",
            "body": "",
            "headers": {},
            "source_ip": "192.168.1.100"
        }
        features = {}
        
        result = evaluate(request, features)
        
        assert result["is_attack"] is True
        assert result["attack_type"] == "PATH_TRAVERSAL"
        assert result["matched_rule"] == "PT-002"


class TestCRLFInjection:
    """Test CRLF injection detection."""
    
    def test_crlf_injection(self):
        """SRS RE-001: Detect CRLF injection."""
        request = {
            "method": "GET",
            "url": "/redirect?url=http://evil.com%0d%0aSet-Cookie:admin=true",
            "path": "/redirect",
            "query_string": "url=http://evil.com%0d%0aSet-Cookie:admin=true",
            "body": "",
            "headers": {},
            "source_ip": "192.168.1.100"
        }
        features = {}
        
        result = evaluate(request, features)
        
        assert result["is_attack"] is True
        assert result["attack_type"] == "CRLF_INJECTION"
        assert result["matched_rule"] == "CRLF-001"


class TestBruteForceDetection:
    """Test brute force detection."""
    
    def test_brute_force_threshold(self):
        """SRS RE-006: Detect brute force when threshold exceeded."""
        source_ip = "192.168.1.200"
        
        # Send requests below threshold
        for i in range(9):
            request = {
                "method": "POST",
                "url": "/login",
                "path": "/login",
                "query_string": "",
                "body": f"username=user{i}&password=test",
                "headers": {},
                "source_ip": source_ip
            }
            features = {}
            result = evaluate(request, features)
            # Should not trigger yet
            if i < 9:
                assert result["is_attack"] is False or result["attack_type"] != "BRUTE_FORCE"
        
        # 10th request should trigger
        request = {
            "method": "POST",
            "url": "/login",
            "path": "/login",
            "query_string": "",
            "body": "username=admin&password=test",
            "headers": {},
            "source_ip": source_ip
        }
        features = {}
        result = evaluate(request, features)
        
        assert result["is_attack"] is True
        assert result["attack_type"] == "BRUTE_FORCE"
        assert result["matched_rule"] == "BF-001"


class TestCleanRequests:
    """Test that clean requests pass through."""
    
    def test_clean_get_request(self):
        """SRS RE-004: Clean GET request returns is_attack=False."""
        request = {
            "method": "GET",
            "url": "/products?category=electronics",
            "path": "/products",
            "query_string": "category=electronics",
            "body": "",
            "headers": {},
            "source_ip": "192.168.1.100"
        }
        features = {}
        
        result = evaluate(request, features)
        
        assert result["is_attack"] is False
        assert result["detection_source"] == "rule_engine"
        assert result["attack_type"] is None
        assert result["matched_rule"] is None
    
    def test_clean_post_request(self):
        """SRS RE-004: Clean POST request returns is_attack=False."""
        request = {
            "method": "POST",
            "url": "/contact",
            "path": "/contact",
            "query_string": "",
            "body": "name=John&email=john@example.com&message=Hello",
            "headers": {},
            "source_ip": "192.168.1.100"
        }
        features = {}
        
        result = evaluate(request, features)
        
        assert result["is_attack"] is False


class TestShortCircuit:
    """Test that rule engine short-circuits on first match."""
    
    def test_multiple_attacks_returns_first_match(self):
        """SRS RE-003: Multiple attack patterns, returns first match only."""
        # This request contains both SQLi and XSS patterns
        request = {
            "method": "GET",
            "url": "/search?q=<script>alert(1)</script>' OR 1=1--",
            "path": "/search",
            "query_string": "q=<script>alert(1)</script>' OR 1=1--",
            "body": "",
            "headers": {},
            "source_ip": "192.168.1.100"
        }
        features = {}
        
        result = evaluate(request, features)
        
        # Should match first rule encountered (order in rules.json)
        assert result["is_attack"] is True
        assert result["matched_rule"] is not None
        # Only one rule should be returned, not multiple
