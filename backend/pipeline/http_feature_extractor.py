"""
AA-IDS Feature Extraction Pipeline
===================================

Implements Software Requirements Specification v1.0 (Section 4.2)
- FE-001: Exactly 53 numeric features
- FE-002: URL decoding for attack detection
- FE-003: Shannon entropy computation
- FE-004: Semantic handling of missing fields
- FE-005: Reproducible, JSON-serializable output
- FE-006: <50ms per request performance

"""

import numpy as np
import re
import time
from urllib.parse import unquote
from typing import Dict, List


class HTTPFeatureExtractor:
    """
    Production-grade HTTP feature extractor for AA-IDS.
    
    Extracts 53 features from raw HTTP requests for ML classification.
    
    Features:
    - 12 URL features (url_length, url_path_depth, etc.)
    - 11 Query string features (query_length, query_params, etc.)
    - 13 Body/payload features (body_length, body_entropy, etc.)
    - 4 HTTP method features (method_get, method_post, etc.)
    - 13 Header features (cookie, content_type, connection, etc.)
    """
    
    # ===== ATTACK PATTERN DEFINITIONS (From CSIC 2010 analysis) =====
    SQLI_PATTERN = re.compile(
        r"(\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bINSERT\b|\bDELETE\b|\bDROP\b|\bUPDATE\b|\bWHERE\b|--|;|\*|\bLIKE\b)",
        re.IGNORECASE
    )
    
    XSS_PATTERN = re.compile(
        r"(<script|javascript:|onerror=|onload=|onclick=|onmouseover=|alert\(|document\.cookie|eval\(|innerHTML|src=|href=)",
        re.IGNORECASE
    )
    
    TRAVERSAL_PATTERN = re.compile(
        r"(\.\.\/|%2e%2e|\/etc\/passwd|\/windows\/system32|\.\.\\|\.\./|%252e%252e)",
        re.IGNORECASE
    )
    
    ENCODING_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")
    
    # Risky file extensions
    RISKY_EXTENSIONS = {'.php', '.asp', '.aspx', '.jsp', '.cgi', '.exe', '.sh', '.bat', '.cmd', '.pl', '.py'}
    
    # Feature column names (matching  training data order)
    FEATURE_COLUMNS = [
        # URL features (12)
        'url_length', 'url_path_depth', 'url_num_dots', 'url_num_special',
        'url_num_hyphens', 'url_num_underscores', 'url_num_percent', 'url_num_equal',
        'url_num_ampersand', 'url_entropy', 'url_has_risky_ext', 'url_has_double_encoding',
        # Query string features (11)
        'query_length', 'query_num_params', 'query_num_equals', 'query_num_special',
        'query_num_percent', 'query_entropy', 'query_has_sqli', 'query_has_xss',
        'query_has_traversal', 'query_has_encoding', 'query_is_empty',
        # Body/payload features (13)
        'body_length', 'body_entropy', 'body_num_params', 'body_num_special',
        'body_num_percent', 'body_num_quotes', 'body_num_semicolons', 'body_num_brackets',
        'body_has_sqli', 'body_has_xss', 'body_has_traversal', 'body_has_encoding',
        'body_is_empty',
        # HTTP method features (4)
        'method_get', 'method_post', 'method_put', 'method_suspicious',
        # Header features (13)
        'cookie_length', 'cookie_has_sqli', 'cookie_has_xss', 'cookie_is_present',
        'content_type_is_form', 'content_type_is_json', 'content_type_is_none',
        'connection_is_close', 'connection_keep_alive', 'post_no_content_type',
        'get_with_body', 'post_empty_body', 'content_length_mismatch'
    ]
    
    def __init__(self, verbose=False):
        """Initialize feature extractor."""
        self.verbose = verbose
        self.extraction_times = []
        
        # Validating feature count
        if len(self.FEATURE_COLUMNS) != 53:
            raise ValueError(f"Expected 53 features, got {len(self.FEATURE_COLUMNS)}")
    
    # UTILITY FUNCTIONS
    
    @staticmethod
    def calculate_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s or len(s) == 0:
            return 0.0
        
        probs = [s.count(c) / len(s) for c in set(s)]
        entropy = -sum(p * np.log2(p) for p in probs if p > 0)
        
        return round(float(entropy), 4)
    
    @staticmethod
    def safe_decode(s: str) -> str:
        """Safely decode URL-encoded strings (FE-002)."""
        if not s:
            return ""
        
        try:
            decoded = s
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
            return s
    
    @staticmethod
    def has_pattern(text: str, pattern: re.Pattern) -> bool:
        """Check if text contains a dangerous pattern."""
        if not text:
            return False
        return bool(pattern.search(text))
    
    #FEATURE EXTRACTION FUNCTIONS
    
    def extract_url_features(self, url: str) -> Dict[str, float]:
        """Extracts 12 URL features."""
        features = {}
        
        if not url:
            url = "/"
        url = str(url).strip()
        url_decoded = self.safe_decode(url)
        
        features['url_length'] = len(url)
        features['url_path_depth'] = url.count('/')
        features['url_num_dots'] = url.count('.')
        features['url_num_special'] = len(re.findall(r'[<>\'";(){}\[\]]', url))
        features['url_num_hyphens'] = url.count('-')
        features['url_num_underscores'] = url.count('_')
        features['url_num_percent'] = url.count('%')
        features['url_num_equal'] = url.count('=')
        features['url_num_ampersand'] = url.count('&')
        features['url_entropy'] = self.calculate_entropy(url)
        features['url_has_risky_ext'] = float(
            any(url_decoded.lower().endswith(ext) for ext in self.RISKY_EXTENSIONS)
        )
        features['url_has_double_encoding'] = float('%25' in url.lower())
        
        return features
    
    def extract_query_features(self, query_string: str) -> Dict[str, float]:
        """Extracts 11 query string features."""
        features = {}
        
        if not query_string:
            query_string = ""
        query_string = str(query_string).strip()
        query_decoded = self.safe_decode(query_string)
        
        features['query_length'] = len(query_string)
        features['query_num_params'] = query_string.count('=')
        features['query_num_equals'] = query_string.count('=')
        features['query_num_special'] = len(re.findall(r'[<>\'";(){}\[\]]', query_string))
        features['query_num_percent'] = query_string.count('%')
        features['query_entropy'] = self.calculate_entropy(query_string)
        features['query_has_sqli'] = float(self.has_pattern(query_decoded, self.SQLI_PATTERN))
        features['query_has_xss'] = float(self.has_pattern(query_decoded, self.XSS_PATTERN))
        features['query_has_traversal'] = float(self.has_pattern(query_decoded, self.TRAVERSAL_PATTERN))
        features['query_has_encoding'] = float(bool(self.ENCODING_PATTERN.search(query_string)))
        features['query_is_empty'] = float(query_string == "")
        
        return features
    
    def extract_body_features(self, body: str) -> Dict[str, float]:
        """Extract 13s body/payload features."""
        features = {}
        
        if not body:
            body = ""
        body = str(body).strip()
        body_decoded = self.safe_decode(body)
        
        features['body_length'] = len(body)
        features['body_entropy'] = self.calculate_entropy(body)
        features['body_num_params'] = body.count('=')
        features['body_num_special'] = len(re.findall(r'[<>\'";(){}\[\]]', body))
        features['body_num_percent'] = body.count('%')
        features['body_num_quotes'] = body.count('"') + body.count("'")
        features['body_num_semicolons'] = body.count(';')
        features['body_num_brackets'] = body.count('[') + body.count(']') + body.count('{') + body.count('}')
        features['body_has_sqli'] = float(self.has_pattern(body_decoded, self.SQLI_PATTERN))
        features['body_has_xss'] = float(self.has_pattern(body_decoded, self.XSS_PATTERN))
        features['body_has_traversal'] = float(self.has_pattern(body_decoded, self.TRAVERSAL_PATTERN))
        features['body_has_encoding'] = float(bool(self.ENCODING_PATTERN.search(body)))
        features['body_is_empty'] = float(body == "")
        
        return features
    
    def extract_method_features(self, method: str) -> Dict[str, float]:
        """Extracts 4 HTTP method features."""
        features = {}
        
        method = str(method).strip().upper()
        
        features['method_get'] = float(method == 'GET')
        features['method_post'] = float(method == 'POST')
        features['method_put'] = float(method == 'PUT')
        features['method_suspicious'] = float(method in ['DELETE', 'TRACE', 'CONNECT', 'PATCH'])
        
        return features
    
    @staticmethod
    def _normalise_headers(headers: Dict) -> Dict[str, str]:
        """
        Normalise HTTP header keys to lowercase with underscores.

        Handles all casing variants sent by different clients:
          'Content-Type'  → 'content_type'
          'content-type'  → 'content_type'
          'content_type'  → 'content_type'  (already normalised)
          'Cookie'        → 'cookie'
          'HTTP_COOKIE'   → 'http_cookie'   (Django META format)

        SRS Requirement: FE-004 (graceful handling of missing/variant fields)
        Called at the start of extract_header_features() before any header access.
        """
        if not headers:
            return {}
        normalised = {}
        for k, v in headers.items():
            key = str(k).lower().replace("-", "_").replace(" ", "_")
            normalised[key] = str(v) if v is not None else ""
        return normalised

    def extract_header_features(self, headers: Dict, method: str, body: str, content_length: int) -> Dict[str, float]:
        """Extracts 13 header/context features."""
        features = {}

        # Normalise header keys before any access (handles Title-Case, hyphen, underscore variants)
        headers = self._normalise_headers(headers)

        # FE-004: Semantic defaults for missing fields
        cookie = headers.get('cookie', 'none') if headers else 'none'
        cookie = str(cookie).strip() if cookie else 'none'
        if not cookie or cookie.lower() == 'missing':
            cookie = 'none'

        # Accept both 'content_type' and 'content-type' (already normalised above)
        content_type = headers.get('content_type', 'none') if headers else 'none'
        content_type = str(content_type).strip() if content_type else 'none'
        if not content_type or content_type.lower() == 'missing':
            content_type = 'none'

        connection = headers.get('connection', 'keep-alive') if headers else 'keep-alive'
        connection = str(connection).strip().lower() if connection else 'keep-alive'
        
        method = str(method).strip().upper()
        body = str(body).strip() if body else ""
        
        # Cookie features
        features['cookie_length'] = len(cookie) if cookie != 'none' else 0
        features['cookie_has_sqli'] = float(self.has_pattern(cookie, self.SQLI_PATTERN))
        features['cookie_has_xss'] = float(self.has_pattern(cookie, self.XSS_PATTERN))
        features['cookie_is_present'] = float(cookie != 'none')
        
        # Content-Type features
        features['content_type_is_form'] = float('form' in content_type.lower())
        features['content_type_is_json'] = float('json' in content_type.lower())
        features['content_type_is_none'] = float(content_type == 'none')
        
        # Connection features
        features['connection_is_close'] = float('close' in connection.lower())
        features['connection_keep_alive'] = float('keep-alive' in connection.lower())
        
        # Anomaly features
        features['post_no_content_type'] = float(method == 'POST' and content_type == 'none')
        features['get_with_body'] = float(method == 'GET' and len(body) > 0)
        features['post_empty_body'] = float(method == 'POST' and len(body) == 0)
        features['content_length_mismatch'] = float(len(body) != content_length)
        
        return features
    
    #  MAIN EXTRACTION FUNCTION 
    
    def extract_features(self, http_request: Dict) -> Dict[str, float]:
        """
        Extract all 53 features from HTTP request.
        
        Implements FE-001 through FE-006 requirements.
        
        Args:
            http_request: Dictionary with HTTP request data
            
        Returns:
            Dictionary with exactly 53 numeric features
        """
        
        start_time = time.time()
        
        if not isinstance(http_request, dict):
            raise TypeError("http_request must be a dictionary")
        
        # Extract fields
        url = http_request.get('url', '/') or '/'
        method = http_request.get('method', 'GET') or 'GET'
        query_string = http_request.get('query_string', '') or ''
        body = http_request.get('body', '') or ''
        headers = http_request.get('headers', {}) or {}
        content_length = int(http_request.get('content_length', len(body)) or len(body))
        
        if not isinstance(headers, dict):
            headers = {}
        
        # Extract feature groups
        features = {}
        features.update(self.extract_url_features(url))
        features.update(self.extract_query_features(query_string))
        features.update(self.extract_body_features(body))
        features.update(self.extract_method_features(method))
        features.update(self.extract_header_features(headers, method, body, content_length))
        
        # Validate
        if len(features) != 53:
            raise ValueError(f"Expected 53 features, got {len(features)}")
        
        # FE-004: Ensure all numeric, no NaN/Inf
        ordered_features = {}
        for col in self.FEATURE_COLUMNS:
            value = features.get(col, 0.0)
            
            if isinstance(value, (int, float)):
                if np.isnan(value) or np.isinf(value):
                    value = 0.0
            
            ordered_features[col] = float(value)
        
        # FE-006: Track performance
        elapsed_ms = (time.time() - start_time) * 1000
        self.extraction_times.append(elapsed_ms)
        
        if self.verbose and elapsed_ms > 50:
            print(f"⚠️  WARNING: Feature extraction took {elapsed_ms:.2f}ms (target: <50ms)")
        
        return ordered_features
    
    def extract_features_batch(self, requests: List[Dict]) -> List[Dict[str, float]]:
        """Extract features from multiple requests."""
        return [self.extract_features(req) for req in requests]
    
    def get_performance_stats(self) -> Dict:
        """Get performance statistics."""
        if not self.extraction_times:
            return {}
        
        times = np.array(self.extraction_times)
        return {
            'mean_ms': float(np.mean(times)),
            'median_ms': float(np.median(times)),
            'min_ms': float(np.min(times)),
            'max_ms': float(np.max(times)),
            'p95_ms': float(np.percentile(times, 95)),
            'p99_ms': float(np.percentile(times, 99)),
            'total_extractions': len(times),
        }


# Global instance
_extractor = HTTPFeatureExtractor()

def extract_http_features(http_request: Dict) -> Dict[str, float]:
    """Convenience function for Flask integration."""
    return _extractor.extract_features(http_request)

def get_extractor() -> HTTPFeatureExtractor:
    """Get global extractor instance."""
    return _extractor


if __name__ == "__main__":
    print("AA-IDS Feature Extraction Pipeline - Test Suite")
    print("="*80)
    
    extractor = HTTPFeatureExtractor(verbose=True)
    
    # Test 1: Normal GET
    print("\n[Test 1] Normal GET request")
    normal_get = {
        'url': '/index.html',
        'method': 'GET',
        'query_string': '',
        'body': '',
        'headers': {'accept': 'text/html'},
        'content_length': 0,
    }
    features = extractor.extract_features(normal_get)
    print(f"✓ {len(features)} features extracted")
    
    # Test 2: SQL injection
    print("\n[Test 2] SQL injection (encoded)")
    sqli = {
        'url': '/search',
        'method': 'GET',
        'query_string': "q=test%27%20OR%20%271%27%3D%271",
        'body': '',
        'headers': {},
        'content_length': 0,
    }
    features = extractor.extract_features(sqli)
    print(f"✓ query_has_sqli: {features['query_has_sqli']}")
    
    # Test 3: XSS
    print("\n[Test 3] XSS attempt")
    xss = {
        'url': '/comments',
        'method': 'POST',
        'query_string': '',
        'body': 'comment=<script>alert("xss")</script>',
        'headers': {'content-type': 'application/x-www-form-urlencoded'},
        'content_length': 35,
    }
    features = extractor.extract_features(xss)
    print(f"✓ body_has_xss: {features['body_has_xss']}")
    
    # Performance
    print("\n" + "="*80)
    stats = extractor.get_performance_stats()
    print(f"Mean: {stats['mean_ms']:.2f}ms, P99: {stats['p99_ms']:.2f}ms")
    print(f"Status: {' PASS' if stats['p99_ms'] < 50 else ' FAIL'} (<50ms target)")
    print("="*80)
