"""
api/validation.py
=================
Request validation utilities for AA-IDS backend API.

This module provides validation middleware and utilities for:
- Request body size limiting
- String sanitization for database insertion
- Enhanced validation decorators
- JSON schema validation
- Rate limiting support

Requirements: 19.3, 19.4, 19.5, 19.6
"""

import html
import re
import logging
import time
from functools import wraps
from typing import Any, Dict, Union, Optional
from collections import defaultdict

from flask import request, jsonify
from marshmallow import ValidationError

log = logging.getLogger(__name__)

# Maximum request body size in bytes (10 MB)
MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10 MB

# Rate limiting: 100 requests per minute per IP
RATE_LIMIT_REQUESTS = 100
RATE_LIMIT_WINDOW = 60  # seconds

# In-memory rate limiting storage (for production, use Redis)
_rate_limit_storage = defaultdict(list)

# SQL injection patterns for sanitization
SQL_INJECTION_PATTERNS = [
    r"(\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bINSERT\b|\bDELETE\b|\bDROP\b|\bUPDATE\b|\bWHERE\b)",
    r"(--|;|\*|\bLIKE\b)",
    r"(\bEXEC\b|\bDECLARE\b|\bCAST\b|\bCONVERT\b)",
    r"(\bHAVING\b|\bGROUP\s+BY\b)",
]

# XSS patterns for sanitization
XSS_PATTERNS = [
    r"(<script[^>]*>.*?</script>)",
    r"(javascript:)",
    r"(onerror=|onload=|onclick=|onmouseover=)",
    r"(alert\(|document\.cookie|window\.location)",
]

# Path traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    r"(\.\./|%2e%2e)",
    r"(/etc/passwd|/etc/shadow)",
    r"(\\\.\.\\|%5c%2e%2e%5c)",
]

# Compile patterns for performance
_SQL_PATTERN = re.compile("|".join(SQL_INJECTION_PATTERNS), re.IGNORECASE)
_XSS_PATTERN = re.compile("|".join(XSS_PATTERNS), re.IGNORECASE)
_PATH_PATTERN = re.compile("|".join(PATH_TRAVERSAL_PATTERNS), re.IGNORECASE)


def check_request_size(max_size: int = MAX_REQUEST_SIZE):
    """
    Decorator to check request body size limit.
    
    Requirements: 19.6 - Limit request body size to 10 MB
    
    Args:
        max_size: Maximum allowed request body size in bytes
        
    Returns:
        HTTP 413 if request body exceeds limit
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check Content-Length header first (most efficient)
            content_length = request.content_length
            if content_length and content_length > max_size:
                log.warning(
                    "Request body size %d bytes exceeds limit %d bytes for %s",
                    content_length, max_size, getattr(request, 'endpoint', 'unknown')
                )
                return jsonify({
                    "error": "REQUEST_TOO_LARGE",
                    "detail": f"Request body size {content_length} bytes exceeds maximum {max_size} bytes",
                }), 413
            
            # For requests without Content-Length, check actual data size
            # Use get_data() to access request data properly
            try:
                data = request.get_data()
                if len(data) > max_size:
                    log.warning(
                        "Request data size %d bytes exceeds limit %d bytes for %s",
                        len(data), max_size, getattr(request, 'endpoint', 'unknown')
                    )
                    return jsonify({
                        "error": "REQUEST_TOO_LARGE", 
                        "detail": f"Request data size {len(data)} bytes exceeds maximum {max_size} bytes",
                    }), 413
            except Exception as e:
                # If we can't read the data, log and continue
                log.debug("Could not read request data for size check: %s", e)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def rate_limit(max_requests: int = RATE_LIMIT_REQUESTS, window_seconds: int = RATE_LIMIT_WINDOW):
    """
    Rate limiting decorator for API endpoints.
    
    Requirements: 19.7 - Rate-limit API requests to 100 requests per minute per IP address
    
    Args:
        max_requests: Maximum number of requests allowed in the time window
        window_seconds: Time window in seconds
        
    Returns:
        HTTP 429 if rate limit is exceeded
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client IP address
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))
            if ',' in client_ip:
                client_ip = client_ip.split(',')[0].strip()
            
            current_time = time.time()
            
            # Clean old entries for this IP
            _rate_limit_storage[client_ip] = [
                timestamp for timestamp in _rate_limit_storage[client_ip]
                if current_time - timestamp < window_seconds
            ]
            
            # Check if rate limit is exceeded
            if len(_rate_limit_storage[client_ip]) >= max_requests:
                log.warning(
                    "Rate limit exceeded for IP %s: %d requests in %d seconds",
                    client_ip, len(_rate_limit_storage[client_ip]), window_seconds
                )
                return jsonify({
                    "error": "RATE_LIMIT_EXCEEDED",
                    "detail": f"Rate limit exceeded: {max_requests} requests per {window_seconds} seconds",
                }), 429
            
            # Add current request timestamp
            _rate_limit_storage[client_ip].append(current_time)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def validate_json_schema(schema_class):
    """
    JSON schema validation decorator using marshmallow schemas.
    
    Requirements: 19.3 - Validate JSON request bodies against schema
    Requirements: 19.4 - Return HTTP 400 with descriptive errors on validation failure
    
    Args:
        schema_class: Marshmallow schema class to validate against
        
    Returns:
        HTTP 400 if validation fails
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get JSON data from request
            try:
                json_data = request.get_json(force=True)
            except Exception as e:
                log.warning("Invalid JSON in request: %s", e)
                return jsonify({
                    "error": "VALIDATION_ERROR",
                    "detail": "Request body must be valid JSON",
                }), 400
            
            if json_data is None:
                return jsonify({
                    "error": "VALIDATION_ERROR",
                    "detail": "Request body must contain JSON data",
                }), 400
            
            # Validate against schema
            schema = schema_class()
            try:
                validated_data = schema.load(json_data)
            except ValidationError as err:
                log.warning("Schema validation failed: %s", err.messages)
                return jsonify({
                    "error": "VALIDATION_ERROR",
                    "detail": f"Schema validation failed: {err.messages}",
                }), 400
            
            # Add validated data to request context for use in the endpoint
            request.validated_json = validated_data
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator
    """
    Decorator to check request body size limit.
    
    Requirements: 19.6 - Limit request body size to 10 MB
    
    Args:
        max_size: Maximum allowed request body size in bytes
        
    Returns:
        HTTP 413 if request body exceeds limit
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check Content-Length header first (most efficient)
            content_length = request.content_length
            if content_length and content_length > max_size:
                log.warning(
                    "Request body size %d bytes exceeds limit %d bytes for %s",
                    content_length, max_size, getattr(request, 'endpoint', 'unknown')
                )
                return jsonify({
                    "error": "REQUEST_TOO_LARGE",
                    "detail": f"Request body size {content_length} bytes exceeds maximum {max_size} bytes",
                }), 413
            
            # For requests without Content-Length, check actual data size
            # Use get_data() to access request data properly
            try:
                data = request.get_data()
                if len(data) > max_size:
                    log.warning(
                        "Request data size %d bytes exceeds limit %d bytes for %s",
                        len(data), max_size, getattr(request, 'endpoint', 'unknown')
                    )
                    return jsonify({
                        "error": "REQUEST_TOO_LARGE", 
                        "detail": f"Request data size {len(data)} bytes exceeds maximum {max_size} bytes",
                    }), 413
            except Exception as e:
                # If we can't read the data, log and continue
                log.debug("Could not read request data for size check: %s", e)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def sanitize_string(value: Union[str, None], max_length: int = 8192) -> Union[str, None]:
    """
    Sanitize user-provided strings before database insertion.
    
    Requirements: 19.5 - Sanitize user-provided strings before database insertion
    
    This function:
    1. Handles None values by returning None
    2. Truncates strings to maximum length
    3. Removes/escapes SQL injection patterns
    4. Removes/escapes XSS patterns
    5. Removes/escapes path traversal patterns
    6. HTML-escapes dangerous characters (done last to preserve entities)
    
    Args:
        value: String to sanitize (can be None)
        max_length: Maximum allowed string length
        
    Returns:
        Sanitized string safe for database insertion
    """
    if value is None:
        return None
    
    if not isinstance(value, str):
        value = str(value)
    
    # Truncate to maximum length
    if len(value) > max_length:
        value = value[:max_length]
        log.debug("String truncated to %d characters", max_length)
    
    # Remove SQL injection patterns first (replace with safe equivalents)
    if _SQL_PATTERN.search(value):
        log.debug("SQL injection patterns detected and sanitized")
        value = _SQL_PATTERN.sub("[SQL_REMOVED]", value)
    
    # Remove XSS patterns
    if _XSS_PATTERN.search(value):
        log.debug("XSS patterns detected and sanitized")
        value = _XSS_PATTERN.sub("[XSS_REMOVED]", value)
    
    # Remove path traversal patterns
    if _PATH_PATTERN.search(value):
        log.debug("Path traversal patterns detected and sanitized")
        value = _PATH_PATTERN.sub("[PATH_REMOVED]", value)
    
    # HTML escape to prevent XSS (done last to preserve replacement tokens)
    value = html.escape(value, quote=True)
    
    return value


def sanitize_dict(data: Dict[str, Any], max_string_length: int = 8192) -> Dict[str, Any]:
    """
    Recursively sanitize all string values in a dictionary.
    
    Requirements: 19.5 - Sanitize user-provided strings before database insertion
    
    Args:
        data: Dictionary to sanitize
        max_string_length: Maximum length for string values
        
    Returns:
        Dictionary with all string values sanitized
    """
    if not isinstance(data, dict):
        return data
    
    sanitized = {}
    for key, value in data.items():
        # Sanitize the key itself
        clean_key = sanitize_string(key, max_length=256)  # Keys should be shorter
        
        if isinstance(value, str):
            sanitized[clean_key] = sanitize_string(value, max_string_length)
        elif isinstance(value, dict):
            sanitized[clean_key] = sanitize_dict(value, max_string_length)
        elif isinstance(value, list):
            sanitized[clean_key] = [
                sanitize_string(item, max_string_length) if isinstance(item, str)
                else sanitize_dict(item, max_string_length) if isinstance(item, dict)
                else item
                for item in value
            ]
        else:
            # Keep non-string values as-is (numbers, booleans, etc.)
            sanitized[clean_key] = value
    
    return sanitized


def validate_request_data(schema_class=None, enable_rate_limit=True):
    """
    Comprehensive request validation decorator.
    
    Combines multiple validation checks:
    - Request body size limiting
    - JSON schema validation (if schema provided)
    - String sanitization
    - Rate limiting (if enabled)
    
    Requirements: 19.3, 19.4, 19.5, 19.6, 19.7
    
    Args:
        schema_class: Optional marshmallow schema class for JSON validation
        enable_rate_limit: Whether to apply rate limiting
    """
    def decorator(f):
        @wraps(f)
        @check_request_size()
        def decorated_function(*args, **kwargs):
            # Apply rate limiting if enabled
            if enable_rate_limit:
                rate_limit_result = rate_limit()(lambda: None)()
                if rate_limit_result is not None:
                    return rate_limit_result
            
            # Apply JSON schema validation if schema provided
            if schema_class:
                schema_result = validate_json_schema(schema_class)(lambda: None)()
                if schema_result is not None:
                    return schema_result
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def get_validation_errors(data: Dict[str, Any], schema_class) -> Optional[str]:
    """
    Validate data against a schema and return error messages.
    
    Args:
        data: Data to validate
        schema_class: Marshmallow schema class
        
    Returns:
        Error message string if validation fails, None if valid
    """
    schema = schema_class()
    try:
        schema.load(data)
        return None
    except ValidationError as err:
        return str(err.messages)


def is_suspicious_request(data: Dict[str, Any]) -> bool:
    """
    Check if request data contains suspicious patterns.
    
    This is a helper function for additional security checks beyond sanitization.
    
    Args:
        data: Request data to check
        
    Returns:
        True if suspicious patterns are detected
    """
    def check_string(value: str) -> bool:
        if not isinstance(value, str):
            return False
        
        # Check for multiple attack patterns in a single string
        pattern_count = 0
        if _SQL_PATTERN.search(value):
            pattern_count += 1
        if _XSS_PATTERN.search(value):
            pattern_count += 1
        if _PATH_PATTERN.search(value):
            pattern_count += 1
        
        return pattern_count >= 2  # Multiple attack types in one string is suspicious
    
    def check_dict(d: Dict[str, Any]) -> bool:
        for key, value in d.items():
            if isinstance(value, str) and check_string(value):
                return True
            elif isinstance(value, dict) and check_dict(value):
                return True
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and check_string(item):
                        return True
                    elif isinstance(item, dict) and check_dict(item):
                        return True
        return False
    
    return check_dict(data)