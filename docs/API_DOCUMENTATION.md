# AA-IDS API Documentation

## Authentication
All `/api/v1/analyse` endpoints require an API key to be passed in the headers.
- **Header Key**: `X-IDS-Key`
- **Header Value**: The configured API key (e.g. `dev-api-key-12345`)

## Endpoints

### 1. Analysis Endpoint
**POST** `/api/v1/analyse`

Accepts a batch of HTTP log entries, runs the detection pipeline on each, emits Socket.IO alerts for ATTACK/ANOMALY verdicts, and returns the analysis results.

**Headers**:
- `X-IDS-Key`: required
- `Content-Type`: `application/json`

**Request Body** (JSON):
```json
{
    "logs": [
        {
            "method": "POST",
            "url": "/api/login",
            "path": "/api/login",
            "query_string": "user=admin' OR '1'='1",
            "headers": {
                "User-Agent": "Mozilla/5.0",
                "Host": "localhost"
            },
            "body": "password=admin",
            "response_code": 200,
            "content_length": 14,
            "timestamp": "2026-05-26T10:00:00Z"
        }
    ]
}
```

**Response** (200 OK):
```json
{
    "summary": {
        "total_processed": 1,
        "total_clean": 0,
        "total_attacks": 1,
        "total_anomalies": 0,
        "processing_time_ms": 15,
        "average_processing_time_ms": 15,
        "individual_processing_times_ms": [15]
    },
    "results": [
        {
            "request_id": "uuid",
            "timestamp": "2026-05-26T10:00:00Z",
            "verdict": "ATTACK",
            "detection_source": "RULE",
            "attack_type": "SQLi",
            "confidence": 0.95,
            "matched_rule": "rule_001",
            "severity": "high",
            "features": {}
        }
    ]
}
```

**Example cURL**:
```bash
curl -X POST http://localhost:5000/api/v1/analyse \
  -H "X-IDS-Key: dev-api-key-12345" \
  -H "Content-Type: application/json" \
  -d '{"logs": [{"method": "GET", "url": "/index.html", "path": "/index.html", "query_string": "", "headers": {}, "body": "", "response_code": 200, "content_length": 0}]}'
```

---

### 2. Health Endpoint
**GET** `/api/v1/health`

Returns system health status and engine readiness.

**Response** (200 OK):
```json
{
    "status": "ok",
    "models_loaded": true,
    "db_connected": true,
    "rule_engine_loaded": true,
    "ml_model_loaded": true,
    "uptime_seconds": 3600
}
```

---

### 3. Alerts Endpoint
**GET** `/api/v1/alerts`

Return paginated, filterable alert history.

**Query Parameters**:
- `page`: Page number (default: 1)
- `limit`: Number of alerts per page (default: 50, max: 500)
- `attack_type`: Filter by attack type
- `source`: Filter by "RULE" or "ML"
- `is_attack`: Filter by attack status (true/false)
- `from_date`: ISO 8601 timestamp
- `to_date`: ISO 8601 timestamp

**Response** (200 OK):
```json
{
    "alerts": [
        {
            "alert_id": "uuid",
            "timestamp": "2026-05-26T10:00:00Z",
            "verdict": "ATTACK",
            "attack_type": "SQLi",
            "detection_source": "RULE"
        }
    ],
    "total": 1,
    "page": 1,
    "page_size": 50
}
```

---

### 4. Statistics Endpoint
**GET** `/api/v1/stats`

Return aggregate statistics for the session.

**Response** (200 OK):
```json
{
    "total_requests": 100,
    "total_attacks": 5,
    "total_anomalies": 2,
    "total_clean": 93,
    "attack_type_breakdown": {"SQLi": 3, "XSS": 2},
    "detection_source_split": {"RULE": 5, "ML": 2},
    "severity_breakdown": {"critical": 0, "high": 5, "medium": 2, "low": 0},
    "session_uptime_seconds": 3600
}
```
