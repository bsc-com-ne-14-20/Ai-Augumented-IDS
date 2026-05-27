# Integration Audit Report
**AA-IDS Prototype v1.0 | COM422 | University of Malawi | May 2026**

---

## Middleware → Backend Contract Verification

### Actual Middleware Payload (from `ids_middleware/payload_builder.py`)

```json
{
  "method": "GET",
  "path": "/search/",
  "query_string": "q=test",
  "body": "",
  "headers": {
    "Cookie": "session=abc",
    "Content-Type": "text/html",
    "Content-Length": "0",
    "Connection": "keep-alive",
    "Accept": "text/html"
  }
}
```

Key observations:
- Uses `path` (not `url`)
- Headers use **Title-Case** keys: `Cookie`, `Content-Type`, `Content-Length`, `Connection`, `Accept`
- Auth header sent: `X-IDS-API-Key` (in `ids_client.py`)
- Endpoint: `IDS_BACKEND_URL` (env var, expected to be `http://host/api/v1/analyse`)
- Timeout: 500 ms (configurable via `IDS_TIMEOUT`)
- Async: ThreadPoolExecutor fire-and-forget (MW-004 ✅)
- Error handling: all errors logged and swallowed (MW-005 ✅)
- Sends a **single flat JSON object** — NOT wrapped in `{"logs": [...]}`

### SRS Required Payload (§3.2.1)

```json
{
  "method": "GET",
  "url": "/checkout/",
  "query_string": "item=1&qty=1",
  "body": "",
  "headers": {
    "cookie": "session=abc",
    "content_type": "text/html",
    "content_length": "0",
    "connection": "keep-alive",
    "accept": "text/html"
  }
}
```

### MATCH / MISMATCH

| Field | Middleware Sends | Backend Expects | Status |
|-------|-----------------|-----------------|--------|
| `method` | ✅ `method` | `method` | MATCH |
| `url` | ❌ sends `path` | `url` | **MISMATCH** |
| `query_string` | ✅ `query_string` | `query_string` | MATCH |
| `body` | ✅ `body` | `body` | MATCH |
| `headers.cookie` | ❌ `Cookie` (Title-Case) | `cookie` (lowercase) | **MISMATCH** |
| `headers.content_type` | ❌ `Content-Type` (hyphen) | `content_type` (underscore) | **MISMATCH** |
| `headers.content_length` | ❌ `Content-Length` (hyphen) | `content_length` (underscore) | **MISMATCH** |
| `headers.connection` | ❌ `Connection` (Title-Case) | `connection` (lowercase) | **MISMATCH** |
| `headers.accept` | ❌ `Accept` (Title-Case) | `accept` (lowercase) | **MISMATCH** |
| Auth header | ❌ `X-IDS-API-Key` | `X-IDS-Key` | **MISMATCH** |
| Payload wrapper | ❌ flat object | `{"logs": [...]}` (schema) | **MISMATCH** |

**Root cause**: The backend `AnalyzeRequestSchema` wraps entries in a `logs` array, but the middleware sends a single flat object. The `/api/v1/analyse` route must accept BOTH formats.

---

## Backend → Dashboard Contract Verification

### Actual WebSocket Event (from `backend/sockets/events.py`)

For ATTACK/ANOMALY:
```json
{
  "event": "alert",
  "data": {
    "alert_id": "uuid",
    "timestamp": "ISO8601",
    "verdict": "ATTACK",
    "detection_source": "RULE",
    "severity": "critical",
    "attack_type": "SQL_INJECTION",
    "confidence": null,
    "request_summary": {"method": "GET", "path": "/search/", "query_string": "..."},
    "rule_triggered": "SQLI-001"
  }
}
```

For CLEAN:
```json
{
  "event": "clean_request",
  "data": { ... }
}
```

### SRS Required Event (§3.2.2)

```json
{
  "request_id": "uuid-v4",
  "timestamp": "ISO8601",
  "is_attack": true,
  "method": "POST",
  "url": "/checkout/",
  "query_string": "item=1",
  "body_snippet": "...",
  "detection_source": "rule_engine",
  "attack_type": "SQLi",
  "confidence": null,
  "matched_rule": "SQLI-001"
}
```

### MATCH / MISMATCH (WebSocket)

| SRS Field | Backend Sends | Status |
|-----------|--------------|--------|
| `request_id` | `alert_id` | **MISMATCH** (different key name) |
| `is_attack` | `verdict` (ATTACK/ANOMALY/CLEAN) | **MISMATCH** (different representation) |
| `method` | inside `request_summary.method` | **MISMATCH** (nested) |
| `url` | inside `request_summary.path` | **MISMATCH** (nested + wrong key) |
| `query_string` | inside `request_summary.query_string` | **MISMATCH** (nested) |
| `body_snippet` | ❌ not sent | **MISSING** |
| `detection_source` | `detection_source` (RULE/ML) | ⚠️ values differ (RULE vs rule_engine) |
| `attack_type` | `attack_type` (SQL_INJECTION) | ⚠️ values differ (SQL_INJECTION vs SQLi) |
| `confidence` | `confidence` | MATCH |
| `matched_rule` | `rule_triggered` | **MISMATCH** (different key name) |
| CLEAN events | emitted as `clean_request` | ⚠️ dashboard only listens to `alert` |

**Dashboard actual contract** (from `dashboard_models.dart` `DetectionResult.fromJson`):
The Flutter dashboard reads: `alert_id`, `timestamp`, `verdict`, `detection_source`, `severity`, `attack_type`, `rule_triggered`, `confidence`, `affected_field`, `request_summary.method`, `request_summary.path`, `request_summary.query_string`

**The dashboard is already aligned with the BACKEND's actual format** (not the SRS format). The backend and dashboard have a working contract. The SRS format is aspirational.

### Actual REST API Response (from `backend/api/routes.py`)

`GET /api/v1/alerts` returns:
```json
{
  "alerts": [...],
  "total": 150,
  "page": 1,
  "page_size": 50
}
```

`GET /api/v1/stats` returns:
```json
{
  "total_requests": 150,
  "total_attacks": 42,
  "total_anomalies": 10,
  "total_clean": 98,
  "attack_type_breakdown": {...},
  "detection_source_split": {"RULE": 30, "ML": 12},
  ...
}
```

### Dashboard Expected Structure (from Flutter code)

`AlertsResponse.fromJson` reads: `alerts`, `total`, `page`
`MetricsData.fromJson` reads: `total_requests_analyzed`, `total_attacks_detected`, `total_anomalies_detected`, `total_clean`, `attack_type_breakdown`, `detection_source_breakdown`, `severity_breakdown`, `ml_confidence_distribution`

### MATCH / MISMATCH (REST)

| Endpoint | Issue | Status |
|----------|-------|--------|
| `GET /api/v1/alerts` | Backend returns `page_size`, dashboard reads `page` (present) | ✅ OK |
| `GET /api/v1/stats` | Dashboard calls `/api/v1/metrics` — endpoint doesn't exist | **MISSING** |
| `GET /api/v1/metrics` | Not implemented | **MISSING** |
| Stats field `total_requests` | Dashboard reads `total_requests_analyzed` | **MISMATCH** |
| Stats field `detection_source_split` | Dashboard reads `detection_source_breakdown` | **MISMATCH** |

---

## What Is Already Working

- ✅ Feature extractor: 53 features, correct order, no NaN
- ✅ Rule engine: loads from `rules.json`, short-circuits on first match
- ✅ ML adapter: loads RF model + scaler, applies z-scoring, returns verdict
- ✅ Orchestrator: correct pipeline sequence (rule → ML → clean)
- ✅ Flask app factory: CORS, SocketIO, blueprint registration
- ✅ Database: SQLAlchemy models, init_db, update_stats
- ✅ WebSocket: emit_alert works for ATTACK/ANOMALY
- ✅ API key auth: `require_api_key` decorator reads `X-IDS-Key`
- ✅ Middleware: async fire-and-forget, error handling, env config
- ✅ Dashboard: models aligned with backend's actual payload format

## What Is Broken or Missing

1. **CRITICAL**: Middleware sends `path` key; backend schema requires `url` — route rejects all middleware requests
2. **CRITICAL**: Middleware sends `X-IDS-API-Key`; backend reads `X-IDS-Key` — all middleware requests get 403
3. **CRITICAL**: Middleware sends flat object; backend schema wraps in `{"logs": [...]}` — all middleware requests get 400
4. **CRITICAL**: `sanitize_dict()` is called on the validated payload BEFORE pipeline — destroys SQLi/XSS patterns, making detection impossible
5. **MISSING**: `GET /api/v1/metrics` endpoint — dashboard calls this, gets 404
6. **MISMATCH**: `/api/v1/stats` field names don't match what dashboard reads
7. **MISMATCH**: Dashboard calls `/api/v1/analyze` (no `s`); backend registers `/api/v1/analyse` (with `s`)
8. **MISSING**: Header normalisation — `Content-Type` → `content_type` not done in feature extractor
9. **PARTIAL**: CLEAN requests not persisted to DB (persist_alert not called from route)
10. **PARTIAL**: WebSocket emits `clean_request` for CLEAN — dashboard only listens to `alert`

## Files That Need Changes

| File | Change Required |
|------|----------------|
| `backend/api/routes.py` | Accept both flat object and `{"logs":[...]}` format; accept `path` as alias for `url`; accept `X-IDS-API-Key` header; remove `sanitize_dict` from pipeline path; add `/analyze` alias; call `persist_alert` for ALL requests; add `/metrics` endpoint |
| `backend/api/schemas.py` | Make `url` optional with `path` fallback; make `response_code` and `timestamp` optional (middleware doesn't send them) |
| `backend/sockets/events.py` | Emit `alert` event for CLEAN requests too (with `is_attack: false`) |
| `backend/pipeline/http_feature_extractor.py` | Add header normalisation (Title-Case → lowercase_underscore) |
