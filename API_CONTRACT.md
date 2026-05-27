# AA-IDS API Contract
## Prototype v1.0 | COM422 | University of Malawi

---

## Base URL

```
http://<server>:5000/api/v1
```

---

## Authentication

All `POST /analyse` and `POST /analyze` requests require an API key header.

| Header | Value |
|--------|-------|
| `X-IDS-Key` | Your API key (matches `IDS_API_KEY` in `.env`) |
| `X-IDS-API-Key` | Alias — accepted for Django middleware compatibility |

Missing or invalid key → HTTP 403.

---

## Endpoints

### POST /api/v1/analyse (or /analyze)

Submit one or more HTTP log entries for analysis.

**Request formats:**

*Flat format (Django middleware):*
```json
{
  "method": "GET",
  "path": "/products/",
  "query_string": "id=5",
  "body": "",
  "headers": {}
}
```

*Batch format (dashboard):*
```json
{
  "logs": [
    { "method": "GET", "url": "/products/", "query_string": "id=5", "body": "", "headers": {} }
  ]
}
```

**Single-entry response:**
```json
{
  "alert_id":         "uuid-string",
  "timestamp":        "2026-05-27T10:30:00+00:00",
  "verdict":          "ATTACK | ANOMALY | CLEAN | ERROR",
  "detection_source": "RULE | ML | null",
  "severity":         "critical | high | medium | low | null",
  "attack_type":      "see table below | null",
  "rule_triggered":   "SQLI-001 | XSS-001 | ... | null",
  "confidence":       0.91,
  "affected_field":   "query_string | body | cookie | null",
  "request_summary": {
    "method":       "GET",
    "path":         "/products/",
    "url":          "/products/",
    "query_string": "id=5"
  }
}
```

---

### `attack_type` values

`attack_type` is determined by **either** the rule engine (deterministic signature
match) or XGBoost (ML classification). The ML engine now classifies specific attack
types — it is no longer limited to a generic anomaly label.

| Value | Source | Description |
|-------|--------|-------------|
| `"SQL_INJECTION"` | Rule engine | SQL injection (rule match) |
| `"XSS"` | Rule engine or ML engine | Cross-site scripting |
| `"PATH_TRAVERSAL"` | Rule engine or ML engine | Directory path traversal |
| `"CRLF_INJECTION"` | Rule engine | CRLF injection |
| `"BRUTE_FORCE"` | Rule engine | Repeated login attempts |
| `"SQLI"` | ML engine (XGBoost) | SQL injection (ML classification) |
| `"OTHER"` | ML engine (XGBoost) | Unknown/novel attack — XGBoost detected anomalous behaviour not matching SQLI, XSS, or PATH_TRAVERSAL |
| `null` | Either | Not an attack — clean request (`is_attack = false`) |

> **Note:** The ML engine uses XGBoost class labels (`SQLI`, `XSS`, `PATH_TRAVERSAL`,
> `OTHER`) which differ slightly from rule engine labels (`SQL_INJECTION`, `XSS`,
> `PATH_TRAVERSAL`). Both sources can produce `"XSS"` and `"PATH_TRAVERSAL"`.
> The dashboard must handle any string value for `attack_type` gracefully.

---

### `detection_source` values

| Value | Description |
|-------|-------------|
| `"RULE"` | Rule engine matched a signature. `attack_type` is a rule engine label. `rule_triggered` contains the rule ID. `confidence` is null. |
| `"ML"` | Stacked ML ensemble fired. `attack_type` is an XGBoost class label (`SQLI`/`XSS`/`PATH_TRAVERSAL`/`OTHER`). `confidence` is RF P(attack). `rule_triggered` is null. |
| `null` | Clean request — neither engine fired. |

---

### `verdict` values

| Value | Meaning |
|-------|---------|
| `"ATTACK"` | Rule engine detected a known attack signature |
| `"ANOMALY"` | ML stacked ensemble (RF + XGBoost) detected an attack |
| `"CLEAN"` | Neither engine fired — request appears normal |
| `"ERROR"` | Pipeline error on this entry (processing continues for remaining entries) |

---

### GET /api/v1/health

```json
{
  "status":            "ok",
  "models_loaded":     true,
  "db_connected":      true,
  "rule_engine_loaded": true,
  "ml_model_loaded":   true,
  "uptime_seconds":    3600
}
```

`models_loaded` is `true` only when **both** the Random Forest (layer 1) and
XGBoost (layer 2) models are loaded. If either fails to load, `models_loaded`
is `false` and the system operates in rule-engine-only mode.

---

### GET /api/v1/stats

```json
{
  "total_requests":        1000,
  "total_attacks":         42,
  "total_anomalies":       15,
  "total_clean":           943,
  "attack_type_breakdown": {
    "SQL_INJECTION":  12,
    "XSS":            8,
    "PATH_TRAVERSAL": 5,
    "SQLI":           9,
    "OTHER":          6,
    "BRUTE_FORCE":    2
  },
  "detection_source_split": {
    "RULE": 27,
    "ML":   15
  },
  "severity_breakdown": {
    "critical": 5,
    "high":     18,
    "medium":   22,
    "low":      12
  },
  "ml_confidence_distribution": {
    "mean": 0.82,
    "min":  0.65,
    "max":  0.99
  },
  "session_uptime_seconds": 3600
}
```

`attack_type_breakdown` is built dynamically from all verdicts seen in the
current session. It includes both rule engine types and XGBoost types. Only
types with at least one detection appear in the breakdown.

---

### GET /api/v1/alerts

Returns paginated alert history.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | int | Page number (default 1) |
| `limit` | int | Page size (default 50, max 500) |
| `verdict` | str | Filter: `ATTACK`, `ANOMALY`, `CLEAN` |
| `attack_type` | str | Filter by attack type (exact match) |
| `detection_source` | str | Filter: `RULE`, `ML` |
| `severity` | str | Filter: `critical`, `high`, `medium`, `low` |
| `from_date` | ISO 8601 | Start of time range |
| `to_date` | ISO 8601 | End of time range |

---

## ML Engine Architecture

The ML detection engine uses a **stacked ensemble**:

```
Feature Vector (53 features from FEATURE_SCHEMA.json)
        │
        ▼
┌─────────────────────┐
│  Random Forest      │  Layer 1: binary gate
│  classes_: [0, 1]   │  0 = normal, 1 = attack
│  53 features        │  Produces P(attack) as confidence
└──────────┬──────────┘
           │
           │  P(attack) < threshold → CLEAN (XGBoost not called)
           │  P(attack) ≥ threshold → XGBoost runs
           ▼
┌─────────────────────┐
│  XGBoost            │  Layer 2: attack-type classifier
│  classes_: [0,1,2,3]│  0=OTHER, 1=SQLI, 2=XSS, 3=PATH_TRAVERSAL
│  58 features        │  53 base + 5 engineered ratio/flag features
└──────────┬──────────┘
           │
           ▼
  verdict = ANOMALY
  attack_type = XGBoost predicted class label
  confidence  = RF P(attack)
  xgb_confidence = XGBoost predicted-class probability
```

**Important:** XGBoost was trained on attack samples only (no normal class).
It is only called when RF says attack. RF is the authoritative `is_attack`
decision maker. XGBoost is the authoritative `attack_type` decision maker.

---

## Error Responses

| HTTP Status | Meaning |
|-------------|---------|
| 400 | Invalid request body or missing required field |
| 403 | Missing or invalid API key |
| 413 | Request body exceeds 10 MB limit |
| 429 | Rate limit exceeded (100 req/min per IP) |
| 500 | Internal pipeline error |
