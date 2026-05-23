# AA-IDS: AI-Augmented HTTP Anomaly Intrusion Detection System

**University of Malawi | COM422 ICT Project | May 2026**

A lightweight, application-layer intrusion detection system targeting web applications operated by Small and Medium-sized Enterprises (SMEs) in Malawi.

## System Architecture

The AA-IDS uses a hybrid detection approach:

1. **Rule-Based Engine** — Signature-based detection for known attack patterns (SQLi, XSS, Path Traversal, CRLF Injection, Brute Force)
2. **ML Detection Engine** — Random Forest + XGBoost stacked ensemble for anomaly detection
3. **Sequential Pipeline** — Rule engine runs first; ML engine only evaluates requests that pass rule checks

## Project Structure

```
.
├── backend/                    # Core detection system
│   ├── api/                    # REST API endpoints
│   │   ├── routes.py          # Flask routes
│   │   └── schemas.py         # Request validation
│   ├── engines/               # Detection engines
│   │   ├── rule_engine.py     # Rule-based detection
│   │   ├── rules.json         # Attack signature rules
│   │   ├── ml_adapter.py      # ML model adapter
│   │   └── README.md          # Rule engine documentation
│   ├── pipeline/              # Detection pipeline
│   │   ├── orchestrator.py    # Pipeline coordinator
│   │   └── preprocessor.py    # Feature extraction
│   ├── sockets/               # WebSocket handlers
│   │   └── events.py          # Real-time alert emission
│   └── tests/                 # Test suite
│       ├── test_rule_engine.py
│       └── test_api.py
├── data/                      # Datasets (CSIC 2010, CICIDS 2017)
├── models/                    # Trained ML models
├── app.py                     # Flask application factory
├── config.py                  # Configuration management
├── .env.example               # Environment variables template
└── requirements.txt           # Python dependencies
```

## Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd aa-ids
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env and set:
# - IDS_API_KEY (32+ character random string)
# - FLASK_SECRET_KEY
# - Model paths (if different from defaults)
```

### 3. Run Locally

```bash
python app.py
```

The server starts on `http://localhost:5000`

### 4. Test the System

```bash
# Run all tests
pytest backend/tests/ -v

# Run specific test module
pytest backend/tests/test_rule_engine.py -v

# Run with coverage
pytest backend/tests/ --cov=backend --cov-report=html
```

## API Endpoints

### Health Check
```bash
GET /api/v1/health
```

Returns system status and engine readiness.

### Analyze HTTP Requests
```bash
POST /api/v1/analyse
Headers: X-IDS-Key: <your-api-key>
Content-Type: application/json

{
  "logs": [
    {
      "method": "GET",
      "url": "/search?q=test",
      "path": "/search",
      "query_string": "q=test",
      "headers": {},
      "body": "",
      "response_code": 200,
      "content_length": 0,
      "timestamp": "2026-05-23T10:00:00Z"
    }
  ]
}
```

### Get Alerts
```bash
GET /api/v1/alerts?page=1&limit=50&attack_type=SQL_INJECTION
```

### Get Statistics
```bash
GET /api/v1/stats
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `IDS_API_KEY` | Shared API key for authentication | `dev-api-key-change-in-production` |
| `FLASK_SECRET_KEY` | Flask session secret | `aa-ids-dev-secret-change-in-production` |
| `ML_MODEL_PATH` | Path to trained ML model | `models/rf_model.joblib` |
| `ML_SCALER_PATH` | Path to feature scaler | `data/final/scaler.pkl` |
| `ML_FEATURE_NAMES_PATH` | Path to feature names | `data/final/feature_names.txt` |
| `ML_CONFIDENCE_THRESHOLD` | ML detection threshold | `0.65` |
| `RULE_ENGINE_THRESHOLD` | Rule engine anomaly score threshold | `5` |
| `BF_REQUEST_THRESHOLD` | Brute force request count threshold | `10` |
| `BF_TIME_WINDOW_SECONDS` | Brute force time window | `60` |
| `SOCKETIO_CORS_ORIGINS` | Allowed CORS origins | `*` |

## Detection Rules

Rules are defined in `backend/engines/rules.json`. Each rule has:

- **id**: Unique identifier (e.g., `SQLI-001`)
- **name**: Human-readable description
- **category**: Attack classification
- **pattern**: Regular expression pattern
- **fields**: Request fields to check
- **severity**: Alert severity level

See `backend/engines/README.md` for detailed rule documentation.

## Adding New Rules

1. Open `backend/engines/rules.json`
2. Add a new rule object:
```json
{
  "id": "CUSTOM-001",
  "name": "Custom Attack Pattern",
  "category": "CUSTOM_ATTACK",
  "pattern": "your-regex-pattern",
  "fields": ["query_string", "body"],
  "severity": "high"
}
```
3. Restart the Flask server

## ML Model Integration

The ML adapter (`backend/engines/ml_adapter.py`) currently runs in graceful degradation mode if models are unavailable. To integrate trained models:

1. Train models using `scripts/train_and_save_model.py`
2. Place model files in `models/` directory
3. Update paths in `.env`
4. Restart the server

The system will automatically detect and load the models.

## Deployment

### DigitalOcean (Flask Backend)

```bash
# Install dependencies
pip install -r requirements.txt gunicorn eventlet

# Run with gunicorn
gunicorn -k eventlet -w 1 -b 0.0.0.0:5000 "app:create_app()"
```

### Environment Setup

Set environment variables on the server:
```bash
export IDS_API_KEY="your-32-char-random-key"
export FLASK_SECRET_KEY="your-flask-secret"
export SOCKETIO_CORS_ORIGINS="https://your-dashboard-domain.com"
```

## Testing

The test suite covers:

- **Rule Engine**: All attack types, URL decoding, brute force detection
- **API Endpoints**: Authentication, validation, error handling
- **Feature Extraction**: 53-feature vector generation
- **Pipeline**: End-to-end detection flow

Run tests before merging to main:
```bash
pytest backend/tests/ -v --cov=backend
```

## SRS Compliance

This implementation satisfies all requirements in the Software Requirements Specification v1.0:

- **Section 4.3**: Rule-Based Detection Engine (RE-001 through RE-006)
- **Section 4.4**: ML Detection Engine (ML-001 through ML-007)
- **Section 4.6**: Flask IDS Backend (FL-001 through FL-005)
- **Section 7.1**: Integration Requirements
- **Section 8.1**: Unit Testing Requirements

## Team

- **Project Manager**: Memory Lukhere (BSC-COM-NE-14-20)
- **Team Members**:
  - Rashid Sidreck (BSC-COM-NE-10-22)
  - Yewo Mkandawire (BSC-COM-NE-07-22)
  - Dennis Bakaya (BSC-32-22)
- **Supervisor**: Mr Martin Thodi

## License

Academic project for COM422 | University of Malawi | May 2026
