# ids_middleware — IDS Traffic Interception Middleware

Django middleware that intercepts every HTTP request and asynchronously
forwards request metadata to the AI-Augmented IDS Flask backend for analysis.

## Requirements Implemented

| ID     | Description |
|--------|-------------|
| MW-001 | Intercepts GET, POST, PUT, DELETE, HEAD |
| MW-002 | Extracts method, path, query string, body, and five headers |
| MW-003 | POSTs JSON payload to `IDS_BACKEND_URL` (`/api/v1/analyse`) |
| MW-004 | Forwarding is asynchronous via `ThreadPoolExecutor` — response never delayed |
| MW-005 | All errors logged; middleware never crashes the application |
| MW-006 | `IDS_BACKEND_URL` and `IDS_API_KEY` read from environment variables |

## Module Structure

```
ids_middleware/
├── __init__.py
├── apps.py              # Django AppConfig
├── config.py            # Environment variable loading
├── logger.py            # Named logger (ids_middleware)
├── middleware.py        # IDSMiddleware class — main entry point
├── payload_builder.py   # Request metadata extraction helpers
├── ids_client.py        # HTTP POST to IDS backend (urllib)
├── async_forwarder.py   # ThreadPoolExecutor wrapper
└── tests/
    ├── conftest.py
    ├── test_payload_builder.py
    ├── test_ids_client.py
    ├── test_async_forwarder.py
    ├── test_middleware.py
    └── test_integration.py
```

## Environment Variables

| Variable          | Required | Default | Description |
|-------------------|----------|---------|-------------|
| `IDS_BACKEND_URL` | Yes      | —       | Full URL of the IDS analyse endpoint |
| `IDS_API_KEY`     | Yes      | —       | Shared secret sent as `X-IDS-API-Key` header |
| `IDS_TIMEOUT`     | No       | `0.5`   | Max seconds to wait for IDS backend |
| `IDS_MAX_WORKERS` | No       | `4`     | Thread pool size for async forwarding |

Copy `dummy_site/django-blog-main/.env.example` to `.env` and fill in values.

## Running Tests

```bash
cd dummy_site/django-blog-main
python -m pytest
```

All 39 tests should pass.

## How It Works

1. `IDSMiddleware.__call__` is invoked for every request.
2. `payload_builder.build_payload()` extracts metadata from the Django `HttpRequest`.
3. `get_response(request)` is called — Django processes the request normally.
4. `async_forwarder.forward_async(payload)` submits `ids_client.send_to_ids` to a
   background `ThreadPoolExecutor` thread.
5. The response is returned to the client immediately — IDS forwarding happens in the background.
6. If the IDS backend is unreachable or slow, the error is logged and the user is unaffected.
