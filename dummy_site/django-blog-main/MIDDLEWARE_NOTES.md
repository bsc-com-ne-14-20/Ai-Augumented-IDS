# Middleware Implementation Notes

## Project Structure Inspection (Commit 1)

### Django Project: `dummy_site/django-blog-main/`
- **Settings module**: `blog_page/settings.py`
- **Root URLconf**: `blog_page/urls.py`
- **Django version**: 5.2.1
- **Apps**: `feature`, `accounts`
- **Existing MIDDLEWARE list** in settings.py (8 entries)

### Middleware Placement Decision
Middleware will live in a new dedicated app: `ids_middleware/`
- Keeps IDS logic isolated from blog apps
- Follows Django convention of one-app-per-concern
- Easy to enable/disable via INSTALLED_APPS + MIDDLEWARE

### Requirements (MW-001 to MW-006)
- MW-001: Intercept GET, POST, PUT, DELETE, HEAD
- MW-002: Extract method, path, query, body, headers
- MW-003: POST to /api/v1/analyse (env var URL)
- MW-004: Async forwarding, max 500ms timeout
- MW-005: Fail-safe — log errors, never crash
- MW-006: IDS_BACKEND_URL, IDS_API_KEY from env

### Files to Create
- `ids_middleware/__init__.py`
- `ids_middleware/apps.py`
- `ids_middleware/middleware.py`
- `ids_middleware/ids_client.py`
- `ids_middleware/payload_builder.py`
- `ids_middleware/tests/`
