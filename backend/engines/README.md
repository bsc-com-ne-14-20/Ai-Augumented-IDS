# AA-IDS Rule Engine

## Overview

The rule engine evaluates HTTP requests against signature-based detection rules defined in `rules.json`. Rules are loaded at server startup and compiled for performance.

## Rule Schema

Each rule in `rules.json` must follow this structure:

```json
{
  "id": "RULE-NNN",
  "name": "Human-readable rule name",
  "category": "ATTACK_TYPE",
  "pattern": "regex pattern",
  "fields": ["field1", "field2"],
  "severity": "critical|high|medium|low"
}
```

### Fields

- **id** (required): Unique identifier (e.g., `SQLI-001`, `XSS-002`)
- **name** (required): Human-readable description
- **category** (required): Attack classification (used as `attack_type` in API response)
- **pattern** (required for regex rules): Regular expression pattern (Python `re` syntax)
- **fields** (required): List of request fields to check against the pattern
- **severity** (required): Severity level for alerting

### Supported Fields

The rule engine can check these request fields:

- `url` — Full URL including path and query string
- `query_string` — Query parameters only
- `body` — Request body/payload
- `cookie` — Cookie header value
- `headers` — All headers (as string representation)

### Attack Categories

Standard categories (used in `category` field):

- `SQL_INJECTION` — SQL injection attacks
- `XSS` — Cross-site scripting
- `PATH_TRAVERSAL` — Directory traversal attacks
- `CRLF_INJECTION` — HTTP response splitting
- `BRUTE_FORCE` — Brute force login attempts (handled by counter, not regex)

## Adding New Rules

1. Open `rules.json`
2. Add a new rule object to the `rules` array
3. Assign a unique ID following the pattern `CATEGORY-NNN`
4. Write a regex pattern using Python `re` syntax
5. Specify which fields to check
6. Set appropriate severity level
7. Restart the Flask server to load the new rule

### Example: Adding a Command Injection Rule

```json
{
  "id": "CMDi-001",
  "name": "Command Injection - Shell Metacharacters",
  "category": "COMMAND_INJECTION",
  "pattern": "(;|\\||&|`|\\$\\(|\\$\\{)",
  "fields": ["query_string", "body"],
  "severity": "critical"
}
```

## Brute Force Detection

Brute force detection (rule `BF-001`) is handled separately via an in-memory per-IP counter, not by regex matching. Configuration:

- `BF_REQUEST_THRESHOLD` — Number of requests to trigger alert (default: 10)
- `BF_TIME_WINDOW_SECONDS` — Time window in seconds (default: 60)

The counter tracks POST requests to paths containing `/login`.

## URL Decoding

The rule engine automatically URL-decodes all fields up to 3 layers deep before pattern matching. This detects encoded attack payloads like:

- `%27%20OR%20%271` → `' OR '1`
- `%253Cscript%253E` → `<script>` (double-encoded)

## Performance

- Rules are compiled at server startup (not per-request)
- Evaluation short-circuits on first match
- Typical evaluation time: <5ms per request

## Testing Rules

Use the test suite to verify rule behavior:

```bash
pytest backend/tests/test_rule_engine.py -v
```

## SRS Requirements

This implementation satisfies:

- **RE-001**: Attack coverage (SQLi, XSS, Path Traversal, CRLF, Brute Force)
- **RE-002**: Rule identifiers and metadata
- **RE-003**: Short-circuit on first match
- **RE-004**: Clean pass-through when no match
- **RE-005**: External rule definitions
- **RE-006**: Brute force per-IP counter
