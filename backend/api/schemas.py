"""
==============================================================================
FILE: backend/api/schemas.py
COMPONENT: Request Validation Schemas
SRS REQUIREMENTS: FL-002
OWNER: Backend Team
==============================================================================

WHAT THIS FILE DOES:
    Defines marshmallow schemas for validating incoming POST /api/v1/analyse
    requests. Accepts both the SRS-defined format (url field) and the actual
    middleware format (path field, Title-Case headers, no response_code).

PIPELINE POSITION:
    Pre-Stage 1 — validates the raw HTTP request body before the orchestrator
    is invoked. Invalid requests are rejected with HTTP 400.

HOW IT IS IMPLEMENTED:
    - LogEntrySchema accepts both `url` and `path` fields (middleware sends `path`)
    - `response_code` and `timestamp` are optional (middleware doesn't send them)
    - Extra fields are silently ignored (EXCLUDE) for forward compatibility
    - AnalyzeRequestSchema accepts EITHER a `logs` array OR a flat single entry

INPUTS:
    Raw JSON body from POST /api/v1/analyse

OUTPUTS:
    Validated and normalised dict ready for the orchestrator

DEPENDENCIES (internal):
    None

INTEGRATION NOTES:
    The middleware sends: {"method", "path", "query_string", "body", "headers"}
    This schema normalises "path" → "url" so the rest of the pipeline always
    sees "url". The route handler calls schema.load() then passes the result
    directly to run_pipeline() — do NOT sanitize before the pipeline.
==============================================================================
"""

from marshmallow import Schema, fields, validate, ValidationError, validates_schema, pre_load, post_load, EXCLUDE


class LogEntrySchema(Schema):
    """
    Schema for a single HTTP log entry submitted for analysis.

    Accepts both the SRS format (url field) and the middleware format
    (path field). Extra fields are silently ignored.

    The middleware (ids_middleware/payload_builder.py) sends:
        method, path, query_string, body, headers
    It does NOT send: url, response_code, timestamp, content_length

    This schema normalises path → url so downstream code always sees url.
    """

    method = fields.Str(required=True, validate=validate.Length(min=1, max=16))

    # Accept both 'url' and 'path' — middleware sends 'path'
    url = fields.Str(load_default=None, validate=validate.Length(min=0, max=8192))
    path = fields.Str(load_default=None, validate=validate.Length(min=0, max=4096))

    query_string = fields.Str(load_default="")
    headers = fields.Dict(
        keys=fields.Str(),
        values=fields.Str(),
        load_default={},
    )
    body = fields.Str(load_default="")

    # Optional fields — middleware does not send these
    response_code = fields.Int(
        load_default=None,
        validate=validate.Range(min=100, max=599),
    )
    content_length = fields.Int(load_default=0)
    timestamp = fields.Str(load_default=None, validate=validate.Length(min=0, max=64))

    # Optional source IP for brute-force detection
    source_ip = fields.Str(load_default="unknown")

    class Meta:
        unknown = EXCLUDE

    @post_load
    def normalise_url(self, data, **kwargs):
        """
        Normalise path → url so the pipeline always sees the 'url' key.

        The middleware sends 'path'; the SRS and pipeline expect 'url'.
        If both are present, 'url' takes precedence.
        """
        if not data.get("url") and data.get("path"):
            data["url"] = data["path"]
        if not data.get("url"):
            data["url"] = "/"
        return data


class AnalyzeRequestSchema(Schema):
    """
    Schema for the POST /api/v1/analyse request body.

    Accepts TWO formats:
    1. Wrapped format (SRS): {"logs": [{...}, ...]}
    2. Flat format (middleware): {"method": "GET", "path": "/...", ...}

    Both are normalised to the wrapped format internally.
    """

    logs = fields.List(
        fields.Nested(LogEntrySchema),
        load_default=None,
        validate=validate.Length(min=1, max=5000),
    )

    # Flat format fields — present when middleware sends a single entry directly
    method = fields.Str(load_default=None)
    url = fields.Str(load_default=None)
    path = fields.Str(load_default=None)
    query_string = fields.Str(load_default=None)
    body = fields.Str(load_default=None)
    headers = fields.Dict(keys=fields.Str(), values=fields.Str(), load_default=None)
    response_code = fields.Int(load_default=None)
    content_length = fields.Int(load_default=None)
    timestamp = fields.Str(load_default=None)
    source_ip = fields.Str(load_default=None)

    class Meta:
        unknown = EXCLUDE

    @post_load
    def normalise_to_logs(self, data, **kwargs):
        """
        If the request is a flat single entry (middleware format), wrap it
        in a logs list so the rest of the pipeline always sees logs[].
        """
        if data.get("logs") is not None:
            return data

        # Flat format — build a single-entry logs list
        entry = {}
        for field_name in ("method", "url", "path", "query_string", "body",
                           "headers", "response_code", "content_length",
                           "timestamp", "source_ip"):
            val = data.get(field_name)
            if val is not None:
                entry[field_name] = val

        if not entry.get("method"):
            raise ValidationError({"method": ["Missing required field: method"]})

        # Normalise path → url
        if not entry.get("url") and entry.get("path"):
            entry["url"] = entry["path"]
        if not entry.get("url"):
            entry["url"] = "/"

        # Apply defaults for optional fields
        entry.setdefault("query_string", "")
        entry.setdefault("body", "")
        entry.setdefault("headers", {})
        entry.setdefault("content_length", 0)
        entry.setdefault("source_ip", "unknown")

        data["logs"] = [entry]
        return data
