"""
api/schemas.py
==============
Request and response validation schemas using marshmallow.

Schemas
-------
  LogEntrySchema       — validates a single HTTP log entry in the request body
  AnalyzeRequestSchema — validates the full POST /api/v1/analyze payload
"""

from marshmallow import Schema, fields, validate, ValidationError, validates_schema


class LogEntrySchema(Schema):
    """
    Schema for a single HTTP log entry submitted for analysis.

    All fields listed below are required unless noted.  Extra fields are
    silently ignored (unknown = EXCLUDE) to allow forward-compatible clients.
    """

    method = fields.Str(required=True, validate=validate.Length(min=1, max=16))
    url = fields.Str(required=True, validate=validate.Length(min=1, max=8192))
    path = fields.Str(required=True, validate=validate.Length(min=1, max=4096))
    query_string = fields.Str(load_default="")
    headers = fields.Dict(
        keys=fields.Str(),
        values=fields.Str(),
        load_default={},
    )
    body = fields.Str(load_default="")
    response_code = fields.Int(
        required=True,
        validate=validate.Range(min=100, max=599),
    )
    content_length = fields.Int(load_default=0)
    timestamp = fields.Str(required=True, validate=validate.Length(min=1, max=64))

    class Meta:
        unknown = "EXCLUDE"  # marshmallow 3.x constant value


class AnalyzeRequestSchema(Schema):
    """
    Schema for the POST /api/v1/analyze request body.

    Validates that `logs` is a non-empty list within the per-request limit,
    and that each element is a valid LogEntrySchema.
    """

    logs = fields.List(
        fields.Nested(LogEntrySchema),
        required=True,
        validate=validate.Length(min=1, max=5000),
    )

    class Meta:
        unknown = "EXCLUDE"
