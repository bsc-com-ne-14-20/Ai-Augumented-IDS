"""
tests/conftest.py
=================
Shared pytest fixtures for the AA-IDS test suite.

Ensures the aa_ids_backend/ directory is on sys.path before any test module
imports project code — this allows `pytest tests/` to be run from the project
root without manual PYTHONPATH manipulation.
"""

import json
import pathlib
import sys

import pytest

# ── Make aa_ids_backend/ importable from the project root ────────────────────
_BACKEND_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

_FIXTURES_PATH = pathlib.Path(__file__).parent / "fixtures" / "sample_logs.json"


@pytest.fixture(scope="session")
def sample_logs() -> dict:
    """Load the sample log fixtures once per test session."""
    return json.loads(_FIXTURES_PATH.read_text())


@pytest.fixture
def client(app):
    """Flask test client produced from the app fixture."""
    with app.test_client() as c:
        yield c


@pytest.fixture
def app():
    """Create a fresh app instance for each test."""
    from app import create_app
    application = create_app()
    application.config["TESTING"] = True
    return application
