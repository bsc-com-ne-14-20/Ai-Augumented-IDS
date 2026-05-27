"""
Shared pytest fixtures for ids_middleware tests.
"""

import sys
import os

import django
from django.conf import settings

# Ensure the django-blog-main directory is on sys.path so package imports work.
_DJANGO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _DJANGO_ROOT not in sys.path:
    sys.path.insert(0, _DJANGO_ROOT)

# Configure Django once for the entire test session.
if not settings.configured:
    settings.configure(
        DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
        INSTALLED_APPS=["django.contrib.contenttypes", "django.contrib.auth"],
        SECRET_KEY="test-secret-key-for-ids-middleware",
    )
    django.setup()
