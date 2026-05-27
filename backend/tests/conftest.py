"""
Pytest configuration and fixtures for AA-IDS backend tests.
"""

import sys
import pytest
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add project root to sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from backend.database import Base


@pytest.fixture(scope="function")
def db_session():
    """
    Create a test database session for each test function.
    
    Uses an in-memory SQLite database that is created fresh for each test
    and torn down after the test completes.
    """
    # Create in-memory SQLite database for testing
    engine = create_engine("sqlite:///:memory:", echo=False)
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    # Create session
    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestSessionLocal()
    
    yield session
    
    # Cleanup
    session.close()
    Base.metadata.drop_all(bind=engine)
