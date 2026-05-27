import os
import logging
import time
from pathlib import Path
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text, event, text
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.exc import OperationalError, DBAPIError
from sqlalchemy.pool import QueuePool, NullPool
from dotenv import load_dotenv

load_dotenv(dotenv_path=str(Path(__file__).parent.parent / ".env"))

logger = logging.getLogger(__name__)

# Default to SQLite for development if DATABASE_URL not set
# PostgreSQL requires psycopg2-binary to be installed
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    # Use SQLite as fallback for development
    db_path = Path(__file__).parent.parent / "ids.db"
    DATABASE_URL = f"sqlite:///{db_path}"

# Test PostgreSQL connectivity before committing to it; fall back to SQLite
_using_postgres = DATABASE_URL.startswith("postgresql") or DATABASE_URL.startswith("postgres")
if _using_postgres:
    import socket as _socket
    try:
        # Quick TCP probe to see if PostgreSQL port is reachable
        from urllib.parse import urlparse as _urlparse
        _parsed = _urlparse(DATABASE_URL)
        _host = _parsed.hostname or "localhost"
        _port = _parsed.port or 5432
        _s = _socket.create_connection((_host, _port), timeout=1)
        _s.close()
        # Port is open — now test actual authentication with a short-lived connection
        import psycopg2 as _pg2
        try:
            _conn = _pg2.connect(DATABASE_URL, connect_timeout=2)
            _conn.close()
            logger.info("PostgreSQL reachable and authenticated at %s:%s — using PostgreSQL", _host, _port)
        except Exception as _auth_exc:
            logger.warning(
                "PostgreSQL authentication failed (%s) — falling back to SQLite. "
                "Fix DATABASE_URL credentials or remove DATABASE_URL to use SQLite.",
                _auth_exc
            )
            db_path = Path(__file__).parent.parent / "ids.db"
            DATABASE_URL = f"sqlite:///{db_path}"
            _using_postgres = False
    except (OSError, Exception):
        logger.warning(
            "PostgreSQL not reachable — falling back to SQLite for this session. "
            "Set DATABASE_URL to a valid PostgreSQL URL or leave it unset to use SQLite."
        )
        db_path = Path(__file__).parent.parent / "ids.db"
        DATABASE_URL = f"sqlite:///{db_path}"
        _using_postgres = False

# Connection pool configuration
# SQLite uses NullPool (no pooling) as it doesn't support concurrent connections well
# PostgreSQL uses QueuePool with connection pooling
is_sqlite = DATABASE_URL.startswith("sqlite")
pool_class = NullPool if is_sqlite else QueuePool

# Engine configuration with connection pooling and health checks
engine_config = {
    "pool_pre_ping": True,  # Test connections before using them
    "pool_recycle": 3600,   # Recycle connections after 1 hour
    "echo": False,          # Set to True for SQL query logging
}

# Add pooling configuration for non-SQLite databases
if not is_sqlite:
    engine_config.update({
        "poolclass": QueuePool,
        "pool_size": 10,           # Number of connections to maintain
        "max_overflow": 20,        # Additional connections when pool is full
        "pool_timeout": 30,        # Timeout for getting connection from pool
    })
else:
    engine_config["poolclass"] = NullPool

engine       = create_engine(DATABASE_URL, **engine_config)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base         = declarative_base()

# Connection retry configuration
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds

# Connection pool event listeners for monitoring
@event.listens_for(engine, "connect")
def receive_connect(dbapi_conn, connection_record):
    """Log successful database connections."""
    logger.debug("Database connection established")

@event.listens_for(engine, "checkout")
def receive_checkout(dbapi_conn, connection_record, connection_proxy):
    """Log connection checkout from pool."""
    logger.debug("Connection checked out from pool")

@event.listens_for(engine, "checkin")
def receive_checkin(dbapi_conn, connection_record):
    """Log connection return to pool."""
    logger.debug("Connection returned to pool")

class Alert(Base):
    """
    Alert model for storing detection results.
    Satisfies Requirements 8.2, 8.3: Stores timestamp, method, URL, source IP,
    verdict, attack type, confidence, rule_id, and geolocation data.
    """
    __tablename__ = "alerts"
    id             = Column(Integer, primary_key=True, index=True)
    timestamp      = Column(DateTime, default=datetime.utcnow, index=True)
    method         = Column(String(10))
    url            = Column(Text)
    source_ip      = Column(String(50))
    country        = Column(String(100), nullable=True)
    city           = Column(String(100), nullable=True)
    latitude       = Column(Float, nullable=True)
    longitude      = Column(Float, nullable=True)
    isp            = Column(String(200), nullable=True)
    is_vpn         = Column(Boolean, default=False)
    is_proxy       = Column(Boolean, default=False)
    is_tor         = Column(Boolean, default=False)
    verdict        = Column(String(10), index=True)
    attack_type    = Column(String(100), nullable=True, index=True)  # CHANGED: String(100) to support XGBoost multi-class labels (SQLI/XSS/PATH_TRAVERSAL/OTHER)
    rule_id        = Column(String(50), nullable=True, index=True)  # Matched rule ID for signature-based detections
    stage          = Column(String(10), index=True)
    confidence     = Column(Float)
    crs_score      = Column(Integer)
    recommendation = Column(Text, nullable=True)

class Statistics(Base):
    """
    Statistics model for aggregate metrics.
    Satisfies Requirement 8.5: Stores aggregate statistics including total requests,
    attacks by type, and detection source breakdown.
    """
    __tablename__ = "statistics"
    id              = Column(Integer, primary_key=True)
    total_requests  = Column(Integer, default=0)
    total_attacks   = Column(Integer, default=0)
    total_normal    = Column(Integer, default=0)
    sqli_count      = Column(Integer, default=0)
    xss_count       = Column(Integer, default=0)
    traversal_count = Column(Integer, default=0)
    other_count     = Column(Integer, default=0)
    crs_caught      = Column(Integer, default=0)
    rf_caught       = Column(Integer, default=0)
    xgb_classified  = Column(Integer, default=0)
    vpn_count       = Column(Integer, default=0)
    last_updated    = Column(DateTime, default=datetime.utcnow)

def check_connection_health() -> bool:
    """
    Check if the database connection is healthy.
    
    Returns:
        bool: True if connection is healthy, False otherwise
    
    Satisfies Requirement 8.6: Connection health check function
    """
    try:
        # Execute a simple query to test connection
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.debug("Database connection health check passed")
        return True
    except (OperationalError, DBAPIError) as e:
        logger.error(f"Database connection health check failed: {e}")
        return False

def reconnect_with_retry(max_retries: int = MAX_RETRIES, delay: int = RETRY_DELAY) -> bool:
    """
    Attempt to reconnect to the database with exponential backoff.
    
    Args:
        max_retries: Maximum number of reconnection attempts
        delay: Initial delay between retries in seconds
    
    Returns:
        bool: True if reconnection successful, False otherwise
    
    Satisfies Requirement 8.7: Graceful reconnection on connection failure
    """
    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"Attempting database reconnection (attempt {attempt}/{max_retries})")
            
            # Dispose of existing connections
            engine.dispose()
            
            # Test new connection
            if check_connection_health():
                logger.info("Database reconnection successful")
                return True
                
        except Exception as e:
            logger.warning(f"Reconnection attempt {attempt} failed: {e}")
            
        if attempt < max_retries:
            wait_time = delay * (2 ** (attempt - 1))  # Exponential backoff
            logger.info(f"Waiting {wait_time} seconds before next attempt")
            time.sleep(wait_time)
    
    logger.error(f"Failed to reconnect after {max_retries} attempts")
    return False

def get_db():
    """
    Get a database session with automatic reconnection on failure.
    
    Yields:
        Session: SQLAlchemy database session
    
    Satisfies Requirement 8.7: Graceful reconnection on connection failure
    """
    db = None
    try:
        db = SessionLocal()
        yield db
    except (OperationalError, DBAPIError) as e:
        logger.error(f"Database operation failed: {e}")
        # Attempt reconnection
        if reconnect_with_retry():
            # Retry with new connection
            if db:
                db.close()
            db = SessionLocal()
            yield db
        else:
            raise
    finally:
        if db:
            db.close()

def init_db():
    """
    Initialize database tables and seed initial data.
    Creates tables on first startup and ensures Statistics table has initial row.
    
    Satisfies Requirements 8.6, 8.7: Table creation on first startup with connection management
    """
    try:
        logger.info("Initializing database...")
        
        # Check connection health before initialization
        if not check_connection_health():
            logger.warning("Database connection unhealthy, attempting reconnection")
            if not reconnect_with_retry():
                raise RuntimeError("Failed to establish database connection during initialization")
        
        # Create all tables
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
        
        # Seed initial statistics row
        db = SessionLocal()
        try:
            if not db.query(Statistics).first():
                db.add(Statistics())
                db.commit()
                logger.info("Initial statistics row created")
            else:
                logger.debug("Statistics row already exists")
        finally:
            db.close()
            
        logger.info("Database initialization complete")
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise

def update_stats(db, result: dict):
    """
    Update aggregate statistics based on detection result.
    
    Satisfies Requirement 8.5: Updates total requests, attack counts by type,
    detection source breakdown, and aggregate statistics table.
    
    Parameters
    ----------
    db : Session
        Database session
    result : dict
        Detection result containing:
        - verdict: str (ATTACK, ANOMALY, CLEAN, ERROR)
        - attack_type: str | None
        - stage: str | None (detection source: RULE or ML)
        - is_vpn: bool
    """
    stats = db.query(Statistics).first()
    if not stats:
        stats = Statistics()
        db.add(stats)
        db.flush()  # Ensure defaults are applied before incrementing
    
    # Update total request count
    stats.total_requests += 1
    stats.last_updated = datetime.utcnow()
    
    # Update attack/normal counts based on verdict
    # Both ATTACK and ANOMALY verdicts are considered attacks
    if result["verdict"] in ("ATTACK", "ANOMALY"):
        stats.total_attacks += 1

        # Update attack counts by type.
        # Rule engine returns:  SQL_INJECTION, XSS, PATH_TRAVERSAL, CRLF_INJECTION, BRUTE_FORCE
        # ML engine (XGBoost):  SQLI, XSS, PATH_TRAVERSAL, OTHER
        # Both sources are mapped to the same statistics columns where possible.
        attack_type = result.get("attack_type")
        if attack_type:
            if attack_type in ("SQLI", "SQL_INJECTION"):
                stats.sqli_count += 1
            elif attack_type == "XSS":
                stats.xss_count += 1
            elif attack_type in ("PATH_TRAVERSAL",):
                stats.traversal_count += 1
            else:
                # CRLF_INJECTION, BRUTE_FORCE, OTHER, and any future XGBoost classes
                stats.other_count += 1
    else:
        # CLEAN and ERROR verdicts are counted as normal
        stats.total_normal += 1
    
    # Update detection source breakdown
    detection_source = result.get("stage")
    if detection_source == "RULE":
        stats.crs_caught += 1  # Rule engine detections
    elif detection_source == "ML":
        stats.rf_caught += 1   # ML engine detections (RF layer)
        # Also increment xgb_classified when XGBoost classified the attack type
        if result.get("attack_type") and result.get("verdict") == "ANOMALY":
            stats.xgb_classified += 1
    
    # Update VPN count
    if result.get("is_vpn"):
        stats.vpn_count += 1
    
    db.commit()
