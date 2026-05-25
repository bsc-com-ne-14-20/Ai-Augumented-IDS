import os
from pathlib import Path
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from dotenv import load_dotenv

load_dotenv(dotenv_path=str(Path(__file__).parent / ".env"))

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://ids_user:ids_password@localhost:5432/aa_ids")
engine       = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base         = declarative_base()

class RequestLog(Base):
    __tablename__ = "requests"
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
    attack_type    = Column(String(50), nullable=True, index=True)
    stage          = Column(String(10), index=True)
    confidence     = Column(Float)
    crs_score      = Column(Integer)
    recommendation = Column(Text, nullable=True)

class Stats(Base):
    __tablename__ = "stats"
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

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if not db.query(Stats).first():
            db.add(Stats())
            db.commit()
    finally:
        db.close()

def update_stats(db, result: dict):
    stats = db.query(Stats).first()
    if not stats:
        stats = Stats(); db.add(stats)
    stats.total_requests += 1
    stats.last_updated    = datetime.utcnow()
    if result["verdict"] == "ATTACK":
        stats.total_attacks += 1
        t = result.get("attack_type")
        if t == "SQLI":           stats.sqli_count += 1
        elif t == "XSS":          stats.xss_count += 1
        elif t == "PATH_TRAVERSAL": stats.traversal_count += 1
        elif t == "OTHER":        stats.other_count += 1
    else:
        stats.total_normal += 1
    s = result.get("stage")
    if s == "CRS":      stats.crs_caught += 1
    elif s == "RF":     stats.rf_caught += 1
    elif s == "XGBoost": stats.xgb_classified += 1
    if result.get("is_vpn"): stats.vpn_count += 1
    db.commit()
