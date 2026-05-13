
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from dotenv import load_dotenv

load_dotenv(dotenv_path=str(Path(__file__).parent / ".env"))

# ── Add project root to path ──────────────────────────────────────
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "pipeline" / "rule_engine"))

from controller import IDSController
from api.feature_extractor import extract_features
from api.geo import get_ip_info
from api.recommender import get_recommendation
from api.schemas import AnalyzeRequest, AnalyzeResponse, StatsResponse, HistoryItem, GeoInfo
from api.database import get_db, init_db, update_stats, RequestLog, Stats

# ── App setup ─────────────────────────────────────────────────────
app = FastAPI(
    title="AA-IDS API",
    description="AI-Augmented Intrusion Detection System — REST API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Load models once at startup ───────────────────────────────────
controller = None

@app.on_event("startup")
def startup():
    global controller
    init_db()
    controller = IDSController()
    print("[API] Ready.")


# ══════════════════════════════════════════════════════════════════
# Endpoints
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
def health():
    """Check if the API and models are ready."""
    return {
        "status":  "ok",
        "models":  "loaded" if controller else "not loaded",
        "version": "1.0.0",
    }


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest, db: Session = Depends(get_db)):
    """
    Analyze an incoming HTTP request through the full IDS pipeline.

    Flow:
      1. Extract 53 features from raw request
      2. CRS Rule Engine  → ATTACK? stop.
      3. Random Forest    → NORMAL? stop.
      4. XGBoost          → classify attack type
      5. Geo + VPN lookup
      6. LLM recommendation (attacks only)
      7. Save to DB + update stats
    """
    if not controller:
        raise HTTPException(status_code=503, detail="Models not loaded yet")

    # ── 1. Extract features ───────────────────────────────────────
    features_df, features_raw_df = extract_features(request.dict())
    features     = features_df.iloc[0].to_dict()
    features_raw = features_raw_df.iloc[0].to_dict()
    # Pass raw unscaled features for XGBoost
    features['_raw'] = features_raw

    # Add raw fields CRS needs
    features["url"]          = request.url
    features["query_string"] = request.query_string or ""
    features["body"]         = request.body or ""
    features["cookie"]       = (request.headers or {}).get("cookie", "none")
    features["method"]       = request.method
    features["content_type"] = (request.headers or {}).get("content-type", "none")
    features["content_length"] = int((request.headers or {}).get("content-length", 0) or 0)

    # ── 2-4. Run controller ───────────────────────────────────────
    result = controller.predict(features)

    # ── 5. Geo lookup ─────────────────────────────────────────────
    geo = get_ip_info(request.source_ip or "127.0.0.1")

    # ── 6. LLM recommendation (attacks only) ─────────────────────
    recommendation = None
    if result["verdict"] == "ATTACK":
        recommendation = get_recommendation(result, geo)

    # ── 7. Save to DB ─────────────────────────────────────────────
    log = RequestLog(
        method         = request.method,
        url            = request.url,
        source_ip      = request.source_ip or "127.0.0.1",
        country        = geo["country"],
        city           = geo["city"],
        latitude       = geo["latitude"],
        longitude      = geo["longitude"],
        isp            = geo["isp"],
        is_vpn         = geo["is_vpn"],
        is_proxy       = geo["is_proxy"],
        is_tor         = geo["is_tor"],
        verdict        = result["verdict"],
        attack_type    = result.get("attack_type"),
        stage          = result["stage"],
        confidence     = result["confidence"],
        crs_score      = result["crs_score"],
        recommendation = recommendation,
    )
    db.add(log)
    db.commit()

    update_stats(db, {**result, "is_vpn": geo["is_vpn"]})

    return AnalyzeResponse(
        verdict        = result["verdict"],
        attack_type    = result.get("attack_type"),
        stage          = result["stage"],
        confidence     = result["confidence"],
        crs_score      = result["crs_score"],
        geo            = GeoInfo(**geo),
        recommendation = recommendation,
        timestamp      = datetime.utcnow(),
    )


@app.get("/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)):
    """Return aggregated detection statistics for the dashboard."""
    stats = db.query(Stats).first()
    if not stats:
        raise HTTPException(status_code=404, detail="No stats yet")
    return stats


@app.get("/history")
def get_history(
    page:    int = Query(default=1, ge=1),
    limit:   int = Query(default=20, ge=1, le=100),
    verdict: Optional[str] = Query(default=None),
    db:      Session = Depends(get_db),
):
    """
    Return paginated request history.
    Optional filter: ?verdict=ATTACK or ?verdict=NORMAL
    """
    query = db.query(RequestLog)
    if verdict:
        query = query.filter(RequestLog.verdict == verdict.upper())
    total  = query.count()
    items  = query.order_by(RequestLog.timestamp.desc()) \
                  .offset((page - 1) * limit) \
                  .limit(limit).all()
    return {
        "total": total,
        "page":  page,
        "limit": limit,
        "items": [HistoryItem.from_orm(i) for i in items],
    }


@app.get("/history/{request_id}")
def get_request_detail(request_id: int, db: Session = Depends(get_db)):
    """Get full detail of a single analyzed request including recommendation."""
    log = db.query(RequestLog).filter(RequestLog.id == request_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Request not found")
    return log


@app.get("/recommend/{request_id}")
def get_recommendation_endpoint(request_id: int, db: Session = Depends(get_db)):
    """
    Fetch or regenerate LLM recommendation for a specific request.
    Useful if the dashboard wants on-demand recommendations.
    """
    log = db.query(RequestLog).filter(RequestLog.id == request_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Request not found")
    if log.verdict == "NORMAL":
        return {"recommendation": "No recommendation needed for normal traffic."}
    if log.recommendation:
        return {"recommendation": log.recommendation}

    geo = {
        "country": log.country, "city": log.city,
        "isp": log.isp, "is_vpn": log.is_vpn,
    }
    result = {
        "attack_type": log.attack_type,
        "stage":       log.stage,
        "confidence":  log.confidence,
        "crs_score":   log.crs_score,
    }
    recommendation = get_recommendation(result, geo)
    log.recommendation = recommendation
    db.commit()
    return {"recommendation": recommendation}