from pydantic import BaseModel, Field
from typing import Optional, Dict
from datetime import datetime

class AnalyzeRequest(BaseModel):
    method:       str              = Field(..., example="GET")
    url:          str              = Field(..., example="/login?id=1")
    query_string: Optional[str]   = Field(default="", example="id=1' OR '1'='1")
    body:         Optional[str]   = Field(default="", example="")
    headers:      Optional[Dict[str, str]] = Field(default={})
    source_ip:    Optional[str]   = Field(default="127.0.0.1", example="41.70.12.45")

class GeoInfo(BaseModel):
    country:   Optional[str]
    city:      Optional[str]
    latitude:  Optional[float]
    longitude: Optional[float]
    isp:       Optional[str]
    is_vpn:    bool
    is_proxy:  bool
    is_tor:    bool

class AnalyzeResponse(BaseModel):
    verdict:        str
    attack_type:    Optional[str]
    stage:          str
    confidence:     float
    crs_score:      int
    geo:            GeoInfo
    recommendation: Optional[str]
    timestamp:      datetime

class StatsResponse(BaseModel):
    total_requests:  int
    total_attacks:   int
    total_normal:    int
    sqli_count:      int
    xss_count:       int
    traversal_count: int
    other_count:     int
    crs_caught:      int
    rf_caught:       int
    xgb_classified:  int
    vpn_count:       int
    last_updated:    datetime

class HistoryItem(BaseModel):
    id:          int
    timestamp:   datetime
    method:      str
    url:         str
    source_ip:   str
    country:     Optional[str]
    city:        Optional[str]
    is_vpn:      bool
    verdict:     str
    attack_type: Optional[str]
    stage:       str
    confidence:  float

    class Config:
        from_attributes = True
