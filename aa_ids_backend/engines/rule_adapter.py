"""
engines/rule_adapter.py
=======================
Adapter wrapping the existing OWASP CRS rule engine (src/rule_engine/crs_engine.py).

Original function being wrapped
--------------------------------
  CRSEngine.inspect(row: pd.Series) -> DetectionResult

  The engine expects a pandas Series whose index values are the 53 z-scored
  feature column names from data/final/feature_names.txt.  It returns a
  DetectionResult dataclass whose key fields are:
    .is_attack     bool
    .anomaly_score int
    .threshold     int
    .attack_types  List[str]   — e.g. ["SQL Injection", "XSS"]
    .matched_rules List[RuleMatch]

Public API added by this adapter
---------------------------------
  adapt_rule_engine(feature_vector: dict) -> dict
      Accepts a dict of z-scored features (output of preprocessor.extract_features),
      returns a normalised verdict dict compatible with the orchestrator contract.

# ADAPTER CHANGE: Added this module to bridge the dict-based Flask pipeline to
#   the DataFrame/Series-based CRSEngine — the original crs_engine.py and
#   crs_rules.py are NOT modified at all.
"""

import logging
import sys
from pathlib import Path
from typing import Any

import pandas as pd

# ── Make the original rule engine importable ─────────────────────────────────
# ADAPTER CHANGE: Inject src/rule_engine into sys.path at import time so the
#   existing crs_engine / crs_rules modules are usable without modification.
_RULE_ENGINE_DIR = Path(__file__).resolve().parent.parent.parent / "src" / "rule_engine"
if str(_RULE_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(_RULE_ENGINE_DIR))

from crs_engine import CRSEngine  # noqa: E402  — original, unmodified
import config  # noqa: E402

log = logging.getLogger(__name__)

# ── Module-level engine instance (created once at import time) ────────────────
# ADAPTER CHANGE: Instantiated once here instead of per-call to avoid recreating
#   the rule list on every request.
_ENGINE = CRSEngine(threshold=config.RULE_ENGINE_THRESHOLD)
log.info("CRSEngine loaded with %d rules, threshold=%d",
         len(_ENGINE.rules), _ENGINE.threshold)

# Category → canonical attack_type label used in the API response
_CATEGORY_TO_ATTACK_TYPE: dict[str, str] = {
    "SQL Injection":    "SQL_INJECTION",
    "XSS":              "XSS",
    "Path Traversal":   "PATH_TRAVERSAL",
    "Encoding Evasion": "ENCODING_EVASION",
    "Protocol Anomaly": "PROTOCOL_ANOMALY",
    "Scanner":          "SCANNER",
    "Entropy Anomaly":  "ENTROPY_ANOMALY",
}

# Category → severity mapping for the API response
_CATEGORY_TO_SEVERITY: dict[str, str] = {
    "SQL Injection":    "critical",
    "XSS":              "critical",
    "Path Traversal":   "high",
    "Encoding Evasion": "medium",
    "Protocol Anomaly": "medium",
    "Scanner":          "high",
    "Entropy Anomaly":  "low",
}


def adapt_rule_engine(feature_vector: dict[str, Any]) -> dict[str, Any]:
    """
    Call the original CRSEngine.inspect() with a z-scored feature dict and
    return a normalised result dict for the orchestrator.

    Parameters
    ----------
    feature_vector : dict
        Z-scored features produced by pipeline.preprocessor.extract_features().
        Keys must include every feature column the rule engine references
        (subset of the 53-column feature set in data/final/feature_names.txt).

    Returns
    -------
    dict with keys:
        verdict         : "ATTACK" | "CLEAN"
        anomaly_score   : int
        attack_types    : list[str]  — canonical API labels
        attack_type     : str | None — primary (highest-score) attack type
        severity        : str | None — "critical" | "high" | "medium" | "low"
        rule_triggered  : str | None — first matching rule_id
        affected_field  : str | None — feature field that triggered the rule
        raw_attack_types: list[str]  — original category names from CRS
    """
    # ADAPTER CHANGE: Convert dict to pd.Series so the original inspect()
    #   method receives exactly the type it expects.
    row = pd.Series(feature_vector)

    result = _ENGINE.inspect(row)  # ← original function, untouched

    if not result.is_attack:
        return {
            "verdict":          "CLEAN",
            "anomaly_score":    result.anomaly_score,
            "attack_types":     [],
            "attack_type":      None,
            "severity":         None,
            "rule_triggered":   None,
            "affected_field":   None,
            "raw_attack_types": [],
        }

    # Map raw category names to canonical API labels
    canonical_types = [
        _CATEGORY_TO_ATTACK_TYPE.get(cat, "UNKNOWN_ATTACK")
        for cat in result.attack_types
    ]

    primary_category = result.attack_types[0] if result.attack_types else None
    primary_attack_type = canonical_types[0] if canonical_types else "UNKNOWN_ATTACK"
    severity = _CATEGORY_TO_SEVERITY.get(primary_category or "", "medium")

    # First matched rule ID and the feature that triggered it
    first_rule = result.matched_rules[0] if result.matched_rules else None
    rule_id = first_rule.rule_id if first_rule else None
    affected_field = first_rule.feature if first_rule else None

    log.info(
        "Rule engine ATTACK: score=%d types=%s rule=%s",
        result.anomaly_score, canonical_types, rule_id,
    )

    return {
        "verdict":          "ATTACK",
        "anomaly_score":    result.anomaly_score,
        "attack_types":     canonical_types,
        "attack_type":      primary_attack_type,
        "severity":         severity,
        "rule_triggered":   rule_id,
        "affected_field":   affected_field,
        "raw_attack_types": result.attack_types,
    }


def is_rule_engine_loaded() -> bool:
    """Return True if the CRS engine is available and initialised."""
    return _ENGINE is not None
