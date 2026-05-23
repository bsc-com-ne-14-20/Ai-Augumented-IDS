"""
crs_engine.py
=============
OWASP CRS — Feature-Based Detection Engine
-------------------------------------------

Architecture
------------
    DataFrame row  ──►  Rule Dispatcher  ──►  Anomaly Scorer  ──►  DetectionResult
                           (per rule:                (sum of
                        feature > threshold?)      severity weights)

The engine mirrors the OWASP CRS anomaly scoring mode:
  - Every matching rule adds its severity weight to the anomaly score.
  - If total score >= threshold → label = 1 (attack).
  - All matched rules and their categories are recorded for auditability.

The `threshold` parameter is the primary tuning knob:
  Lower  → more sensitive (more true positives, more false positives)
  Higher → more specific  (fewer false positives, fewer true positives)

Usage
-----
    import pandas as pd
    from crs_engine import CRSEngine

    df = pd.read_csv("test.csv")
    engine = CRSEngine(threshold=5)
    results_df = engine.run(df)
    engine.print_rule_summary()
"""

import pandas as pd
import numpy as np
from dataclasses import dataclass, field
from typing import List, Dict, Optional

from crs_rules import ALL_RULES, ALL_RULE_GROUPS, CRSRule, SEVERITY_WEIGHT


# ──────────────────────────────────────────────────────────────────
# Result data structures
# ──────────────────────────────────────────────────────────────────

@dataclass
class RuleMatch:
    """A single rule that fired for a request."""
    rule_id:  str
    feature:  str
    value:    float
    category: str
    severity: str
    message:  str

    def __repr__(self):
        return (f"[{self.rule_id}] {self.category} | "
                f"{self.severity} | feat={self.feature}={self.value:.4f} | "
                f"{self.message}")


@dataclass
class DetectionResult:
    """
    Full output for a single request inspection.

    label        : 0 (clean) or 1 (attack)
    anomaly_score: accumulated CRS anomaly score
    threshold    : engine threshold used for this decision
    attack_types : deduplicated list of matched attack categories
    matched_rules: all individual rule matches (audit trail)
    """
    label:         int
    anomaly_score: int
    threshold:     int
    attack_types:  List[str]
    matched_rules: List[RuleMatch]

    @property
    def is_attack(self) -> bool:
        return self.label == 1

    def summary(self) -> str:
        if not self.is_attack:
            return f"CLEAN  (score={self.anomaly_score}/{self.threshold})"
        types = ", ".join(self.attack_types)
        return (f"ATTACK (score={self.anomaly_score}/{self.threshold}) "
                f"| [{types}] | {len(self.matched_rules)} rules fired")


# ──────────────────────────────────────────────────────────────────
# Engine
# ──────────────────────────────────────────────────────────────────

class CRSEngine:
    """
    OWASP CRS-inspired anomaly scoring engine for pre-engineered
    z-scored HTTP feature datasets.

    Parameters
    ----------
    threshold : int
        Minimum accumulated anomaly score to classify as attack.
        Default = 5  (equivalent to one CRITICAL rule match).
        Tune this to trade off precision vs. recall.

    active_categories : list[str] | None
        Restrict to a subset of attack categories. None = all enabled.

    Example
    -------
    >>> engine = CRSEngine(threshold=5)
    >>> df = pd.read_csv("test.csv")
    >>> results = engine.run(df)
    """

    def __init__(
        self,
        threshold: int = 5,
        active_categories: Optional[List[str]] = None,
    ):
        self.threshold = threshold
        if active_categories:
            self.rules = [r for r in ALL_RULES if r.category in active_categories]
        else:
            self.rules = ALL_RULES

    # ── Single-row inspection ─────────────────────────────────────

    def inspect(self, row: pd.Series) -> DetectionResult:
        """
        Inspect one DataFrame row (a single HTTP request's features).
        Returns a DetectionResult with full audit trail.
        """
        matches: List[RuleMatch] = []
        score = 0

        for rule in self.rules:
            if rule.feature not in row.index:
                continue
            value = row[rule.feature]
            if pd.isna(value):
                continue
            if value > rule.threshold:
                matches.append(RuleMatch(
                    rule_id=rule.rule_id,
                    feature=rule.feature,
                    value=float(value),
                    category=rule.category,
                    severity=rule.severity,
                    message=rule.message,
                ))
                score += SEVERITY_WEIGHT.get(rule.severity, 1)

        attack_types = list(dict.fromkeys(m.category for m in matches))
        label = 1 if score >= self.threshold else 0

        return DetectionResult(
            label=label,
            anomaly_score=score,
            threshold=self.threshold,
            attack_types=attack_types,
            matched_rules=matches,
        )

    # ── Batch: run over full DataFrame ───────────────────────────

    def run(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Run the CRS engine over every row in df.

        Adds the following columns to a copy of df:
          crs_label       : 0 or 1 (final classification)
          crs_score       : raw anomaly score
          crs_rules_fired : number of rules matched
          crs_attack_types: comma-separated attack category names
        """
        out = df.copy()

        labels, scores, n_rules, atypes = [], [], [], []

        for _, row in df.iterrows():
            result = self.inspect(row)
            labels.append(result.label)
            scores.append(result.anomaly_score)
            n_rules.append(len(result.matched_rules))
            atypes.append(", ".join(result.attack_types) if result.attack_types else "clean")

        out["crs_label"]        = labels
        out["crs_score"]        = scores
        out["crs_rules_fired"]  = n_rules
        out["crs_attack_types"] = atypes

        return out

    # ── Diagnostics ───────────────────────────────────────────────

    def print_rule_summary(self) -> None:
        """Print a formatted table of all loaded rules grouped by category."""
        total = len(self.rules)
        print(f"\n{'═'*65}")
        print(f"  CRS Engine — {total} rules loaded  |  threshold = {self.threshold}")
        print(f"{'═'*65}")
        for group_name, group_rules in ALL_RULE_GROUPS.items():
            active = [r for r in group_rules if r in self.rules]
            if not active:
                continue
            print(f"\n  ▸ {group_name}  ({len(active)} rules)")
            for r in active:
                w = SEVERITY_WEIGHT[r.severity]
                print(f"    [{r.rule_id}]  {r.severity:<8}  +{w}pt  "
                      f"thresh>{r.threshold:.3f}  {r.message}")
        print(f"\n{'═'*65}\n")
