"""
controller.py
=============
AA-IDS Inference Controller
----------------------------
Loads all 3 models once at startup (joblib) and routes each
incoming request through the pipeline:

  1. CRS Rule Engine  → ATTACK?  → stop, return "ATTACK"
  2. Random Forest    → NORMAL?  → stop, return "NORMAL"
  3. XGBoost          → classify → return attack category

Usage (standalone test):
    python controller.py

Usage (import):
    from controller import IDSController
    controller = IDSController()          # loads models once
    result = controller.predict(features) # call per request
"""

import joblib
import numpy as np
import pandas as pd
from pathlib import Path


# ── Paths ─────────────────────────────────────────────────────────
ROOT      = Path(__file__).parent
MODEL_DIR = ROOT / "models"
rf_model_path    = Path(os.environ.get("RF_MODEL_PATH",    MODEL_DIR / "rf_model.pkl"))

CRS_THRESHOLD = 5   # same threshold yewo used



# CRS Rule Engine — imported inline so controller is self-contained

import sys
sys.path.insert(0, "/home/rashid/Documents/FYP/Ai-Augumented-IDS/pipeline/rule_engine")
from crs_engine import CRSEngine

# ══════════════════════════════════════════════════════════════════
# IDS Controller
# ══════════════════════════════════════════════════════════════════

class IDSController:
    """
    Loads all models once on init. Call .predict(features) per request.

    Parameters
    ----------
    crs_threshold : int
        Anomaly score threshold for CRS stage (default 5).
    """

    def __init__(self, crs_threshold: int = CRS_THRESHOLD):
        self.crs_threshold = crs_threshold
        self._load_models()

    def _load_models(self):
        """Load all models into memory. Called once at startup."""
        print("[Controller] Loading models...")

        # Stage 1 — CRS Rule Engine (stateless, no pkl needed)
        self.crs = CRSEngine(threshold=self.crs_threshold)
        print("  ✓  CRS Rule Engine ready")

        # Stage 2 — Random Forest (binary: normal vs attack)
        rf_model_path    = MODEL_DIR / "rf_model.pkl"
        rf_features_path = MODEL_DIR / "rf_feature_names.pkl"

        if not rf_model_path.exists():
            raise FileNotFoundError(
                f"RF model not found at {rf_model_path}. "
                "Run train1.py first to generate it."
            )

        self.rf           = joblib.load(rf_model_path)
        self.rf_features  = joblib.load(rf_features_path)
        print("  ✓  Random Forest ready")

        # Stage 3 — XGBoost (multi-class attack classification)
        xgb_model_path    = MODEL_DIR / "xgb_model.pkl"
        xgb_features_path = MODEL_DIR / "xgb_feature_names.pkl"
        xgb_labels_path   = MODEL_DIR / "xgb_label_mapping.pkl"

        if not xgb_model_path.exists():
            raise FileNotFoundError(
                f"XGBoost model not found at {xgb_model_path}. "
                "Run train2.py first to generate it."
            )

        self.xgb              = joblib.load(xgb_model_path)
        self.xgb_features     = joblib.load(xgb_features_path)
        label_mapping         = joblib.load(xgb_labels_path)
        self.reverse_mapping  = {v: k for k, v in label_mapping.items()}
        print("  ✓  XGBoost ready")

        print("[Controller] All models loaded.\n")

    # ──────────────────────────────────────────────────────────────
    # Main prediction entry point
    # ──────────────────────────────────────────────────────────────

    def predict(self, features: dict) -> dict:
        """
        Run a single request through the full pipeline.

        Parameters
        ----------
        features : dict
            A dictionary of feature_name → value for the request.
            Must contain all features expected by CRS, RF, and XGBoost.

        Returns
        -------
        dict with keys:
            - verdict      : "NORMAL" | "ATTACK"
            - attack_type  : None | "SQLI" | "XSS" | "PATH_TRAVERSAL" | "OTHER"
            - stage        : "CRS" | "RF" | "XGBoost"
            - confidence   : float (0–1) from the deciding model
            - crs_score    : int — raw CRS anomaly score
        """

        row = pd.Series(features)

        # ── STAGE 1: CRS Rule Engine ──────────────────────────────
        crs_result = self.crs.inspect(row)
        crs_score  = crs_result.anomaly_score

        if crs_score >= self.crs_threshold:
            # Map CRS category names to XGBoost label format
            category_map = {
                "SQL Injection":   "SQLI",
                "SQLi":            "SQLI",
                "XSS":             "XSS",
                "Cross-Site Scripting": "XSS",
                "Path Traversal":  "PATH_TRAVERSAL",
                "Directory Traversal": "PATH_TRAVERSAL",
                "Encoding Evasion":"OTHER",
                "Scanner":         "OTHER",
                "Entropy Anomaly": "OTHER",
            }
            crs_type = None
            if crs_result.attack_types:
                crs_type = category_map.get(crs_result.attack_types[0], "OTHER")
            return {
                "verdict":     "ATTACK",
                "attack_type": crs_type,
                "stage":       "CRS",
                "confidence":  1.0,
                "crs_score":   crs_score,
            }

        # ── STAGE 2: Random Forest (binary) ──────────────────────
        rf_input = self._prepare_rf_input(row)
        rf_proba = self.rf.predict_proba(rf_input)[0]  # [P(normal), P(attack)]
        rf_pred  = int(np.argmax(rf_proba))

        if rf_pred == 0:  # RF says NORMAL → stop here
            return {
                "verdict":     "NORMAL",
                "attack_type": None,
                "stage":       "ML Model",
                "confidence":  float(rf_proba[0]),
                "crs_score":   crs_score,
            }

        # ── STAGE 3: XGBoost (multi-class) ───────────────────────
        # Use raw unscaled features for XGBoost
        raw_features = row.get('_raw', row.to_dict())
        raw_row      = pd.Series(raw_features) if isinstance(raw_features, dict) else pd.Series(raw_features.to_dict())
        xgb_input    = self._prepare_xgb_input(raw_row)
        xgb_proba   = self.xgb.predict_proba(xgb_input)[0]
        xgb_pred    = int(np.argmax(xgb_proba))
        attack_type = self.reverse_mapping[xgb_pred]

        return {
            "verdict":     "ATTACK",
            "attack_type": attack_type,
            "stage":       "ML Model",
            "confidence":  float(np.max(xgb_proba)),
            "crs_score":   crs_score,
        }

    # ──────────────────────────────────────────────────────────────
    # Feature preparation helpers
    # ──────────────────────────────────────────────────────────────

    def _prepare_rf_input(self, row: pd.Series) -> pd.DataFrame:
        """Align input to the exact features RF was trained on."""
        df = pd.DataFrame([row])
        for col in self.rf_features:
            if col not in df.columns:
                df[col] = 0.0
        return df[self.rf_features]

    def _prepare_xgb_input(self, row: pd.Series) -> pd.DataFrame:
        """
        Apply XGBoost feature engineering and align to trained features.
        Mirrors the engineer_features() logic from train2.py.
        """
        df = pd.DataFrame([row])

        # Engineered features — must match retrain_xgb.py add_engineered()
        def gcol(col):
            return df[col] if col in df.columns else 0

        df['special_ratio_query'] = gcol('query_num_special') / (gcol('query_length') + 1e-5)
        df['special_ratio_body']  = gcol('body_num_special')  / (gcol('body_length')  + 1e-5)
        df['percent_ratio_query'] = gcol('query_num_percent') / (gcol('query_length') + 1e-5)
        df['dots_ratio_url']      = gcol('url_num_dots')      / (gcol('url_length')   + 1e-5)
        df['semicolon_ratio']     = gcol('body_num_semicolons')/ (gcol('body_length') + 1e-5)
        df['quotes_ratio']        = gcol('body_num_quotes')   / (gcol('body_length')  + 1e-5)
        df['entropy_diff']        = gcol('query_entropy')     - gcol('url_entropy')
        df['high_query_entropy']  = (gcol('query_entropy')    > 4.0).astype(int)
        df['high_body_entropy']   = (gcol('body_entropy')     > 4.0).astype(int)
        df['deep_path']           = (gcol('url_path_depth')   > 4).astype(int)
        df['many_dots']           = (gcol('url_num_dots')     > 3).astype(int)

        # Align to trained feature set
        for col in self.xgb_features:
            if col not in df.columns:
                df[col] = 0.0

        return df[self.xgb_features]


# ══════════════════════════════════════════════════════════════════
# Standalone test
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    controller = IDSController()

    # ── Example 1: Normal request ─────────────────────────────────
    normal_request = {
        "url_length": -0.47, "url_path_depth": -0.03, "url_num_dots": -0.27,
        "url_num_hyphens": -0.25, "url_num_underscores": -0.13,
        "url_num_percent": -0.20, "url_num_equal": -0.45,
        "url_num_ampersand": -0.40, "url_entropy": -0.16,
        "url_has_risky_ext": 0, "url_has_double_encoding": 0,
        "query_length": 0, "query_num_params": 0, "query_num_equals": 0,
        "query_num_special": 0, "query_num_percent": 0, "query_entropy": 0,
        "query_has_sqli": 0, "query_has_xss": 0, "query_has_traversal": 0,
        "query_has_encoding": 0, "query_is_empty": 1,
        "body_length": 0, "body_entropy": 0, "body_num_params": 0,
        "body_num_special": 0, "body_num_percent": 0,
        "body_has_sqli": 0, "body_has_xss": 0, "body_has_traversal": 0,
        "body_has_encoding": 0, "body_is_empty": 1,
        "method_get": 1, "method_post": 0, "method_put": 0,
        "content_type_is_form": 0, "content_type_is_none": 1,
        "url": "/index.html", "query_string": "", "body": "", "cookie": "",
        "method": "GET", "content_type": "", "content_length": 0,
    }

    # ── Example 2: SQLi attack ────────────────────────────────────
    sqli_request = {**normal_request,
        "query_has_sqli": 1, "query_num_special": 8, "query_length": 50,
        "query_num_equals": 4, "query_entropy": 5.2,
        "url": "/login?id=1' OR '1'='1", "query_string": "id=1' OR '1'='1",
    }

    print("=" * 50)
    print("Test 1 — Normal request")
    result = controller.predict(normal_request)
    for k, v in result.items():
        print(f"  {k:<15}: {v}")

    print("\n" + "=" * 50)
    print("Test 2 — SQLi attack")
    result = controller.predict(sqli_request)
    for k, v in result.items():
        print(f"  {k:<15}: {v}")