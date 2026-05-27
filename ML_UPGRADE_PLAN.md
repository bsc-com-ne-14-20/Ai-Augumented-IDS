# ML Upgrade Change Plan
# AA-IDS Prototype v1.0 | COM422 | University of Malawi

## Model Facts

- **RF model path**: `models/rf_combined.pkl`
- **RF classes_**: `[0, 1]` — binary (0 = normal, 1 = attack)
- **RF n_features_in_**: 53 (matches FEATURE_SCHEMA.json exactly)

- **XGB model path**: `models/xgb_model.pkl`
- **XGB classes_**: `[0, 1, 2, 3]` — multi-class attack-type classifier
  - 0 = OTHER (generic/unknown attack)
  - 1 = SQLI
  - 2 = XSS
  - 3 = PATH_TRAVERSAL
- **XGB n_features_in_**: 58 (53 base + 5 engineered ratio features)
- **XGB objective**: `multi:softprob`
- **XGB feature_names_in_**: 53 base features from FEATURE_SCHEMA.json PLUS:
  - `special_ratio_query` = query_num_special / (query_length + 1e-5)
  - `special_ratio_body`  = body_num_special  / (body_length  + 1e-5)
  - `percent_ratio_query` = query_num_percent / (query_length + 1e-5)
  - `dots_ratio_url`      = url_num_dots      / (url_length   + 1e-5)
  - `semicolon_ratio`     = body_num_semicolons / (body_length + 1e-5)
  - `quotes_ratio`        = body_num_quotes   / (body_length  + 1e-5)
  - `entropy_diff`        = query_entropy - url_entropy
  - `high_query_entropy`  = int(query_entropy > 4.0)
  - `high_body_entropy`   = int(body_entropy  > 4.0)
  - `deep_path`           = int(url_path_depth > 4)
  - `many_dots`           = int(url_num_dots   > 3)
  
  NOTE: The model was saved with 58 features (not all 11 engineered features were
  included — the actual feature_names_in_ stored in the model is the authoritative
  list and is used at runtime).

## Critical Design Note: XGB is Attack-Type-Only

XGBoost was trained ONLY on attack samples. It has NO "normal" class.
Its classes_ [0,1,2,3] all represent attack types.

Therefore the correct stacked design is:
1. RF (layer 1): binary gate — decides if the request is an attack at all
2. XGB (layer 2): attack-type classifier — called ONLY when RF says attack
   - Classifies which type of attack it is
   - Returns: OTHER, SQLI, XSS, or PATH_TRAVERSAL

This differs from the prompt's "XGB always runs" design because XGB has no
normal class — running it on clean traffic would always return an attack type,
which is incorrect. RF is the authoritative is_attack decision maker.
XGB is the authoritative attack_type decision maker.

## New Output Contract

The ML engine will now return:
```json
{
  "is_attack":        <bool>,         // True if RF predicted attack (class 1)
  "detection_source": "ml_engine",
  "attack_type":      <str | null>,   // XGB predicted class label if attack, else null
                                      // Values: "SQLI", "XSS", "PATH_TRAVERSAL", "OTHER"
  "confidence":       <float>,        // RF P(attack) — primary confidence signal
  "xgb_confidence":   <float | null>, // XGB predicted-class probability (when attack)
  "matched_rule":     null            // Always null for ML engine results
}
```

## Config Changes Required

`backend/config.py` needs `XGB_MODEL_PATH` added alongside `ML_MODEL_PATH`.

## Files to Modify (in order)

1. `backend/config.py`           — add XGB_MODEL_PATH property
2. `.env` / `.env.example`       — add XGB_MODEL_PATH env var
3. `backend/engines/ml_adapter.py` — CORE CHANGE: load XGB, implement stacked predict
4. `backend/api/routes.py`       — update ANOMALY handling to use attack_type from ML
5. `backend/database.py`         — verify attack_type column is unconstrained String
6. `backend/sockets/events.py`   — verify attack_type flows through unchanged
7. `backend/tests/test_integration_pipeline.py` — update ANOMALY assertions
8. `API_CONTRACT.md`             — update attack_type enum table

## Files That Do NOT Need Changes

- `backend/pipeline/orchestrator.py` — already calls `adapt_ml_model()` cleanly, no hardcoded "Anomaly"
- `backend/api/schemas.py`           — attack_type is Optional[str] already (no Literal/Enum)
- `backend/pipeline/http_feature_extractor.py` — feature extraction unchanged
- `backend/engines/rule_engine.py`   — rule engine unchanged
- `backend/engines/rules.json`       — rule definitions unchanged
- `FEATURE_SCHEMA.json`              — frozen, do not modify
- `dashboard/`                       — Flutter handles attack_type as generic string
