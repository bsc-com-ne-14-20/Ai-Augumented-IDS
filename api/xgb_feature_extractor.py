"""
xgb_feature_extractor.py
XGBoost-specific feature extractor — produces all 64 features the
XGBoost model was trained on.

Usage:
    from api.xgb_feature_extractor import extract_features_xgb
    scaled_df, raw_df = extract_features_xgb(request_dict)

The base 53 features are produced identically to feature_extractor.py.
The 11 engineered features are appended from raw (unscaled) values,
matching exactly what retrain_xgb.py did during training.
"""

import joblib
import pandas as pd
from pathlib import Path

# Re-use the base extractor — no duplication
from api.feature_extractor import extract_features as _base_extract_features

ROOT   = Path(__file__).parent.parent
scaler = joblib.load(ROOT / "data/augmented/scaler_augmented.pkl")

# Load the exact feature-column order XGBoost was trained on
_XGB_FEATURE_NAMES = joblib.load(ROOT / "models/xgb_feature_names.pkl")


def _add_engineered(raw: pd.DataFrame) -> pd.DataFrame:
    """
    Append the 11 engineered features to a raw (unscaled) feature DataFrame.
    Thresholds match retrain_xgb.py exactly.
    """
    df = raw.copy()

    # Ratio features (safe division via + 1e-5)
    df["special_ratio_query"] = df["query_num_special"] / (df["query_length"] + 1e-5)
    df["special_ratio_body"]  = df["body_num_special"]  / (df["body_length"]  + 1e-5)
    df["percent_ratio_query"] = df["query_num_percent"] / (df["query_length"] + 1e-5)
    df["dots_ratio_url"]      = df["url_num_dots"]      / (df["url_length"]   + 1e-5)
    df["semicolon_ratio"]     = df["body_num_semicolons"]/ (df["body_length"] + 1e-5)
    df["quotes_ratio"]        = df["body_num_quotes"]   / (df["body_length"]  + 1e-5)

    # Interaction / difference features
    df["entropy_diff"]       = df["query_entropy"] - df["url_entropy"]

    # Binary threshold features  (match retrain_xgb.py thresholds exactly)
    df["high_query_entropy"] = (df["query_entropy"]  > 4.0).astype(int)
    df["high_body_entropy"]  = (df["body_entropy"]   > 4.0).astype(int)
    df["deep_path"]          = (df["url_path_depth"] > 4  ).astype(int)
    df["many_dots"]          = (df["url_num_dots"]   > 3  ).astype(int)

    return df


def extract_features_xgb(request: dict):
    """
    Extract and scale all 64 features required by the XGBoost model.

    Returns
    -------
    scaled_df : pd.DataFrame  — 64 scaled features, ready for xgb.predict()
    raw_df    : pd.DataFrame  — 64 unscaled features (for inspection / logging)
    """
    # Step 1 — get the base 53 features (scaled + raw) from the shared extractor
    _, raw_base = _base_extract_features(request)

    # Step 2 — append the 11 engineered features (computed on raw values)
    raw_full = _add_engineered(raw_base)

    # Step 3 — reorder columns to exactly match training order
    raw_full = raw_full[_XGB_FEATURE_NAMES]

    # Step 4 — scale the full 64-feature vector using the same scaler
    #           (scaler was fit on base 53; unknown cols get pass-through — see note)
    #
    # NOTE: the scaler was fit on 53 features, so the 11 new ratio/binary
    # columns are not in its vocabulary. We scale what we can and leave the
    # engineered features unscaled — they are already in a [0, ~1] range
    # that XGBoost handles well without standardisation.
    base_cols = [c for c in _XGB_FEATURE_NAMES if c in scaler.feature_names_in_]
    new_cols  = [c for c in _XGB_FEATURE_NAMES if c not in scaler.feature_names_in_]

    scaled_base = pd.DataFrame(
        scaler.transform(raw_full[base_cols]),
        columns=base_cols
    ).clip(-5, 5)

    scaled_full = pd.concat(
        [scaled_base, raw_full[new_cols].reset_index(drop=True)],
        axis=1
    )[_XGB_FEATURE_NAMES]   # restore training column order

    return scaled_full, raw_full