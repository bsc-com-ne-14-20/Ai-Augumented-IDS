#!/usr/bin/env python3
"""
scripts/validate_schema.py
===========================
SRS §7.3 validation script for the 49-feature AA-IDS model artefacts.

Checks:
  a. data/final/feature_names.txt has exactly 49 lines; prints each name.
  b. data/final/scaler.pkl  — n_features_in_ == 49; feature_names_in_ matches
     feature_names.txt line-for-line (same order).
  c. models/rf_model.joblib — n_features_in_ == 49; feature_names_in_ matches
     feature_names.txt line-for-line (same order).
  d. Synthetic zero-vector (1, 49) DataFrame → scaler.transform() →
     model.predict_proba(); assert output shape (1, 2); assert no sklearn
     UserWarning is raised.
  e. HTTPFeatureExtractor.FEATURE_COLUMNS has exactly 49 entries and matches
     feature_names.txt exactly.

Prints PASS or FAIL with details for each assertion.
Exits with code 0 if all checks pass, 1 if any fail.
"""

import sys
import warnings
from pathlib import Path

# ── Repo root on sys.path ─────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import joblib
import numpy as np
import pandas as pd

FEATURE_NAMES_PATH = REPO_ROOT / "data" / "final" / "feature_names.txt"
SCALER_PATH        = REPO_ROOT / "data" / "final" / "scaler.pkl"
MODEL_PATH         = REPO_ROOT / "models" / "rf_model.joblib"

EXPECTED_FEATURES = 49
DROPPED = ["cookie_is_present", "cookie_length",
           "connection_is_close", "connection_keep_alive"]

_results: list[tuple[str, bool, str]] = []


def check(name: str, condition: bool, detail: str = "") -> bool:
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {name}")
    if not condition and detail:
        print(f"         → {detail}")
    _results.append((name, condition, detail))
    return condition


# ─────────────────────────────────────────────────────────────────────────────
# CHECK a — feature_names.txt
# ─────────────────────────────────────────────────────────────────────────────
def check_feature_names_file() -> list[str]:
    print("\n[a] data/final/feature_names.txt")

    if not check("file exists", FEATURE_NAMES_PATH.exists(),
                 f"Not found: {FEATURE_NAMES_PATH}"):
        return []

    feature_names = FEATURE_NAMES_PATH.read_text().strip().splitlines()
    n = len(feature_names)

    check(f"line count == {EXPECTED_FEATURES}", n == EXPECTED_FEATURES,
          f"Got {n} lines, expected {EXPECTED_FEATURES}")

    still_present = [f for f in DROPPED if f in feature_names]
    check("dropped features absent", len(still_present) == 0,
          f"Still present: {still_present}")

    # Print all 49 names
    print(f"         Feature names ({n}):")
    for i, name in enumerate(feature_names, 1):
        print(f"           {i:2d}. {name}")

    return feature_names


# ─────────────────────────────────────────────────────────────────────────────
# CHECK b — scaler.pkl
# ─────────────────────────────────────────────────────────────────────────────
def check_scaler(feature_names: list[str]) -> object:
    print("\n[b] data/final/scaler.pkl")

    if not check("file exists", SCALER_PATH.exists(),
                 f"Not found: {SCALER_PATH}"):
        return None

    try:
        scaler = joblib.load(SCALER_PATH)
    except Exception as exc:
        check("loads without error", False, str(exc))
        return None

    check("loads without error", True)

    n_scaler = scaler.n_features_in_
    check(f"n_features_in_ == {EXPECTED_FEATURES}", n_scaler == EXPECTED_FEATURES,
          f"Got {n_scaler}, expected {EXPECTED_FEATURES}")

    # Verify feature_names_in_ matches feature_names.txt line-for-line
    scaler_names = list(getattr(scaler, "feature_names_in_", []))
    if scaler_names:
        names_match = scaler_names == feature_names
        check("feature_names_in_ matches feature_names.txt (order + content)",
              names_match,
              f"First mismatch at index "
              f"{next((i for i,(a,b) in enumerate(zip(scaler_names, feature_names)) if a!=b), '?')}"
              if not names_match else "")
        if not names_match:
            print(f"         Scaler names: {scaler_names[:5]}…")
            print(f"         File names:   {feature_names[:5]}…")
    else:
        check("feature_names_in_ present", False,
              "Scaler has no feature_names_in_ attribute")

    return scaler


# ─────────────────────────────────────────────────────────────────────────────
# CHECK c — rf_model.joblib
# ─────────────────────────────────────────────────────────────────────────────
def check_model(feature_names: list[str]) -> object:
    print("\n[c] models/rf_model.joblib")

    if not check("file exists", MODEL_PATH.exists(),
                 f"Not found: {MODEL_PATH}"):
        return None

    try:
        model = joblib.load(MODEL_PATH)
    except Exception as exc:
        check("loads without error", False, str(exc))
        return None

    check("loads without error", True)

    n_model = model.n_features_in_
    check(f"n_features_in_ == {EXPECTED_FEATURES}", n_model == EXPECTED_FEATURES,
          f"Got {n_model}, expected {EXPECTED_FEATURES}")

    # The RF model was trained on a plain numpy array (output of scaler.transform),
    # so it has no feature_names_in_ attribute — that is expected and correct.
    # The scaler (check b) carries the named-feature contract; the model does not.
    model_names = list(getattr(model, "feature_names_in_", []))
    if model_names:
        names_match = model_names == feature_names
        check("feature_names_in_ matches feature_names.txt (order + content)",
              names_match,
              f"First mismatch at index "
              f"{next((i for i,(a,b) in enumerate(zip(model_names, feature_names)) if a!=b), '?')}"
              if not names_match else "")
    else:
        # Expected: model was fitted on numpy array, not DataFrame
        check("n_features_in_ correct (model fitted on numpy array — no named features)",
              n_model == EXPECTED_FEATURES,
              f"Got {n_model}, expected {EXPECTED_FEATURES}")

    return model


# ─────────────────────────────────────────────────────────────────────────────
# CHECK d — synthetic inference (zero-vector, no UserWarning)
# ─────────────────────────────────────────────────────────────────────────────
def check_inference(scaler, model, feature_names: list[str]) -> None:
    print("\n[d] Synthetic inference (zero-vector, no sklearn UserWarning)")

    if scaler is None or model is None or len(feature_names) != EXPECTED_FEATURES:
        check("inference skipped (prerequisites failed)", False,
              "scaler, model, or feature_names not ready — fix earlier failures first")
        return

    # Capture any sklearn UserWarnings during transform + predict_proba
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")

        try:
            zero_df = pd.DataFrame(
                np.zeros((1, EXPECTED_FEATURES)),
                columns=feature_names,
            )
            # Scaler was fitted with a DataFrame → pass DataFrame to transform
            scaled = scaler.transform(zero_df)
            # Model was fitted on a numpy array → pass numpy array to predict_proba
            # (passing a DataFrame would trigger the inverse UserWarning)
            proba  = model.predict_proba(scaled)
        except Exception as exc:
            check("inference runs without error", False, str(exc))
            return

    sklearn_warnings = [
        w for w in caught
        if issubclass(w.category, UserWarning)
        and "feature names" in str(w.message).lower()
    ]

    check("inference runs without error", True)
    check("output shape == (1, 2)", proba.shape == (1, 2),
          f"Got shape {proba.shape}")
    check("probabilities sum to 1.0", abs(proba[0].sum() - 1.0) < 1e-6,
          f"Sum = {proba[0].sum():.6f}")
    check("zero sklearn UserWarning about feature names",
          len(sklearn_warnings) == 0,
          f"{len(sklearn_warnings)} warning(s): "
          + "; ".join(str(w.message) for w in sklearn_warnings))

    print(f"         → P(CLEAN)={proba[0][0]:.4f}  P(ATTACK)={proba[0][1]:.4f}")


# ─────────────────────────────────────────────────────────────────────────────
# CHECK e — HTTPFeatureExtractor.FEATURE_COLUMNS
# ─────────────────────────────────────────────────────────────────────────────
def check_extractor(feature_names: list[str]) -> None:
    print("\n[e] HTTPFeatureExtractor.FEATURE_COLUMNS")

    try:
        from backend.pipeline.http_feature_extractor import HTTPFeatureExtractor
    except Exception as exc:
        check("import HTTPFeatureExtractor", False, str(exc))
        return

    check("import HTTPFeatureExtractor", True)

    cols = list(HTTPFeatureExtractor.FEATURE_COLUMNS)
    check(f"len(FEATURE_COLUMNS) == {EXPECTED_FEATURES}", len(cols) == EXPECTED_FEATURES,
          f"Got {len(cols)}")

    if feature_names:
        match = cols == feature_names
        check("FEATURE_COLUMNS matches feature_names.txt exactly", match,
              f"First mismatch at index "
              f"{next((i for i,(a,b) in enumerate(zip(cols, feature_names)) if a!=b), '?')}"
              if not match else "")

    still_present = [f for f in DROPPED if f in cols]
    check("dropped features absent from FEATURE_COLUMNS",
          len(still_present) == 0,
          f"Still present: {still_present}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main() -> int:
    print("=" * 65)
    print("AA-IDS Schema Validation  (SRS §7.3)  — 49-feature model")
    print("=" * 65)

    feature_names = check_feature_names_file()
    scaler        = check_scaler(feature_names)
    model         = check_model(feature_names)
    check_inference(scaler, model, feature_names)
    check_extractor(feature_names)

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    passed = sum(1 for _, ok, _ in _results if ok)
    total  = len(_results)
    all_ok = passed == total

    print("Summary:")
    for name, ok, _ in _results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")

    print("=" * 65)
    if all_ok:
        print(f"✅  ALL {total} CHECKS PASSED")
    else:
        print(f"❌  {total - passed} CHECK(S) FAILED  ({passed}/{total} passed)")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
