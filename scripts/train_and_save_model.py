"""
train_and_save_model.py
=======================
One-shot script to train the RandomForestClassifier from the CSIC feature
dataset and serialise it to disk as a joblib file.

Run once before starting the Flask backend:
    python scripts/train_and_save_model.py

The script trains from data/final/train.csv (same split used in the notebook)
and saves the model to models/rf_model.joblib relative to the repo root.
"""

import sys
import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, f1_score

# ── Make repo root importable ─────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "aa_ids_backend"))

import config  # noqa: E402 — must come after sys.path manipulation

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
log = logging.getLogger(__name__)


def train_and_save() -> None:
    """Train the RF model and persist it along with the feature column order."""

    # ── Load training data ───────────────────────────────────────────────────
    train_path = Path(config.TRAIN_DATA_PATH)
    if not train_path.exists():
        raise FileNotFoundError(f"Training data not found: {train_path}")

    log.info("Loading training data from %s …", train_path)
    train_df = pd.read_csv(train_path)

    X = train_df.drop(columns=["label"])
    y = train_df["label"].astype(int)

    log.info("Train shape: %s  |  Attack ratio: %.4f", X.shape, y.mean())

    # ── (Optional) quick validation on held-out slice ─────────────────────────
    from sklearn.model_selection import train_test_split
    X_tr, X_val, y_tr, y_val = train_test_split(
        X, y, test_size=0.1, stratify=y, random_state=42
    )

    # ── Train ─────────────────────────────────────────────────────────────────
    log.info("Training RandomForestClassifier (300 estimators) …")
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_split=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_tr, y_tr)

    # ── Quick evaluation ──────────────────────────────────────────────────────
    y_pred = rf.predict(X_val)
    f1 = f1_score(y_val, y_pred)
    log.info("Validation F1: %.4f", f1)
    log.info("\n%s", classification_report(y_val, y_pred, digits=4))

    # ── Save model ────────────────────────────────────────────────────────────
    model_path = Path(config.ML_MODEL_PATH)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(rf, model_path)
    log.info("Model saved → %s", model_path)

    # ── Save feature column order (for deterministic inference ordering) ───────
    feature_order_path = model_path.parent / "feature_columns.txt"
    feature_order_path.write_text("\n".join(X.columns.tolist()))
    log.info("Feature column order saved → %s", feature_order_path)


if __name__ == "__main__":
    train_and_save()
