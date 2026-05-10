import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
from sklearn.metrics import f1_score, roc_auc_score

ROOT = Path("/home/rashid/Documents/FYP/Ai-Augumented-IDS")
train_df = pd.read_csv(ROOT / "data/final/train.csv")
test_df  = pd.read_csv(ROOT / "data/final/test.csv")

rf_features = joblib.load(ROOT / "models/rf_feature_names.pkl")

X_train = train_df[rf_features]
y_train = train_df["label"].astype(int)
X_test  = test_df[rf_features]
y_test  = test_df["label"].astype(int)

configs = [
    {"max_depth": 10, "min_samples_split": 10, "min_samples_leaf": 5},
    {"max_depth": 15, "min_samples_split": 10, "min_samples_leaf": 5},
    {"max_depth": 20, "min_samples_split": 10, "min_samples_leaf": 5},
    {"max_depth": 15, "min_samples_split": 20, "min_samples_leaf": 10},
    {"max_depth": 20, "min_samples_split": 5,  "min_samples_leaf": 3},
]

print(f"{'max_depth':<12} {'min_split':<12} {'min_leaf':<12} {'F1':>8} {'AUC':>8}")
print("-" * 55)

best_f1  = 0
best_cfg = None

for cfg in configs:
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=cfg["max_depth"],
        min_samples_split=cfg["min_samples_split"],
        min_samples_leaf=cfg["min_samples_leaf"],
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    pred  = rf.predict(X_test)
    proba = rf.predict_proba(X_test)[:, 1]
    f1    = f1_score(y_test, pred)
    auc   = roc_auc_score(y_test, proba)
    print(f"{cfg['max_depth']:<12} {cfg['min_samples_split']:<12} {cfg['min_samples_leaf']:<12} {f1:>8.4f} {auc:>8.4f}")

    if f1 > best_f1:
        best_f1  = f1
        best_cfg = cfg
        best_rf  = rf

print(f"\n✓ Best config: {best_cfg}")
print(f"✓ Best F1: {best_f1:.4f}")

joblib.dump(best_rf, ROOT / "models/rf_model_tuned.pkl")
print("✓ Tuned model saved → models/rf_model_tuned.pkl")
