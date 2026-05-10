import pandas as pd
import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score, roc_auc_score

ROOT      = Path("/home/rashid/Documents/FYP/Ai-Augumented-IDS")
AUG_DIR   = ROOT / "data/augmented"
MODEL_DIR = ROOT / "models"

print("="*60)
print("  Retraining RF on Augmented Dataset")
print("="*60)

train_df = pd.read_csv(AUG_DIR / "train_augmented.csv")
test_df  = pd.read_csv(AUG_DIR / "test_augmented.csv")

feature_cols = [c for c in train_df.columns if c != 'label']
X_train = train_df[feature_cols]
y_train = train_df['label'].astype(int)
X_test  = test_df[feature_cols]
y_test  = test_df['label'].astype(int)

print(f"\nTrain: {len(X_train)} rows | Test: {len(X_test)} rows")
print(f"Normal: {(y_train==0).sum()} | Attack: {(y_train==1).sum()}")

print("\nTraining Random Forest (augmented)...")
rf = RandomForestClassifier(
    n_estimators=300,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=3,
    max_features="sqrt",
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)
rf.fit(X_train, y_train)

y_pred  = rf.predict(X_test)
y_proba = rf.predict_proba(X_test)[:,1]

print("\n=== AUGMENTED RF RESULTS ===")
print(classification_report(y_test, y_pred))
print(f"F1      : {f1_score(y_test, y_pred):.4f}")
print(f"ROC-AUC : {roc_auc_score(y_test, y_proba):.4f}")

cm = confusion_matrix(y_test, y_pred)
print(f"\nConfusion Matrix:")
print(f"  TN={cm[0][0]}  FP={cm[0][1]}")
print(f"  FN={cm[1][0]}  TP={cm[1][1]}")

print("\n=== BASELINE COMPARISON ===")
print(f"  Baseline F1      : 0.8906")
print(f"  Augmented F1     : {f1_score(y_test, y_pred):.4f}")
print(f"  Baseline ROC-AUC : 0.9791")
print(f"  Augmented ROC-AUC: {roc_auc_score(y_test, y_proba):.4f}")

joblib.dump(rf, MODEL_DIR / "rf_model.pkl")
joblib.dump(feature_cols, MODEL_DIR / "rf_feature_names.pkl")
print(f"\n✓ RF model saved → models/rf_model.pkl")
