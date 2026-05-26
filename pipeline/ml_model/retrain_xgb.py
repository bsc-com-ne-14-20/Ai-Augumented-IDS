import pandas as pd
import numpy as np
import joblib
import xgboost as xgb
from pathlib import Path
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

ROOT      = Path("/home/rashid/Documents/FYP/Ai-Augumented-IDS")
AUG_DIR   = ROOT / "data/augmented"
MODEL_DIR = ROOT / "models"

print("="*60)
print("  Retraining XGBoost on Augmented Dataset")
print("="*60)

# Load augmented data — attacks only
train_df = pd.read_csv(AUG_DIR / "train_augmented.csv")
test_df  = pd.read_csv(AUG_DIR / "test_augmented.csv")

train_attacks = train_df[train_df['label'] == 1].copy()
test_attacks  = test_df[test_df['label'] == 1].copy()

print(f"\nAttack train: {len(train_attacks)} rows")
print(f"Attack test : {len(test_attacks)} rows")

# Label attack types
def get_attack_type(row):
    if row.get('query_has_traversal', 0) > 0 or row.get('body_has_traversal', 0) > 0:
        return 'PATH_TRAVERSAL'
    elif row.get('query_has_sqli', 0) > 0 or row.get('body_has_sqli', 0) > 0:
        return 'SQLI'
    elif row.get('query_has_xss', 0) > 0 or row.get('body_has_xss', 0) > 0:
        return 'XSS'
    return 'OTHER'

train_attacks['attack_type'] = train_attacks.apply(get_attack_type, axis=1)
test_attacks['attack_type']  = test_attacks.apply(get_attack_type, axis=1)

print("\n=== TRAIN ATTACK DISTRIBUTION ===")
print(train_attacks['attack_type'].value_counts())
print("\n=== TEST ATTACK DISTRIBUTION ===")
print(test_attacks['attack_type'].value_counts())

label_mapping   = {'OTHER': 0, 'SQLI': 1, 'XSS': 2, 'PATH_TRAVERSAL': 3}
reverse_mapping = {v: k for k, v in label_mapping.items()}

# ── Engineer discriminative features without leakage ──────────────
import re

SQLI_RE = re.compile(r"(\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|1=1|'--|--)", re.IGNORECASE)
XSS_RE  = re.compile(r"(<script|javascript:|onerror=|alert\(|<img|<svg|eval\()", re.IGNORECASE)
TRAV_RE = re.compile(r"(\.\./|/etc/passwd|cmd\.exe|/proc/self|%2e%2e)", re.IGNORECASE)
CMD_RE  = re.compile(r"(;\s*cat|;\s*ls|;\s*wget|;\s*curl|\|\s*nc|\$\(|`id`)", re.IGNORECASE)

def add_engineered(df):
    # Ratio features
    df['special_ratio_query'] = df['query_num_special'] / (df['query_length'] + 1e-5)
    df['special_ratio_body']  = df['body_num_special']  / (df['body_length']  + 1e-5)
    df['percent_ratio_query'] = df['query_num_percent'] / (df['query_length'] + 1e-5)
    df['dots_ratio_url']      = df['url_num_dots']      / (df['url_length']   + 1e-5)
    df['semicolon_ratio']     = df['body_num_semicolons']/ (df['body_length'] + 1e-5)
    df['quotes_ratio']        = df['body_num_quotes']   / (df['body_length']  + 1e-5)
    df['entropy_diff']        = df['query_entropy']     - df['url_entropy']
    df['high_query_entropy']  = (df['query_entropy'] > 4.0).astype(int)
    df['high_body_entropy']   = (df['body_entropy']  > 4.0).astype(int)
    df['deep_path']           = (df['url_path_depth'] > 4).astype(int)
    df['many_dots']           = (df['url_num_dots']   > 3).astype(int)
    return df

train_attacks = add_engineered(train_attacks)
test_attacks  = add_engineered(test_attacks)
feature_cols = [c for c in train_attacks.columns if c not in ['label', 'attack_type']]
X_train = train_attacks[feature_cols]

y_train = train_attacks['attack_type'].map(label_mapping)
X_test  = test_attacks[feature_cols]
y_test  = test_attacks['attack_type'].map(label_mapping)

# Sample weights
class_counts  = y_train.value_counts()
total_samples = len(y_train)
n_classes     = len(label_mapping)
w_train       = y_train.map(lambda c: total_samples / (n_classes * class_counts[c]))

print("\nTraining XGBoost (augmented)...")
model = xgb.XGBClassifier(
    objective='multi:softprob',
    num_class=4,
    eval_metric='mlogloss',
    n_estimators=400,
    max_depth=8,
    learning_rate=0.08,
    subsample=0.85,
    colsample_bytree=0.85,
    tree_method='hist',
    random_state=42,
    verbosity=0,
)
model.fit(X_train, y_train, sample_weight=w_train,
          eval_set=[(X_test, y_test)], verbose=False)

y_pred        = model.predict(X_test)
y_pred_labels = [reverse_mapping[p] for p in y_pred]
y_test_labels = [reverse_mapping[p] for p in y_test]

print("\n=== AUGMENTED XGB RESULTS ===")
print(classification_report(y_test_labels, y_pred_labels))
print(f"Accuracy : {accuracy_score(y_test_labels, y_pred_labels):.4f}")

print("\n=== BASELINE COMPARISON ===")
print(f"  Baseline Accuracy  : 0.9441")
print(f"  Augmented Accuracy : {accuracy_score(y_test_labels, y_pred_labels):.4f}")

joblib.dump(model,                    MODEL_DIR / "xgb_model.pkl")
joblib.dump(feature_cols,             MODEL_DIR / "xgb_feature_names.pkl")
joblib.dump(label_mapping,            MODEL_DIR / "xgb_label_mapping.pkl")
print(f"\n✓ XGBoost model saved → models/xgb_model.pkl")
