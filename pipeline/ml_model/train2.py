#!/usr/bin/env python
# coding: utf-8

# In[66]:


import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
import xgboost as xgb
import warnings
warnings.filterwarnings('ignore')

plt.style.use('seaborn-v0_8')
sns.set_palette("husl")
plt.rcParams['figure.figsize'] = (12, 8)

print("Starting Analysis of Web Attack Dataset...\n")


# In[67]:


df_train = pd.read_csv('/home/rashid/Documents/FYP/Ai-Augumented-IDS/train_attacks_only.csv')
df_test = pd.read_csv('/home/rashid/Documents/FYP/Ai-Augumented-IDS/test_attacks_only.csv')

print(f"Train samples: {len(df_train)}")
print(f"Test samples: {len(df_test)}")


# In[68]:


def get_attack_type(row):
    has_sqli = (row.get('query_has_sqli', 0) > 0 or row.get('body_has_sqli', 0) > 0)
    has_xss  = (row.get('query_has_xss', 0) > 0 or row.get('body_has_xss', 0) > 0)
    has_trav = (row.get('query_has_traversal', 0) > 0 or row.get('body_has_traversal', 0) > 0)

    if has_trav:               # check traversal FIRST
        return 'PATH_TRAVERSAL'
    elif has_sqli:
        return 'SQLI'
    elif has_xss:
        return 'XSS'
    else:
        return 'OTHER'

# Apply to both train and test
df_train['attack_type'] = df_train.apply(get_attack_type, axis=1)
df_test['attack_type'] = df_test.apply(get_attack_type, axis=1)

# Show distribution
print("=== TRAIN SET ATTACK TYPE DISTRIBUTION ===")
train_attack_counts = df_train['attack_type'].value_counts()
train_attack_percent = df_train['attack_type'].value_counts(normalize=True) * 100
print(train_attack_counts)
print("\nPercentage:")
print(train_attack_percent.round(2))

print("\n=== TEST SET ATTACK TYPE DISTRIBUTION ===")
test_attack_counts = df_test['attack_type'].value_counts()
test_attack_percent = df_test['attack_type'].value_counts(normalize=True) * 100
print(test_attack_counts)
print("\nPercentage:")
print(test_attack_percent.round(2))

# Path Traversal Statistics
print("\n=== PATH TRAVERSAL STATISTICS ===")
train_path_traversal = train_attack_counts.get('PATH_TRAVERSAL', 0)
test_path_traversal = test_attack_counts.get('PATH_TRAVERSAL', 0)
train_path_percent = train_attack_percent.get('PATH_TRAVERSAL', 0)
test_path_percent = test_attack_percent.get('PATH_TRAVERSAL', 0)

print(f"Train - Path Traversal: {train_path_traversal} ({train_path_percent:.2f}%)")
print(f"Test - Path Traversal: {test_path_traversal} ({test_path_percent:.2f}%)")
print(f"Total Path Traversal: {train_path_traversal + test_path_traversal}")


# In[69]:


# Define feature engineering function
def engineer_features(df):
    df['sqli_equals_density'] = df['query_num_equals'] / (df['query_length'] + 1e-5)
    df['sqli_special_ratio']  = df['query_num_special'] / (df['query_length'] + 1e-5)
    df['sqli_tautology_proxy'] = ((df['query_has_sqli'] > 0) & (df['query_num_equals'] > 2)).astype(int)

    df['xss_special_ratio']   = df['query_num_special'] / (df['query_length'] + 1e-5)
    df['xss_bracket_proxy']   = ((df['query_has_xss'] > 0) & (df['query_num_special'] > 4)).astype(int)

    df['traversal_depth_ratio'] = df['url_path_depth'] / (df['url_length'] + 1e-5)
    df['traversal_dots_ratio']  = df['url_num_dots'] / (df['url_length'] + 1e-5)
    df['traversal_proxy']       = ((df['query_has_traversal'] > 0) | (df['body_has_traversal'] > 0)).astype(int)

    df['encoding_intensity']     = df['url_num_percent'] + df['query_num_percent'] + df['body_num_percent']
    df['double_encoding_flag']   = (df['url_has_double_encoding'] > 0).astype(int)
    df['high_entropy_query']     = (df['query_entropy'] > 4.5).astype(int)
    df['high_entropy_body']      = (df['body_entropy'] > 4.5).astype(int)
    df['entropy_spike_query']    = (df['query_entropy'] - df['url_entropy']).clip(lower=0)

    df['method_body_mismatch']   = ((df['method_get'] > 0) & (df['body_length'] > 20)).astype(int)
    df['post_no_content_type']   = ((df['method_post'] > 0) & (df['content_type_is_none'] > 0)).astype(int)

    df['special_char_density_query'] = df['query_num_special'] / (df['query_length'] + 1e-5)
    df['special_char_density_body']  = df['body_num_special'] / (df['body_length'] + 1e-5)

    return df

# Apply feature engineering to both datasets
df_train = engineer_features(df_train)
df_test = engineer_features(df_test)

print("Feature engineering completed for both train and test sets")
print(f"Train features: {df_train.shape[1]}")
print(f"Test features: {df_test.shape[1]}")


# In[ ]:


fig, axes = plt.subplots(2, 2, figsize=(16, 12))


axes[0,0].bar(train_attack_counts.index, train_attack_counts.values, color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728'])
axes[0,0].set_title('Train Set - Distribution of Attack Types', fontsize=14, fontweight='bold')
axes[0,0].set_ylabel('Number of Samples')
axes[0,0].set_xlabel('Attack Type')
for i, v in enumerate(train_attack_counts.values):
    axes[0,0].text(i, v + 50, str(v), ha='center', fontsize=11)


axes[0,1].bar(test_attack_counts.index, test_attack_counts.values, color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728'])
axes[0,1].set_title('Test Set - Distribution of Attack Types', fontsize=14, fontweight='bold')
axes[0,1].set_ylabel('Number of Samples')
axes[0,1].set_xlabel('Attack Type')
for i, v in enumerate(test_attack_counts.values):
    axes[0,1].text(i, v + 50, str(v), ha='center', fontsize=11)

# Plot 3: Train Special Character Density (Boxplot)
sns.boxplot(data=df_train, x='attack_type', y='special_char_density_query', ax=axes[1,0])
axes[1,0].set_title('Train Set - Special Character Density in Query by Attack Type', fontsize=14, fontweight='bold')
axes[1,0].set_ylabel('Special Char Density')

# Plot 4: Test Special Character Density (Boxplot)
sns.boxplot(data=df_test, x='attack_type', y='special_char_density_query', ax=axes[1,1])
axes[1,1].set_title('Test Set - Special Character Density in Query by Attack Type', fontsize=14, fontweight='bold')
axes[1,1].set_ylabel('Special Char Density')

plt.tight_layout()
plt.show()

print("\nAnalysis and plots complet")


# In[71]:


leakage_cols = [
    'query_has_sqli', 'body_has_sqli',
    'query_has_xss', 'body_has_xss',
    'query_has_traversal', 'body_has_traversal'
]

proxy_cols = [
    'sqli_tautology_proxy',
    'xss_bracket_proxy',
    'traversal_proxy'
]

df_train = df_train.drop(columns=leakage_cols + proxy_cols)
df_test = df_test.drop(columns=leakage_cols + proxy_cols)


# In[72]:


drop_cols = ['label', 'attack_type',
             'url_num_special', 'body_num_quotes', 'body_num_semicolons',
             'body_num_brackets', 'method_suspicious', 'cookie_length',
             'cookie_has_sqli', 'cookie_has_xss', 'cookie_is_present',
             'content_type_is_json', 'connection_is_close', 'connection_keep_alive',
             'post_no_content_type', 'get_with_body', 'post_empty_body',
             'content_length_mismatch']

# Prepare train data
X_train = df_train.drop(columns=drop_cols)
y_train = df_train['attack_type']

# Prepare test data
X_test = df_test.drop(columns=drop_cols)
y_test = df_test['attack_type']

# Map to integers
label_mapping = {'OTHER': 0, 'SQLI': 1, 'XSS': 2, 'PATH_TRAVERSAL': 3}
y_train_encoded = y_train.map(label_mapping)
y_test_encoded = y_test.map(label_mapping)

print(f"Train features: {X_train.shape}")
print(f"Test features: {X_test.shape}")


# In[73]:


class_counts = y_train_encoded.value_counts()
total_samples = len(y_train_encoded)
n_classes = len(label_mapping)

# Higher weight for rare classes in training set
w_train = y_train_encoded.map(lambda cls: total_samples / (n_classes * class_counts[cls]))

print("Sample weights calculated for training set")


# In[74]:


# Use predetermined train and test sets directly - no further splitting
print(f"Using predetermined train/test split")
print(f"Training samples: {len(X_train)}")
print(f"Test samples: {len(X_test)}")


# In[75]:


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
    verbosity=1
)

model.fit(
    X_train, y_train_encoded,
    sample_weight=w_train,
    eval_set=[(X_test, y_test_encoded)],
    verbose=False
)


# In[76]:


y_pred = model.predict(X_test)

print("\n" + "="*60)
print("CLASSIFICATION REPORT (with sample weights)")
print("="*60)
print(classification_report(y_test_encoded, y_pred, target_names=list(label_mapping.keys()), labels=sorted(label_mapping.values())))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test_encoded, y_pred, labels=sorted(label_mapping.values())))


importances = pd.Series(model.feature_importances_, index=X_train.columns).sort_values(ascending=False)
print("\nTop 15 Important Features:")
print(importances.head(15))


# In[77]:


fig, ax = plt.subplots(figsize=(10, 8))
cm = confusion_matrix(y_test_encoded, y_pred, labels=sorted(label_mapping.values()))
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=list(label_mapping.keys()))
disp.plot(cmap='Blues', ax=ax)
ax.set_title('Confusion Matrix - Attack Classification', fontsize=14, fontweight='bold')
plt.tight_layout()
plt.show()


# In[78]:


importances = pd.Series(model.feature_importances_, index=X_train.columns)
top20 = importances.nlargest(20)

fig, ax = plt.subplots(figsize=(11, 8))
top20.sort_values(ascending=True).plot(kind='barh', ax=ax, color='steelblue')

ax.set_title('Top 20 Most Important Features', fontsize=14, fontweight='bold')
ax.set_xlabel('Importance Score')
ax.set_ylabel('Features')

plt.tight_layout()
plt.savefig('model_diagnostics.png', dpi=200, bbox_inches='tight')
plt.show()

print("\nTop 15 Most Important Features:")
print(importances.nlargest(15).round(5))


import joblib
from pathlib import Path

MODEL_DIR = Path("/home/rashid/Documents/FYP/Ai-Augumented-IDS/models")
MODEL_DIR.mkdir(parents=True, exist_ok=True)

label_mapping = {'OTHER': 0, 'SQLI': 1, 'XSS': 2, 'PATH_TRAVERSAL': 3}

joblib.dump(model, MODEL_DIR / "xgb_model.pkl")
joblib.dump(X_train.columns.tolist(), MODEL_DIR / "xgb_feature_names.pkl")
joblib.dump(label_mapping, MODEL_DIR / "xgb_label_mapping.pkl")

print(f"\n✓  XGB model saved    → {MODEL_DIR / 'xgb_model.pkl'}")
print(f"✓  XGB features saved → {MODEL_DIR / 'xgb_feature_names.pkl'}")
print(f"✓  XGB labels saved   → {MODEL_DIR / 'xgb_label_mapping.pkl'}")
