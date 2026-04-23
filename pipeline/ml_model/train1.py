#!/usr/bin/env python
# coding: utf-8

# In[68]:


import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score, roc_auc_score
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.pipeline import Pipeline as ImbPipeline
import seaborn as sns
import matplotlib.pyplot as plt
import re


# In[69]:


train_df = pd.read_csv("/home/rashid/Documents/FYP/Ai-Augumented-IDS/data/final/train.csv")
test_df = pd.read_csv("/home/rashid/Documents/FYP/Ai-Augumented-IDS/data/final/test.csv")

print("Dataset shape:", train_df.shape)
print("\nColumns in new dataset:")
print(train_df.columns.tolist())

print("\n=== Label Distribution ===")
print(train_df['label'].value_counts())
print("\nNormalized:")
print(train_df['label'].value_counts(normalize=True).round(4))

print("\nFirst 5 rows preview:")
print(train_df.head())


# In[70]:


train_cols = set(train_df.columns)
test_cols = set(test_df.columns)

print("In train but not in test:", train_cols - test_cols)
print("In test but not in train:", test_cols - train_cols)


# In[71]:


feature_cols = [col for col in train_df.columns if col != 'label']


variances = train_df[feature_cols].var()
zero_var_features = variances[variances == 0].index.tolist()

print(f"\nFound {len(zero_var_features)} features with zero variance. Removing them.")
print("Zero variance features:", zero_var_features)


useful_features = variances[variances > 0].index.tolist()

print(f"Remaining useful features: {len(useful_features)}")

X = train_df[useful_features]
y = train_df['label'].astype(int)

print("\nFinal feature matrix shape:", X.shape)


# In[72]:


X = train_df.drop(columns=['label'])
y = train_df['label'].astype(int)


# In[73]:


X_train, X_val, y_train, y_val = train_test_split(
    X, y,
    test_size=0.2,        # 80% train, 20% validation
    stratify=y,
    random_state=42
)
print("\nTrain set shape:", X_train.shape)
print("Validation set shape: ", X_val.shape)
print("Attack ratio in train:", y_train.mean().round(4))
print("Attack ratio in test: ", y_val.mean().round(4))


# In[74]:


rf = RandomForestClassifier(
    n_estimators=300,
    max_depth=None,
    min_samples_split=2,
    class_weight='balanced',   
    random_state=42,
    n_jobs=-1
)

print("\nTraining Random Forest model...")
rf.fit(X_train, y_train)


# In[75]:


y_pred = rf.predict(X_val)
y_prob = rf.predict_proba(X_val)[:, 1]


# In[76]:


print("\n=== Classification Report ===")
print(classification_report(y_val, y_pred, digits=4))

print("\n=== Confusion Matrix ===")
print(confusion_matrix(y_val, y_pred))

print(f"\nF1 Score: {f1_score(y_val, y_pred):.4f}")
print(f"ROC-AUC Score: {roc_auc_score(y_val, y_prob):.4f}")


# In[80]:


from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay

conf_matrix = confusion_matrix(y_val, y_pred, labels=rf.classes_)
display = ConfusionMatrixDisplay(confusion_matrix=conf_matrix, display_labels=rf.classes_)

display.plot()
plt.title("Validation Confusion matrix")
plt.show()


# In[77]:


X_test = test_df[X.columns]
y_test = test_df['label'].astype(int)

y_test_pred = rf.predict(X_test)
print(classification_report(y_test, y_test_pred))


# In[78]:


y_test_pred = rf.predict(X_test)
y_test_prob = rf.predict_proba(X_test)[:, 1]

print("\n=== TEST Classification Report ===")
print(classification_report(y_test, y_test_pred))

print("\n=== TEST Confusion Matrix ===")
print(confusion_matrix(y_test, y_test_pred))

print(f"\nTEST F1 Score: {f1_score(y_test, y_test_pred):.4f}")
print(f"TEST ROC-AUC Score: {roc_auc_score(y_test, y_test_prob):.4f}")


# In[79]:


from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay

conf_matrix = confusion_matrix(y_test, y_test_pred, labels=rf.classes_)
display = ConfusionMatrixDisplay(confusion_matrix=conf_matrix, display_labels=rf.classes_)

display.plot()
plt.title("Confusion matrix")
plt.show()

