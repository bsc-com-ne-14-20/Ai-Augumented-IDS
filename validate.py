"""
validate.py
===========
AA-IDS Model Validation Suite
------------------------------
Validates:
  1. CRS Rule Engine       — binary detection on CICIDS test set
  2. Random Forest         — binary detection on CICIDS test set
  3. Full Pipeline         — end-to-end binary verdict on CICIDS test set
  4. Combined              — CICIDS test + JSONL raw data merged

Outputs:
  - Classification reports (precision / recall / F1)
  - Confusion matrices
  - ROC-AUC curves (saved as PNG)
  - Per-class breakdown
  - validation_results.json  (all metrics in one file)

Usage:
  python3 validate.py
"""

import sys, os, json, warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns
import joblib

from pathlib import Path
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, roc_curve, accuracy_score,
    precision_score, recall_score, f1_score,
)

warnings.filterwarnings("ignore")

# ── Paths ──────────────────────────────────────────────────────────
ROOT      = Path("/home/rashid/Documents/FYP/Ai-Augumented-IDS")
MODEL_DIR = ROOT / "models"
DATA_DIR  = ROOT / "data/final"
OUT_DIR   = ROOT / "validation_results"
OUT_DIR.mkdir(exist_ok=True)

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "pipeline" / "rule_engine"))

from api.feature_extractor import extract_features
from controller import IDSController

# ── Colours ────────────────────────────────────────────────────────
PALETTE = {
    "bg":      "#0f1117",
    "panel":   "#1a1d27",
    "accent":  "#00d4ff",
    "green":   "#00ff9d",
    "red":     "#ff4757",
    "yellow":  "#ffd32a",
    "text":    "#e8eaf6",
    "subtext": "#7986cb",
}

plt.rcParams.update({
    "figure.facecolor":  PALETTE["bg"],
    "axes.facecolor":    PALETTE["panel"],
    "axes.edgecolor":    PALETTE["subtext"],
    "axes.labelcolor":   PALETTE["text"],
    "xtick.color":       PALETTE["text"],
    "ytick.color":       PALETTE["text"],
    "text.color":        PALETTE["text"],
    "grid.color":        "#2a2d3e",
    "grid.linestyle":    "--",
    "grid.alpha":        0.5,
    "font.family":       "monospace",
})

results = {}   # collects all metrics for JSON export

# ══════════════════════════════════════════════════════════════════
# 1. Load data
# ══════════════════════════════════════════════════════════════════

print("\n" + "="*60)
print("  AA-IDS Validation Suite")
print("="*60)

print("\n[1/5] Loading CICIDS datasets...")
train_df = pd.read_csv(DATA_DIR / "cicids_cv_train.csv")
val_df   = pd.read_csv(DATA_DIR / "cicids_cv_val.csv")
test_df  = pd.read_csv(DATA_DIR / "cicids_cv_test.csv")

# Combine val + test for a larger held-out evaluation set
eval_df = pd.concat([val_df, test_df], ignore_index=True)

print(f"  Train : {len(train_df):,} rows  (attacks: {train_df['label'].sum():,})")
print(f"  Val   : {len(val_df):,}  rows  (attacks: {val_df['label'].sum():,})")
print(f"  Test  : {len(test_df):,}  rows  (attacks: {test_df['label'].sum():,})")
print(f"  Eval  : {len(eval_df):,}  rows  (attacks: {eval_df['label'].sum():,})")

# ── Load JSONL raw data for combined validation ────────────────────
print("\n[2/5] Re-extracting JSONL raw features...")
import json as _json
RAW_DIR  = ROOT / "traffic_data/raw"
jsonl_records = []
for jsonl_file in sorted(RAW_DIR.glob("*.jsonl")):
    with open(jsonl_file) as f:
        for line in f:
            try:
                req = _json.loads(line.strip())
                request = {
                    "method":       req.get("method", "GET"),
                    "url":          req.get("path", req.get("url", "/")),
                    "query_string": req.get("query_string", ""),
                    "body":         req.get("body", ""),
                    "headers":      req.get("headers", {}),
                    "source_ip":    "127.0.0.1",
                }
                _, raw_df = extract_features(request)
                row = raw_df.iloc[0].to_dict()
                row["label"] = 1 if req.get("label","NORMAL").upper() == "ATTACK" else 0
                jsonl_records.append(row)
            except:
                continue

jsonl_df = pd.DataFrame(jsonl_records)
print(f"  JSONL : {len(jsonl_df):,} rows  (attacks: {jsonl_df['label'].sum():,})")

# ══════════════════════════════════════════════════════════════════
# 2. Load models
# ══════════════════════════════════════════════════════════════════

print("\n[3/5] Loading models...")
controller   = IDSController()
rf_model     = controller.rf
rf_features  = controller.rf_features
xgb_model    = controller.xgb
xgb_features = controller.xgb_features
crs_engine   = controller.crs
print("  ✓ All models loaded")

# ══════════════════════════════════════════════════════════════════
# Helper: plot confusion matrix
# ══════════════════════════════════════════════════════════════════

def plot_confusion_matrix(cm, labels, title, filename):
    fig, ax = plt.subplots(figsize=(6, 5))
    fig.patch.set_facecolor(PALETTE["bg"])
    ax.set_facecolor(PALETTE["panel"])

    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=labels, yticklabels=labels,
        linewidths=0.5, linecolor="#2a2d3e",
        ax=ax, cbar=False,
        annot_kws={"size": 13, "weight": "bold", "color": PALETTE["text"]},
    )
    ax.set_xlabel("Predicted", fontsize=11, labelpad=10)
    ax.set_ylabel("Actual",    fontsize=11, labelpad=10)
    ax.set_title(title, fontsize=13, pad=15, color=PALETTE["accent"])
    plt.tight_layout()
    path = OUT_DIR / filename
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=PALETTE["bg"])
    plt.close()
    print(f"  ✓ Saved: {path.name}")

# ══════════════════════════════════════════════════════════════════
# Helper: plot ROC curve
# ══════════════════════════════════════════════════════════════════

def plot_roc(y_true, y_scores_dict, title, filename):
    fig, ax = plt.subplots(figsize=(7, 5))
    fig.patch.set_facecolor(PALETTE["bg"])
    ax.set_facecolor(PALETTE["panel"])

    colors = [PALETTE["accent"], PALETTE["green"], PALETTE["yellow"]]
    for (label, scores), color in zip(y_scores_dict.items(), colors):
        fpr, tpr, _ = roc_curve(y_true, scores)
        auc = roc_auc_score(y_true, scores)
        ax.plot(fpr, tpr, color=color, lw=2,
                label=f"{label}  (AUC = {auc:.4f})")

    ax.plot([0,1],[0,1], "--", color=PALETTE["subtext"], lw=1, label="Random")
    ax.set_xlabel("False Positive Rate", fontsize=11)
    ax.set_ylabel("True Positive Rate",  fontsize=11)
    ax.set_title(title, fontsize=13, pad=15, color=PALETTE["accent"])
    ax.legend(fontsize=10, facecolor=PALETTE["panel"],
              edgecolor=PALETTE["subtext"], labelcolor=PALETTE["text"])
    ax.grid(True)
    plt.tight_layout()
    path = OUT_DIR / filename
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=PALETTE["bg"])
    plt.close()
    print(f"  ✓ Saved: {path.name}")

# ══════════════════════════════════════════════════════════════════
# 3. CRS Validation
# ══════════════════════════════════════════════════════════════════

print("\n[4/5] Validating models...\n")
print("─"*50)
print("  A) CRS Rule Engine")
print("─"*50)

y_true_crs = eval_df["label"].values
crs_preds, crs_scores = [], []

for _, row in eval_df.iterrows():
    res = crs_engine.inspect(row)
    crs_preds.append(res.label)
    crs_scores.append(res.anomaly_score)

crs_preds  = np.array(crs_preds)
crs_scores = np.array(crs_scores)

print(classification_report(y_true_crs, crs_preds,
      target_names=["NORMAL","ATTACK"]))

cm_crs = confusion_matrix(y_true_crs, crs_preds)
plot_confusion_matrix(cm_crs, ["NORMAL","ATTACK"],
    "CRS Rule Engine — Confusion Matrix", "crs_confusion_matrix.png")

results["CRS"] = {
    "accuracy":  float(accuracy_score(y_true_crs, crs_preds)),
    "precision": float(precision_score(y_true_crs, crs_preds)),
    "recall":    float(recall_score(y_true_crs, crs_preds)),
    "f1":        float(f1_score(y_true_crs, crs_preds)),
    "confusion_matrix": cm_crs.tolist(),
}

# ══════════════════════════════════════════════════════════════════
# 4. Random Forest Validation
# ══════════════════════════════════════════════════════════════════

print("\n─"*50)
print("  B) Random Forest")
print("─"*50)

# Align columns
feature_cols_rf = [c for c in rf_features if c in eval_df.columns]
missing_rf = [c for c in rf_features if c not in eval_df.columns]
if missing_rf:
    print(f"  ⚠ Missing RF features (filling 0): {missing_rf}")

X_eval_rf = eval_df[feature_cols_rf].copy()
for col in missing_rf:
    X_eval_rf[col] = 0.0
X_eval_rf = X_eval_rf[rf_features]

y_true_rf   = eval_df["label"].values
rf_proba    = rf_model.predict_proba(X_eval_rf)[:, 1]
rf_preds    = (rf_proba >= 0.5).astype(int)

print(classification_report(y_true_rf, rf_preds,
      target_names=["NORMAL","ATTACK"]))

cm_rf = confusion_matrix(y_true_rf, rf_preds)
plot_confusion_matrix(cm_rf, ["NORMAL","ATTACK"],
    "Random Forest — Confusion Matrix", "rf_confusion_matrix.png")

roc_auc_rf = roc_auc_score(y_true_rf, rf_proba)
print(f"  ROC-AUC: {roc_auc_rf:.4f}")

plot_roc(y_true_rf, {"Random Forest": rf_proba},
    "Random Forest — ROC Curve", "rf_roc_curve.png")

results["RandomForest"] = {
    "accuracy":  float(accuracy_score(y_true_rf, rf_preds)),
    "precision": float(precision_score(y_true_rf, rf_preds)),
    "recall":    float(recall_score(y_true_rf, rf_preds)),
    "f1":        float(f1_score(y_true_rf, rf_preds)),
    "roc_auc":   float(roc_auc_rf),
    "confusion_matrix": cm_rf.tolist(),
}

# ══════════════════════════════════════════════════════════════════
# 5. Full Pipeline Validation (end-to-end)
# ══════════════════════════════════════════════════════════════════

print("\n─"*50)
print("  C) Full Pipeline (CRS → RF end-to-end)")
print("─"*50)

pipeline_preds  = []
pipeline_scores = []   # RF probability where available, else 1.0 for CRS hits

sample_size = min(5000, len(eval_df))
sample_df   = eval_df.sample(n=sample_size, random_state=42)
y_true_pipe = sample_df["label"].values

print(f"  Running pipeline on {sample_size:,} samples (sampled for speed)...")

for _, row in sample_df.iterrows():
    features = row.to_dict()
    features["url"]          = ""
    features["query_string"] = ""
    features["body"]         = ""
    features["cookie"]       = "none"
    features["method"]       = "GET"
    features["content_type"] = "none"
    features["content_length"] = 0

    # CRS stage
    crs_res = crs_engine.inspect(pd.Series(features))
    if crs_res.anomaly_score >= controller.crs_threshold:
        pipeline_preds.append(1)
        pipeline_scores.append(1.0)
        continue

    # RF stage
    rf_input = pd.DataFrame([features])
    for col in rf_features:
        if col not in rf_input.columns:
            rf_input[col] = 0.0
    rf_input = rf_input[rf_features]
    rf_p     = rf_model.predict_proba(rf_input)[0, 1]
    pipeline_preds.append(1 if rf_p >= 0.5 else 0)
    pipeline_scores.append(float(rf_p))

pipeline_preds  = np.array(pipeline_preds)
pipeline_scores = np.array(pipeline_scores)

print(classification_report(y_true_pipe, pipeline_preds,
      target_names=["NORMAL","ATTACK"]))

cm_pipe = confusion_matrix(y_true_pipe, pipeline_preds)
plot_confusion_matrix(cm_pipe, ["NORMAL","ATTACK"],
    "Full Pipeline — Confusion Matrix", "pipeline_confusion_matrix.png")

roc_auc_pipe = roc_auc_score(y_true_pipe, pipeline_scores)
print(f"  ROC-AUC: {roc_auc_pipe:.4f}")

plot_roc(y_true_pipe,
    {"CRS → RF Pipeline": pipeline_scores,
     "RF alone":          rf_model.predict_proba(
         sample_df[[c for c in rf_features if c in sample_df.columns]]
         .assign(**{c: 0.0 for c in rf_features if c not in sample_df.columns})
         [rf_features]
     )[:, 1]},
    "Pipeline vs RF Alone — ROC Curve", "pipeline_vs_rf_roc.png")

results["Pipeline"] = {
    "accuracy":  float(accuracy_score(y_true_pipe, pipeline_preds)),
    "precision": float(precision_score(y_true_pipe, pipeline_preds)),
    "recall":    float(recall_score(y_true_pipe, pipeline_preds)),
    "f1":        float(f1_score(y_true_pipe, pipeline_preds)),
    "roc_auc":   float(roc_auc_pipe),
    "confusion_matrix": cm_pipe.tolist(),
    "sample_size": sample_size,
}

# ══════════════════════════════════════════════════════════════════
# 6. Combined Summary Plot
# ══════════════════════════════════════════════════════════════════

print("\n─"*50)
print("  D) Combined Summary Chart")
print("─"*50)

models     = ["CRS", "Random Forest", "Pipeline"]
metrics    = ["accuracy", "precision", "recall", "f1"]
model_keys = ["CRS", "RandomForest", "Pipeline"]

fig, axes = plt.subplots(1, 4, figsize=(18, 5))
fig.patch.set_facecolor(PALETTE["bg"])
fig.suptitle("AA-IDS — Model Comparison", fontsize=16,
             color=PALETTE["accent"], y=1.02)

bar_colors = [PALETTE["accent"], PALETTE["green"], PALETTE["yellow"]]

for i, metric in enumerate(metrics):
    ax = axes[i]
    ax.set_facecolor(PALETTE["panel"])
    vals = [results[k][metric] for k in model_keys]
    bars = ax.bar(models, vals, color=bar_colors, width=0.5,
                  edgecolor=PALETTE["bg"], linewidth=1.5)
    for bar, val in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() + 0.01,
                f"{val:.3f}", ha="center", va="bottom",
                fontsize=10, color=PALETTE["text"], fontweight="bold")
    ax.set_ylim(0, 1.12)
    ax.set_title(metric.upper(), fontsize=12,
                 color=PALETTE["accent"], pad=10)
    ax.set_xticklabels(models, rotation=15, ha="right", fontsize=9)
    ax.grid(axis="y", alpha=0.3)
    ax.spines[["top","right"]].set_visible(False)

plt.tight_layout()
summary_path = OUT_DIR / "model_comparison.png"
plt.savefig(summary_path, dpi=150, bbox_inches="tight",
            facecolor=PALETTE["bg"])
plt.close()
print(f"  ✓ Saved: {summary_path.name}")

# ══════════════════════════════════════════════════════════════════
# 7. Save JSON results
# ══════════════════════════════════════════════════════════════════

json_path = OUT_DIR / "validation_results.json"
with open(json_path, "w") as f:
    json.dump(results, f, indent=2)
print(f"\n  ✓ All metrics saved → {json_path}")

# ══════════════════════════════════════════════════════════════════
# 8. Final summary table
# ══════════════════════════════════════════════════════════════════

print("\n" + "="*60)
print("  VALIDATION SUMMARY")
print("="*60)
print(f"{'Model':<20} {'Acc':>7} {'Prec':>7} {'Rec':>7} {'F1':>7} {'AUC':>7}")
print("-"*60)
for key, label in zip(model_keys, models):
    r = results[key]
    auc = f"{r['roc_auc']:.4f}" if "roc_auc" in r else "  N/A "
    print(f"{label:<20} {r['accuracy']:>7.4f} {r['precision']:>7.4f} "
          f"{r['recall']:>7.4f} {r['f1']:>7.4f} {auc:>7}")
print("="*60)
print(f"\n✓ All outputs saved to: {OUT_DIR}/")
print("  Files:")
for f in sorted(OUT_DIR.iterdir()):
    print(f"    {f.name}")