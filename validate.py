"""
validate.py
===========
AA-IDS Model Validation Suite
------------------------------
Validates:
  1. CRS Rule Engine       — binary detection on CICIDS eval set
  2. Random Forest         — binary detection on CICIDS eval set
  3. Full Pipeline         — end-to-end binary verdict on CICIDS eval set
  4. RF on ECML Balanced   — honest benchmark on balanced external dataset
  5. Combined Summary      — comparison across all models/datasets

Outputs:
  - Classification reports (precision / recall / F1)
  - Confusion matrices (PNG)
  - ROC-AUC curves (PNG)
  - Per-attack-class bar chart (PNG)
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
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
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
    "orange":  "#ff6b35",
    "purple":  "#a55eea",
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
# Helpers
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


def plot_roc(y_true, y_scores_dict, title, filename):
    fig, ax = plt.subplots(figsize=(7, 5))
    fig.patch.set_facecolor(PALETTE["bg"])
    ax.set_facecolor(PALETTE["panel"])
    colors = [PALETTE["accent"], PALETTE["green"], PALETTE["yellow"], PALETTE["orange"]]
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


def record_metrics(key, y_true, y_pred, y_proba=None, extra=None):
    """Store metrics dict into results under key."""
    d = {
        "accuracy":  float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall":    float(recall_score(y_true, y_pred, zero_division=0)),
        "f1":        float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }
    if y_proba is not None:
        d["roc_auc"] = float(roc_auc_score(y_true, y_proba))
    if extra:
        d.update(extra)
    results[key] = d
    return d


# ══════════════════════════════════════════════════════════════════
# 1. Load CICIDS data
# ══════════════════════════════════════════════════════════════════

print("\n" + "="*60)
print("  AA-IDS Validation Suite")
print("="*60)

print("\n[1/6] Loading CICIDS datasets...")
train_df = pd.read_csv(DATA_DIR / "cicids_cv_train.csv")
val_df   = pd.read_csv(DATA_DIR / "cicids_cv_val.csv")
test_df  = pd.read_csv(DATA_DIR / "cicids_cv_test.csv")
eval_df  = pd.concat([val_df, test_df], ignore_index=True)

print(f"  Train : {len(train_df):,} rows  (attacks: {train_df['label'].sum():,})")
print(f"  Val   : {len(val_df):,}  rows  (attacks: {val_df['label'].sum():,})")
print(f"  Test  : {len(test_df):,}  rows  (attacks: {test_df['label'].sum():,})")
print(f"  Eval  : {len(eval_df):,}  rows  (attacks: {eval_df['label'].sum():,})")
cicids_attack_pct = 100 * eval_df['label'].sum() / len(eval_df)
print(f"  ⚠  Class imbalance: {cicids_attack_pct:.2f}% attacks  "
      f"({100-cicids_attack_pct:.2f}% normal)")
print(f"  ⚠  Dummy classifier baseline (predict all normal): "
      f"{100*(1 - eval_df['label'].mean()):.2f}% accuracy")

# ── Load JSONL raw data ────────────────────────────────────────────
print("\n[2/6] Re-extracting JSONL raw features...")
import json as _json
RAW_DIR       = ROOT / "traffic_data/raw"
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

print("\n[3/6] Loading models...")
controller   = IDSController()
rf_model     = controller.rf
rf_features  = controller.rf_features
xgb_model    = controller.xgb
xgb_features = controller.xgb_features
crs_engine   = controller.crs
print("  ✓ All models loaded")


# ══════════════════════════════════════════════════════════════════
# 3. CRS Validation
# ══════════════════════════════════════════════════════════════════

print("\n[4/6] Validating models...\n")
print("─"*60)
print("  A) CRS Rule Engine  [CICIDS eval — imbalanced]")
print("─"*60)

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
    "CRS Rule Engine — Confusion Matrix (CICIDS)", "crs_confusion_matrix.png")
record_metrics("CRS", y_true_crs, crs_preds)


# ══════════════════════════════════════════════════════════════════
# 4. Random Forest — CICIDS (imbalanced, shown for comparison)
# ══════════════════════════════════════════════════════════════════

print("\n─"*60)
print("  B) Random Forest  [CICIDS eval — imbalanced]")
print("─"*60)
print("  NOTE: High accuracy expected due to class imbalance.")
print(f"        Dummy baseline = {100*(1-eval_df['label'].mean()):.2f}%\n")

feature_cols_rf = [c for c in rf_features if c in eval_df.columns]
missing_rf      = [c for c in rf_features if c not in eval_df.columns]
if missing_rf:
    print(f"  ⚠ Missing RF features (filling 0): {missing_rf}")

X_eval_rf = eval_df[feature_cols_rf].copy()
for col in missing_rf:
    X_eval_rf[col] = 0.0
X_eval_rf = X_eval_rf[rf_features]

y_true_rf = eval_df["label"].values
rf_proba  = rf_model.predict_proba(X_eval_rf)[:, 1]
rf_preds  = (rf_proba >= 0.5).astype(int)

print(classification_report(y_true_rf, rf_preds,
      target_names=["NORMAL","ATTACK"]))
cm_rf = confusion_matrix(y_true_rf, rf_preds)
plot_confusion_matrix(cm_rf, ["NORMAL","ATTACK"],
    "Random Forest — Confusion Matrix (CICIDS, Imbalanced)",
    "rf_cicids_confusion_matrix.png")

roc_auc_rf = roc_auc_score(y_true_rf, rf_proba)
print(f"  ROC-AUC: {roc_auc_rf:.4f}")
plot_roc(y_true_rf, {"Random Forest (CICIDS)": rf_proba},
    "Random Forest — ROC Curve (CICIDS)", "rf_cicids_roc_curve.png")
record_metrics("RandomForest_CICIDS", y_true_rf, rf_preds, rf_proba)


# ══════════════════════════════════════════════════════════════════
# 5. Full Pipeline — CICIDS
# ══════════════════════════════════════════════════════════════════

print("\n─"*60)
print("  C) Full Pipeline CRS → RF  [CICIDS — imbalanced]")
print("─"*60)

pipeline_preds  = []
pipeline_scores = []
sample_size     = min(5000, len(eval_df))
sample_df       = eval_df.sample(n=sample_size, random_state=42)
y_true_pipe     = sample_df["label"].values

print(f"  Running pipeline on {sample_size:,} samples (sampled for speed)...")

for _, row in sample_df.iterrows():
    features = row.to_dict()
    features.update({
        "url": "", "query_string": "", "body": "",
        "cookie": "none", "method": "GET",
        "content_type": "none", "content_length": 0,
    })
    crs_res = crs_engine.inspect(pd.Series(features))
    if crs_res.anomaly_score >= controller.crs_threshold:
        pipeline_preds.append(1)
        pipeline_scores.append(1.0)
        continue
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
    "Full Pipeline — Confusion Matrix (CICIDS)", "pipeline_confusion_matrix.png")
roc_auc_pipe = roc_auc_score(y_true_pipe, pipeline_scores)
print(f"  ROC-AUC: {roc_auc_pipe:.4f}")

sample_rf_input = (
    sample_df[[c for c in rf_features if c in sample_df.columns]]
    .assign(**{c: 0.0 for c in rf_features if c not in sample_df.columns})
    [rf_features]
)
plot_roc(y_true_pipe,
    {"CRS → RF Pipeline": pipeline_scores,
     "RF alone":          rf_model.predict_proba(sample_rf_input)[:, 1]},
    "Pipeline vs RF Alone — ROC Curve (CICIDS)", "pipeline_vs_rf_roc.png")
record_metrics("Pipeline_CICIDS", y_true_pipe, pipeline_preds, pipeline_scores,
               extra={"sample_size": sample_size})


# ══════════════════════════════════════════════════════════════════
# 6. RF on ECML Balanced — the honest benchmark
# ══════════════════════════════════════════════════════════════════

print("\n─"*60)
print("  D) Random Forest  [ECML Balanced — 50/50 split]")
print("─"*60)
print("  This is the primary honest benchmark.")
print("  Balanced dataset eliminates accuracy inflation from imbalance.\n")

ecml_path = DATA_DIR / "ECML_CV_BALANCED.txt"
if not ecml_path.exists():
    print(f"  ⚠ ECML file not found at {ecml_path} — skipping section D")
else:
    ecml_df = pd.read_csv(ecml_path)
    print(f"  ECML total  : {len(ecml_df):,} rows")
    print(f"  Attack ratio: {100*ecml_df['label'].mean():.1f}%  "
          f"(normal: {100*(1-ecml_df['label'].mean()):.1f}%)")

    # Align features
    ecml_feats_present = [c for c in rf_features if c in ecml_df.columns]
    ecml_feats_missing = [c for c in rf_features if c not in ecml_df.columns]
    if ecml_feats_missing:
        print(f"  ⚠ Missing features (filling 0): {ecml_feats_missing}")

    X_ecml = ecml_df[ecml_feats_present].copy()
    for col in ecml_feats_missing:
        X_ecml[col] = 0.0
    X_ecml = X_ecml[rf_features]
    y_ecml = ecml_df["label"]

    # Stratified 80/20 split
    X_tr, X_val, y_tr, y_val = train_test_split(
        X_ecml, y_ecml, test_size=0.2, random_state=42, stratify=y_ecml
    )
    print(f"  Train split : {len(X_tr):,}  Val split: {len(X_val):,}")

    # ── Zero-shot: original model, no fine-tuning ──────────────────
    print("\n  [D.1] Zero-shot (original RF, no fine-tuning):")
    proba_zs = rf_model.predict_proba(X_val)[:, 1]
    preds_zs = (proba_zs >= 0.5).astype(int)
    print(classification_report(y_val, preds_zs,
          target_names=["NORMAL","ATTACK"]))
    print(f"  Accuracy: {accuracy_score(y_val, preds_zs):.4f}  "
          f"ROC-AUC: {roc_auc_score(y_val, proba_zs):.4f}")
    record_metrics("RF_ECML_ZeroShot", y_val, preds_zs, proba_zs)

    # ── Fine-tuned on ECML train ───────────────────────────────────
    print("\n  [D.2] Fine-tuned RF on ECML train split:")
    rf_ecml = RandomForestClassifier(
        n_estimators=rf_model.n_estimators,
        max_depth=rf_model.max_depth,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf_ecml.fit(X_tr, y_tr)

    proba_ft = rf_ecml.predict_proba(X_val)[:, 1]
    preds_ft = (proba_ft >= 0.5).astype(int)

    print(classification_report(y_val, preds_ft,
          target_names=["NORMAL","ATTACK"]))
    cm_ecml = confusion_matrix(y_val, preds_ft)
    print(f"  Accuracy : {accuracy_score(y_val, preds_ft):.4f}")
    print(f"  ROC-AUC  : {roc_auc_score(y_val, proba_ft):.4f}")
    print(f"  Confusion matrix:\n{cm_ecml}")

    plot_confusion_matrix(cm_ecml, ["NORMAL","ATTACK"],
        "Random Forest — Confusion Matrix\n(ECML Balanced, Fine-tuned)",
        "rf_ecml_confusion_matrix.png")

    plot_roc(y_val,
        {"RF Zero-shot":   proba_zs,
         "RF Fine-tuned":  proba_ft},
        "Random Forest — ROC Curve (ECML Balanced)",
        "rf_ecml_roc_curve.png")

    record_metrics("RF_ECML_Finetuned", y_val, preds_ft, proba_ft)

    # Save fine-tuned model
    joblib.dump(rf_ecml, MODEL_DIR / "rf_finetuned_ecml.pkl")
    print(f"\n  ✓ Fine-tuned model saved → models/rf_finetuned_ecml.pkl")

    # ── Per-attack-class breakdown ─────────────────────────────────
    print("\n  [D.3] Per-attack-class detection rate (fine-tuned RF):")
    val_idx    = X_val.index
    ecml_val   = ecml_df.loc[val_idx].copy()
    ecml_val["predicted"] = preds_ft

    attack_classes = ecml_val[ecml_val["label"] == 1]["attack_class"].unique()
    class_results  = {}

    for cls in sorted(attack_classes):
        subset   = ecml_val[ecml_val["attack_class"] == cls]
        detected = int(subset["predicted"].sum())
        total    = len(subset)
        rate     = 100 * detected / total
        class_results[cls] = {"detected": detected, "total": total, "rate": rate}
        bar = "█" * int(rate / 5)
        print(f"    {cls:<20} {detected:>4}/{total:<4}  {rate:>5.1f}%  {bar}")

    results["RF_ECML_Finetuned"]["per_class"] = class_results

    # ── Per-class bar chart ────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor(PALETTE["bg"])
    ax.set_facecolor(PALETTE["panel"])

    cls_names = list(class_results.keys())
    cls_rates = [class_results[c]["rate"] for c in cls_names]
    cls_totals = [class_results[c]["total"] for c in cls_names]

    bar_colors = [
        PALETTE["green"] if r >= 80 else
        PALETTE["yellow"] if r >= 65 else
        PALETTE["red"]
        for r in cls_rates
    ]
    bars = ax.bar(cls_names, cls_rates, color=bar_colors,
                  edgecolor=PALETTE["bg"], linewidth=1.5)

    for bar, rate, total in zip(bars, cls_rates, cls_totals):
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() + 1,
                f"{rate:.1f}%\n(n={total})",
                ha="center", va="bottom",
                fontsize=9, color=PALETTE["text"], fontweight="bold")

    ax.axhline(y=80, color=PALETTE["subtext"], linestyle="--",
               linewidth=1, alpha=0.7, label="80% threshold")
    ax.set_ylim(0, 115)
    ax.set_xlabel("Attack Class", fontsize=11, labelpad=10)
    ax.set_ylabel("Detection Rate (%)", fontsize=11, labelpad=10)
    ax.set_title("Per-Attack-Class Detection Rate\n(ECML Balanced, Fine-tuned RF)",
                 fontsize=13, pad=15, color=PALETTE["accent"])
    ax.set_xticklabels(cls_names, rotation=20, ha="right", fontsize=10)
    ax.legend(fontsize=9, facecolor=PALETTE["panel"],
              edgecolor=PALETTE["subtext"], labelcolor=PALETTE["text"])
    ax.grid(axis="y", alpha=0.3)
    ax.spines[["top", "right"]].set_visible(False)
    plt.tight_layout()
    path = OUT_DIR / "rf_ecml_per_class.png"
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=PALETTE["bg"])
    plt.close()
    print(f"\n  ✓ Saved: {path.name}")


# ══════════════════════════════════════════════════════════════════
# 7. Combined Summary Plot
# ══════════════════════════════════════════════════════════════════

print("\n─"*60)
print("  E) Combined Summary Chart")
print("─"*60)

# Models to compare in summary
summary_keys   = ["CRS", "RandomForest_CICIDS", "Pipeline_CICIDS", "RF_ECML_Finetuned"]
summary_labels = ["CRS\n(CICIDS)", "RF\n(CICIDS)", "Pipeline\n(CICIDS)", "RF\n(ECML Bal.)"]
summary_keys   = [k for k in summary_keys if k in results]
summary_labels = summary_labels[:len(summary_keys)]

metrics  = ["accuracy", "precision", "recall", "f1"]
fig, axes = plt.subplots(1, 4, figsize=(20, 6))
fig.patch.set_facecolor(PALETTE["bg"])
fig.suptitle("AA-IDS — Model Comparison\n"
             "(Note: CICIDS metrics inflated by class imbalance — "
             "ECML Balanced is the primary benchmark)",
             fontsize=13, color=PALETTE["accent"], y=1.03)

bar_colors = [PALETTE["accent"], PALETTE["green"], PALETTE["yellow"], PALETTE["orange"]]

for i, metric in enumerate(metrics):
    ax = axes[i]
    ax.set_facecolor(PALETTE["panel"])
    vals  = [results[k][metric] for k in summary_keys]
    bars  = ax.bar(summary_labels, vals,
                   color=bar_colors[:len(summary_keys)],
                   width=0.55, edgecolor=PALETTE["bg"], linewidth=1.5)
    for bar, val in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() + 0.01,
                f"{val:.3f}", ha="center", va="bottom",
                fontsize=10, color=PALETTE["text"], fontweight="bold")
    ax.set_ylim(0, 1.18)
    ax.set_title(metric.upper(), fontsize=12, color=PALETTE["accent"], pad=10)
    ax.set_xticklabels(summary_labels, rotation=10, ha="right", fontsize=9)
    ax.grid(axis="y", alpha=0.3)
    ax.spines[["top","right"]].set_visible(False)

plt.tight_layout()
summary_path = OUT_DIR / "model_comparison.png"
plt.savefig(summary_path, dpi=150, bbox_inches="tight", facecolor=PALETTE["bg"])
plt.close()
print(f"  ✓ Saved: {summary_path.name}")


# ══════════════════════════════════════════════════════════════════
# 8. Save JSON results
# ══════════════════════════════════════════════════════════════════

json_path = OUT_DIR / "validation_results.json"
with open(json_path, "w") as f:
    json.dump(results, f, indent=2)
print(f"\n  ✓ All metrics saved → {json_path}")


# ══════════════════════════════════════════════════════════════════
# 9. Final summary table
# ══════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("  VALIDATION SUMMARY")
print("="*70)
print(f"{'Model':<30} {'Acc':>7} {'Prec':>7} {'Rec':>7} {'F1':>7} {'AUC':>7}")
print("-"*70)

display = [
    ("CRS",                   "CRS Rule Engine (CICIDS)"),
    ("RandomForest_CICIDS",   "RF — CICIDS  [imbalanced]"),
    ("Pipeline_CICIDS",       "Pipeline CRS→RF (CICIDS)"),
    ("RF_ECML_ZeroShot",      "RF — ECML zero-shot"),
    ("RF_ECML_Finetuned",     "RF — ECML fine-tuned ★"),
]

for key, label in display:
    if key not in results:
        continue
    r   = results[key]
    auc = f"{r['roc_auc']:.4f}" if "roc_auc" in r else "  N/A "
    print(f"{label:<30} {r['accuracy']:>7.4f} {r['precision']:>7.4f} "
          f"{r['recall']:>7.4f} {r['f1']:>7.4f} {auc:>7}")

print("="*70)
print("\n  ★ RF — ECML fine-tuned is the primary evaluation metric.")
print("    CICIDS results are shown to demonstrate class imbalance effects.")
print(f"\n✓ All outputs saved to: {OUT_DIR}/")
print("  Files:")
for f in sorted(OUT_DIR.iterdir()):
    print(f"    {f.name}")