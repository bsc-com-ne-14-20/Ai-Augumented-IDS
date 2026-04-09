"""
evaluate_crs.py
===============
CRS Engine Evaluation Script
------------------------------
Runs the OWASP CRS feature-based engine against the CSIC test dataset,
computes all classification metrics, and saves publication-ready plots.

Outputs (all saved to ./results/)
----------------------------------
  confusion_matrix.png        — annotated confusion matrix heatmap
  metrics_bar.png             — precision / recall / F1 / accuracy bar chart
  score_distribution.png      — anomaly score distribution by true label
  threshold_sweep.png         — F1 / precision / recall vs threshold curve
  predictions.csv             — full df with crs_label, crs_score, attack_types
  metrics_summary.txt         — plain-text metrics for your report

Usage
-----
    python evaluate_crs.py                          # default threshold=5
    python evaluate_crs.py --threshold 8            # stricter engine
    python evaluate_crs.py --sweep                  # plot threshold sweep only
    python evaluate_crs.py --data path/to/test.csv  # custom dataset path
"""

import argparse
import os
import sys
import textwrap

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)

# ── local imports ────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
from crs_engine import CRSEngine

# ── global plot style ────────────────────────────────────────────
plt.rcParams.update({
    "figure.dpi":        150,
    "font.family":       "DejaVu Sans",
    "axes.spines.top":   False,
    "axes.spines.right": False,
    "axes.titlesize":    13,
    "axes.labelsize":    11,
})
PALETTE = {"normal": "#4a90d9", "attack": "#e05c5c", "neutral": "#6abf69"}
RESULTS_DIR = "results"


# ════════════════════════════════════════════════════════════════
# Plot 1 — Confusion Matrix
# ════════════════════════════════════════════════════════════════

def plot_confusion_matrix(cm: np.ndarray, path: str, threshold: int) -> None:
    tn, fp, fn, tp = cm.ravel()
    fig, ax = plt.subplots(figsize=(7, 5.5))

    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues", ax=ax,
        xticklabels=["Predicted Normal", "Predicted Attack"],
        yticklabels=["Actual Normal",    "Actual Attack"],
        annot_kws={"size": 16, "weight": "bold"},
        linewidths=0.5, linecolor="#cccccc",
    )
    ax.set_title(f"Confusion Matrix  —  CRS Engine  (threshold={threshold})",
                 pad=14, fontsize=13)

    # Quadrant labels
    for (lbl, r, c) in [("TN", 0, 0), ("FP", 0, 1), ("FN", 1, 0), ("TP", 1, 1)]:
        color = "#2c7bb6" if lbl in ("TN", "TP") else "#d7191c"
        ax.text(c + 0.5, r + 0.78, lbl,
                ha="center", va="center",
                fontsize=11, color=color, style="italic")

    # Rate annotations below matrix
    fpr = fp / (fp + tn) if (fp + tn) else 0
    fnr = fn / (fn + tp) if (fn + tp) else 0
    fig.text(0.5, -0.03,
             f"False Positive Rate: {fpr:.4f}  |  False Negative Rate: {fnr:.4f}",
             ha="center", fontsize=10, color="#555555")

    plt.tight_layout()
    plt.savefig(path, bbox_inches="tight")
    plt.close()
    print(f"  ✓ {path}")


# ════════════════════════════════════════════════════════════════
# Plot 2 — Metrics Bar Chart
# ════════════════════════════════════════════════════════════════

def plot_metrics_bar(metrics: dict, path: str, threshold: int) -> None:
    keys   = ["Accuracy", "Precision", "Recall", "F1 Score"]
    values = [metrics["accuracy"], metrics["precision"],
              metrics["recall"],   metrics["f1"]]
    colors = ["#4a90d9", "#6abf69", "#e08c3c", "#9b59b6"]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    bars = ax.barh(keys, values, color=colors, height=0.5, edgecolor="white")

    for bar, val in zip(bars, values):
        ax.text(val + 0.005, bar.get_y() + bar.get_height() / 2,
                f"{val:.4f}", va="center", ha="left", fontsize=11,
                fontweight="bold")

    ax.set_xlim(0, 1.15)
    ax.set_xlabel("Score")
    ax.set_title(f"CRS Engine — Classification Metrics  (threshold={threshold})")
    ax.axvline(x=0.5, color="#cccccc", linestyle="--", linewidth=1)

    plt.tight_layout()
    plt.savefig(path, bbox_inches="tight")
    plt.close()
    print(f"  ✓ {path}")


# ════════════════════════════════════════════════════════════════
# Plot 3 — Anomaly Score Distribution
# ════════════════════════════════════════════════════════════════

def plot_score_distribution(df: pd.DataFrame, path: str, threshold: int) -> None:
    fig, ax = plt.subplots(figsize=(9, 4.5))

    normal = df[df["label"] == 0]["crs_score"]
    attack = df[df["label"] == 1]["crs_score"]

    max_score = int(df["crs_score"].max()) + 1
    bins = range(0, max_score + 2)

    ax.hist(normal, bins=bins, alpha=0.65, label="Normal (0)",
            color=PALETTE["normal"], edgecolor="white")
    ax.hist(attack, bins=bins, alpha=0.65, label="Attack (1)",
            color=PALETTE["attack"], edgecolor="white")

    ax.axvline(x=threshold, color="#2d2d2d", linestyle="--", linewidth=1.8,
               label=f"Decision threshold = {threshold}")

    ax.set_xlabel("CRS Anomaly Score")
    ax.set_ylabel("Number of Requests")
    ax.set_title("Anomaly Score Distribution by True Label")
    ax.legend(frameon=False)

    # Annotation: overlap region
    ax.text(threshold + 0.2, ax.get_ylim()[1] * 0.9,
            "← classified CLEAN  |  classified ATTACK →",
            fontsize=9, color="#555555")

    plt.tight_layout()
    plt.savefig(path, bbox_inches="tight")
    plt.close()
    print(f"  ✓ {path}")


# ════════════════════════════════════════════════════════════════
# Plot 4 — Threshold Sweep (F1 / Precision / Recall vs threshold)
# ════════════════════════════════════════════════════════════════

def plot_threshold_sweep(df: pd.DataFrame, path: str, current_threshold: int) -> None:
    y_true   = df["label"].astype(int)
    scores   = df["crs_score"].values
    max_score = int(scores.max())

    thresholds  = list(range(0, max_score + 2))
    precisions, recalls, f1s, accuracies = [], [], [], []

    for t in thresholds:
        y_pred = (scores >= t).astype(int)
        precisions.append(precision_score(y_true, y_pred, zero_division=0))
        recalls.append(recall_score(y_true, y_pred, zero_division=0))
        f1s.append(f1_score(y_true, y_pred, zero_division=0))
        accuracies.append(accuracy_score(y_true, y_pred))

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(thresholds, precisions, label="Precision",  color="#4a90d9", lw=2)
    ax.plot(thresholds, recalls,    label="Recall",     color="#e05c5c", lw=2)
    ax.plot(thresholds, f1s,        label="F1 Score",   color="#6abf69", lw=2.5)
    ax.plot(thresholds, accuracies, label="Accuracy",   color="#9b59b6", lw=1.5,
            linestyle="--")

    best_t = thresholds[int(np.argmax(f1s))]
    ax.axvline(x=current_threshold, color="#2d2d2d", linestyle="--", linewidth=1.5,
               label=f"Current threshold = {current_threshold}")
    ax.axvline(x=best_t, color="#f0a500", linestyle=":", linewidth=1.5,
               label=f"Best F1 threshold = {best_t}")

    ax.set_xlabel("Anomaly Score Threshold")
    ax.set_ylabel("Score")
    ax.set_title("Threshold Sweep — CRS Engine")
    ax.set_ylim(0, 1.05)
    ax.legend(frameon=False, loc="lower right")

    plt.tight_layout()
    plt.savefig(path, bbox_inches="tight")
    plt.close()
    print(f"  ✓ {path}")


# ════════════════════════════════════════════════════════════════
# Plot 5 — Attack Type Breakdown
# ════════════════════════════════════════════════════════════════

def plot_attack_breakdown(df: pd.DataFrame, path: str) -> None:
    attack_df = df[df["crs_label"] == 1].copy()
    type_counts: dict = {}
    for types_str in attack_df["crs_attack_types"]:
        for t in str(types_str).split(", "):
            t = t.strip()
            if t and t != "clean":
                type_counts[t] = type_counts.get(t, 0) + 1

    if not type_counts:
        return

    sorted_types  = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
    categories    = [x[0] for x in sorted_types]
    counts        = [x[1] for x in sorted_types]

    colors = plt.cm.Blues(np.linspace(0.4, 0.85, len(categories)))[::-1]

    fig, ax = plt.subplots(figsize=(9, max(3.5, len(categories) * 0.7)))
    bars = ax.barh(categories, counts, color=colors, edgecolor="white", height=0.6)
    for bar, val in zip(bars, counts):
        ax.text(val + max(counts) * 0.01, bar.get_y() + bar.get_height() / 2,
                f"{val:,}", va="center", ha="left", fontsize=10)

    ax.set_xlabel("Number of Requests Flagged")
    ax.set_title("CRS Engine — Attack Type Distribution (Predicted Attacks)")
    ax.invert_yaxis()

    plt.tight_layout()
    plt.savefig(path, bbox_inches="tight")
    plt.close()
    print(f"  ✓ {path}")


# ════════════════════════════════════════════════════════════════
# Metrics computation & text summary
# ════════════════════════════════════════════════════════════════

def compute_metrics(y_true, y_pred) -> dict:
    cm      = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    return dict(
        cm        = cm,
        tn=tn, fp=fp, fn=fn, tp=tp,
        accuracy  = accuracy_score(y_true, y_pred),
        precision = precision_score(y_true, y_pred, zero_division=0),
        recall    = recall_score(y_true, y_pred, zero_division=0),
        f1        = f1_score(y_true, y_pred, zero_division=0),
        fpr       = fp / (fp + tn) if (fp + tn) else 0,
        fnr       = fn / (fn + tp) if (fn + tp) else 0,
        report    = classification_report(
                        y_true, y_pred,
                        target_names=["Normal (0)", "Attack (1)"],
                        digits=4),
    )


def print_and_save_metrics(metrics: dict, threshold: int, save_path: str) -> None:
    lines = [
        "═" * 58,
        f"  OWASP CRS ENGINE — EVALUATION RESULTS",
        f"  Threshold = {threshold}",
        "═" * 58,
        f"  True  Negatives (TN) : {metrics['tn']:>8,}",
        f"  False Positives (FP) : {metrics['fp']:>8,}   ← false alarms",
        f"  False Negatives (FN) : {metrics['fn']:>8,}   ← missed attacks",
        f"  True  Positives (TP) : {metrics['tp']:>8,}",
        "─" * 58,
        f"  Accuracy             : {metrics['accuracy']:.4f}",
        f"  Precision            : {metrics['precision']:.4f}",
        f"  Recall  (TPR)        : {metrics['recall']:.4f}",
        f"  F1 Score             : {metrics['f1']:.4f}",
        f"  False Positive Rate  : {metrics['fpr']:.4f}",
        f"  False Negative Rate  : {metrics['fnr']:.4f}  ← lower is better",
        "─" * 58,
        "",
        "  Per-Class Classification Report:",
        metrics["report"],
        "═" * 58,
    ]
    text = "\n".join(lines)
    print("\n" + text)

    with open(save_path, "w") as f:
        f.write(text)
    print(f"  ✓ {save_path}")


# ════════════════════════════════════════════════════════════════
# Entry point
# ════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Evaluate OWASP CRS engine against the CSIC test dataset"
    )
    parser.add_argument("--data",      default="test.csv",
                        help="Path to the test CSV (default: test.csv)")
    parser.add_argument("--threshold", default=5, type=int,
                        help="CRS anomaly score threshold (default: 5)")
    parser.add_argument("--sweep",     action="store_true",
                        help="Only run the threshold sweep plot (fast)")
    args = parser.parse_args()

    # ── Setup ────────────────────────────────────────────────────
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # ── Load data ─────────────────────────────────────────────────
    print(f"\nLoading dataset: {args.data}")
    try:
        df = pd.read_csv(args.data)
    except FileNotFoundError:
        print(f"ERROR: File not found → '{args.data}'\n"
              f"Pass the correct path with --data <path>")
        sys.exit(1)

    df["label"] = df["label"].astype(int)
    n_normal = (df["label"] == 0).sum()
    n_attack = (df["label"] == 1).sum()
    print(f"  Rows: {len(df):,}  |  Normal: {n_normal:,}  |  Attack: {n_attack:,}")

    # ── Initialise engine ─────────────────────────────────────────
    engine = CRSEngine(threshold=args.threshold)
    engine.print_rule_summary()

    # ── Run engine ────────────────────────────────────────────────
    print(f"Running CRS engine (threshold={args.threshold}) ...")
    results_df = engine.run(df)

    y_true = results_df["label"].astype(int)
    y_pred = results_df["crs_label"].astype(int)

    # ── Compute metrics ───────────────────────────────────────────
    metrics = compute_metrics(y_true, y_pred)

    print_and_save_metrics(
        metrics,
        threshold=args.threshold,
        save_path=os.path.join(RESULTS_DIR, "metrics_summary.txt"),
    )

    if args.sweep:
        # Only sweep plot
        plot_threshold_sweep(
            results_df,
            path=os.path.join(RESULTS_DIR, "threshold_sweep.png"),
            current_threshold=args.threshold,
        )
        print("\nSweep plot saved. Done.\n")
        return

    # ── Save all plots ────────────────────────────────────────────
    print("\nGenerating plots...")

    plot_confusion_matrix(
        metrics["cm"],
        path=os.path.join(RESULTS_DIR, "confusion_matrix.png"),
        threshold=args.threshold,
    )
    plot_metrics_bar(
        metrics,
        path=os.path.join(RESULTS_DIR, "metrics_bar.png"),
        threshold=args.threshold,
    )
    plot_score_distribution(
        results_df,
        path=os.path.join(RESULTS_DIR, "score_distribution.png"),
        threshold=args.threshold,
    )
    plot_threshold_sweep(
        results_df,
        path=os.path.join(RESULTS_DIR, "threshold_sweep.png"),
        current_threshold=args.threshold,
    )
    plot_attack_breakdown(
        results_df,
        path=os.path.join(RESULTS_DIR, "attack_breakdown.png"),
    )

    # ── Save predictions CSV ──────────────────────────────────────
    out_csv = os.path.join(RESULTS_DIR, "predictions.csv")
    results_df.to_csv(out_csv, index=False)
    print(f"  ✓ {out_csv}")

    print(f"\n  All outputs saved to ./{RESULTS_DIR}/")
    print("  Done.\n")


if __name__ == "__main__":
    main()
