"""
pipeline.py
===========
AA-IDS — Full Pipeline Orchestrator
-------------------------------------
Runs all 3 stages of the AI-Augmented IDS pipeline in order:

  Stage 1 — Data Preparation & Feature Engineering
  Stage 2 — OWASP CRS Rule-Based Detection
  Stage 3 — ML Models (Random Forest + XGBoost)

Usage
-----
    python pipeline.py                        # run all stages
    python pipeline.py --stage 1              # run only Stage 1
    python pipeline.py --stage 2              # run only Stage 2
    python pipeline.py --stage 3              # run only Stage 3
    python pipeline.py --threshold 8          # custom CRS threshold (Stage 2)
    python pipeline.py --data path/to/raw.csv # custom raw data path

Directory Layout Expected
--------------------------
    data/
      raw/csic/csic_database.csv   ← raw input
      cleaned/                     ← Stage 1 intermediate output
      features/                    ← Stage 1 feature matrix
      final/                       ← Stage 1 final train/test splits
    pipeline/
      data/                        ← converted data prep scripts
      rule_engine/                 ← CRS engine files
      ml_model/                    ← converted ML training scripts
    results/                       ← Stage 2 + Stage 3 outputs
"""

import argparse
import os
import sys
import subprocess
import time
import textwrap
from pathlib import Path

# ── Terminal colours ─────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def log(msg, colour=CYAN):
    print(f"{colour}{msg}{RESET}")

def success(msg):
    print(f"{GREEN}  ✓  {msg}{RESET}")

def warn(msg):
    print(f"{YELLOW}  ⚠  {msg}{RESET}")

def error(msg):
    print(f"{RED}  ✗  {msg}{RESET}")

def section(title):
    width = 60
    print(f"\n{BOLD}{'═' * width}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'═' * width}{RESET}\n")

def step(n, total, msg):
    print(f"{CYAN}  [{n}/{total}] {msg}...{RESET}")

# ── Path helpers ─────────────────────────────────────────────────

ROOT         = Path(__file__).parent
PIPELINE_DIR = ROOT / "pipeline"
DATA_DIR     = ROOT / "data"
RESULTS_DIR  = ROOT / "results"

PATHS = {
    # Stage 1 inputs / outputs
    "raw_csv":            DATA_DIR / "raw/csic_database.csv",
    "cleaned_csv":        DATA_DIR / "cleaned/csic_cleaned_final.csv",
    "feature_matrix":     DATA_DIR / "features/feature_matrix.csv",
    "train_csv":          DATA_DIR / "final/train.csv",
    "test_csv":           DATA_DIR / "final/test.csv",
    "scaler":             DATA_DIR / "final/scaler.pkl",
    "feature_names":      DATA_DIR / "final/feature_names.txt",

    # Stage 3 intermediate
    "train_attacks_only": ROOT / "train_attacks_only.csv",
    "test_attacks_only":  ROOT / "test_attacks_only.csv",

    # Pipeline scripts
    "data_clean_nb":      ROOT / "notebooks/data_exploration.ipynb",
    "feature_eng_nb":     ROOT / "notebooks/cleaning_data.ipynb",
    "data_clean_py":      PIPELINE_DIR / "data/data_exploration.py",
    "feature_eng_py":     PIPELINE_DIR / "data/cleaning_data.py",

    "crs_engine":         PIPELINE_DIR / "rule_engine/crs_engine.py",
    "crs_rules":          PIPELINE_DIR / "rule_engine/crs_rules.py",
    "evaluate_crs":       PIPELINE_DIR / "rule_engine/evaluate_crs.py",

    "train1_nb":          ROOT / "src/detection/train1.ipynb",
    "train2_nb":          ROOT / "src/detection/train2.ipynb",
    "train1_py":          PIPELINE_DIR / "ml_model/train1.py",
    "train2_py":          PIPELINE_DIR / "ml_model/train2.py",
    "file_manip_py":      ROOT / "src/detection/file_manuplation2.py",
}


# ════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════

def ensure_dirs():
    """Create all required output directories."""
    for d in [
        DATA_DIR / "cleaned",
        DATA_DIR / "features",
        DATA_DIR / "final",
        PIPELINE_DIR / "data",
        PIPELINE_DIR / "rule_engine",
        PIPELINE_DIR / "ml_model",
        RESULTS_DIR,
    ]:
        d.mkdir(parents=True, exist_ok=True)


def run_cmd(cmd: list, cwd=None, desc="") -> bool:
    """Run a shell command, stream output, return True on success."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd or ROOT,
            check=True,
            text=True,
        )
        return True
    except subprocess.CalledProcessError as e:
        error(f"Command failed: {' '.join(cmd)}")
        if e.stderr:
            print(e.stderr)
        return False


def convert_notebook(nb_path: Path, out_path: Path) -> bool:
    """Convert a .ipynb notebook to a .py script via nbconvert."""
    if not nb_path.exists():
        warn(f"Notebook not found: {nb_path}")
        return False

    out_path.parent.mkdir(parents=True, exist_ok=True)
    stem = out_path.stem

    ok = run_cmd([
        "jupyter", "nbconvert",
        "--to", "script",
        str(nb_path),
        "--output", str(out_path.parent / stem),
    ])
    if ok:
        success(f"Converted {nb_path.name} → {out_path}")
    return ok


def check_file(path: Path, label: str) -> bool:
    """Assert a required file exists; log result."""
    if path.exists():
        success(f"{label} found  ({path})")
        return True
    error(f"{label} missing → {path}")
    return False


# ════════════════════════════════════════════════════════════════
# Stage 1 — Data Preparation & Feature Engineering
# ════════════════════════════════════════════════════════════════

def run_stage1(raw_csv: Path) -> bool:
    section("STAGE 1 — Data Preparation & Feature Engineering")

    # ── Check if outputs already exist → skip re-processing ──
    already_done = all([
        PATHS["cleaned_csv"].exists(),
        PATHS["train_csv"].exists(),
        PATHS["test_csv"].exists(),
        PATHS["scaler"].exists(),
    ])
    if already_done:
        success("All Stage 1 outputs already exist — skipping re-processing")
        success(f"cleaned : {PATHS['cleaned_csv']}")
        success(f"train   : {PATHS['train_csv']}")
        success(f"test    : {PATHS['test_csv']}")
        success(f"scaler  : {PATHS['scaler']}")
        return True

    # ── 1a. Validate raw input ────────────────────────────────
    step(1, 4, "Checking raw dataset")
    if not check_file(raw_csv, "Raw CSV"):
        error(f"Place the raw CSIC dataset at:\n       {raw_csv}")
        return False

    # ── 1b. Convert notebooks → .py ──────────────────────────
    step(2, 4, "Converting notebooks to scripts")

    nb_clean   = PATHS["data_clean_nb"]
    nb_feature = PATHS["feature_eng_nb"]
    py_clean   = PATHS["data_clean_py"]
    py_feature = PATHS["feature_eng_py"]

    if not nb_clean.exists() or not nb_feature.exists():
        error("One or more Stage 1 notebooks are missing.")
        error(f"  Expected: {nb_clean}")
        error(f"  Expected: {nb_feature}")
        return False

    convert_notebook(nb_clean,   py_clean)
    convert_notebook(nb_feature, py_feature)

    # ── 1c. Run data cleaning ─────────────────────────────────
    step(3, 4, "Running data cleaning (data_exploration)")
    log(f"  Input  : {raw_csv}")
    log(f"  Output : {PATHS['cleaned_csv']}")

    # Patch the hardcoded path in the converted script before running
    _patch_paths(py_clean, {
        "../data/raw/csic/csic_database.csv": str(raw_csv),
        "../data/cleaned/csic_cleaned_final.csv": str(PATHS["cleaned_csv"]),
    })

    ok = run_cmd([sys.executable, str(py_clean)], cwd=ROOT)
    if not ok:
        return False
    if not check_file(PATHS["cleaned_csv"], "Cleaned CSV"):
        return False

    # ── 1d. Run feature engineering ───────────────────────────
    step(4, 4, "Running feature engineering (cleaning_data)")
    log(f"  Input  : {PATHS['cleaned_csv']}")
    log(f"  Outputs: train.csv, test.csv, scaler.pkl, feature_names.txt")

    _patch_paths(py_feature, {
        "../data/cleaned/csic_cleaned_final.csv": str(PATHS["cleaned_csv"]),
        "../data/features/feature_matrix.csv":    str(PATHS["feature_matrix"]),
        "../data/final/train.csv":                str(PATHS["train_csv"]),
        "../data/final/test.csv":                 str(PATHS["test_csv"]),
        "../data/final/scaler.pkl":               str(PATHS["scaler"]),
        "../data/final/feature_names.txt":        str(PATHS["feature_names"]),
    })

    ok = run_cmd([sys.executable, str(py_feature)], cwd=ROOT)
    if not ok:
        return False

    # Validate outputs
    all_ok = all([
        check_file(PATHS["train_csv"],      "train.csv"),
        check_file(PATHS["test_csv"],       "test.csv"),
        check_file(PATHS["scaler"],         "scaler.pkl"),
        check_file(PATHS["feature_names"],  "feature_names.txt"),
    ])

    if all_ok:
        success("Stage 1 complete — all outputs verified")
    return all_ok


# ════════════════════════════════════════════════════════════════
# Stage 2 — OWASP CRS Rule-Based Detection
# ════════════════════════════════════════════════════════════════

def run_stage2(threshold: int) -> bool:
    section("STAGE 2 — OWASP CRS Rule-Based Detection")

    # ── 2a. Check prerequisites ───────────────────────────────
    step(1, 3, "Checking prerequisites")
    if not check_file(PATHS["test_csv"], "test.csv"):
        error("Run Stage 1 first to generate test.csv")
        return False

    for f in ["crs_engine", "crs_rules", "evaluate_crs"]:
        if not check_file(PATHS[f], f):
            return False

    # ── 2b. Run engine evaluation ─────────────────────────────
    step(2, 3, f"Running CRS engine (threshold={threshold})")
    log(f"  Input  : {PATHS['test_csv']}")
    log(f"  Output : {RESULTS_DIR}/")

    ok = run_cmd([
        sys.executable,
        str(PATHS["evaluate_crs"]),
        "--data",      str(PATHS["test_csv"]),
        "--threshold", str(threshold),
    ], cwd=PIPELINE_DIR / "rule_engine")

    if not ok:
        return False

    # ── 2c. Validate outputs ──────────────────────────────────
    step(3, 3, "Validating outputs")
    rule_results = PIPELINE_DIR / "rule_engine" / "results"
    expected = [
        "confusion_matrix.png",
        "metrics_bar.png",
        "score_distribution.png",
        "threshold_sweep.png",
        "attack_breakdown.png",
        "predictions.csv",
        "metrics_summary.txt",
    ]
    all_ok = True
    for f in expected:
        path = rule_results / f
        if path.exists():
            success(f"{f}")
        else:
            warn(f"{f} not found")
            all_ok = False

    if all_ok:
        success("Stage 2 complete — all outputs verified")
    return all_ok


# ════════════════════════════════════════════════════════════════
# Stage 3 — ML Models
# ════════════════════════════════════════════════════════════════

def run_stage3() -> bool:
    section("STAGE 3 — ML Models (Random Forest + XGBoost)")

    # ── 3a. Check prerequisites ───────────────────────────────
    step(1, 5, "Checking prerequisites")
    if not check_file(PATHS["train_csv"], "train.csv") or \
       not check_file(PATHS["test_csv"],  "test.csv"):
        error("Run Stage 1 first to generate train/test splits")
        return False

    # ── 3b. Generate attacks-only files ──────────────────────
    step(2, 5, "Generating attacks-only datasets (file_manuplation2.py)")
    log(f"  Input  : train.csv + test.csv")
    log(f"  Output : train_attacks_only.csv + test_attacks_only.csv")

    file_manip = PATHS["file_manip_py"]
    if not file_manip.exists():
        error(f"file_manuplation2.py not found at {file_manip}")
        return False

    # Patch hardcoded absolute paths
    _patch_paths(file_manip, {
        "/home/rashid/Documents/FYP/Ai-Augumented-IDS/data/final/train.csv":
            str(PATHS["train_csv"]),
        "/home/rashid/Documents/FYP/Ai-Augumented-IDS/data/final/test.csv":
            str(PATHS["test_csv"]),
        "/home/rashid/Documents/FYP/Ai-Augumented-IDS/train_attacks_only.csv":
            str(PATHS["train_attacks_only"]),
        "/home/rashid/Documents/FYP/Ai-Augumented-IDS/test_attacks_only.csv":
            str(PATHS["test_attacks_only"]),
    })

    ok = run_cmd([sys.executable, str(file_manip)], cwd=ROOT)
    if not ok:
        return False

    check_file(PATHS["train_attacks_only"], "train_attacks_only.csv")
    check_file(PATHS["test_attacks_only"],  "test_attacks_only.csv")

    # ── 3c. Convert ML notebooks → .py ───────────────────────
    step(3, 5, "Converting ML notebooks to scripts")
    convert_notebook(PATHS["train1_nb"], PATHS["train1_py"])
    convert_notebook(PATHS["train2_nb"], PATHS["train2_py"])

    # ── 3d. Run Random Forest (train1) ────────────────────────
    step(4, 5, "Training Random Forest — binary classification")
    log(f"  Input  : train.csv + test.csv")
    log(f"  Task   : Normal (0) vs Attack (1)")

    _patch_paths(PATHS["train1_py"], {
        "/home/rashid/Documents/FYP/Ai-Augumented-IDS/data/final/train.csv":
            str(PATHS["train_csv"]),
        "/home/rashid/Documents/FYP/Ai-Augumented-IDS/data/final/test.csv":
            str(PATHS["test_csv"]),
    })

    ok = run_cmd([sys.executable, str(PATHS["train1_py"])], cwd=ROOT)
    if not ok:
        warn("Random Forest training encountered an issue — check output above")

    # ── 3e. Run XGBoost (train2) ──────────────────────────────
    step(5, 5, "Training XGBoost — multi-class attack classification")
    log(f"  Input  : train_attacks_only.csv + test_attacks_only.csv")
    log(f"  Task   : SQLi | XSS | Path Traversal | Other")

    _patch_paths(PATHS["train2_py"], {
        "/home/rashid/Documents/FYP/Ai-Augumented-IDS/train_attacks_only.csv":
            str(PATHS["train_attacks_only"]),
        "/home/rashid/Documents/FYP/Ai-Augumented-IDS/test_attacks_only.csv":
            str(PATHS["test_attacks_only"]),
    })

    ok = run_cmd([sys.executable, str(PATHS["train2_py"])], cwd=ROOT)
    if not ok:
        warn("XGBoost training encountered an issue — check output above")
        return False

    success("Stage 3 complete")
    return True


# ════════════════════════════════════════════════════════════════
# Path patcher — fixes hardcoded absolute paths in scripts
# ════════════════════════════════════════════════════════════════

def _patch_paths(script_path: Path, replacements: dict) -> None:
    """Replace hardcoded paths in a script with portable ones."""
    if not script_path.exists():
        return
    text = script_path.read_text()
    changed = False
    for old, new in replacements.items():
        if old in text:
            text = text.replace(old, new)
            changed = True
    if changed:
        script_path.write_text(text)
        log(f"  Patched paths in {script_path.name}", YELLOW)


# ════════════════════════════════════════════════════════════════
# Summary
# ════════════════════════════════════════════════════════════════

def print_summary(stages_run: dict, elapsed: float) -> None:
    section("PIPELINE SUMMARY")
    for stage, (ok, label) in stages_run.items():
        status = f"{GREEN}PASSED{RESET}" if ok else f"{RED}FAILED{RESET}"
        print(f"  {stage:<10}  {label:<45}  {status}")
    print(f"\n  Total time: {elapsed:.1f}s\n")


# ════════════════════════════════════════════════════════════════
# Entry point
# ════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="AA-IDS Full Pipeline Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Examples:
              python pipeline.py               # run all 3 stages
              python pipeline.py --stage 1     # data prep only
              python pipeline.py --stage 2     # CRS engine only
              python pipeline.py --stage 3     # ML models only
              python pipeline.py --threshold 8 # stricter CRS threshold
        """)
    )
    parser.add_argument(
        "--stage", type=int, choices=[1, 2, 3],
        help="Run only this stage (default: all stages)"
    )
    parser.add_argument(
        "--threshold", type=int, default=5,
        help="CRS anomaly score threshold for Stage 2 (default: 5)"
    )
    parser.add_argument(
        "--data", type=str,
        default=str(PATHS["raw_csv"]),
        help="Path to raw CSIC CSV (Stage 1 input)"
    )
    args = parser.parse_args()

    raw_csv = Path(args.data)
    t_start = time.time()

    log(f"\n{'═'*60}", BOLD)
    log(f"  AA-IDS Pipeline  —  starting", BOLD)
    log(f"{'═'*60}\n", BOLD)

    ensure_dirs()

    stages_run = {}

    run_all = args.stage is None

    if run_all or args.stage == 1:
        ok = run_stage1(raw_csv)
        stages_run["Stage 1"] = (ok, "Data Preparation & Feature Engineering")
        if not ok and run_all:
            error("Stage 1 failed — aborting pipeline")
            print_summary(stages_run, time.time() - t_start)
            sys.exit(1)

    if run_all or args.stage == 2:
        ok = run_stage2(args.threshold)
        stages_run["Stage 2"] = (ok, f"CRS Rule Engine (threshold={args.threshold})")

    if run_all or args.stage == 3:
        ok = run_stage3()
        stages_run["Stage 3"] = (ok, "ML Models (Random Forest + XGBoost)")

    print_summary(stages_run, time.time() - t_start)

    all_passed = all(ok for ok, _ in stages_run.values())
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()