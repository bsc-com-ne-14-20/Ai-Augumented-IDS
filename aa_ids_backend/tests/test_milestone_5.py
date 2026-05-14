import json, pathlib, io
from dashboard.csv_parser import parse_csv
from dashboard.report_builder import build_comparison_report

SAMPLE_CSV = pathlib.Path("tests/fixtures/sample_dataset.csv").read_text()

def get_rows():
    rows, _ = parse_csv(io.StringIO(SAMPLE_CSV))
    return rows

def test_report_top_level_keys():
    report = build_comparison_report(get_rows())
    for key in ["dataset", "rule_engine", "ml_engine", "comparison", "row_details"]:
        assert key in report, f"Missing top-level key: {key}"

def test_rule_engine_metrics_present():
    report = build_comparison_report(get_rows())
    re = report["rule_engine"]
    for key in ["total_detections", "total_clean", "detection_rate",
                "attack_type_breakdown", "severity_breakdown",
                "rules_triggered", "top_attacked_paths"]:
        assert key in re, f"Missing rule_engine key: {key}"

def test_ml_engine_metrics_present():
    report = build_comparison_report(get_rows())
    ml = report["ml_engine"]
    for key in ["total_detections", "total_clean", "detection_rate",
                "confidence_stats", "confidence_histogram",
                "top_attacked_paths"]:
        assert key in ml, f"Missing ml_engine key: {key}"

def test_comparison_keys():
    report = build_comparison_report(get_rows())
    cmp = report["comparison"]
    for key in ["both_flagged", "only_rule_flagged", "only_ml_flagged",
                "both_clean", "agreement_rate"]:
        assert key in cmp

def test_counts_add_up():
    report = build_comparison_report(get_rows())
    total = report["dataset"]["total_rows"]
    re = report["rule_engine"]
    assert re["total_detections"] + re["total_clean"] + re["total_errors"] == total
    ml = report["ml_engine"]
    assert ml["total_detections"] + ml["total_clean"] + ml["total_errors"] == total

def test_agreement_rate_is_fraction():
    report = build_comparison_report(get_rows())
    rate = report["comparison"]["agreement_rate"]
    assert 0.0 <= rate <= 1.0

def test_confidence_histogram_has_10_buckets():
    report = build_comparison_report(get_rows())
    hist = report["ml_engine"]["confidence_histogram"]
    assert len(hist) == 10

def test_row_details_capped_at_500():
    report = build_comparison_report(get_rows())
    assert len(report["row_details"]) <= 500

def test_both_engines_run_on_every_row():
    """Neither engine result should affect whether the other runs."""
    rows = get_rows()
    report = build_comparison_report(rows)
    total = report["dataset"]["total_rows"]
    re = report["rule_engine"]
    ml = report["ml_engine"]
    assert re["total_detections"] + re["total_clean"] + re["total_errors"] == total
    assert ml["total_detections"] + ml["total_clean"] + ml["total_errors"] == total
