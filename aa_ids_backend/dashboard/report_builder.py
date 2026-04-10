import time
import statistics

from pipeline.orchestrator import run_independent_comparison
import config

def build_comparison_report(raw_rows: list[dict]) -> dict:
    """
    Calls run_independent_comparison, then computes all metrics.
    Returns the full report dict consumed by the dashboard template.
    """
    start = time.perf_counter_ns()
    out = run_independent_comparison(raw_rows)
    results = out["results"]
    duration_ms = int((time.perf_counter_ns() - start) / 1_000_000)

    dataset = {
        "total_rows": len(raw_rows),
        "processing_time_ms": duration_ms,
        "csv_filename": "",
    }

    rule_engine = {
        "engine_name": "Rule-Based Engine (OWASP-Inspired)",
        "total_detections": 0,
        "total_clean": 0,
        "total_errors": 0,
        "detection_rate": 0.0,
        "attack_type_breakdown": {},
        "severity_breakdown": {},
        "rules_triggered": {},
        "top_attacked_paths": [],
        "top_attacked_methods": {}
    }

    ml_engine = {
        "engine_name": "ML Anomaly Detector",
        "total_detections": 0,
        "total_clean": 0,
        "total_errors": 0,
        "detection_rate": 0.0,
        "attack_type_breakdown": {},
        "severity_breakdown": {},
        "confidence_stats": {
            "mean": 0.0,
            "median": 0.0,
            "min": 0.0,
            "max": 0.0,
            "std": 0.0,
        },
        "confidence_histogram": [],
        "top_attacked_paths": [],
        "top_attacked_methods": {}
    }

    comparison = {
        "both_flagged": 0,
        "only_rule_flagged": 0,
        "only_ml_flagged": 0,
        "both_clean": 0,
        "agreement_rate": 0.0,
        "disagreement_rate": 0.0
    }

    row_details = []

    rule_path_counts = {}
    ml_path_counts = {}
    ml_confidences = []

    row_cap = config.ROW_DETAILS_CAP

    for idx, (raw, res) in enumerate(zip(raw_rows, results)):
        rule = res["rule_result"]
        ml = res["ml_result"]

        rule_verdict = rule.get("verdict", "CLEAN")
        ml_verdict = ml.get("verdict", "CLEAN")

        # Rule Engine totals
        if rule_verdict == "ATTACK":
            rule_engine["total_detections"] += 1
        elif rule_verdict == "CLEAN":
            rule_engine["total_clean"] += 1
        else:
            rule_engine["total_errors"] += 1

        # ML Engine totals
        if ml_verdict == "ANOMALY":
            ml_engine["total_detections"] += 1
        elif ml_verdict == "CLEAN":
            ml_engine["total_clean"] += 1
        else:
            ml_engine["total_errors"] += 1

        # Breakdowns
        if rule_verdict == "ATTACK":
            atype = rule.get("attack_type", "UNKNOWN")
            rule_engine["attack_type_breakdown"][atype] = rule_engine["attack_type_breakdown"].get(atype, 0) + 1
            
            sev = rule.get("severity", "medium")
            rule_engine["severity_breakdown"][sev] = rule_engine["severity_breakdown"].get(sev, 0) + 1
            
            rt = rule.get("rule_triggered", "unknown")
            rule_engine["rules_triggered"][rt] = rule_engine["rules_triggered"].get(rt, 0) + 1

            path = raw.get("path", "")
            rule_path_counts[path] = rule_path_counts.get(path, 0) + 1

            meth = raw.get("method", "OTHER")
            rule_engine["top_attacked_methods"][meth] = rule_engine["top_attacked_methods"].get(meth, 0) + 1

        if ml_verdict == "ANOMALY":
            atype = ml.get("attack_type", "UNKNOWN_ANOMALY")
            ml_engine["attack_type_breakdown"][atype] = ml_engine["attack_type_breakdown"].get(atype, 0) + 1
            
            sev = ml.get("severity", "medium")
            ml_engine["severity_breakdown"][sev] = ml_engine["severity_breakdown"].get(sev, 0) + 1
            
            path = raw.get("path", "")
            ml_path_counts[path] = ml_path_counts.get(path, 0) + 1

            meth = raw.get("method", "OTHER")
            ml_engine["top_attacked_methods"][meth] = ml_engine["top_attacked_methods"].get(meth, 0) + 1

        conf = ml.get("confidence")
        if conf is not None:
            try:
                ml_confidences.append(float(conf))
            except ValueError:
                pass

        # Comparison agreement
        rf = (rule_verdict == "ATTACK")
        mf = (ml_verdict == "ANOMALY")

        if rf and mf:
            comparison["both_flagged"] += 1
        elif rf and not mf:
            comparison["only_rule_flagged"] += 1
        elif mf and not rf:
            comparison["only_ml_flagged"] += 1
        else:
            comparison["both_clean"] += 1

        agreement = (rf == mf)

        if len(row_details) < row_cap:
            row_details.append({
                "row_index": idx + 1,
                "method": raw.get("method", "OTHER"),
                "path": raw.get("path", ""),
                "rule_verdict": rule_verdict,
                "rule_attack_type": rule.get("attack_type"),
                "rule_severity": rule.get("severity"),
                "ml_verdict": ml_verdict,
                "ml_confidence": ml.get("confidence"),
                "agreement": agreement,
            })

    total = dataset["total_rows"]
    if total > 0:
        rule_engine["detection_rate"] = rule_engine["total_detections"] / total
        ml_engine["detection_rate"] = ml_engine["total_detections"] / total
        comparison["agreement_rate"] = (comparison["both_flagged"] + comparison["both_clean"]) / total
        comparison["disagreement_rate"] = 1.0 - comparison["agreement_rate"]

    # Top paths
    rule_engine["top_attacked_paths"] = [{"path": k, "count": v} for k, v in sorted(rule_path_counts.items(), key=lambda x: x[1], reverse=True)[:10]]
    ml_engine["top_attacked_paths"] = [{"path": k, "count": v} for k, v in sorted(ml_path_counts.items(), key=lambda x: x[1], reverse=True)[:10]]

    # ML Confidence stats
    if ml_confidences:
        ml_engine["confidence_stats"]["mean"] = statistics.mean(ml_confidences)
        ml_engine["confidence_stats"]["median"] = statistics.median(ml_confidences)
        ml_engine["confidence_stats"]["min"] = min(ml_confidences)
        ml_engine["confidence_stats"]["max"] = max(ml_confidences)
        ml_engine["confidence_stats"]["std"] = statistics.pstdev(ml_confidences) if len(ml_confidences) > 1 else 0.0

    # 10 buckets
    bucket_counts = [0] * 10
    for c in ml_confidences:
        idx = int(c * 10)
        if idx == 10: idx = 9
        if 0 <= idx <= 9: bucket_counts[idx] += 1
    
    hist = []
    for i in range(10):
        low = i / 10.0
        high = (i + 1) / 10.0
        hist.append({"bucket": f"{low:.1f}–{high:.1f}", "count": bucket_counts[i]})
    
    ml_engine["confidence_histogram"] = hist

    return {
        "dataset": dataset,
        "rule_engine": rule_engine,
        "ml_engine": ml_engine,
        "comparison": comparison,
        "row_details": row_details
    }
