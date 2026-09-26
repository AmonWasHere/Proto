from rewardaudit.repeats import aggregate


def _e1_result(model, flips, per_pair):
    runs = [
        {
            "flip_rate": f,
            "naive_coverage": f,
            "vuln_only": f * 10,
            "both": 0.0,
            "neither": 10.0 - f * 10,
            "n": 10,
            "per_pair": per_pair,
        }
        for f in flips
    ]
    return {"model": model, "experiment": "e1", "k": len(flips), "runs": runs}


def _cal_result(model, detections):
    runs = [
        {
            "detection_rate": d,
            "false_negative_rate": 1 - d,
            "fixed_side_fp_rate": 0.0,
            "accuracy": 0.8,
            "ece": 0.05,
            "abstention_rate": 0.5,
            "n": 10,
        }
        for d in detections
    ]
    return {"model": model, "experiment": "calibrate", "k": len(detections), "runs": runs}


def test_aggregate_e1_reports_mean_and_ci():
    raw = [
        _e1_result("a", [0.5, 0.5, 0.5], {"p1": True, "p2": False}),
        _e1_result("b", [0.2, 0.2, 0.2], {"p1": True, "p2": True}),
    ]
    agg = aggregate(raw, "e1")
    a = agg["models"]["a"]["metrics"]["flip_rate"]
    assert abs(a["mean"] - 0.5) < 1e-9
    assert a["lo"] <= a["mean"] <= a["hi"]
    assert agg["models"]["a"]["n"] == 10


def test_aggregate_e1_mcnemar_on_discordant_pairs():
    raw = [
        _e1_result("a", [0.5], {"p1": True, "p2": False}),
        _e1_result("b", [0.5], {"p1": True, "p2": True}),
    ]
    agg = aggregate(raw, "e1")
    comparison = agg["comparison"]
    assert comparison["a"] == "a" and comparison["b"] == "b"
    assert comparison["b_only"] == 1 and comparison["a_only"] == 0
    assert comparison["mcnemar_p"] == 1.0  # one discordant pair cannot be significant


def test_aggregate_calibrate_metrics():
    raw = [_cal_result("a", [0.4, 0.4, 0.4])]
    agg = aggregate(raw, "calibrate")
    metrics = agg["models"]["a"]["metrics"]
    assert abs(metrics["detection_rate"]["mean"] - 0.4) < 1e-9
    assert abs(metrics["false_negative_rate"]["mean"] - 0.6) < 1e-9
    assert "comparison" not in agg  # only one model
