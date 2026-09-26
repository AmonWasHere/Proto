from rewardaudit.calibration import (
    Point,
    analyze,
    expected_calibration_error,
    selective_risk,
)


def _p(conf, correct, side, flagged, disp="true_positive"):
    return Point(conf, correct, side, flagged, disp)


def test_ece_zero_when_confidence_matches_accuracy():
    # All points at confidence 1.0 and all correct -> ECE 0.
    points = [_p(1.0, True, "vuln", True) for _ in range(4)]
    assert expected_calibration_error(points, bins=5) == 0.0


def test_ece_positive_when_overconfident():
    points = [_p(1.0, False, "vuln", False) for _ in range(4)]
    assert expected_calibration_error(points, bins=5) == 1.0


def test_selective_risk_trades_coverage_for_risk():
    points = [
        _p(0.9, True, "vuln", True),
        _p(0.8, True, "vuln", True),
        _p(0.2, False, "fixed", True),
    ]
    rows = {row["threshold"]: row for row in selective_risk(points, (0.0, 0.5, 0.9))}
    assert rows[0.0]["coverage"] == 1.0
    assert abs(rows[0.5]["risk"] - 0.0) < 1e-9  # the wrong point is dropped
    assert rows[0.9]["coverage"] == 1 / 3


def test_analyze_reports_fnr_and_fp_and_abstention():
    points = [
        _p(0.9, True, "vuln", True),
        _p(0.0, False, "vuln", False, disp="unknown_risk"),
        _p(0.9, False, "fixed", True),  # false positive on the fixed side
        _p(0.8, True, "fixed", False),
    ]
    result = analyze(points, abstained=1)
    assert result["n_pairs"] == 2
    assert result["abstentions"] == 1
    assert result["detection_rate"] == 0.5       # 1 of 2 vulnerable revisions flagged
    assert result["false_negative_rate"] == 0.5
    assert result["fixed_side_fp_rate"] == 0.5   # 1 of 2 fixed revisions flagged
    assert result["scored_points"] == 3          # abstention excluded from scoring
