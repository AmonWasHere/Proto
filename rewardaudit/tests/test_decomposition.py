from rewardaudit.decomposition import (
    Cell,
    RevisionPair,
    by_category,
    classify,
    decompose,
)
from rewardaudit.schema import Finding, Location


def test_classify_truth_table():
    assert classify(True, True) is Cell.BOTH
    assert classify(True, False) is Cell.VULN_ONLY
    assert classify(False, True) is Cell.FIXED_ONLY
    assert classify(False, False) is Cell.NEITHER


def _finding(path: str) -> Finding:
    return Finding(id="x", analyzer="a", rule="r", message="", location=Location(path, 1))


def test_decompose_counts_and_rates():
    pairs = [
        RevisionPair("p1", "v1.py", "f1.py", "cmdi"),
        RevisionPair("p2", "v2.py", "f2.py", "cmdi"),
        RevisionPair("p3", "v3.py", "f3.py", "sqli"),
        RevisionPair("p4", "v4.py", "f4.py", "sqli"),
    ]
    findings = [
        _finding("v1.py"),  # vuln_only
        _finding("v2.py"), _finding("f2.py"),  # both
        _finding("f3.py"),  # fixed_only
        # p4: neither
    ]
    report = decompose(pairs, findings)
    assert report.cells == {
        "p1": Cell.VULN_ONLY,
        "p2": Cell.BOTH,
        "p3": Cell.FIXED_ONLY,
        "p4": Cell.NEITHER,
    }
    assert report.total == 4
    assert report.vuln_only == 1
    assert report.both == 1
    assert report.neither == 1
    assert report.naive_coverage == 0.5  # (1 vuln_only + 1 both) / 4
    assert report.flip_rate == 0.25
    assert report.over_report_factor == 2.0
    assert report.counts() == {"both": 1, "vuln_only": 1, "fixed_only": 1, "neither": 1}


def test_decompose_matches_path_suffixes():
    pairs = [RevisionPair("p1", "case_a_vuln.py", "case_a_fixed.py")]
    findings = [_finding("some/deep/dir/case_a_vuln.py")]
    report = decompose(pairs, findings)
    assert report.cells["p1"] is Cell.VULN_ONLY


def test_by_category():
    pairs = [
        RevisionPair("p1", "v1.py", "f1.py", "cmdi"),
        RevisionPair("p2", "v2.py", "f2.py", "cmdi"),
    ]
    report = decompose(pairs, [_finding("v1.py"), _finding("f2.py")])
    grouped = by_category(report)
    assert grouped["cmdi"]["vuln_only"] == 1
    assert grouped["cmdi"]["fixed_only"] == 1


def test_over_report_factor_is_infinite_without_a_flip():
    report = decompose(
        [RevisionPair("p1", "v1.py", "f1.py")], [_finding("v1.py"), _finding("f1.py")]
    )
    assert report.flip_rate == 0.0
    assert report.over_report_factor == float("inf")
