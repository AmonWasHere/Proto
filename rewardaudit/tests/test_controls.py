from pathlib import Path

from rewardaudit.controls import control_matrix, load_controls
from rewardaudit import config
from rewardaudit.schema import ControlCase, Finding, Location


def test_load_controls_has_21_cases():
    if not config.CONTROLS_DIR.is_dir():
        import pytest

        pytest.skip("control set not present")
    cases = load_controls(config.CONTROLS_DIR)
    assert len(cases) == 21
    assert sum(c.is_vulnerable for c in cases) == 18
    assert sum(not c.is_vulnerable for c in cases) == 3


def test_control_matrix_unit():
    cases = [
        ControlCase("src/a.java", "vulnerable", "CWE-78", "cmdi"),
        ControlCase("src/b.java", "safe", "CWE-78", "cmdi"),
    ]
    findings = [
        Finding(id="1", analyzer="x", rule="r", message="", location=Location("src/a.java", 4))
    ]
    matrix = control_matrix(cases, findings)
    assert matrix["vulnerable_detected"] == 1
    assert matrix["vulnerable_total"] == 1
    assert matrix["safe_flagged"] == 0
    assert matrix["safe_total"] == 1


def test_control_matrix_matches_suffix_paths():
    cases = [ControlCase("src/a.java", "vulnerable", "CWE-78", "cmdi")]
    findings = [
        Finding(id="1", analyzer="x", rule="r", message="", location=Location("/abs/src/a.java", 1))
    ]
    matrix = control_matrix(cases, findings)
    assert matrix["vulnerable_detected"] == 1
