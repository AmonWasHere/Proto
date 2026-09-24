"""M0 exit gate: reproduce the pinned opengrep control result through the new
interface. Skipped automatically when the bundled binary is absent."""

import pytest

from rewardaudit import config
from rewardaudit.analyzers.opengrep import Opengrep
from rewardaudit.controls import control_matrix, load_controls


@pytest.fixture(scope="module")
def scan():
    analyzer = Opengrep(config.OPENGREP_BIN, config.JAVA_RULES)
    if not analyzer.available():
        pytest.skip(f"opengrep not available at {config.OPENGREP_BIN}")
    if not config.CONTROLS_DIR.is_dir():
        pytest.skip("control set not present")
    return analyzer, analyzer.scan(config.CONTROLS_DIR)


def test_analyzer_reports_version(scan):
    analyzer, result = scan
    assert result.ok
    assert result.version and result.version != "unknown"


def test_reproduces_pinned_control_numbers(scan):
    analyzer, result = scan
    matrix = control_matrix(load_controls(config.CONTROLS_DIR), result.findings)
    # Pinned to the prior study: opengrep detects 12/18 vulnerable controls and
    # flags 1 of 3 safe controls.
    assert matrix["vulnerable_total"] == 18
    assert matrix["vulnerable_detected"] == 12
    assert matrix["safe_flagged"] == 1


def test_findings_carry_locations_and_rules(scan):
    _, result = scan
    assert result.findings
    for finding in result.findings:
        assert finding.location.path.endswith(".java")
        assert finding.location.start_line > 0
        assert finding.rule
