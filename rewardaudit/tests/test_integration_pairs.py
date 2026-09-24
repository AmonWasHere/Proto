"""M1 integration: the four-way decomposition over the Python revision pairs and
the false-positive check over the canary set. Skipped when opengrep is absent."""

import pytest

from rewardaudit import config
from rewardaudit.analyzers.opengrep import Opengrep
from rewardaudit.datasets import canary_report, load_canaries, load_pairs
from rewardaudit.decomposition import decompose


def _analyzer() -> Opengrep:
    analyzer = Opengrep(config.OPENGREP_BIN, config.PYTHON_RULES)
    if not analyzer.available():
        pytest.skip(f"opengrep not available at {config.OPENGREP_BIN}")
    return analyzer


@pytest.fixture(scope="module")
def pair_scan():
    analyzer = _analyzer()
    return analyzer, analyzer.scan(config.PYTHON_PAIRS)


def test_pairs_manifest_present():
    assert (config.PYTHON_PAIRS / "manifest.json").is_file()
    assert len(load_pairs(config.PYTHON_PAIRS / "manifest.json")) == 5


def test_decomposition_is_clean_flip(pair_scan):
    _, result = pair_scan
    report = decompose(load_pairs(config.PYTHON_PAIRS / "manifest.json"), result.findings)
    # Each pair is a substitution the pinned rules should separate: the verdict
    # flips with the fix and nothing is flagged on both revisions.
    assert report.total == 5
    assert report.vuln_only == 5
    assert report.both == 0
    assert report.neither == 0
    assert report.flip_rate == 1.0
    assert report.naive_coverage == 1.0


def test_canaries_are_not_flagged():
    analyzer = _analyzer()
    result = analyzer.scan(config.PYTHON_CANARIES)
    report = canary_report(load_canaries(config.PYTHON_CANARIES / "manifest.json"), result.findings)
    assert report["total"] == 3
    assert report["flagged"] == 0
