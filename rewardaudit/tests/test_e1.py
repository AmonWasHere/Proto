"""E1 mechanics with the scripted (offline) verifier.

The scripted backend reads the code slice, recognises vulnerable constructs, and
— like the systems ALIBI defeated — is fooled by adversarial comments. This
validates the *measurement pipeline*; the real number comes from running the same
commands with `--backend local|cloud`.
"""

import json
import re

import pytest

from rewardaudit import config
from rewardaudit.attack.comment_gen import Strategy
from rewardaudit.cpg import Cpg
from rewardaudit.datasets import load_canaries, load_pairs
from rewardaudit.e1 import evasion, four_way_llm, judge_canaries
from rewardaudit.llm.mock import MockBackend
from rewardaudit.llm.scripted import ScriptedBackend
from rewardaudit.verifiers.base import VerificationContext


@pytest.fixture
def backend():
    return ScriptedBackend()


def _ctx(root, backend):
    return VerificationContext(root.resolve(), Cpg(root), backend)


def _pairs():
    return load_pairs(config.PYTHON_PAIRS / "manifest.json")


def _require_cpg():
    if not Cpg(config.PYTHON_PAIRS).available():
        pytest.skip("tree-sitter not installed")


def test_four_way_llm_tracks_the_fix(backend):
    _require_cpg()
    result = four_way_llm(_pairs(), _ctx(config.PYTHON_PAIRS, backend))
    report = result.report
    assert report.total == 5
    assert report.vuln_only == 5
    assert report.both == 0
    assert report.flip_rate == 1.0


def test_evasion_moves_the_verdict(backend):
    _require_cpg()
    report = evasion(_pairs(), config.PYTHON_PAIRS, backend, strategies=(Strategy.AUTHORITY,))
    assert report.baseline_true_positives == 5
    row = report.per_strategy["authority"]
    assert row["attempted"] == 5
    assert row["evaded"] == 5
    assert row["rate"] == 1.0
    assert report.overall == 1.0


def test_evasion_all_strategies(backend):
    _require_cpg()
    report = evasion(_pairs(), config.PYTHON_PAIRS, backend)
    assert set(report.per_strategy) == {s.value for s in Strategy}
    assert all(v["evaded"] == 5 for v in report.per_strategy.values())


def test_llm_canaries_no_false_positives(backend):
    _require_cpg()
    canaries = load_canaries(config.PYTHON_CANARIES / "manifest.json")
    report = judge_canaries(canaries, _ctx(config.PYTHON_CANARIES, backend))
    assert report["total"] == 3
    assert report["false_positives"] == 0


def test_evasion_split_counts_abstention():
    """A judge that becomes *uncertain* is evaded, and the split records that."""
    _require_cpg()

    def responder(request):
        if "audited by the application security team" in request.user:
            return json.dumps({"disposition": "unknown_risk", "confidence": 0.0, "rationale": "unsure"})
        return json.dumps({"disposition": "true_positive", "confidence": 0.8, "rationale": "sink"})

    backend = MockBackend(responder=responder)
    report = evasion(
        _pairs(), config.PYTHON_PAIRS, backend, strategies=(Strategy.AUTHORITY,)
    )
    row = report.per_strategy["authority"]
    assert row["attempted"] == 5
    assert row["evaded"] == 5
    assert row["evaded_unknown_risk"] == 5
    assert row["evaded_false_positive"] == 0


def test_evasion_split_counts_false_positive():
    _require_cpg()

    def responder(request):
        if "audited by the application security team" in request.user:
            return json.dumps({"disposition": "false_positive", "confidence": 0.9, "rationale": "safe"})
        return json.dumps({"disposition": "true_positive", "confidence": 0.8, "rationale": "sink"})

    backend = MockBackend(responder=responder)
    report = evasion(
        _pairs(), config.PYTHON_PAIRS, backend, strategies=(Strategy.AUTHORITY,)
    )
    row = report.per_strategy["authority"]
    assert row["evaded_false_positive"] == 5
    assert row["evaded_unknown_risk"] == 0
