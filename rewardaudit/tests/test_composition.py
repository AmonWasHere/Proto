"""P4 — composition: does requiring a deterministic verifier improve trust?"""

import json

import pytest

from rewardaudit import config
from rewardaudit.cpg import Cpg
from rewardaudit.datasets import load_pairs
from rewardaudit.e1 import four_way_hybrid, four_way_tool
from rewardaudit.llm.mock import MockBackend
from rewardaudit.llm.scripted import ScriptedBackend
from rewardaudit.schema import Disposition, Finding, Location
from rewardaudit.verifiers.base import VerificationContext
from rewardaudit.verifiers.llm_judge import LLMJudge


def _pairs():
    return load_pairs(config.PYTHON_PAIRS / "manifest.json")


def _ctx():
    return VerificationContext(config.PYTHON_PAIRS.resolve(), Cpg(config.PYTHON_PAIRS), ScriptedBackend())


def _require_cpg():
    if not Cpg(config.PYTHON_PAIRS).available():
        pytest.skip("tree-sitter not installed")


def test_tool_decomposition_from_findings():
    pairs = _pairs()
    findings = [
        Finding(id="1", analyzer="t", rule="r", message="", location=Location(p.vuln, 1)) for p in pairs
    ]
    report = four_way_tool(pairs, findings)
    assert report.total == 5
    assert report.vuln_only == 5


def test_hybrid_requires_tool_agreement():
    _require_cpg()
    pairs = _pairs()
    ctx = _ctx()

    # No deterministic findings -> the LLM's positives do not survive composition.
    empty = four_way_hybrid(pairs, ctx, [], LLMJudge())
    assert empty.report.vuln_only == 0
    assert empty.report.counts()["neither"] == 5

    # Tool flags the vulnerable revision of every pair -> hybrid flags them.
    tool = [
        Finding(id=p.id, analyzer="t", rule="r", message="", location=Location(p.vuln, 1))
        for p in pairs
    ]
    full = four_way_hybrid(pairs, ctx, tool, LLMJudge())
    assert full.report.vuln_only == 5


def test_gate_evidence_downgrades_unverified_positive():
    if not Cpg(config.PYTHON_CANARIES).available():
        pytest.skip("tree-sitter not installed")
    responder = lambda req: json.dumps(  # noqa: E731
        {"disposition": "true_positive", "confidence": 0.9, "evidence": ["nope.java:999"],
         "rationale": "trust me"}
    )
    backend = MockBackend(responder=responder)
    ctx = VerificationContext(
        config.PYTHON_PAIRS.resolve(), Cpg(config.PYTHON_PAIRS), backend
    )
    finding = Finding(
        id="f", analyzer="a", rule="r", message="", location=Location("case_eval_vuln.py", 1)
    )
    gated = LLMJudge(gate_evidence=True).verify(finding, ctx)
    ungated = LLMJudge(gate_evidence=False).verify(finding, ctx)
    assert gated.disposition is Disposition.UNKNOWN_RISK
    assert ungated.disposition is Disposition.TRUE_POSITIVE
