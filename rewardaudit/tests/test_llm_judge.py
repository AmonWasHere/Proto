import json

import pytest

from rewardaudit.cpg import Cpg
from rewardaudit.llm.base import LLMError
from rewardaudit.llm.mock import MockBackend
from rewardaudit.schema import Disposition, Finding, Location
from rewardaudit.verifiers.base import VerificationContext
from rewardaudit.verifiers.llm_judge import LLMJudge, extract_json

JAVA = (
    "class A {\n"
    "    void f(String u) {\n"
    "        Runtime.getRuntime().exec(u);\n"
    "    }\n"
    "}\n"
)


def _finding() -> Finding:
    return Finding(
        id="f1",
        analyzer="opengrep",
        rule="java.lang.security.cmdi",
        message="command injection",
        location=Location("A.java", 3, 3),
        cwes=("CWE-78",),
    )


@pytest.fixture
def ctx(tmp_path):
    (tmp_path / "A.java").write_text(JAVA)
    return tmp_path


def _context(root, responses):
    return VerificationContext(
        repo_root=root, cpg=Cpg(root), llm=MockBackend(responses=responses)
    )


def test_extract_json_variants():
    assert extract_json('{"a": 1}') == {"a": 1}
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json("prose before {\"a\": 1} after") == {"a": 1}
    assert extract_json("no json") is None
    assert extract_json("{not valid}") is None


def test_judge_accepts_verified_evidence(ctx):
    if not Cpg(ctx).available():
        pytest.skip("tree-sitter not installed")
    response = json.dumps(
        {
            "disposition": "true_positive",
            "confidence": 0.9,
            "cwe": "CWE-78",
            "evidence": ["A.java:3"],
            "rationale": "user input reaches exec",
        }
    )
    verdict = LLMJudge().verify(_finding(), _context(ctx, [response]))
    assert verdict.disposition is Disposition.TRUE_POSITIVE
    assert verdict.confidence == 0.9
    assert verdict.cwe == "CWE-78"
    assert verdict.evidence_refs == ("A.java:3",)


def test_judge_downgrades_unverifiable_positive(ctx):
    if not Cpg(ctx).available():
        pytest.skip("tree-sitter not installed")
    response = json.dumps(
        {
            "disposition": "true_positive",
            "confidence": 0.99,
            "evidence": ["A.java:999"],
            "rationale": "trust me",
        }
    )
    verdict = LLMJudge().verify(_finding(), _context(ctx, [response]))
    assert verdict.disposition is Disposition.UNKNOWN_RISK
    assert verdict.abstain


def test_judge_abstains_on_garbage(ctx):
    verdict = LLMJudge().verify(_finding(), _context(ctx, ["not json at all"]))
    assert verdict.disposition is Disposition.UNKNOWN_RISK
    assert verdict.abstain


def test_judge_invalid_disposition(ctx):
    response = json.dumps({"disposition": "maybe", "confidence": 0.5})
    verdict = LLMJudge().verify(_finding(), _context(ctx, [response]))
    assert verdict.disposition is Disposition.UNKNOWN_RISK


def test_judge_requires_backend(ctx):
    context = VerificationContext(repo_root=ctx, cpg=Cpg(ctx), llm=None)
    with pytest.raises(LLMError):
        LLMJudge().verify(_finding(), context)


def test_false_positive_is_reported_plainly(ctx):
    response = json.dumps(
        {"disposition": "false_positive", "confidence": 0.7, "rationale": "constant input"}
    )
    verdict = LLMJudge().verify(_finding(), _context(ctx, [response]))
    assert verdict.disposition is Disposition.FALSE_POSITIVE
    assert not verdict.abstain
