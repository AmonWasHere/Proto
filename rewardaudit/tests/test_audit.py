"""LLM code audit: function extraction, finding parsing, evidence gating."""

from rewardaudit.audit import audit_codebase
from rewardaudit.cpg import Cpg
from rewardaudit.llm.base import LLMResponse

PAYLOAD = (
    '{"findings": [{"kind": "code injection", "severity": "high", "line": 2, '
    '"cwe": "CWE-95", "confidence": 0.9, "rationale": "eval on untrusted input"}]}'
)


class FakeBackend:
    name = "fake"

    def __init__(self, text: str) -> None:
        self.text = text
        self.calls = 0

    def complete(self, request):  # noqa: ANN001
        self.calls += 1
        return LLMResponse(text=self.text, backend="fake", model="fake", tokens_in=1, tokens_out=1)


def test_functions_are_extracted(tmp_path):
    (tmp_path / "m.py").write_text("def a():\n    return 1\n\n\ndef b():\n    return 2\n")
    fns = Cpg(tmp_path).functions("m.py")
    assert [f.name for f in fns] == ["a", "b"]
    assert fns[0].start_line == 1 and fns[1].start_line == 5


def test_audit_finds_and_gates_evidence(tmp_path):
    (tmp_path / "m.py").write_text("def f(x):\n    return eval(x)\n")
    report = audit_codebase(tmp_path, FakeBackend(PAYLOAD), gate=True)
    s = report.summary()
    assert s["functions_audited"] == 1
    assert s["findings"] == 1
    assert s["verified"] == 1
    f = report.findings[0]
    assert (f.severity, f.cwe, f.kind) == ("high", "CWE-95", "code injection")
    assert f.verified is True


def test_audit_gate_rejects_bad_line(tmp_path):
    (tmp_path / "m.py").write_text("def f(x):\n    return x\n")
    bad = '{"findings": [{"kind": "x", "severity": "low", "line": 999, "confidence": 0.5, "rationale": "no"}]}'
    report = audit_codebase(tmp_path, FakeBackend(bad), gate=True)
    assert report.findings[0].verified is False


def test_audit_clean_and_unparseable(tmp_path):
    (tmp_path / "m.py").write_text("def f():\n    return 1\n")
    clean = audit_codebase(tmp_path, FakeBackend('{"findings": []}'))
    assert clean.findings == []
    assert clean.summary()["parse_failures"] == 0

    junk = audit_codebase(tmp_path, FakeBackend("not json at all"))
    assert junk.findings == []
    assert junk.summary()["parse_failures"] == 1


def test_audit_reports_unchecked_languages(tmp_path):
    (tmp_path / "m.py").write_text("def f():\n    return 1\n")
    (tmp_path / "a.go").write_text("package main\nfunc f() {}\n")
    report = audit_codebase(tmp_path, FakeBackend('{"findings": []}'))
    assert "go" in report.summary()["unchecked_languages"]
