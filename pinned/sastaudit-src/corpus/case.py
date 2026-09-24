"""Ground-truth and finding models for SAST evaluation corpora.

These mirror the fields that scoring actually depends on in BenchmarkUtils:

  org.owasp.benchmarkutils.score.TestCaseResult
      - `truePositive` — despite the name this is the *ground-truth label*:
        "Is this test case a true or false positive?" i.e. is it a real
        vulnerability (true) or a deliberately fake one (false).
        See TestCaseResult.java:30.
      - `result` / `isPassed()` — "Did a tool properly detect this as a true or
        false positive?" i.e. did the tool's verdict match the label.
        See TestCaseResult.java:31.
      - `cwe`, `category`, `number`.

The naming is a persistent source of confusion, so this module keeps the
Benchmark's names in the docstrings and uses unambiguous ones in the code.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Case:
    """One benchmark test case and its ground-truth label."""

    name: str
    """Test case identifier, e.g. "BenchmarkTest00001"."""

    number: int
    """Numeric part of the name; the join key between expected and actual results."""

    category: str
    """Vulnerability family, e.g. "cmdi", "sqli", "xpathi". Case-sensitive."""

    is_real_vuln: bool
    """Ground truth: True if this case contains a real vulnerability.

    This is TestCaseResult.truePositive in BenchmarkUtils.
    """

    cwe: int
    """The CWE the case is expected to be reported as."""


@dataclass(frozen=True, slots=True)
class Finding:
    """A single tool finding, normalised onto the Benchmark's case numbering.

    A tool may emit several findings for one case (see the `actList` in
    BenchmarkScore.compare), so findings are a bag, not a map.
    """

    case_number: int
    cwe: int


@dataclass(frozen=True, slots=True)
class ToolRun:
    """All findings from one tool over one corpus, plus the tool's name.

    The tool name matters for scoring: BenchmarkScore.compare applies
    tool-specific CWE leniency, so scores are not directly comparable across
    tools. See scoring/owasp_original.py.
    """

    tool: str
    findings: tuple[Finding, ...]

    def by_case(self) -> dict[int, list[Finding]]:
        """Group findings by case number, preserving order within a case."""
        out: dict[int, list[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.case_number, []).append(f)
        return out


def parse_case_number(name: str, prefix: str = "BenchmarkTest") -> int:
    """Extract the numeric test-case id from a test name or path.

    A faithful-but-simplified port of Reader.testNumber (Reader.java:247), which
    copes with paths, URLs, query strings and inner-class suffixes. We only need
    the well-formed "<prefix>NNNNN" case that the expected-results and scorecard
    files actually use; anything else returns -1, matching the Java behaviour of
    returning -1 on failure.
    """
    if prefix not in name:
        return -1
    tail = name[name.index(prefix) + len(prefix) :]
    digits = ""
    for ch in tail:
        if ch.isdigit():
            digits += ch
        else:
            break
    return int(digits) if digits else -1
