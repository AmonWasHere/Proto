"""V2 — the deterministic verifier: the tool's own verdict, exact-matched.

This is deliberately *not* clever. It exists so that any LLM verdict (V1) can be
compared against a deterministic one on the same finding, and so the four-way
decomposition can be read for both.
"""

from __future__ import annotations

from pathlib import Path

from ..analyzers.base import Analyzer
from ..schema import Disposition, Finding, Verdict
from .base import VerificationContext


class ToolVerdict:
    name = "tool_verdict"

    def __init__(self, findings: list[Finding], *, tolerance: int = 0, source: str = "tool") -> None:
        self._findings = list(findings)
        self.tolerance = tolerance
        self.source = source

    @classmethod
    def from_analyzer(
        cls, analyzer: Analyzer, root: Path, *, tolerance: int = 0
    ) -> "ToolVerdict":
        result = analyzer.scan(root)
        return cls(result.findings, tolerance=tolerance, source=analyzer.name)

    def verify(self, finding: Finding, ctx: VerificationContext) -> Verdict:
        hit = self._match(finding)
        if hit is not None:
            return Verdict(
                finding_id=finding.id,
                verifier=self.name,
                disposition=Disposition.TRUE_POSITIVE,
                confidence=1.0,
                cwe=hit.cwes[0] if hit.cwes else None,
                rationale=f"{self.source} flags {hit.rule} at {hit.location.ref()}",
                evidence_refs=(hit.location.ref(),),
            )
        return Verdict(
            finding_id=finding.id,
            verifier=self.name,
            disposition=Disposition.FALSE_POSITIVE,
            confidence=1.0,
            rationale=f"{self.source} does not flag this location",
            evidence_refs=(finding.location.ref(),),
        )

    def _match(self, finding: Finding) -> Finding | None:
        for other in self._findings:
            if other.location.path != finding.location.path:
                continue
            if abs(other.location.start_line - finding.location.start_line) <= self.tolerance:
                return other
        return None
