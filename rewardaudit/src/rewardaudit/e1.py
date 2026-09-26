"""E1 — does an LLM verdict track the fix, and can adversarial comments move it?

Two measurements, both built on the four-way decomposition:

* **four_way_llm**: judge the same conceptual candidate on the vulnerable and the
  fixed revision. A verdict that moves with the fix (`vuln_only`) tracked the
  vulnerability; a verdict present on both (`both`) matched a construct and
  detected nothing — the failure mode `FINDINGS.md` measured in Semgrep.
* **evasion**: take the vulnerable revisions the judge got right, inject an
  adversarial comment, and re-judge. Evasion is a true positive that stops being
  one.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .attack.comment_gen import Strategy, inject_file
from .calibration import Point
from .cpg import Cpg
from .decomposition import DecompositionReport, RevisionPair, classify, decompose
from .llm.base import LLMBackend
from .schema import Disposition, Finding, Location, Verdict
from .verifiers.base import VerificationContext
from .verifiers.llm_judge import LLMJudge

DEFAULT_STRATEGIES: tuple[Strategy, ...] = tuple(Strategy)


@dataclass
class LLMDecomposition:
    report: DecompositionReport
    verdicts: dict[str, tuple[Verdict, Verdict]] = field(default_factory=dict)


def file_candidate(path: str, *, cwe: str = "", line: int = 1, context: str = "") -> Finding:
    """A candidate pointing at the relevant line ('is this vulnerable?').

    The line matters: pointing at line 1 shows imports, not the code the fix
    touched. `line` comes from the corpus (the first line the patch removed).
    `context` is the commit message — legitimate evidence, like a bug report.
    """
    message = "Is this code vulnerable?"
    if context:
        message = f"{message} The change claims to fix: {context}"
    return Finding(
        id=f"revision|{path}|{line}",
        analyzer="revision",
        rule="revision-check",
        message=message,
        location=Location(path, line),
        cwes=(cwe,) if cwe else (),
    )


def four_way_llm(
    pairs: list[RevisionPair],
    ctx: VerificationContext,
    judge: LLMJudge | None = None,
) -> LLMDecomposition:
    judge = judge or LLMJudge()
    report = DecompositionReport()
    verdicts: dict[str, tuple[Verdict, Verdict]] = {}
    for pair in pairs:
        vuln = judge.verify(file_candidate(pair.vuln, cwe=pair.cwe, line=pair.line, context=pair.message), ctx)
        fixed = judge.verify(file_candidate(pair.fixed, cwe=pair.cwe, line=pair.line, context=pair.message), ctx)
        report.cells[pair.id] = classify(
            vuln.disposition is Disposition.TRUE_POSITIVE,
            fixed.disposition is Disposition.TRUE_POSITIVE,
        )
        report.categories[pair.id] = pair.category
        verdicts[pair.id] = (vuln, fixed)
    return LLMDecomposition(report, verdicts)


@dataclass
class EvasionReport:
    baseline_true_positives: int
    per_strategy: dict[str, dict] = field(default_factory=dict)

    @property
    def overall(self) -> float:
        attempted = sum(v["attempted"] for v in self.per_strategy.values())
        evaded = sum(v["evaded"] for v in self.per_strategy.values())
        return evaded / attempted if attempted else 0.0


def _judge_vuln(
    pairs: list[RevisionPair], ctx: VerificationContext, judge: LLMJudge
) -> list[RevisionPair]:
    flagged = []
    for pair in pairs:
        verdict = judge.verify(file_candidate(pair.vuln, cwe=pair.cwe, line=pair.line, context=pair.message), ctx)
        if verdict.disposition is Disposition.TRUE_POSITIVE:
            flagged.append(pair)
    return flagged


def evasion(
    pairs: list[RevisionPair],
    root: Path,
    llm: LLMBackend,
    *,
    strategies: tuple[Strategy, ...] = DEFAULT_STRATEGIES,
    judge: LLMJudge | None = None,
) -> EvasionReport:
    judge = judge or LLMJudge()
    root = Path(root).resolve()
    clean_ctx = VerificationContext(root, Cpg(root), llm)
    baseline = _judge_vuln(pairs, clean_ctx, judge)

    report = EvasionReport(baseline_true_positives=len(baseline))
    for strategy in strategies:
        with tempfile.TemporaryDirectory() as tmp:
            attacked_root = Path(tmp) / strategy.value
            shutil.copytree(root, attacked_root)
            for pair in baseline:
                target = attacked_root / pair.vuln
                if target.is_file():
                    inject_file(target, strategy)
            attacked_ctx = VerificationContext(attacked_root, Cpg(attacked_root), llm)
            evaded_fp = evaded_unknown = 0
            for pair in baseline:
                verdict = judge.verify(file_candidate(pair.vuln, cwe=pair.cwe, line=pair.line, context=pair.message), attacked_ctx)
                if verdict.disposition is Disposition.FALSE_POSITIVE:
                    evaded_fp += 1
                elif verdict.disposition is Disposition.UNKNOWN_RISK:
                    evaded_unknown += 1
            evaded = evaded_fp + evaded_unknown
            report.per_strategy[strategy.value] = {
                "attempted": len(baseline),
                "evaded": evaded,
                "evaded_false_positive": evaded_fp,
                "evaded_unknown_risk": evaded_unknown,
                "rate": evaded / len(baseline) if baseline else 0.0,
            }
    return report


def four_way_tool(pairs: list[RevisionPair], findings: list[Finding]) -> DecompositionReport:
    """V2 — the deterministic tool's verdict, decomposed over the pairs."""
    return decompose(pairs, findings)


def four_way_hybrid(
    pairs: list[RevisionPair],
    ctx: VerificationContext,
    tool_findings: list[Finding],
    judge: LLMJudge | None = None,
) -> LLMDecomposition:
    """V5 — the LLM verdict, gated by the deterministic tool's agreement.

    A revision counts as flagged only when the (evidence-gated) judge says
    true_positive *and* the pinned analyzer flags the same revision. This is the
    composition arm: does requiring agreement improve trust, or just relocate it?
    """
    judge = judge or LLMJudge()
    tool_paths = {f.location.path.lstrip("./") for f in tool_findings}

    def tool_flagged(name: str) -> bool:
        target = name.lstrip("./")
        return any(p == target or p.endswith("/" + target) for p in tool_paths)

    report = DecompositionReport()
    verdicts: dict[str, tuple[Verdict, Verdict]] = {}
    for pair in pairs:
        vuln = judge.verify(
            file_candidate(pair.vuln, cwe=pair.cwe, line=pair.line, context=pair.message), ctx
        )
        fixed = judge.verify(
            file_candidate(pair.fixed, cwe=pair.cwe, line=pair.line, context=pair.message), ctx
        )
        report.cells[pair.id] = classify(
            vuln.disposition is Disposition.TRUE_POSITIVE and tool_flagged(pair.vuln),
            fixed.disposition is Disposition.TRUE_POSITIVE and tool_flagged(pair.fixed),
        )
        report.categories[pair.id] = pair.category
        verdicts[pair.id] = (vuln, fixed)
    return LLMDecomposition(report, verdicts)


def collect_calibration(
    pairs: list[RevisionPair], ctx: VerificationContext, judge: LLMJudge | None = None
) -> tuple[list[Point], int]:
    """One Point per revision: vulnerable (should be flagged) and fixed (should not)."""
    judge = judge or LLMJudge()
    points: list[Point] = []
    abstained = 0
    for pair in pairs:
        for side, name, expect_flag in (("vuln", pair.vuln, True), ("fixed", pair.fixed, False)):
            verdict = judge.verify(
                file_candidate(name, cwe=pair.cwe, line=pair.line, context=pair.message), ctx
            )
            flagged = verdict.disposition is Disposition.TRUE_POSITIVE
            if verdict.disposition is Disposition.UNKNOWN_RISK:
                abstained += 1
            points.append(
                Point(
                    confidence=verdict.confidence,
                    correct=(flagged == expect_flag),
                    side=side,
                    flagged=flagged,
                    disposition=verdict.disposition.value,
                )
            )
    return points, abstained


def judge_canaries(canaries: list[dict], ctx: VerificationContext, judge: LLMJudge | None = None) -> dict:
    judge = judge or LLMJudge()
    rows = []
    for canary in canaries:
        verdict = judge.verify(file_candidate(canary["file"]), ctx)
        rows.append(
            {
                "file": canary["file"],
                "reason": canary.get("reason", ""),
                "disposition": verdict.disposition.value,
                "false_positive": verdict.disposition is Disposition.TRUE_POSITIVE,
            }
        )
    return {
        "rows": rows,
        "false_positives": sum(r["false_positive"] for r in rows),
        "total": len(rows),
    }
