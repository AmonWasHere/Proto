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
from .cpg import Cpg
from .decomposition import DecompositionReport, RevisionPair, classify
from .llm.base import LLMBackend
from .schema import Disposition, Finding, Location, Verdict
from .verifiers.base import VerificationContext
from .verifiers.llm_judge import LLMJudge

DEFAULT_STRATEGIES: tuple[Strategy, ...] = tuple(Strategy)


@dataclass
class LLMDecomposition:
    report: DecompositionReport
    verdicts: dict[str, tuple[Verdict, Verdict]] = field(default_factory=dict)


def file_candidate(path: str, *, cwe: str = "") -> Finding:
    """A file-level candidate: 'is this code vulnerable?'.

    The point of a file-level candidate is that the *same* question is asked of
    both revisions, so a verdict change can only come from the code change.
    """
    return Finding(
        id=f"revision|{path}",
        analyzer="revision",
        rule="revision-check",
        message="Is this code vulnerable?",
        location=Location(path, 1),
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
        vuln = judge.verify(file_candidate(pair.vuln, cwe=pair.cwe), ctx)
        fixed = judge.verify(file_candidate(pair.fixed, cwe=pair.cwe), ctx)
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
        verdict = judge.verify(file_candidate(pair.vuln, cwe=pair.cwe), ctx)
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
            evaded = 0
            for pair in baseline:
                verdict = judge.verify(file_candidate(pair.vuln, cwe=pair.cwe), attacked_ctx)
                if verdict.disposition is not Disposition.TRUE_POSITIVE:
                    evaded += 1
            report.per_strategy[strategy.value] = {
                "attempted": len(baseline),
                "evaded": evaded,
                "rate": evaded / len(baseline) if baseline else 0.0,
            }
    return report


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
