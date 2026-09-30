"""End-to-end review of a directory: scan -> graph paths -> verdicts.

This is the same flow as the web app's Review tab, exposed as a function so both
the CLI (`harness review`) and the server can use it.
"""

from __future__ import annotations

from pathlib import Path

from . import config, graph, languages
from .analyzers import AnalyzerError, Opengrep
from .cpg import Cpg
from .llm import build_backend
from .verifiers.base import VerificationContext
from .verifiers.llm_judge import LLMJudge


def run_review(
    path: str | Path,
    *,
    backend_kind: str = "scripted",
    verifier: str = "llm",
    limit: int = 0,
    no_thinking: bool = False,
    rules: Path | None = None,
) -> dict:
    root = Path(path).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"path not found: {root}")

    coverage = languages.coverage_report(root)
    rulesets = [rules] if rules else languages.rules_for(root)
    if not rulesets:
        raise AnalyzerError(
            "no ruleset for any language present; unchecked languages: "
            + ", ".join(coverage["unchecked_languages"] or ["(none)"])
        )

    analyzer = Opengrep(config.OPENGREP_BIN, rulesets)
    if not analyzer.available():
        raise AnalyzerError(f"opengrep not available at {config.OPENGREP_BIN}")
    scan = analyzer.scan(root)

    findings = scan.findings[: limit or None]
    paths = {row["finding"]: row for row in graph.path_candidates(root, findings)}

    backend = build_backend(backend_kind, no_thinking=no_thinking)
    judge = LLMJudge(gate_evidence=verifier != "llm_ungated")
    ctx = VerificationContext(root, Cpg(root), backend)

    rows = []
    for finding in findings:
        verdict = judge.verify(finding, ctx)
        path_row = paths.get(finding.id, {})
        rows.append(
            {
                "path": finding.location.path,
                "line": finding.location.start_line,
                "rule": finding.rule,
                "cwe": finding.cwes[0] if finding.cwes else "",
                "language": path_row.get("language") or "",
                "disposition": verdict.disposition.value,
                "confidence": round(verdict.confidence, 3),
                "rationale": verdict.rationale,
                "evidence": list(verdict.evidence_refs),
                "entry": path_row.get("entry"),
                "hops": path_row.get("hops") or [],
                "reachable": bool(path_row.get("reachable")),
                "coverage": path_row.get("coverage", "unknown"),
            }
        )

    summary = {
        "analyzer": analyzer.name,
        "analyzer_version": scan.version,
        "rulesets": [Path(r).name for r in rulesets],
        "candidates": len(findings),
        "true_positive": sum(r["disposition"] == "true_positive" for r in rows),
        "false_positive": sum(r["disposition"] == "false_positive" for r in rows),
        "unknown_risk": sum(r["disposition"] == "unknown_risk" for r in rows),
        "reachable": sum(r["reachable"] for r in rows),
        "tokens_in": judge.tokens_in,
        "tokens_out": judge.tokens_out,
        "coverage": coverage,
    }
    if hasattr(backend, "stats"):
        summary["cache"] = backend.stats()
    return {"root": str(root), "summary": summary, "rows": rows}
