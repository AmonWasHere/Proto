"""Every tool against the OWASP Benchmark, scored with the ported scorer.

    python3 -m sastaudit.eval.benchmark_owasp --tool codeql

This is the control half of the study. The real-corpus half says what a tool
does with vulnerabilities a human had to fix; on its own that could be read as
"the tool is bad", which is not a finding. The benchmark is the corpus built to
be findable, scored by the benchmark's own published metric, so the contrast
between the two is the actual result.

Two scores are recorded for each tool
-------------------------------------
* **published** -- `score = TPR - FPR` with TPR and FPR macro-averaged, exactly
  as BenchmarkUtils computes them. This is the number OWASP would publish.
* **corrected** -- the same counts pooled case-weightedly, which is how the same
  codebase treats precision. The gap between the two is the aggregation
  finding, and it is reported per category so the difference is attributable
  rather than asserted.

Tool naming is load-bearing
---------------------------
BenchmarkScore.compare grants a hardcoded CWE-327-for-328 leniency to any tool
whose name starts with "AppScan", "Vera" or "CodeQL" (BenchmarkScore.java:731).
That leniency is part of what this study examines, so the upstream spelling is
used deliberately and recorded in the output as `scorer_tool_name` -- scoring
CodeQL under a name the scorer does not recognise would silently remove a
concession the benchmark actually makes, and comparing that to Semgrep's score
would be comparing two different rulesets while claiming to compare two tools.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

from ..corpus.case import Finding, ToolRun
from ..corpus.owasp import load_expected_results
from ..scoring.corrected import score_tool_corrected
from ..scoring.owasp_original import score_from_findings
from ..tools import REGISTRY, ToolError, build_tool
from .real_corpus import tool_metadata

ROOT = Path(__file__).resolve().parents[2]
UPSTREAM = ROOT / "sastaudit" / "upstream" / "benchmarkjava"
TESTCODE = UPSTREAM / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
GROUND_TRUTH = UPSTREAM / "expectedresults-1.2.csv"
RESULTS = ROOT / "sastaudit" / "results"
CONTROL_SRC = ROOT / "sastaudit" / "controls" / "src"

CASE_NAME = re.compile(r"(BenchmarkTest\d+)\.java$")

#: Study tool id -> the name the upstream scorer must see. See module docstring.
SCORER_TOOL_NAME = {
    "semgrep": "Semgrep",
    "opengrep": "Opengrep",
    "codeql": "CodeQL",
}


def to_findings(outcome, *, tool_name: str) -> tuple[ToolRun, dict[str, int]]:
    """Map a tool's findings onto Benchmark case numbers and CWEs.

    Returns the ToolRun plus a tally of how findings were dropped. A silent drop
    would understate the tool and inflate whatever we conclude, so the drops are
    counted and published rather than filtered away.

    CWEs come from the adapters already normalised to "CWE-89" form, which is
    what makes a CodeQL `external/cwe/cwe-089` tag and a Semgrep `CWE-89`
    metadata entry directly comparable here.
    """
    findings: list[Finding] = []
    dropped = {"no_case_name": 0, "no_cwe": 0, "outside_testcode": 0}
    for f in outcome.findings:
        m = CASE_NAME.search(f.path)
        if not m:
            dropped["no_case_name"] += 1
            continue
        number = int(m.group(1).replace("BenchmarkTest", ""))
        nums = [int(c.split("-", 1)[1]) for c in f.cwes if c.startswith("CWE-")]
        if not nums:
            dropped["no_cwe"] += 1
            continue
        # A rule citing several CWEs is credited with all of them. Upstream
        # accepts a case if any reported CWE matches, so keeping all is the
        # generous reading and cannot understate the tool.
        findings.extend(Finding(case_number=number, cwe=n) for n in sorted(set(nums)))
    return ToolRun(tool=tool_name, findings=tuple(findings)), dropped


def positive_control(tool) -> dict:
    """Prove the scanner works before trusting a 2,740-file result.

    A tool that is misconfigured scores zero on the benchmark, and zero is also
    what a tool that genuinely finds nothing scores. The shared control set
    separates the two.
    """
    outcome = tool.scan(CONTROL_SRC)
    manifest = json.loads(
        (CONTROL_SRC.parent / "manifest.json").read_text()
    )["cases"]
    by_name: dict[str, int] = {}
    for f in outcome.findings:
        by_name[Path(f.path).name] = by_name.get(Path(f.path).name, 0) + 1
    vuln = [c for c in manifest if c["expect"] == "vulnerable"]
    safe = [c for c in manifest if c["expect"] == "safe"]
    hit = sum(1 for c in vuln if by_name.get(Path(c["file"]).name))
    fp = sum(1 for c in safe if by_name.get(Path(c["file"]).name))
    return {
        "vulnerable_detected": f"{hit}/{len(vuln)}",
        "negative_controls_flagged": f"{fp}/{len(safe)}",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", choices=sorted(REGISTRY), default="semgrep")
    ap.add_argument("--out", default=None)
    ap.add_argument("--skip-control", action="store_true")
    args = ap.parse_args(argv)

    for path in (TESTCODE, GROUND_TRUTH):
        if not path.exists():
            print(f"missing: {path}", file=sys.stderr)
            return 2

    out_name = args.out or f"{args.tool}_owasp.json"
    scorer_name = SCORER_TOOL_NAME.get(args.tool, args.tool)

    try:
        tool = build_tool(args.tool)
    except ToolError as exc:
        print(exc, file=sys.stderr)
        return 2
    if not tool.available():
        print(f"{args.tool} is not available", file=sys.stderr)
        return 2

    cases = load_expected_results(GROUND_TRUTH)
    meta = tool_metadata(tool)
    print(f"OWASP Benchmark v1.2: {len(cases)} cases")
    print(f"tool {tool.name} {tool.version()} (scored as {scorer_name!r})")
    if "ruleset" in meta:
        print(f"rules {meta['ruleset']} sha256 {meta['ruleset_sha256'][:12]}")

    control = {}
    if not args.skip_control:
        control = positive_control(tool)
        print(
            f"positive control: {control['vulnerable_detected']} canonical "
            f"vulnerabilities, {control['negative_controls_flagged']} negative "
            f"controls flagged"
        )

    print(f"scanning {TESTCODE.name} ...")
    started = time.monotonic()
    try:
        outcome = tool.scan(TESTCODE)
    except ToolError as exc:
        print(f"scan failed: {exc}", file=sys.stderr)
        return 1
    elapsed = time.monotonic() - started

    run, dropped = to_findings(outcome, tool_name=scorer_name)
    print(f"  {len(outcome.findings)} raw findings in {elapsed:.0f}s; dropped {dropped}")

    published = score_from_findings(cases, run)
    flagged = {f.case_number for f in run.findings}
    passed = {n: _passed(cases[n], run) for n in cases}
    corrected = score_tool_corrected(cases, passed, tool=scorer_name)

    summary = {
        "corpus": "owasp-benchmark-1.2",
        "tool": tool.name,
        "tool_version": tool.version(),
        # Same provenance block the real-corpus half writes, produced by the
        # same function. Without the ruleset hash a benchmark number is not
        # reproducible -- the registry URL resolves to whatever is current --
        # and if the two halves recorded provenance differently there would be
        # no way to show the ruleset had not changed between them.
        "tool_meta": meta,
        "scorer_tool_name": scorer_name,
        "cwe_leniency_applied": scorer_name.startswith(("AppScan", "Vera", "CodeQL")),
        "raw_findings": len(outcome.findings),
        "dropped": dropped,
        "cases_flagged": len(flagged),
        "total_cases": len(cases),
        "scan_seconds": round(elapsed, 1),
        "positive_control": control,
        "published": {
            "tpr": published.true_positive_rate,
            "fpr": published.false_positive_rate,
            "score": published.score,
            "precision": published.precision,
            "fscore": published.fscore,
            "tp": published.tp, "fp": published.fp,
            "fn": published.fn, "tn": published.tn,
        },
        "corrected": corrected.as_row(),
        "tpr_contributions": [c.as_row() for c in corrected.tpr_contributions],
        "fpr_contributions": [c.as_row() for c in corrected.fpr_contributions],
    }

    print("\n" + "=" * 60)
    print(f"cases flagged          {len(flagged)}/{len(cases)}")
    p = summary["published"]
    print(f"TP={p['tp']} FP={p['fp']} FN={p['fn']} TN={p['tn']}")
    print(f"TPR (macro)            {p['tpr']:.2%}")
    print(f"FPR (macro)            {p['fpr']:.2%}")
    print(f"precision              {p['precision']:.2%}")
    print(f"score = TPR - FPR      {p['score']:.2%}   <- as OWASP publishes it")
    c = summary["corrected"]
    print(f"score, case-weighted   {c['corrected_score']:.2%}   <- corrected")
    print(f"  (macro {c['macro_tpr']:.2%} TPR / {c['macro_fpr']:.2%} FPR vs "
          f"micro {c['micro_tpr']:.2%} / {c['micro_fpr']:.2%})")
    print("=" * 60)

    RESULTS.mkdir(parents=True, exist_ok=True)
    out = RESULTS / out_name
    out.write_text(json.dumps(summary, indent=2))
    print(f"wrote {out}")
    return 0


def _passed(case, run: ToolRun) -> bool:
    """Per-case verdict under upstream's leniency rules."""
    from ..scoring.owasp_original import compare

    return compare(case, run.by_case().get(case.number, []), run.tool)


if __name__ == "__main__":
    raise SystemExit(main())
