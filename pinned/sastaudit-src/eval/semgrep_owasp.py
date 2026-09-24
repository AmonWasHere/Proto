"""Semgrep on the OWASP Benchmark, scored with the ported upstream scorer.

This exists to close the loop between the two halves of the study. The corpus
audit says JavaVFC is ~16% genuine security fixes; the real-world run says
Semgrep's verdict changes with the fix in 1 of 120 such commits. On its own
that could be read as "Semgrep is bad". The OWASP number is the control that
rules that out: the same tool, on the same machine, with the same pinned
ruleset, scored on the corpus built to be findable.

The contrast is the finding. Neither number is meaningful without the other.

Upstream ships scripts/runSemgrep.sh, which runs p/security-audit in Docker and
emits SARIF, but no published Semgrep scorecard is checked in. So the number is
generated here rather than quoted.

Run from the repo root (needs the upstream clone):

    python3 -m sastaudit.eval.semgrep_owasp
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

from ..corpus.case import Finding, ToolRun
from ..corpus.owasp import load_expected_results
from ..scoring.owasp_original import score_from_findings

ROOT = Path(__file__).resolve().parents[2]
UPSTREAM = ROOT / "sastaudit" / "upstream" / "benchmarkjava"
TESTCODE = UPSTREAM / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
GROUND_TRUTH = UPSTREAM / "expectedresults-1.2.csv"
RULES = ROOT / "sastaudit" / "rules" / "p-java-best.yaml"
RESULTS = ROOT / "sastaudit" / "results"

CASE_NAME = re.compile(r"(BenchmarkTest\d+)\.java$")
CWE_NUMBER = re.compile(r"CWE-(\d+)")


def scan(target: Path, rules: Path) -> list[dict]:
    """Run the pinned ruleset over the test cases and return raw findings."""
    cmd = [
        "semgrep",
        "--config", str(rules),
        "--json",
        "--quiet",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--timeout", "60",
        "--max-target-bytes", "4000000",
        str(target),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
    if proc.returncode not in (0, 1):
        detail = (proc.stderr.strip() or proc.stdout.strip())[:300]
        raise RuntimeError(f"semgrep rc={proc.returncode}: {detail}")
    return json.loads(proc.stdout or "{}").get("results", [])


def to_findings(raw: list[dict]) -> tuple[ToolRun, dict[str, int]]:
    """Map Semgrep findings onto Benchmark case numbers and CWEs.

    Returns the ToolRun plus a tally of how findings were dropped, because a
    silent drop would understate the tool and inflate whatever we conclude.
    """
    findings: list[Finding] = []
    dropped = {"no_case_name": 0, "no_cwe": 0}
    for f in raw:
        m = CASE_NAME.search(f.get("path", ""))
        if not m:
            dropped["no_case_name"] += 1
            continue
        number = int(m.group(1).replace("BenchmarkTest", ""))
        meta = f.get("extra", {}).get("metadata", {}) or {}
        cwe_raw = meta.get("cwe")
        cwes = [cwe_raw] if isinstance(cwe_raw, str) else list(cwe_raw or [])
        nums = [int(n) for c in cwes for n in CWE_NUMBER.findall(str(c))]
        if not nums:
            dropped["no_cwe"] += 1
            continue
        # A rule citing several CWEs is credited with all of them; upstream
        # accepts a case if any reported CWE matches, so keeping all is the
        # generous reading and cannot understate the tool.
        findings.extend(Finding(case_number=number, cwe=n) for n in sorted(set(nums)))
    return ToolRun(tool="Semgrep", findings=tuple(findings)), dropped


def main() -> int:
    for path in (TESTCODE, GROUND_TRUTH, RULES):
        if not path.exists():
            print(f"missing: {path}", file=sys.stderr)
            return 2

    cases = load_expected_results(GROUND_TRUTH)
    print(f"OWASP Benchmark v1.2: {len(cases)} cases")
    print(f"rules: {RULES.name}")
    print(f"scanning {TESTCODE} ...")

    started = time.monotonic()
    raw = scan(TESTCODE, RULES)
    elapsed = time.monotonic() - started
    run, dropped = to_findings(raw)
    print(f"  {len(raw)} raw findings in {elapsed:.0f}s")
    print(f"  dropped: {dropped}")

    metrics = score_from_findings(cases, run)
    flagged = {f.case_number for f in run.findings}

    summary = {
        "corpus": "owasp-benchmark-1.2",
        "tool": "Semgrep",
        "ruleset": RULES.name,
        "ruleset_sha256": __import__("hashlib").sha256(RULES.read_bytes()).hexdigest(),
        "raw_findings": len(raw),
        "dropped": dropped,
        "cases_flagged": len(flagged),
        "scan_seconds": round(elapsed, 1),
        "score": metrics.score,
        "tpr": metrics.true_positive_rate,
        "fpr": metrics.false_positive_rate,
        "precision": metrics.precision,
        "fscore": metrics.fscore,
        "tp": metrics.tp,
        "fp": metrics.fp,
        "fn": metrics.fn,
        "tn": metrics.tn,
    }
    out = RESULTS / "semgrep_owasp.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2))

    print("\n" + "=" * 58)
    print(f"cases flagged          {len(flagged)}/{len(cases)}")
    print(f"TP={metrics.tp} FP={metrics.fp} FN={metrics.fn} TN={metrics.tn}")
    print(f"TPR (macro)            {metrics.true_positive_rate:.2%}")
    print(f"FPR (macro)            {metrics.false_positive_rate:.2%}")
    print(f"precision              {metrics.precision:.2%}")
    print(f"score = TPR - FPR      {metrics.score:.2%}")
    print("=" * 58)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
