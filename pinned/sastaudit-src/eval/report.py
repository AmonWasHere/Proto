"""Produce the macro-vs-micro delta table over every published scorecard.

Run from the repo root:

    python3 -m sastaudit.eval.report

Writes results/aggregation_delta.json and prints a human-readable table.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from sastaudit.corpus.owasp import load_expected_results, load_scorecard
from sastaudit.scoring.corrected import score_tool_corrected

ROOT = Path(__file__).resolve().parents[2]
UPSTREAM = ROOT / "sastaudit" / "upstream" / "benchmarkjava"

SCORECARDS = [
    ("SonarQube Java Plugin", "Benchmark_v1.2_Scorecard_for_SonarQube_Java_Plugin.csv"),
    ("OWASP ZAP", "Benchmark_v1.2_Scorecard_for_OWASP_ZAP.csv"),
    ("FindBugs", "Benchmark_v1.2_Scorecard_for_FindBugs.csv"),
    ("PMD", "Benchmark_v1.2_Scorecard_for_PMD.csv"),
    ("FBwFindSecBugs", "Benchmark_v1.2_Scorecard_for_FBwFindSecBugs.csv"),
]


def main(argv: list[str] | None = None) -> int:
    if not UPSTREAM.exists():
        print(f"upstream benchmark not found at {UPSTREAM}", file=sys.stderr)
        return 2

    cases = load_expected_results(UPSTREAM / "expectedresults-1.2.csv")

    rows = []
    for tool, csv_name in SCORECARDS:
        passed = load_scorecard(UPSTREAM / "scorecard" / csv_name)
        report = score_tool_corrected(cases, passed, tool=tool)
        rows.append(
            {
                **report.as_row(),
                "tpr_contributions": [c.as_row() for c in report.tpr_contributions],
                "fpr_contributions": [c.as_row() for c in report.fpr_contributions],
            }
        )

    out = ROOT / "sastaudit" / "results" / "aggregation_delta.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"corpus": "owasp-benchmark-v1.2", "rows": rows}, indent=2))

    print(f"OWASP Benchmark v1.2 — {len(cases)} cases, "
          f"{len({c.category for c in cases.values()})} categories\n")
    print(f"{'tool':24s} {'published':>10s} {'corrected':>10s} {'delta':>9s}")
    print("-" * 57)
    for r in rows:
        print(
            f"{r['tool']:24s} {r['published_score']:>9.2%} "
            f"{r['corrected_score']:>10.2%} {r['score_delta']:>+9.2%}"
        )

    print("\nPer-category weighting distortion (macro weight / case-proportional weight):")
    worst = rows[0]
    for c in worst["tpr_contributions"]:
        print(
            f"  {c['category']:14s} n={c['n']:>4d}  "
            f"macro {c['macro_weight']:>6.3f}  micro {c['micro_weight']:>6.3f}  "
            f"{c['weight_ratio']:>5.2f}x"
        )
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
