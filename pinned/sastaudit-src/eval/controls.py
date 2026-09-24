"""The capability matrix: every scanner, one shared set of hand-checked cases.

Why this exists before the big runs
-----------------------------------
The study's central claim is comparative -- "the benchmark says 78%, the real
corpus says 1%, therefore the benchmark does not predict". A claim like that is
only as good as the assurance that the tools were actually working when the
second number was produced. A tool that is misconfigured, or that silently
failed, produces exactly the same 0% as a tool that looked at real
vulnerabilities and saw nothing.

So before any corpus is scanned, every tool is put through the same 21
hand-checked files: 18 canonical vulnerabilities and 3 negative controls that
are not vulnerable. The result is a matrix, and it does two jobs at once. It
proves each scanner is alive and configured, and it publishes each scanner's
blind spots in a form a reader can check.

Two scoring views, both reported
--------------------------------
* **loose** -- the file was flagged at all. This is what a human user
  experiences: noise or signal, the tool said something.
* **strict** -- the file was flagged with the *expected CWE*. This is what the
  OWASP Benchmark actually grades, and it is a much harder bar: a tool that
  reports a real SQL injection as CWE-564 rather than CWE-89 has found the bug
  and still scores zero on the benchmark.

Reporting only one of these would hide the interesting case, which is a tool
that finds everything and classifies none of it correctly. PMD is excluded from
this study entirely (see tools/__init__.py EXCLUDED); it would have scored
near-zero here for reasons unrelated to quality.

The negative controls carry as much weight as the positives. A scanner that
flags `new File(BASE, name)` because a path-traversal rule pattern-matches the
constructor will flag the version with a canonical-path containment check too,
and without the safe files that behaviour would be invisible in a table of
detection rates.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

from ..tools import EXCLUDED, REGISTRY, ToolError, available_tools, build_tool

ROOT = Path(__file__).resolve().parents[2]
CONTROLS = ROOT / "sastaudit" / "controls"
SRC = CONTROLS / "src"
RESULTS = ROOT / "sastaudit" / "results"


def load_manifest() -> list[dict]:
    manifest = json.loads((CONTROLS / "manifest.json").read_text())
    return manifest["cases"]


def score_case(case: dict, findings: list) -> dict:
    """Fold one tool's findings for one control file into a verdict."""
    hits = [f for f in findings if Path(f.path).name == Path(case["file"]).name]
    expected_cwe = case["cwe"]
    matched = [f for f in hits if expected_cwe in f.cwes]
    return {
        "file": case["file"],
        "expect": case["expect"],
        "category": case["category"],
        "expected_cwe": expected_cwe,
        "flagged": bool(hits),
        "cwe_match": bool(matched),
        "rules": sorted({f.rule for f in hits}),
        "lines": sorted({f.line for f in hits}),
        "claimed_cwes": sorted({c for f in hits for c in f.cwes}),
    }


def tally(rows: list[dict], *, strict: bool) -> dict:
    """Confusion matrix over the controls, in either scoring view."""
    tp = fn = fp = tn = 0
    for r in rows:
        fired = r["cwe_match"] if strict else r["flagged"]
        if r["expect"] == "vulnerable":
            tp += fired
            fn += not fired
        else:
            fp += fired
            tn += not fired
    n_pos = tp + fn
    n_neg = fp + tn
    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "n_vulnerable": n_pos,
        "n_safe": n_neg,
        "detection_rate": tp / n_pos if n_pos else 0.0,
        "false_positive_rate": fp / n_neg if n_neg else 0.0,
    }


def run_tool(name: str, cases: list[dict]) -> dict:
    """Scan the control directory with one tool and score the result."""
    entry: dict = {"tool": name, "ok": False}
    try:
        tool = build_tool(name)
        if not tool.available():
            entry["error"] = "binary not available"
            return entry
        entry["version"] = tool.version()
        outcome = tool.scan(SRC)
    except ToolError as exc:
        # A failed scan is recorded as a failure, never as zero findings. The
        # distinction is the entire premise of the study's method.
        entry["error"] = str(exc)
        return entry
    except Exception as exc:  # noqa: BLE001 - a crash must not stop the matrix
        entry["error"] = f"{type(exc).__name__}: {exc}"
        entry["traceback"] = traceback.format_exc()[-1500:]
        return entry

    rows = [score_case(c, outcome.findings) for c in cases]
    entry.update(
        ok=True,
        n_findings=len(outcome.findings),
        seconds=round(outcome.seconds, 1),
        stderr=outcome.stderr[:1000],
        per_case={r["file"]: r for r in rows},
        loose=tally(rows, strict=False),
        strict=tally(rows, strict=True),
    )
    return entry


def render(report: dict) -> None:
    cases = report["cases"]
    names = list(report["tools"])
    width = max(len(Path(c["file"]).stem) for c in cases) + 2

    print()
    print("=" * (width + 9 * len(names) + 14))
    print("CONTROL MATRIX  (hand-checked cases, one shared set per tool)")
    print("=" * (width + 9 * len(names) + 14))
    header = "case".ljust(width) + "expect".ljust(11)
    for n in names:
        header += n.center(9)
    print(header)
    print("-" * (width + 9 * len(names) + 14))

    for c in cases:
        stem = Path(c["file"]).stem
        line = stem.ljust(width) + c["expect"].ljust(11)
        for n in names:
            t = report["tools"][n]
            if not t.get("ok"):
                line += "  --   ".center(9)
                continue
            row = t["per_case"][c["file"]]
            if c["expect"] == "vulnerable":
                mark = "HIT" if row["flagged"] else "miss"
                if row["flagged"] and not row["cwe_match"]:
                    mark = "hit?"  # found something, wrong CWE claim
            else:
                mark = "FP!" if row["flagged"] else "ok"
            line += mark.center(9)
        print(line)

    print("-" * (width + 9 * len(names) + 14))
    for view in ("loose", "strict"):
        line = f"{view} (vuln {len([c for c in cases if c['expect']=='vulnerable'])})".ljust(width)
        line = view.ljust(width) + "".ljust(11)
        for n in names:
            t = report["tools"][n]
            line += (f"{t[view]['detection_rate']:.0%}".center(9) if t.get("ok") else "--".center(9))
        print(line)
    line = "false positive rate".ljust(width) + "".ljust(11)
    for n in names:
        t = report["tools"][n]
        line += (f"{t['loose']['false_positive_rate']:.0%}".center(9) if t.get("ok") else "--".center(9))
    print(line)
    print("=" * (width + 9 * len(names) + 14))
    print("  HIT = flagged   hit? = flagged but wrong CWE claim   miss = silent")
    print("  ok  = safe file correctly left alone   FP! = safe file flagged")
    print("  loose counts any finding; strict requires the expected CWE")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", default=",".join(REGISTRY))
    ap.add_argument("--out", default="controls_matrix.json")
    args = ap.parse_args(argv)

    names = [n.strip() for n in args.tools.split(",") if n.strip()]
    cases = load_manifest()

    present = available_tools()
    print(f"controls: {len(cases)} files in {SRC}")
    for name in names:
        state = "available" if present.get(name) else "NOT AVAILABLE"
        print(f"  {name:10s} {state}")
    if EXCLUDED:
        print(f"  excluded by design: {', '.join(sorted(EXCLUDED))}")

    report = {"case_count": len(cases), "cases": cases, "tools": {}}
    for name in names:
        print(f"\n--- {name} ---", flush=True)
        entry = run_tool(name, cases)
        report["tools"][name] = entry
        if entry.get("ok"):
            print(
                f"  {entry['n_findings']} findings in {entry['seconds']}s | "
                f"loose {entry['loose']['detection_rate']:.0%} detect, "
                f"{entry['loose']['false_positive_rate']:.0%} FP | "
                f"strict {entry['strict']['detection_rate']:.0%} detect"
            )
        else:
            print(f"  FAILED: {entry.get('error')}")

    RESULTS.mkdir(parents=True, exist_ok=True)
    out = RESULTS / args.out
    out.write_text(json.dumps(report, indent=2))
    render(report)
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
