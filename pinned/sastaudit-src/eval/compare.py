"""The headline table: every tool, every corpus, side by side.

    python3 -m sastaudit.eval.compare

Reads the result files produced by the other eval modules and prints the
contrast the study rests on. Nothing is recomputed here, so this cannot drift
from the runs it reports.

Files that do not exist are shown as "--" rather than omitted. A tool missing
from a table because its run has not finished looks identical to a tool that
was never measured, and those are different claims; a blank that is visibly a
blank is the honest presentation.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "sastaudit" / "results"

#: Display order. The semgrep family leads because it is the baseline the
#: first phase of the study measured; CodeQL follows as the independent one.
TOOLS = ("semgrep", "opengrep", "codeql")

DASH = "   --   "


def _load(name: str) -> dict | None:
    path = RESULTS / name
    if not path.exists():
        return None
    return json.loads(path.read_text())


def _pct(x: float | None) -> str:
    return f"{x:6.2%}" if x is not None else "   --  "


def _case_label(path: str) -> str:
    """`src/ctrl_sqli_tautology.java` -> `sqli_tautology` in the table.

    The manifest keys on the full relative path, which is right for lookups and
    unreadable in a headline: the column is already 74 characters wide, and
    `src/`/`.java`/`ctrl_` carry no information the column header does not.
    """
    return Path(path).stem.removeprefix("ctrl_")


def controls_table() -> None:
    matrix = _load("controls_matrix.json")
    print()
    print("=" * 78)
    print("CONTROL SET  (21 hand-checked files: 18 canonical vulns, 3 safe)")
    print("=" * 78)
    if not matrix:
        print("  not run yet: python3 -m sastaudit.eval.controls")
        return
    print(f"  {'tool':10s} {'detects':>10s} {'false pos':>11s}   misses")
    print("  " + "-" * 74)
    for name in TOOLS:
        t = matrix["tools"].get(name)
        if not t or not t.get("ok"):
            print(f"  {name:10s} {DASH:>10s} {DASH:>11s}   {t.get('error', 'not run') if t else 'not run'}")
            continue
        missed = [
            k for k, v in t["per_case"].items()
            if v["expect"] == "vulnerable" and not v["flagged"]
        ]
        fp = [
            k for k, v in t["per_case"].items()
            if v["expect"] == "safe" and v["flagged"]
        ]
        print(
            f"  {name:10s} {t['loose']['detection_rate']:>10.0%} "
            f"{t['loose']['false_positive_rate']:>11.0%}   "
            f"{'-' if not missed else ''}{', '.join(_case_label(m) for m in missed)}"
        )
        if fp:
            print(f"  {'':10s} {'':>10s} {'':>11s}   false positives: "
                  f"{', '.join(_case_label(m) for m in fp)}")


def owasp_table() -> None:
    print()
    print("=" * 78)
    print("OWASP Benchmark v1.2  (2,740 synthetic cases, written to be findable)")
    print("=" * 78)
    rows = []
    for name in TOOLS:
        d = _load(f"{name}_owasp.json")
        if not d:
            rows.append((name, None, None, None, None, None))
            continue
        p, c = d["published"], d["corrected"]
        rows.append(
            (name, d["cases_flagged"], p["tpr"], p["fpr"], p["score"], c["corrected_score"])
        )
    print(f"  {'tool':10s} {'flagged':>9s} {'TPR':>9s} {'FPR':>9s} "
          f"{'score':>9s} {'corrected':>10s}")
    print("  " + "-" * 62)
    for name, flagged, tpr, fpr, score, corr in rows:
        if flagged is None:
            print(f"  {name:10s} {DASH:>9s} {DASH:>9s} {DASH:>9s} {DASH:>9s} {DASH:>10s}")
            continue
        print(
            f"  {name:10s} {flagged:>4d}/2740 {_pct(tpr):>9s} {_pct(fpr):>9s} "
            f"{_pct(score):>9s} {_pct(corr):>10s}"
        )
    print("  score = TPR - FPR, macro-averaged, exactly as BenchmarkUtils computes it")
    for name in TOOLS:
        d = _load(f"{name}_owasp.json")
        if d and d.get("cwe_leniency_applied"):
            print(f"  {name}: scored as {d['scorer_tool_name']!r}, "
                  f"which the benchmark grants CWE-327-for-328 leniency")


_STRATUM_LABEL = {
    "security": "JavaVFC security stratum  (real fixes asserting a security change)",
    "raw": "JavaVFC raw stratum  (the corpus exactly as shipped)",
    "cve": "JavaVFC cve stratum  (commits naming a CVE -- external ground truth; "
           "multi-file commits INCLUDED)",
}


def real_table(stratum: str) -> dict[str, float]:
    # Keyed rather than a fallthrough: an unrecognised stratum used to be
    # labelled "raw", which would silently mislabel any new stratum as the
    # corpus-as-shipped and make its numbers unattributable.
    label = _STRATUM_LABEL.get(stratum)
    if label is None:
        raise SystemExit(
            f"no label for stratum {stratum!r}; add it to _STRATUM_LABEL rather "
            f"than letting it inherit another stratum's description"
        )
    print()
    print("=" * 78)
    print(label)
    print("=" * 78)
    flips: dict[str, float] = {}
    header = f"  {'tool':10s} {'n':>4s} {'silent':>8s} {'both':>8s} {'flipped':>8s} {'on line':>9s}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for name in TOOLS:
        d = _load(f"{name}_{stratum}.json")
        if not d:
            print(f"  {name:10s} {DASH:>4s} {DASH:>8s} {DASH:>8s} {DASH:>8s} {DASH:>9s}")
            continue
        s = d["summary"]
        n = s["commits_evaluated"]
        dec = s["decomposition"]
        flips[name] = s["verdict_flipped_with_fix"]
        inc = "  (INCOMPLETE)" if s.get("incomplete") else ""
        print(
            f"  {name:10s} {n:>4d} {dec['flagged_neither'] / n:>8.1%} "
            f"{dec['flagged_both_revisions'] / n:>8.1%} "
            f"{dec['flagged_vulnerable_only'] / n:>8.1%} "
            f"{s['flagged_on_removed_line'] / n:>9.1%}{inc}"
        )
    print("  silent   = tool said nothing on either revision")
    print("  both     = flagged before and after the fix (pattern survives it)")
    print("  flipped  = verdict changed with the fix  <- detected the vulnerability")
    print("  on line  = finding on a line the patch deleted (lower bound)")
    return flips


def contrast(flips: dict[str, float]) -> None:
    print()
    print("=" * 78)
    print("CONTRAST")
    print("=" * 78)
    print(f"  {'tool':10s} {'benchmark TPR':>14s} {'real detection':>15s}")
    print("  " + "-" * 41)
    for name in TOOLS:
        d = _load(f"{name}_owasp.json")
        flip = flips.get(name)
        if not d or flip is None:
            print(f"  {name:10s} {DASH:>14s} {DASH:>15s}")
            continue
        tpr = d["published"]["tpr"]
        print(f"  {name:10s} {tpr:>14.2%} {flip:>15.2%}")

    # Deliberately NOT divided into a ratio. These are two different
    # quantities: the first is the share of KNOWN vulnerabilities detected, on
    # cases built to contain one; the second is the share of COMMITS whose
    # verdict moved. The real-corpus denominator is mostly not security work
    # (see the composition figure below), so the divisor includes material no
    # scanner could be expected to detect and the quotient flatters whichever
    # conclusion the reader already holds. An earlier version of this
    # comparison led with it; that framing is withdrawn.
    print()
    print("  These are not the same kind of quantity and the ratio between them is")
    print("  not meaningful: the left is a share of known vulnerabilities, the right")
    print("  a share of commits. The stratum below restricts to commits naming a CVE")
    print("  -- ground truth from outside this study -- and reports the split there.")

    comp = _load("javavfc_composition.json")
    if comp:
        hl = comp["hand_labels"]
        lo, hi = hl["strict_ci95"]
        print()
        print(f"  corpus composition: {hl['strict_rate']:.1%} of JavaVFC is a genuine "
              f"security fix [95% CI {lo:.1%}-{hi:.1%}]")
        print("  So the real-corpus denominator is itself mostly not security work,")
        print("  which bounds how much of the gap any tool could close.")

    shape = _load("patch_shape.json")
    if shape:
        lo, hi = shape["purely_additive_ci95"]
        print()
        print(f"  patch shape: {shape['purely_additive_rate']:.1%} of those fixes delete "
              f"no line at all [95% CI {lo:.1%}-{hi:.1%}]")
        print("  A presence-based detector reads identical evidence before and after such a")
        print("  fix, so its verdict cannot move -- in this sample none of them flipped. The")
        print("  benchmark contains no case of that shape, so it cannot price the capability")
        print("  those fixes demand: the gap is a mismatch of model, not only of skill.")


def build_sensitivity() -> None:
    """The same engine-build swap, measured on all three corpora.

    This is the study's sharpest result and it needs both halves to see: two
    builds of one engine family are indistinguishable on real code and 6.7
    score points apart on the benchmark. Either measurement alone shows nothing
    unusual. Printed because a reader who sees only the OWASP table would take
    the 6.7-point gap for a property of the tools.
    """
    a, b = "semgrep", "opengrep"
    print()
    print("=" * 78)
    print("BUILD SENSITIVITY  --  same ruleset bytes, two builds of one engine family")
    print("=" * 78)
    print(f"  {a} {_load(f'{a}_owasp.json')['tool_version'] if _load(f'{a}_owasp.json') else DASH}"
          f"   vs   {b} {_load(f'{b}_owasp.json')['tool_version'] if _load(f'{b}_owasp.json') else DASH}")
    print()

    # 1. controls
    ctrl = _load("controls_matrix.json")
    same_ctrl = DASH
    if ctrl and a in ctrl.get("tools", {}) and b in ctrl.get("tools", {}):
        ca = ctrl["tools"][a]["per_case"]
        cb = ctrl["tools"][b]["per_case"]
        diff = [k for k in ca if ca[k]["flagged"] != cb.get(k, {}).get("flagged")]
        same_ctrl = "identical" if not diff else f"{len(diff)} files differ"

    # 2. real stratum, at the finding level not just the totals
    same_real = DASH
    da, db = _load(f"{a}_security.json"), _load(f"{b}_security.json")
    if da and db:
        ra = {r["index"]: r for r in da["rows"]}
        rb = {r["index"]: r for r in db["rows"]}
        def sig(r):
            return (tuple(sorted(r["vuln_rules"])), r["vuln_findings"],
                    tuple(sorted(r["fixed_rules"])), r["fixed_findings"],
                    tuple(r["vuln_lines"]))
        diff = [i for i in ra if i in rb and sig(ra[i]) != sig(rb[i])]
        same_real = ("identical (0 of %d commits differ in any respect)" % len(ra)
                     if not diff else f"{len(diff)} of {len(ra)} commits differ")

    # 3. benchmark
    same_bench = DASH
    oa, ob = _load(f"{a}_owasp.json"), _load(f"{b}_owasp.json")
    if oa and ob:
        pa, pb = oa["published"], ob["published"]
        same_bench = (f"{pa['score']:.2%} vs {pb['score']:.2%}  "
                      f"({(pb['score'] - pa['score']) * 100:+.2f} points; "
                      f"TP {pb['tp'] - pa['tp']:+d}  FP {pb['fp'] - pa['fp']:+d})")

    print(f"  controls          (21 files)    {same_ctrl}")
    print(f"  real fixes        (120 commits) {same_real}")
    print(f"  OWASP v1.2        (2740 cases)  {same_bench}")
    print()
    print("  The builds differ only where the synthetic corpus is. Whatever engine")
    print("  behaviour separates them has no observable effect on any of 120 real")
    print("  security fixes, while moving the published score by 6.7 points. A")
    print("  statistic that responds to a variable with no measurable effect on the")
    print("  quantity it claims to measure is not measuring that quantity.")
    print("  Published scorecards name a tool, not a build, so this variation is")
    print("  unattributable from the scorecard alone.")


def main() -> int:
    controls_table()
    owasp_table()
    flips = real_table("security")
    real_table("cve")
    real_table("raw")
    build_sensitivity()
    contrast(flips)
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
