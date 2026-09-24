"""The strictest real-world denominator available, and what it does to the gap.

    python3 -m sastaudit.eval.cve_denominator

The headline real-corpus figure is a flip rate over commits. That invites the
objection -- correctly -- that JavaVFC commits are not all vulnerabilities: this
study measures that only 18% are, so the denominator contains material no
scanner could be expected to detect, and a gap computed against it is inflated
by construction.

This module answers that objection with the tightest denominator the corpus
admits rather than arguing about it.

Three nested restrictions, each removing something a source scanner provably
cannot report on:

  1. **Names a CVE.** Ground truth from outside this study: an authority with no
     stake in it has asserted the commit fixes a named vulnerability. Needs no
     judgement from us and depends on none of the filters criticised here.
     (32 commits.)

  2. **Changes code.** 18 of the 32 are dependency bumps -- the vulnerable code
     is inside a jar, not in the diff, so no source analysis of this commit
     could ever report it. Each is empty for a reason that says nothing about
     the tool, and leaving them in dilutes the rate toward zero. (14 commits.)

  3. Everything else stays. In particular the single-file rule used by the
     `security` stratum is NOT applied: it would cut 32 to 12 and discard XSS,
     XXE, deserialization and authorization fixes, which are exactly the classes
     a taint engine claims to model. See real_corpus.select().

What survives is the number to report: **among in-code fixes for
externally-certified vulnerabilities, how often did the tool's verdict move?**

The classification in DEPENDENCY_BUMPS is a judgement about 32 specific commits,
recorded here as data rather than inferred, and guarded against the stratum the
way corpus_audit guards its hand labels -- a classification that drifts silently
from the sample it describes is worse than none. The signals that look
mechanical do not work: `has_non_test_java` fails to separate them, because a
version bump routinely touches a Java file incidentally (a version constant, an
API rename, a test that pins the old behaviour).

Honest limits, carried into the output rather than left here:

* n is small. The interval on the flip rate is wide and is reported, not
  suppressed.
* "Dependency bump" and "code fix" are not exhaustive or exclusive; a commit
  that both bumps a library and adapts to its new API is classified by which
  change the message says the fix *is*.
* Losing a file to a fetch failure would remove a commit from the denominator;
  the join reports that gap instead of silently shrinking n.
"""

from __future__ import annotations

import argparse
import json

from ..corpus.javavfc import load, removed_lines
from ..tools import REGISTRY
from .corpus_audit import wilson
from .real_corpus import DATA, RESULTS, select

# Commits in the `cve` stratum whose fix lives in a dependency rather than in
# the diff. Indexed by corpus index, which is stable and unique; the sha is
# neither (JavaVFC repeats fixes across forks).
DEPENDENCY_BUMPS = {
    66,   # guava  -> CVE-2023-2976
    155,  # H2
    193,  # guava
    196,  # guava
    228,  # SnakeYAML 2.0
    254,  # alluxio
    269,  # revert jackson bump
    301,  # rocksdb
    387,  # revert jackson bump
    443,  # avro
    457,  # guava (24 files, all incidental)
    495,  # kubernetes/docker clients
    512,  # jackson
    523,  # avro
    552,  # Flyway refactor + Snowflake/SQLite/MariaDB JDBC bumps
    633,  # hadoop
    728,  # hadoop-common
    767,  # jackson-databind
}


def classify(index: int) -> str:
    """'dependency' or 'code' -- the two members of an exhaustive partition."""
    return "dependency" if index in DEPENDENCY_BUMPS else "code"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", choices=sorted(REGISTRY), default="semgrep")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)
    out_name = args.out or f"cve_denominator_{args.tool}.json"

    commits = load(DATA / "javavfc.jsonl")
    sample = select(commits, limit=0, stride=1, stratum="cve")
    by_index = {c.index: c for c in sample}

    # The classification describes this stratum and nothing else. A CVE commit
    # that is not in the sample, or a listed index that is not a CVE commit,
    # means the table and the sample have drifted apart.
    stray = sorted(set(DEPENDENCY_BUMPS) - set(by_index))
    if stray:
        raise SystemExit(
            f"DEPENDENCY_BUMPS names {len(stray)} index(es) not in the cve stratum: "
            f"{stray}\n  the sample is selected by message content; a listed index "
            f"that no longer qualifies means the table is stale."
        )

    path = RESULTS / f"{args.tool}_cve.json"
    if not path.exists():
        print(f"no {path.name}: run real_corpus --tool {args.tool} --stratum cve first")
        return 1
    doc = json.loads(path.read_text())
    rows = {r["index"]: r for r in doc["rows"]}

    code = [i for i in sorted(by_index) if classify(i) == "code" and i in rows]
    dep = [i for i in sorted(by_index) if classify(i) == "dependency" and i in rows]
    missing = len(by_index) - len(code) - len(dep)

    def outcome(r: dict) -> str:
        v, f = r["vuln_findings"], r["fixed_findings"]
        if v and f:
            return "both"
        if v:
            return "flipped"
        if f:
            return "fixed_only"
        return "silent"

    print(f"tool {args.tool} {doc['summary'].get('tool_version', '')}")
    print(f"cve stratum {len(by_index)} commits -> {len(code)} code, {len(dep)} dependency"
          + (f", {missing} not evaluated" if missing else ""))
    print()
    print("=" * 74)
    print("THE THREE NESTED RESTRICTIONS")
    print("=" * 74)
    print(f"  any Java file changed, names a CVE        {len(by_index):3d}")
    print(f"  ... and the fix is in code, not a jar     {len(code):3d}   <- the denominator")
    print(f"  (dropped as dependency bumps              {len(dep):3d})")

    for label, group in (("dependency bumps", dep), ("in-code fixes", code)):
        tally = {"flipped": 0, "both": 0, "fixed_only": 0, "silent": 0}
        for i in group:
            tally[outcome(rows[i])] += 1
        n = len(group)
        print()
        print(f"  {label} (n={n})")
        if not n:
            continue
        for k in ("flipped", "both", "silent", "fixed_only"):
            note = ""
            if k == "flipped":
                note = "   <- verdict tracked the vulnerability"
            elif k == "both":
                note = "   <- tool fired, but said the same thing before and after"
            print(f"     {k:12s} {tally[k]:3d}  {tally[k] / n:6.1%}{note}")

    n = len(code)
    flips = sum(1 for i in code if outcome(rows[i]) == "flipped")
    lo, hi = wilson(flips, n) if n else (0.0, 1.0)

    # A flip requires a finding on the vulnerable revision and none on the
    # fixed one. A patch that deletes nothing leaves every flagged construct in
    # place, so for those commits a flip is impossible *by construction* rather
    # than unobserved -- they cannot be evidence about detection either way, and
    # counting them in the denominator understates the rate. Split them out so
    # the number reported is over commits where a flip could have happened.
    additive = {
        i for i in code
        if sum(len(removed_lines(cf.patch)) for cf in by_index[i].reconstructible_java_files) == 0
    }
    possible = [i for i in code if i not in additive]
    np_ = len(possible)
    fp_ = sum(1 for i in possible if outcome(rows[i]) == "flipped")
    lo_p, hi_p = wilson(fp_, np_) if np_ else (0.0, 1.0)

    bench = RESULTS / f"{args.tool}_owasp.json"
    tpr = json.loads(bench.read_text())["published"]["tpr"] if bench.exists() else None

    print()
    print("=" * 74)
    print("WHAT THIS DOES TO THE GAP")
    print("=" * 74)
    if tpr is not None:
        print(f"  OWASP Benchmark v1.2 TPR                 {tpr:6.1%}")
    print(f"  in-code CVE fixes, verdict flipped       {flips:3d}/{n}  {flips / n:6.1%}"
          f"   [95% CI {lo:.1%}-{hi:.1%}]")
    if additive:
        print(f"  of which a flip was possible at all      {fp_:3d}/{np_}  {fp_ / np_:6.1%}"
              f"   [95% CI {lo_p:.1%}-{hi_p:.1%}]")
        print(f"    ({len(additive)} commits delete no line, so a flip is impossible for")
        print("     them by construction -- see patch_shape.py. Counting them in the")
        print("     denominator understates the rate; excluding them does not improve")
        print("     it either, it just stops them being evidence they cannot be.)")
    print()
    print("  This is a FLOOR on detection, not a detection rate. A flip is the")
    print("  strongest signal the method can observe, and a tool can detect a")
    print("  vulnerability without producing one -- by flagging the vulnerable")
    print("  revision and something narrower on the fixed one, which reads as")
    print("  'both' here. The 'both' count above is the size of that blind spot.")
    print()
    print("  The restriction is now as tight as the corpus allows: every commit here")
    print("  fixes a vulnerability an outside authority named, in code that a source")
    print("  scanner can read. The interval is wide because n is small -- that is a")
    print("  limit of the corpus, not of the argument. What the number supports is")
    print("  not a precise rate but a direction: tightening the denominator all the")
    print("  way to externally-certified in-code fixes does not close the gap, so")
    print("  the gap is not an artefact of the denominator.")
    print()
    print("  Read it with the 'both' row above. A tool that fires identically before")
    print("  and after a fix has not detected anything, and no coverage metric")
    print("  distinguishes it from one that has.")

    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / out_name).write_text(
        json.dumps(
            {
                "tool": args.tool,
                "stratum": "cve",
                "commits": len(by_index),
                "code_commits": len(code),
                "dependency_commits": len(dep),
                "not_evaluated": missing,
                "by_commit": {
                    str(i): {
                        "kind": classify(i),
                        "outcome": outcome(rows[i]),
                        "vuln_findings": rows[i]["vuln_findings"],
                        "fixed_findings": rows[i]["fixed_findings"],
                        "n_files": rows[i]["n_files"],
                        "message": rows[i]["message"],
                    }
                    for i in sorted(set(code) | set(dep))
                },
                "flip_rate_on_in_code_cve_fixes": flips / n if n else None,
                "flip_rate_ci95": [lo, hi],
                "owasp_tpr": tpr,
                "method": (
                    "Nested restrictions on the cve stratum: names a CVE (external "
                    "ground truth), then the fix is in code rather than in a "
                    "dependency. The dependency/code split is a hand classification "
                    "recorded in DEPENDENCY_BUMPS and guarded against the stratum; "
                    "it is not derivable mechanically -- has_non_test_java fails to "
                    "separate the two, because a version bump routinely touches a "
                    "Java file incidentally."
                ),
            },
            indent=2,
        )
    )
    print(f"\nwrote {out_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
