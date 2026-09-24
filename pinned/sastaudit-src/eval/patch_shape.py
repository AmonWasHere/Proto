"""What shape is a real security fix, and why does that defeat a taint detector?

    python3 -m sastaudit.eval.patch_shape --tool semgrep

The real-corpus result is that a taint-based scanner is silent on the large
majority of real security fixes. Reported alone that invites the reading "the
tool is bad", which is not a finding -- it is a restatement of the number. This
module asks a question the number cannot answer on its own: **what would the
tool have had to do to notice?**

The measurement is free. It needs no scanner, no network and no reconstruction:
the answer is a property of the patch text, which is already on disk. Only the
cross-tabulation against a tool's results touches a scan, and that is a join on
sha.

Purely additive fixes
---------------------
A patch that deletes nothing leaves every construct that was present before the
fix present after it. For a tool whose signal is "this dangerous construct
exists here", such a fix is *unobservable*: the evidence it reads is identical in
both revisions, so its verdict cannot change. The tool is not missing the
vulnerability so much as being structurally unable to express it.

That is exactly the failure mode the four-way decomposition exposes -- a fix of
this shape can only ever produce "flagged both", never a verdict flip -- and it
is invisible to a plain coverage number, because the file *is* flagged.

The OWASP Benchmark contains no case of this shape. Every one of its 2,740 cases
is a synthetic servlet whose vulnerable sink is present when vulnerable and
replaced when fixed. So the benchmark cannot penalise a tool for the behaviour
that dominates real code, and cannot measure the capability that real fixes
demand. The benchmark's score is not merely optimistic; it is answering a
question that the real corpus does not ask.

Honest limits
-------------
* "Purely additive" is a property of the patch, not proof the vulnerability
  survived. A guard added in one place can neutralise a sink defined in another
  file that the commit did not touch. The claim made here is the narrower and
  checkable one: no line the tool reported was removed, so its input did not
  change at that location.
* Single-file commits are all this stratum admits (see real_corpus.select), so
  cross-file neutralisation is outside the sample by construction rather than
  observed to be absent.
* Commits the scanner could not evaluate at all are absent from its result file;
  the join reports that gap rather than silently shrinking the denominator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter

from ..corpus.javavfc import HUNK_HEADER, load, removed_lines
from ..tools import REGISTRY
from .corpus_audit import wilson
from .real_corpus import DATA, RESULTS, select


def added_lines(patch: str) -> int:
    """Lines the patch adds.

    Deliberately parsed by the same state machine as `removed_lines()` rather
    than by counting `+` lines naively: a diff body can contain lines beginning
    `+++` (the file header) and `+` inside content, and the two functions must
    agree about what a hunk is or the added/removed pair would be inconsistent.
    """
    n = 0
    in_hunk = False
    for line in patch.splitlines():
        if line.startswith("diff --git ") or line.startswith("index "):
            in_hunk = False
            continue
        if HUNK_HEADER.match(line):
            in_hunk = True
            continue
        # Same rule as removed_lines(): the in-hunk state, not the line prefix,
        # is what separates a file header from a hunk body line. An added Java
        # line `++x;` arrives as `+++x;` and must count as one addition.
        if not in_hunk or line.startswith("\\"):
            continue
        if line.startswith("+"):
            n += 1
    return n


def shape_of(commit) -> dict:
    """Added/removed line counts for one commit, across its changed files."""
    removed = 0
    added = 0
    files = commit.reconstructible_java_files
    for cf in files:
        removed += len(removed_lines(cf.patch))
        added += added_lines(cf.patch)
    return {"added": added, "removed": removed, "files": len(files)}


def signature(commit) -> str:
    """A commit's identity by patch content rather than by sha.

    JavaVFC double-counts fixes, and the sha does not reveal it. The same
    upstream patch reaches the corpus through several forks -- frameworks_base
    and platform_frameworks_base are one project, Trebuchet and lawnchair
    another -- which are distinct commits in distinct repositories carrying
    byte-identical patches. One Jenkins commit appears three times outright.

    This sample's 120 commits carry 111 distinct patches. Treating the repeats
    as independent observations would inflate n and narrow the confidence
    interval around the headline rate without adding a single new fact.
    """
    h = hashlib.sha256()
    for cf in sorted(commit.reconstructible_java_files, key=lambda f: f.path):
        h.update(cf.patch.strip().encode())
        h.update(b"\0\0")
    return h.hexdigest()


def classify(row: dict) -> str:
    """The four-way decomposition, recomputed from the counts in the row.

    Derived here rather than read from the result file so this module cannot
    drift from the definition it is explaining: the two branches below are the
    definition, applied consistently to every tool.
    """
    v, f = row.get("vuln_findings", 0), row.get("fixed_findings", 0)
    if not v and not f:
        return "neither"
    if v and f:
        return "both"
    if v and not f:
        return "vuln_only"
    return "fixed_only"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", choices=sorted(REGISTRY), default="semgrep")
    ap.add_argument("--stratum", default="security")
    ap.add_argument("--out", default="patch_shape.json")
    args = ap.parse_args(argv)

    commits = load(DATA / "javavfc.jsonl")
    sample = select(commits, limit=0, stride=1, stratum=args.stratum)
    print(f"corpus {len(commits)} commits -> stratum={args.stratum}, sample {len(sample)}")

    shas = len({c.sha for c in sample})
    reps: dict[str, object] = {}
    for c in sample:
        reps.setdefault(signature(c), c)
    kept = sorted(reps.values(), key=lambda c: c.index)
    print(f"  {shas} distinct shas; {len(kept)} distinct patches "
          f"({len(sample) - len(kept)} commits repeat another's patch)")

    # Keyed on the corpus index, not the sha. JavaVFC is scraped, and the same
    # fix commit is linked from more than one issue: this sample's 120 commits
    # carry only 117 distinct shas. Keying on sha would silently collapse three
    # commits and, worse, let a join pair a row with the wrong commit.
    shapes = {c.index: shape_of(c) for c in kept}

    additive = [s for s in shapes.values() if s["removed"] == 0]
    n = len(shapes)
    print()
    print("=" * 70)
    print("PATCH SHAPE")
    print("=" * 70)
    lo, hi = wilson(len(additive), n)
    print(f"  fixes that delete no line at all   {len(additive):3d}/{n}  "
          f"{len(additive) / n:.1%}  [95% CI {lo:.1%}-{hi:.1%}]")

    sizes = sorted(s["removed"] for s in shapes.values())
    median = sizes[len(sizes) // 2]
    print(f"  lines deleted   min {min(sizes)}  median {median}  max {max(sizes)}")
    print("  A fix that deletes nothing leaves every flagged construct in place.")
    print("  For a scanner whose signal is the presence of that construct, the")
    print("  input is unchanged by the fix and the verdict cannot move.")

    # ---- join against a tool's results -----------------------------------
    path = RESULTS / f"{args.tool}_{args.stratum}.json"
    if not path.exists():
        print()
        print(f"  no {path.name}: run real_corpus --tool {args.tool} first")
        RESULTS.mkdir(parents=True, exist_ok=True)
        (RESULTS / args.out).write_text(
            json.dumps(
                {
                    "tool": args.tool,
                    "stratum": args.stratum,
                    "sample_commits": len(sample),
                    "distinct_shas": shas,
                    "distinct_patches": n,
                    "purely_additive": len(additive),
                    "purely_additive_rate": len(additive) / n,
                    "purely_additive_ci95": [lo, hi],
                    "removed_lines": {
                        "min": min(sizes), "median": median, "max": max(sizes)
                    },
                    "tool_result_available": False,
                },
                indent=2,
            )
        )
        return 0

    doc = json.loads(path.read_text())
    rows = {r["index"]: r for r in doc["rows"]}
    matched = [s for s in kept if s.index in rows]
    missing = len(kept) - len(matched)
    print()
    print(f"  joined {len(matched)} of {n} distinct patches against {path.name}"
          + (f"  ({missing} not evaluated by the scanner)" if missing else ""))

    tab = Counter()
    for c in matched:
        key = "additive" if shapes[c.index]["removed"] == 0 else "deletes"
        tab[(key, classify(rows[c.index]))] += 1

    print()
    print("=" * 70)
    print(f"CROSS-TAB  patch shape x {args.tool} outcome")
    print("=" * 70)
    outcomes = ("neither", "both", "vuln_only", "fixed_only")
    print(f"  {'':22s} " + " ".join(f"{o:>11s}" for o in outcomes) + f" {'total':>7s}")
    print("  " + "-" * 68)
    for key, label in (
        ("additive", "deletes no line"),
        ("deletes", "deletes >=1 line"),
    ):
        counts = [tab[(key, o)] for o in outcomes]
        print(f"  {label:22s} " + " ".join(f"{c:>11d}" for c in counts)
              + f" {sum(counts):>7d}")

    add_total = sum(tab[("additive", o)] for o in outcomes)
    flips = tab[("additive", "vuln_only")]
    print()
    print(f"  Of {add_total} purely additive fixes, {flips} produced a verdict change.")
    if add_total:
        print(f"  That is {flips / add_total:.1%} -- and the mechanism predicts near zero,")
        print("  because the fix removed none of the evidence the scanner reads.")
        print("  Note the sample is small and mostly silent either way: only "
              f"{sum(tab[('additive', o)] for o in ('both', 'vuln_only', 'fixed_only'))} "
              "of them were\n  flagged at all. The argument is the mechanism, which is "
              "a priori -- these\n  observations are consistent with it, not proof of it.")

    RESULTS.mkdir(parents=True, exist_ok=True)
    out = RESULTS / args.out
    out.write_text(
        json.dumps(
            {
                "tool": args.tool,
                "stratum": args.stratum,
                "sample_commits": len(sample),
                "distinct_shas": shas,
                "distinct_patches": n,
                "purely_additive": len(additive),
                "purely_additive_rate": len(additive) / n,
                "purely_additive_ci95": [lo, hi],
                "removed_lines": {
                    "min": min(sizes), "median": median, "max": max(sizes)
                },
                "joined": len(matched),
                "not_evaluated": missing,
                "tool_result_available": True,
                "cross_tab": {
                    f"{k}|{o}": v for (k, o), v in sorted(tab.items())
                },
                "method": (
                    "Patch shape is computed from diff_raw alone: no scanner, no "
                    "network, no reconstruction. The joint distribution joins on "
                    "sha to the scanner's per-commit result file. 'Deletes no "
                    "line' is a property of the patch, not proof the "
                    "vulnerability survived; single-file commits are all this "
                    "stratum admits, so cross-file neutralisation is outside the "
                    "sample by construction."
                ),
            },
            indent=2,
        )
    )
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
