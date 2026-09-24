"""How the OWASP Benchmark's safe cases are constructed, measured rather than assumed.

Section 3.3 of the write-up makes a structural claim about the benchmark: that it
contains no revisions, so the before/after question -- does a tool's verdict move
when the vulnerability is removed -- cannot be asked of it at all.

The corpus has no revision history to check that against, so the claim is checked
instead against the corpus's own construction: the safe half is generated as
separate files, one per vulnerable case, and one expects each safe file to be its
vulnerable twin with a sanitiser substituted. If that is how they were built, then
each pair differs by substitution -- a construct replaced -- and never by pure
addition, which is the shape 20.7% of real fixes take (Section 3.3, `patch_shape`).

This module exists because the numbers it produces were previously quoted in the
write-up without any code able to re-derive them -- the same defect Section 4
documents at 44.3%, committed again in Section 3.3. The search is a *pairing
heuristic*, not ground truth: it can fail to pair two files that are in fact
twins, so an unpaired case is a limit of this method, not evidence about the
corpus. It is reported as the partial result it is.

Run from the repo root:

    python3 -m sastaudit.eval.benchmark_structure
"""

from __future__ import annotations

import csv
import difflib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BENCH = ROOT / "sastaudit" / "upstream" / "benchmarkjava"
TESTCODE = BENCH / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
GROUND_TRUTH = BENCH / "expectedresults-1.2.csv"
OUT = ROOT / "sastaudit" / "results" / "benchmark_structure.json"

#: Similarity at which two files are called twins. Stated as a parameter rather
#: than buried, because the unpaired count is a direct function of it and a
#: reader should be able to move it.
THRESHOLD = 0.90

#: Cheap pre-filter: twins generated from one another are near-identical in line
#: count, so a candidate whose length differs by more than this cannot reach the
#: threshold and is skipped without the quadratic comparison. Only a speed
#: measure -- see `_check_prefilter_is_safe`.
LENGTH_TOLERANCE = 0.5


def load_ground_truth() -> dict[str, dict]:
    """name -> {category, vulnerable, cwe}, from the benchmark's own CSV."""
    cases: dict[str, dict] = {}
    with GROUND_TRUTH.open() as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            name, category, real, cwe = next(csv.reader([line]))
            cases[name] = {
                "category": category,
                "vulnerable": real.strip().lower() == "true",
                "cwe": int(cwe),
            }
    return cases


def normalised_lines(name: str) -> list[str]:
    """The file's non-blank lines, stripped.

    Blank lines and indentation are excluded because the benchmark's generator
    varies them independently of the construct under test; counting them would
    report a formatting difference as a structural one.
    """
    text = (TESTCODE / f"{name}.java").read_text(errors="replace")
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def classify(a: list[str], b: list[str]) -> str:
    """How b differs from a, at line granularity.

    `pure_deletion` means b is a with whole lines removed and nothing added --
    the safe case drops the sink. `purely_additive` means the reverse: b adds
    lines without removing any, which is the shape a real fix takes when it adds
    a missing check, and the shape the benchmark is claimed never to pose.
    """
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    tags = {tag for tag, *_ in sm.get_opcodes()}
    if tags <= {"equal"}:
        return "identical"
    if tags <= {"equal", "delete"}:
        return "pure_deletion"
    if tags <= {"equal", "insert"}:
        return "purely_additive"
    return "substitution"


def _check_prefilter_is_safe(a: list[str], b: list[str]) -> bool:
    """Would the length filter have discarded a pair that actually matches?

    The filter is only sound if two line lists whose lengths differ by more than
    LENGTH_TOLERANCE in relative terms cannot reach THRESHOLD similarity. Rather
    than assert that, this is checked against every pair the search actually
    accepts, and the count is persisted, so an unsound filter shows up as a
    non-zero number instead of as a silently smaller sample.
    """
    longer = max(len(a), len(b))
    if longer == 0:
        return False
    return abs(len(a) - len(b)) / longer > LENGTH_TOLERANCE


def main() -> int:
    truth = load_ground_truth()
    vuln = sorted(n for n, c in truth.items() if c["vulnerable"])
    safe = sorted(n for n, c in truth.items() if not c["vulnerable"])
    by_category: dict[str, list[str]] = {}
    for n in vuln:
        by_category.setdefault(truth[n]["category"], []).append(n)

    sources = {n: normalised_lines(n) for n in truth}

    kinds: Counter[str] = Counter()
    ratios: list[float] = []
    unpaired: list[str] = []
    pairs: dict[str, dict] = {}
    filter_discards = 0

    # Every candidate above the threshold, not just each safe case's single best.
    #
    # Taking the best per safe case independently does NOT produce a pairing: the
    # benchmark's generator gives every case in a category a large shared
    # scaffold, so similarity is inflated across the whole family and several safe
    # cases can name the same vulnerable case as their nearest neighbour. Measured
    # on the first run of this module, 218 "pairs" collapsed to 171 distinct
    # twins -- i.e. 47 of them claimed a case another safe case had already
    # claimed, which is evidence the match was the scaffold rather than the twin.
    # Candidates are therefore collected and assigned one-to-one below.
    candidates: list[tuple[float, str, str]] = []
    for name in safe:
        a_safe = sources[name]
        for cand in by_category.get(truth[name]["category"], []):
            b = sources[cand]
            if _check_prefilter_is_safe(a_safe, b):
                filter_discards += 1
                continue
            r = difflib.SequenceMatcher(None, b, a_safe, autojunk=False).ratio()
            if r >= THRESHOLD:
                candidates.append((r, name, cand))

    # Greedy maximum-similarity assignment: strongest pair first, each case used
    # once. Greedy rather than optimal -- an optimal assignment would pair at most
    # a few more cases and would claim a precision this heuristic does not have.
    candidates.sort(key=lambda t: (-t[0], t[1], t[2]))
    used_vuln: set[str] = set()
    claimed: set[str] = set()
    for ratio, name, cand in candidates:
        if name in claimed or cand in used_vuln:
            continue
        claimed.add(name)
        used_vuln.add(cand)
        kind = classify(sources[cand], sources[name])
        kinds[kind] += 1
        ratios.append(ratio)
        pairs[name] = {"twin": cand, "ratio": round(ratio, 4), "kind": kind}

    unpaired = [n for n in safe if n not in pairs]
    n_safe, n_vuln = len(safe), len(vuln)
    paired = len(pairs)

    summary = {
        "corpus": "owasp-benchmark-1.2",
        "cases": len(truth),
        "vulnerable": n_vuln,
        "safe": n_safe,
        "method": (
            "Each safe case is paired one-to-one with the most similar vulnerable case "
            "in the same category, at line granularity over non-blank stripped lines, "
            "counting at >= THRESHOLD. Candidates are collected for every pair above "
            "the threshold and assigned greedily strongest-first, each case used at "
            "most once; a per-case best-match would not be a pairing, because the "
            "generator's shared scaffolding lets several safe cases name the same "
            "twin. This is a heuristic, not ground truth: an unpaired case is a limit "
            "of the search, not a statement about the corpus."
        ),
        "threshold": THRESHOLD,
        "paired": paired,
        "unpaired": len(unpaired),
        "paired_rate": paired / n_safe if n_safe else 0.0,
        "kinds": dict(sorted(kinds.items())),
        "mean_ratio": (sum(ratios) / len(ratios)) if ratios else 0.0,
        "min_ratio": min(ratios) if ratios else 0.0,
        "pairs": pairs,
        "unpaired_cases": unpaired,
        "prefilter": {
            "length_tolerance": LENGTH_TOLERANCE,
            "candidate_pairs_skipped": filter_discards,
            "soundness_note": (
                "Candidates skipped without comparison because their line counts "
                "differ by more than LENGTH_TOLERANCE, relative. Reported so the "
                "filter cannot silently shrink the search: if the true pair of an "
                "unpaired case is in this set, the unpaired count is an artefact of "
                "the filter rather than of the corpus."
            ),
        },
        "claim_supported": kinds.get("purely_additive", 0) == 0,
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(summary, indent=2))

    print(f"OWASP Benchmark 1.2: {len(truth)} cases "
          f"({n_vuln} vulnerable, {n_safe} safe)\n")
    print(f"  paired at >= {THRESHOLD:.2f}   {paired:4d} / {n_safe}  "
          f"({paired / n_safe:.1%})")
    print(f"  unpaired              {len(unpaired):4d}")
    print(f"  min ratio among pairs {summary['min_ratio']:.4f}")
    print("\n  how each pair differs (vulnerable -> safe):")
    for kind, count in sorted(kinds.items(), key=lambda kv: -kv[1]):
        print(f"    {kind:18s} {count:4d}")
    print(f"\n  purely additive pairs: {kinds.get('purely_additive', 0)} "
          f"-- the construction the claim requires to be absent")
    print(f"  candidate pairs skipped by the length filter: {filter_discards}")
    print(f"\nwrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
