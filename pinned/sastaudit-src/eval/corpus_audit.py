"""What is actually inside JavaVFC, measured three ways.

This is the corpus-side result of the study. The claim it supports is narrow and
checkable: the released JavaVFC artifact does not contain what its description
says it contains, and the discrepancy is large enough to invalidate any tool
evaluation run over it unfiltered.

Three independent lines of evidence, deliberately built on different signals so
that agreement between them means something:

  1. Hand labels   -- every 26th usable commit read and judged (n=31).
  2. Keyword pass  -- security vocabulary over all 784 messages.
  3. Included-by   -- which alternative of JavaVFC's own shipped
                      VULNERABILITY_PATTERN admitted each commit.

Line 3 is provenance, not judgment: it shows *how* non-security commits entered,
which is what makes the finding a defect in the artifact rather than an opinion
about its contents.

Run from the repo root:

    python3 -m sastaudit.eval.corpus_audit
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from ..corpus.javavfc import load
from ..corpus.security_filter import is_security_relevant

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "sastaudit" / "data" / "javavfc"

# Hand verdicts from reading the systematic sample (every 26th usable commit).
# Y = genuine security fix, P = partial/security-adjacent, N = not security.
#
# Kept as two tables covering disjoint interleaved samples rather than one
# merged table, because the second was labelled independently of the first and
# that independence is the only reliability evidence available here. A single
# labeller cannot measure inter-rater agreement, but a rate that reproduces on
# a disjoint half of the same population is not an artefact of one reading.
#
# The rubric, applied identically to both halves:
#   Y  a specific exploitable flaw is fixed in code, or a security defect
#      (plaintext credentials, a fixed default password) is eliminated.
#   P  security-motivated but not a code-level flaw fix: a dependency bump for
#      a named CVE, a resource-exhaustion limit, test-only changes, or
#      defensive hardening with no specific flaw.
#   N  not security: crashes, deadlocks, infinite recursion, arithmetic
#      overflow, OOM, performance work, functional bugs.
# DoS is classified N because this study's own shipped-alternative taxonomy
# (below) classifies it as reliability, not security; applying a stricter rule
# to the corpus than to the critique of it would be incoherent.
HAND_LABELS_A = {
    0: "N", 26: "N", 53: "N", 79: "N", 105: "N", 131: "Y", 157: "P", 183: "N",
    209: "N", 235: "P", 261: "N", 287: "N", 313: "N", 339: "N", 365: "Y",
    392: "N", 418: "N", 444: "Y", 470: "P", 496: "N", 522: "N", 548: "Y",
    574: "Y", 600: "N", 626: "N", 652: "P", 678: "P", 704: "N", 730: "N",
    756: "P", 782: "P",
}
# usables[13::26] -- the interleaved complement, labelled from the diff as well
# as the message. Two entries that the message alone would have misplaced:
#   561 "[CST-12108] porting of security part for QAEvents" reads as a security
#       fix but is 1,275 lines adding a UUID field to a research-information
#       system, where "security" means securities/instruments. Labelled N.
#   222 Pulsar "Allow proxy to pass same role for authRole and originalRole"
#       touches authorization but *loosens* the check to fix the authors' own
#       regression. A change that widens access is not a vulnerability fix. N.
HAND_LABELS_B = {
    13: "N", 40: "N", 66: "P", 92: "P", 118: "N", 144: "N", 170: "Y",
    196: "P", 222: "N", 248: "Y", 274: "N", 300: "N", 326: "Y", 352: "N",
    379: "N", 405: "N", 431: "N", 457: "P", 483: "Y", 509: "N", 535: "N",
    561: "N", 587: "N", 613: "Y", 639: "N", 665: "N", 691: "N", 717: "Y",
    743: "N", 769: "P",
}
HAND_LABELS = {**HAND_LABELS_A, **HAND_LABELS_B}

# The alternatives of JavaVFC's shipped VULNERABILITY_PATTERN, transcribed from
# data/javavfc/regex.txt and split by what they actually select for. Anything
# under "reliability" is a defect that is not a security vulnerability.
SECURITY_ALTS = [
    ("CVE", r"\bCVE\b"), ("XSS", r"\bXSS\b"), ("XXE", r"\bXXE\b"),
    ("RCE", r"\bRCE\b"), ("SSRF", r"\bSSRF\b"), ("ReDoS", r"\bReDoS\b"),
    ("XSRF", r"\bXSRF\b"), ("remote_code_exec", r"remote.code.execution"),
    ("open_redirect", r"\bopen.redirect"), ("dir_traversal", r"directory.traversal"),
    ("session_fixation", r"session.fixation"), ("clickjack", r"clickjack"),
    ("html_injection", r"HTML.injection"),
    ("security_exception", r"\b(throw|raise) a [\s\S]*SecurityException\b"),
    ("use_after_free", r"use.after.free"), ("buffer_overflow", r"buffer.overflow"),
    ("ref_overflow", r"reference.overflow"), ("osvdb", r"OSVDB"),
    ("security_fix", r"security.fix"), ("jira_security", r"\[SECURITY-(\d+)\]"),
    ("fix_security", r"fix.security(?! features)"), ("add_sec_check", r"add.security.check"),
    ("cert_revalidation", r"certificate.revalidation"),
    ("cert_lacking", r"lacking(?: proper)? certificate(s)"),
    ("verify_holder", r"\bverify.holder\b"),
    ("unwanted_perm", r"unwanted.permission.check(s)"),
    ("unauthorized", r"unauthori[z|s]ed"), ("insecure", r"insecure (?!configuration)"),
    ("cross_origin", r"\bcross — origin\b"), ("attack", r"attack (?!styles)"),
    ("exploit", r"exploit"), ("malicious", r"malicious"),
    ("vulnerability", r"vulnerabilit(y|ies)"), ("hijack", r"hijack"),
    ("passthrough_attack", r"passthrough.attack"), ("fault_injection", r"fault.injection"),
    ("unpredictable", r"(creating|create).unpredictable[\s\S]* behaviour"),
    ("stackoverflow_word", r"\bStackOverflow\b"),
    ("high_pri_secfix", r"high.priority.security.fix"),
]
RELIABILITY_ALTS = [
    ("DoS", r"\b(DOS\.attack(s)?|dos|denial.of.service)\b"),
    ("infinite_loop", r"infinite.loop"),
    ("stack_overflow", r"stack.overflow(?! exception)"),
    ("crashing", r"crashing"), ("OOM", r"\bOOM\b"), ("boot_loop", r"boot.loop"),
    ("prevent_leak", r"prevent.leak"), ("bypass_keyguard", r"bypass.keyguard"),
    ("fix_bypass", r"fix.bypass"),
    # The clause that does most of the damage: it reaches any commit whose
    # message says it fixes a crash, a clash, a bypass or an "auth" problem.
    ("fix_then_crash_or_bypass",
     r"(prevent|avoid|run into|lead to|fix|would)[\s\S]{0,50}"
     r" (vulnerabilities|vulnerability|crash|clashing|exploit|bypass|bypass.keyguard|auth)"),
]


#: Vocabulary for the "generous" bound: what if availability failures were
#: counted as security fixes? The answer depends entirely on how wide a
#: vocabulary "availability" is given, and an earlier draft of the write-up
#: quoted a single figure for it that this file did not compute -- so it could
#: not be re-derived, which is the failure the study exists to name. Both ends
#: are now computed and persisted.
#:
#: NARROW is the availability half of RELIABILITY_ALTS above: the corpus's OWN
#: vocabulary, which is the one this study already holds the corpus to, so using
#: it here cannot be accused of being chosen to suit an argument.
#:
#: WIDE adds the terms a reader would reach for next. It is deliberately NOT
#: extended further in search of a larger number: the spread between the two is
#: the honest error bar on this row, and widening the set until it produced the
#: old figure would be tuning a proxy to a conclusion.
AVAILABILITY_NARROW = [
    ("DoS", r"\b(DOS\.attack(s)?|dos|denial.of.service)\b"),
    ("infinite_loop", r"infinite.loop"),
    ("stack_overflow", r"stack.overflow(?! exception)"),
    ("OOM", r"\bOOM\b"),
    ("boot_loop", r"boot.loop"),
    ("prevent_leak", r"prevent.leak"),
]
AVAILABILITY_WIDE = AVAILABILITY_NARROW + [
    ("deadlock", r"dead.?lock"),
    ("hang", r"\bhang(s|ing)?\b"),
    ("memory_leak", r"memory.leak"),
    ("resource_exhaustion", r"(resource|memory|heap).(exhaust|starv)"),
    ("unbounded", r"\bunbounded\b"),
]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval -- a bare proportion invites the small-sample objection."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return (centre - half, centre + half)


def main() -> int:
    commits = load(DATA / "javavfc.jsonl")
    by_index = {c.index: c for c in commits}

    # --- 1. hand labels -----------------------------------------------------
    # The tables above are transcriptions of a sampling rule, and a
    # transcription can drift from the rule it claims to follow -- silently,
    # because a shifted sample still looks like a sample. Checking the keys
    # against the rule that generated them makes the claim reproducible
    # instead of asserted.
    usable = [c for c in commits if c.is_usable]
    expect = {
        "A": [c.index for c in usable[::26]],
        "B": [c.index for c in usable[13::26]],
    }
    got = {
        "A": sorted(HAND_LABELS_A),
        "B": sorted(HAND_LABELS_B),
    }
    for half in ("A", "B"):
        if expect[half] != got[half]:
            raise SystemExit(
                f"hand labels {half} do not match usables[{'' if half == 'A' else '13'}::26]:\n"
                f"  table has {len(got[half])} indices, rule selects {len(expect[half])}\n"
                f"  symmetric difference: "
                f"{sorted(set(expect[half]) ^ set(got[half]))[:10]}"
            )

    counts = Counter(HAND_LABELS.values())
    n = len(HAND_LABELS)
    strict_lo, strict_hi = wilson(counts["Y"], n)
    generous_lo, generous_hi = wilson(counts["Y"] + counts["P"], n)

    # Per half, so the two independent readings can be compared rather than
    # averaged into a single number that hides a disagreement.
    halves = {}
    for half, table in (("A", HAND_LABELS_A), ("B", HAND_LABELS_B)):
        c = Counter(table.values())
        k = len(table)
        halves[half] = {
            "n": k,
            "genuine_security": c["Y"],
            "strict_rate": c["Y"] / k,
            "strict_ci95": list(wilson(c["Y"], k)),
            "not_security_rate": c["N"] / k,
        }


    # --- 1b. the availability-generous bound, both ends ---------------------
    # Moves every N-labelled commit whose message names an availability failure
    # into Y. Computed over the hand-labelled sample, not the corpus, because it
    # revises hand labels rather than adding machine ones.
    by_index = {c.index: c for c in commits}
    not_security = [i for i, lab in HAND_LABELS.items() if lab == "N"]
    availability = {}
    for width, vocab in (("narrow", AVAILABILITY_NARROW), ("wide", AVAILABILITY_WIDE)):
        rx = [(name, re.compile(pat, re.I)) for name, pat in vocab]
        flagged = {
            i: name
            for i in not_security
            if (name := next((nm for nm, r in rx if r.search(by_index[i].message or "")), None))
        }
        y2 = counts["Y"] + len(flagged)
        lo2, hi2 = wilson(y2, n)
        availability[width] = {
            "vocabulary": [nm for nm, _ in vocab],
            "flagged": len(flagged),
            "flagged_by_term": dict(sorted(flagged.items())),
            "rate": y2 / n,
            "ci95": [lo2, hi2],
            "not_security_rate": (len(not_security) - len(flagged)) / n,
        }

    # --- 2. keyword pass over the whole corpus ------------------------------
    kw_hits = [c for c in commits if is_security_relevant(c.message)]

    # --- 3. provenance: which shipped alternative admitted each commit -------
    compiled = [
        (name, re.compile(pat, re.I | re.X), kind)
        for kind, alts in (("security", SECURITY_ALTS), ("reliability", RELIABILITY_ALTS))
        for name, pat in alts
    ]
    admitted: Counter[str] = Counter()
    kind_of: dict[str, str] = {}
    for name, _, kind in compiled:
        kind_of[name] = kind
    unexplained = 0
    for c in commits:
        hits = [name for name, rx, _ in compiled if rx.search(c.message)]
        if not hits:
            unexplained += 1
            continue
        for h in hits:
            admitted[h] += 1

    reliability_top = [
        (name, admitted[name]) for name, _ in RELIABILITY_ALTS if admitted[name]
    ]
    reliability_top.sort(key=lambda kv: -kv[1])
    dominant = reliability_top[0] if reliability_top else ("", 0)
    reliability_total = sum(v for _, v in reliability_top)

    summary = {
        "corpus": "javavfc",
        "records": len(commits),
        "usable_commits": sum(c.is_usable for c in commits),
        "single_file_commits": sum(
            1 for c in commits if c.is_usable and len(c.reconstructible_java_files) == 1
        ),
        "hand_labels": {
            "n": n,
            "genuine_security": counts["Y"],
            "partial": counts["P"],
            "not_security": counts["N"],
            "strict_rate": counts["Y"] / n,
            "strict_ci95": [strict_lo, strict_hi],
            "generous_rate": (counts["Y"] + counts["P"]) / n,
            "generous_ci95": [generous_lo, generous_hi],
            "availability_generous": availability,
            "availability_generous_note": (
                "Two ends of one question: if availability failures counted as "
                "security fixes, what is the rate? The answer is not a single "
                "number -- it depends on how wide a vocabulary 'availability' "
                "gets -- so neither end is reported alone. NARROW reuses the "
                "corpus's own reliability vocabulary; WIDE adds the next terms a "
                "reader would reach for, and is deliberately not extended "
                "further, because widening a proxy until it reproduces a "
                "preferred figure is the practice this study documents. The "
                "spread between the two is the error bar on this row. An "
                "earlier draft quoted a single figure (44.3%) that this file "
                "did not compute and could not re-derive."
            ),
            "interleaved_halves": halves,
            "halves_note": (
                "The two halves are disjoint interleaved samples of the same "
                "population (usables[::26] and usables[13::26]), labelled "
                "separately. They are reported separately because a single "
                "labeller cannot supply inter-rater agreement; what this does "
                "supply is a check that the rate is not an artefact of one "
                "reading. Agreement between them is evidence of stability, not "
                "of correctness -- both readings are mine."
            ),
        },
        "keyword_pass": {
            "security_commits": len(kw_hits),
            "rate": len(kw_hits) / len(commits),
        },
        "provenance": {
            "matched_by_a_shipped_alternative": len(commits) - unexplained,
            "unexplained_by_shipped_regex": unexplained,
            "reliability_alternative_total": reliability_total,
            "dominant_alternative": dominant[0],
            "dominant_count": dominant[1],
            "reliability_alternatives": reliability_top,
        },
    }

    out = ROOT / "sastaudit" / "results" / "javavfc_composition.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2))

    print(f"JavaVFC: {len(commits)} records\n")
    print("1. hand labels (every 26th usable commit, two interleaved halves, n=%d)" % n)
    print(f"     genuine security fix   {counts['Y']:2d}  {counts['Y']/n:6.1%}"
          f"   [95% CI {strict_lo:.1%}-{strict_hi:.1%}]")
    print(f"     partial / adjacent     {counts['P']:2d}  {counts['P']/n:6.1%}")
    print(f"     not security           {counts['N']:2d}  {counts['N']/n:6.1%}")
    print()
    print(f"     {'half':6s} {'n':>3s} {'genuine sec':>12s} {'95% CI':>16s} {'not sec':>9s}")
    for half in ("A", "B"):
        h = halves[half]
        print(f"     {half:6s} {h['n']:3d} {h['strict_rate']:12.1%} "
              f"  [{h['strict_ci95'][0]:5.1%}-{h['strict_ci95'][1]:5.1%}] "
              f"{h['not_security_rate']:8.1%}")
    print("     disjoint interleaved samples, labelled independently; the")
    print("     agreement between them is stability, not inter-rater agreement.")
    print(f"\n2. keyword pass over all {len(commits)} messages")
    print(f"     security-asserting     {len(kw_hits):3d}  {len(kw_hits)/len(commits):6.1%}")
    print("\n3. provenance -- what admitted them (shipped regex, by kind)")
    print(f"     admitted by a reliability alternative : {reliability_total}")
    print(f"     largest single alternative            : {dominant[0]} ({dominant[1]})")
    print(f"     not explained by the shipped regex    : {unexplained}")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
