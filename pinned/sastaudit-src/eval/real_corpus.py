"""What do real SAST tools do with real Java vulnerabilities?

This is the generalisation of the phase-one harness, which measured one tool.
The measurement is unchanged; only the scanner is now a parameter.

    python3 -m sastaudit.eval.real_corpus --tool semgrep --stratum security
    python3 -m sastaudit.eval.real_corpus --tool codeql  --stratum security

Why the measurement is shaped this way
--------------------------------------
A single "coverage" number is not enough, because "the tool flagged the file"
is much weaker than "the tool noticed the vulnerability". The report therefore
decomposes every commit four ways, by whether the tool flagged the vulnerable
revision, the fixed revision, both, or neither:

  flagged neither         the tool was silent on code containing a known
                          vulnerability and on the fix that removed it
  flagged both            the tool's pattern fires before and after the fix.
                          It cannot be detecting the vulnerability, because the
                          fix did not clear it.
  flagged vulnerable only the tool's verdict changed with the fix. This is the
                          stringent measure of "did the tool notice".
  on a deleted line       the finding's line is one the patch removed

The last of these is a LOWER BOUND, not the headline, and the reason matters. A
fix often neutralises a vulnerability without touching the line the tool flags:
in the one commit where Semgrep's verdict did flip (Causeway's XXE hardening),
the patch deleted the `TransformerFactory.newInstance()` setup while the tool
flagged `transformerFactory.newTransformer(...)` eight lines below, a line
textually identical in both revisions. The tool was right about the construct
and right to change its mind, but no finding lands on a deleted line. So
line-level matching is the strictest available criterion and under-counts by
construction. It is reported, and it is not the headline.

Guarding the input
------------------
Two design rules were established the hard way in phase one and are load-bearing
here.

* **A positive control runs before the corpus.** A tool that is misconfigured,
  or whose scan crashed, produces the same zero as a tool that looked at real
  vulnerabilities and saw nothing. The shared control set in controls/ is
  scanned first and its result is recorded in the output, so a reader can tell
  the two apart.
* **A failed scan is recorded as a failure, never as zero findings.** One bad
  commit must not end a run, and must not silently shrink the denominator.

Both corpora, one input shape
-----------------------------
Semgrep is intra-file, so the vuln/ and fixed/ trees are analysed in a single
invocation and findings are attributed by path prefix. CodeQL is given the same
shape: one database over a tree containing both revisions, findings attributed
the same way. That keeps the input to every tool identical, which is the whole
basis for comparing them.

The caveat that follows from it is real and is recorded in every result file:
each revision is presented as an *isolated file*. Semgrep is a pattern matcher
and is barely affected; CodeQL resolves types and infers library models, so
stripping the surrounding project handicaps it more. Its numbers here are a
floor, not a measurement of what CodeQL does in a repository with a build.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from ..corpus.javavfc import (
    FetchError,
    JavaVFCCommit,
    load,
    materialize,
    removed_lines,
)
from ..corpus.security_filter import PURITY_ESTIMATE, security_subset
from ..tools import REGISTRY, Tool, ToolError, build_tool

# A CVE identifier in the commit message. Matched case-insensitively and
# anchored on the CVE-YYYY-NNNN... shape, so ordinary prose cannot admit a
# commit -- the failure mode this study documents in JavaVFC's own filter.
CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "sastaudit" / "data" / "javavfc"
CACHE = DATA / "cache"
RESULTS = ROOT / "sastaudit" / "results"
CONTROL_SRC = ROOT / "sastaudit" / "controls" / "src"
CONTROL_MANIFEST = ROOT / "sastaudit" / "controls" / "manifest.json"


@dataclass
class SideFindings:
    """One tool's findings on one revision of the changed files."""

    count: int = 0
    rules: list[str] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)
    lines: list[int] = field(default_factory=list)
    # Findings landing on a line the fix deleted: the difference between "the
    # tool flagged the file" and "the tool pointed at the vulnerability".
    on_removed: int = 0


@dataclass
class CommitResult:
    index: int
    repo: str
    sha: str
    message: str
    n_files: int
    vulnerable: SideFindings
    fixed: SideFindings
    seconds: float
    #: Queries the scanner reported as failing to evaluate, by name. Kept because
    #: the distinction it draws is this study's subject: a query that fails and a
    #: query that runs and matches nothing produce the same absence of findings.
    #:
    #: The failure mode OBSERVED is the loud one -- the evaluator dies, the CLI
    #: exits non-zero, no SARIF is written, and the whole commit is recorded in
    #: `scan_failures`. This field is for the quiet case: a query failing inside a
    #: run that still exits 0 with a partial SARIF. That case has not been
    #: observed, so on every run so far this field has been empty. It is kept
    #: because it is correct for the situation it describes, not because it has
    #: fired. An earlier version of this comment asserted the quiet case as fact;
    #: that was the unmeasured-mechanism error this study exists to name.
    failed_queries: tuple[str, ...] = ()

    @property
    def covered(self) -> bool:
        return self.vulnerable.count > 0

    @property
    def residual(self) -> bool:
        return self.fixed.count > 0

    @property
    def flagged_both(self) -> bool:
        return self.vulnerable.count > 0 and self.fixed.count > 0

    @property
    def vuln_only(self) -> bool:
        return self.vulnerable.count > 0 and self.fixed.count == 0

    def as_row(self) -> dict:
        return {
            "index": self.index,
            "repo": self.repo,
            "sha": self.sha,
            "message": self.message,
            "n_files": self.n_files,
            "vuln_findings": self.vulnerable.count,
            "vuln_rules": self.vulnerable.rules,
            "vuln_cwes": self.vulnerable.cwes,
            "vuln_lines": self.vulnerable.lines,
            "vuln_on_removed_line": self.vulnerable.on_removed,
            "fixed_findings": self.fixed.count,
            "fixed_rules": self.fixed.rules,
            "fixed_cwes": self.fixed.cwes,
            "covered": self.covered,
            "residual": self.residual,
            "failed_queries": list(self.failed_queries),
            "genuine": self.vulnerable.on_removed > 0,
            "seconds": round(self.seconds, 2),
        }


def _partition(findings, root: Path) -> tuple[SideFindings, SideFindings]:
    """Split findings into the vuln/ and fixed/ subtrees by path prefix.

    Paths arrive already root-relative from the adapters, so this cannot be
    fooled by an absolute/relative mismatch.
    """
    vuln, fixed = SideFindings(), SideFindings()
    for f in findings:
        parts = Path(f.path).parts
        side = vuln if parts and parts[0] == "vuln" else fixed
        side.count += 1
        side.rules.append(f.rule)
        side.cwes.extend(f.cwes)
        side.lines.append(f.line)
    return vuln, fixed


_QUERY_FAILED = re.compile(r"Query failed:\s*(\S+?\.ql)", re.IGNORECASE)


def failed_queries(stderr: str) -> tuple[str, ...]:
    """Queries a scanner reported as failing to evaluate.

    Only patterns a tool states unambiguously are matched. CodeQL prints
    `Query failed: <path>.ql (reason)`, which is explicit; inferring failure
    from looser text would misfire on query names and file paths that merely
    contain the word.
    """
    return tuple(sorted(set(_QUERY_FAILED.findall(stderr or ""))))


def evaluate(commit: JavaVFCCommit, *, tool: Tool) -> CommitResult | None:
    """Materialise both revisions, scan them together, assign findings by side."""
    files = commit.reconstructible_java_files
    started = time.monotonic()

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        kept = 0
        removed: dict[str, set[int]] = {}
        for cf in files:
            try:
                vuln_text, fixed_text = materialize(
                    commit, cf.path, cf.patch, cache_dir=CACHE
                )
            except FetchError as exc:
                print(f"    skip {cf.path}: {exc}", file=sys.stderr)
                continue
            for side, text in (("vuln", vuln_text), ("fixed", fixed_text)):
                target = root / side / cf.path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")
            removed[cf.path] = removed_lines(cf.patch)
            kept += 1

        if kept == 0:
            return None

        outcome = tool.scan(root)
        vuln, fixed = _partition(outcome.findings, root)

        for f in outcome.findings:
            parts = Path(f.path).parts
            if not parts or parts[0] != "vuln":
                continue
            path = str(Path(*parts[1:]))
            if f.line in removed.get(path, ()):
                vuln.on_removed += 1

    return CommitResult(
        index=commit.index,
        repo=commit.repo,
        sha=commit.sha,
        message=commit.message.splitlines()[0][:120] if commit.message else "",
        n_files=kept,
        vulnerable=vuln,
        fixed=fixed,
        seconds=time.monotonic() - started,
        failed_queries=failed_queries(outcome.stderr),
    )


def positive_control(tool: Tool) -> dict:
    """Confirm this tool, in this configuration, detects anything at all.

    Uses the shared control set rather than a per-tool set of cases. A control
    chosen to suit the tool under test proves only that the harness can be made
    to pass; the same 21 files are put to every scanner, and each tool's misses
    are reported as its own.
    """
    manifest = json.loads(CONTROL_MANIFEST.read_text())
    cases = manifest["cases"]
    outcome = tool.scan(CONTROL_SRC)
    by_name: dict[str, list[str]] = {Path(c["file"]).name: [] for c in cases}
    for f in outcome.findings:
        name = Path(f.path).name
        if name in by_name:
            by_name[name].append(f.rule)

    result: dict[str, dict] = {}
    for c in cases:
        name = Path(c["file"]).name
        hit = bool(by_name[name])
        result[Path(c["file"]).stem] = {
            "expect": c["expect"],
            "expected_cwe": c["cwe"],
            "flagged": hit,
            "rules": sorted(set(by_name[name])),
            "correct": (hit == (c["expect"] == "vulnerable")),
        }
    hits = sum(1 for c in cases if c["expect"] == "vulnerable" and result[Path(c["file"]).stem]["flagged"])
    fps = sum(1 for c in cases if c["expect"] == "safe" and result[Path(c["file"]).stem]["flagged"])
    n_vuln = sum(1 for c in cases if c["expect"] == "vulnerable")
    n_safe = sum(1 for c in cases if c["expect"] == "safe")
    return {
        "cases": result,
        "vulnerable_detected": f"{hits}/{n_vuln}",
        "negative_controls_flagged": f"{fps}/{n_safe}",
        "detection_rate": hits / n_vuln if n_vuln else 0.0,
        "false_positive_rate": fps / n_safe if n_safe else 0.0,
    }


def select(
    commits: list[JavaVFCCommit], limit: int, stride: int, stratum: str = "raw"
) -> list[JavaVFCCommit]:
    """Deterministic sample: usable commits, evenly strided.

    "raw" and "security" are restricted to single-file commits so "did the tool
    flag the vulnerability" is unambiguous -- with several changed files, a hit
    on any one of them does not say which. Striding rather than slicing keeps
    repositories spread across the sample instead of taking a run of adjacent
    indices.

    stratum="raw"      the corpus as shipped, which is ~84% not security fixes
    stratum="security" only commits whose message asserts a security fix, and
                       which touch non-test source. This is the stratum the
                       headline number is reported from; the raw stratum is the
                       contrast.
    stratum="cve"      every commit whose message names a CVE identifier.

    Why "cve" exists and why it does NOT apply the single-file rule
    ---------------------------------------------------------------
    "security" is this study's own judgement, applied through a message regex
    that the corpus-composition result shows is unreliable. A CVE identifier is
    ground truth from outside the study: an authority with no stake in it
    asserts the commit fixes a named vulnerability. That is a strictly better
    denominator, and it is independent of every filter criticised here.

    It cannot be restricted to single-file commits. Measured: of 32 CVE-naming
    commits, 20 are multi-file, and those 20 are the ones whose classes a taint
    engine actually models -- XSS escaping, XXE doctype parsing, Java
    deserialization, REST bulk-read authorization. The 12 that survive the
    single-file rule are mostly dependency bumps whose only changed Java file
    is incidental, and the two of those that fall outside "security" are both
    guava/Avro version bumps. Keeping the rule would therefore exclude exactly
    the fixes most likely to be detectable and bias the flip rate downward --
    manufacturing the finding. `evaluate()` is unaffected: it materialises every
    reconstructible file on both sides and partitions findings by side, so
    commit-level flagging is already well defined for multi-file commits.
    """
    if stratum == "cve":
        pool = [
            c for c in commits
            if c.is_usable and c.reconstructible_java_files
            and CVE_ID.search(c.message)
        ]
    else:
        pool = [
            c for c in commits
            if c.is_usable and len(c.reconstructible_java_files) == 1
        ]
        if stratum == "security":
            pool = security_subset(pool, single_file=True)
    if stride > 1:
        pool = pool[::stride]
    return pool[:limit] if limit else pool


def partial_path(out: Path) -> Path:
    return out.with_suffix(out.suffix + ".partial")


def load_partial(path: Path, sample_shas: set[str]) -> tuple[list[CommitResult], list[dict]]:
    """Recover completed rows from an interrupted run.

    A CodeQL pass over 120 commits takes hours, and the failure it is most
    likely to hit -- an OOM kill under memory pressure -- lands at the end of
    a long run, not the start. Without checkpointing that means losing every
    completed commit, which is both expensive and a silent incentive to report
    a truncated sample as if it were the whole thing.

    Rows are keyed on commit sha, and only rows whose sha is in the current
    sample are kept, so a checkpoint from a different --limit/--stride/--stratum
    cannot contaminate this run. Failures are deliberately NOT recovered: a
    failed commit is retried, because the usual cause is transient contention.
    """
    if not path.exists():
        return [], []
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return [], []
    rows = []
    for r in data.get("rows", []):
        if r.get("sha") not in sample_shas:
            continue
        rows.append(
            CommitResult(
                index=r["index"], repo=r["repo"], sha=r["sha"], message=r["message"],
                n_files=r["n_files"],
                vulnerable=SideFindings(
                    count=r["vuln_findings"], rules=list(r["vuln_rules"]),
                    cwes=list(r["vuln_cwes"]), lines=list(r["vuln_lines"]),
                    on_removed=r["vuln_on_removed_line"],
                ),
                fixed=SideFindings(
                    count=r["fixed_findings"], rules=list(r["fixed_rules"]),
                    cwes=list(r["fixed_cwes"]),
                ),
                seconds=r.get("seconds", 0.0),
            )
        )
    return rows, data.get("failures", [])


def write_partial(path: Path, rows: list[CommitResult], failures: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {"rows": [r.as_row() for r in rows], "failures": failures}, indent=2
        )
    )


def tool_metadata(tool: Tool) -> dict:
    """Everything needed to re-derive this number later."""
    meta: dict = {"name": tool.name, "version": tool.version()}
    rules = getattr(tool, "rules", None)
    if rules is not None and Path(rules).exists():
        meta["ruleset"] = Path(rules).name
        meta["ruleset_sha256"] = hashlib.sha256(Path(rules).read_bytes()).hexdigest()
    if hasattr(tool, "resolved_suite"):
        try:
            meta["language_mode"] = f"build-mode:{tool.build_mode}"
            meta["note_on_mode"] = (
                "CodeQL was run with --build-mode=none, which GitHub rates "
                "'Good' rather than 'Best' and which does not analyse generated "
                "code. It is used here because each revision is presented as an "
                "isolated file and a build is impossible. Read the numbers as a "
                "floor."
            )
        except Exception:  # noqa: BLE001
            pass
    return meta


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", choices=sorted(REGISTRY), default="semgrep")
    ap.add_argument("--limit", type=int, default=40, help="0 = all")
    ap.add_argument("--stride", type=int, default=1)
    ap.add_argument(
        "--stratum",
        choices=("raw", "security", "cve"),
        default="security",
        help="raw = corpus as shipped; security = only security-asserting "
             "commits (single-file); cve = commits naming a CVE identifier "
             "(all changed files, see select())",
    )
    ap.add_argument("--jobs", type=int, default=4, help="parallel commits in flight")
    ap.add_argument(
        "--tool-ram", type=int, default=4096,
        help="per-process heap for analysers that take one (CodeQL). Lower it "
             "when --jobs is raised: N jobs x ram must fit in physical memory, "
             "or the analyser is OOM-killed and the commit is recorded as a "
             "failure rather than a miss.",
    )
    ap.add_argument("--tool-threads", type=int, default=4)
    ap.add_argument("--out", default=None)
    ap.add_argument(
        "--resume", action="store_true",
        help="reuse commits already completed in the .partial.json checkpoint",
    )
    args = ap.parse_args(argv)

    out_name = args.out or f"{args.tool}_{args.stratum}.json"
    out = RESULTS / out_name
    chk = partial_path(out)

    try:
        tool = build_tool(
            args.tool, ram_mb=args.tool_ram, threads=args.tool_threads
        )
    except TypeError:
        # Tools that take no resource arguments (the semgrep family) are
        # constructed plainly; the flags are simply irrelevant to them.
        tool = build_tool(args.tool)
    except ToolError as exc:
        print(exc, file=sys.stderr)
        return 2
    if not tool.available():
        print(f"{args.tool} is not available", file=sys.stderr)
        return 2

    meta = tool_metadata(tool)
    print(f"tool {meta['name']} {meta['version']}")
    if "ruleset" in meta:
        print(f"rules {meta['ruleset']} sha256 {meta['ruleset_sha256'][:12]}")

    commits = load(DATA / "javavfc.jsonl")
    sample = select(commits, args.limit, args.stride, args.stratum)
    print(f"corpus {len(commits)} commits -> stratum={args.stratum}, sample {len(sample)}")
    if args.stratum == "security":
        print(f"  (subset estimated {PURITY_ESTIMATE:.0%} genuinely security-relevant)")
    print()

    control = positive_control(tool)
    print(
        f"positive control: {control['vulnerable_detected']} canonical vulnerabilities "
        f"detected, {control['negative_controls_flagged']} negative controls flagged"
    )
    for name, v in control["cases"].items():
        if v["expect"] == "vulnerable" and not v["flagged"]:
            print(f"    MISS {name}")
    print()

    rows: list[CommitResult] = []
    failures: list[dict] = []
    already: set[str] = set()
    if args.resume:
        rows, _ = load_partial(chk, {c.sha for c in sample})
        already = {r.sha for r in rows}
        if already:
            print(f"resuming: {len(already)} commits recovered from {chk.name}")

    todo = [c for c in sample if c.sha not in already]
    done = len(already)
    # Network-bound (one fetch per commit) with an independent subprocess, so
    # threads give real overlap despite the GIL. Results are sorted by corpus
    # index afterwards so the JSON does not depend on scheduling.
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(evaluate, c, tool=tool): c for c in todo}
        for fut in as_completed(futures):
            commit = futures[fut]
            done += 1
            try:
                res = fut.result()
            except Exception as exc:  # noqa: BLE001 - one bad commit must not end the run
                failures.append({"sha": commit.sha, "error": f"{type(exc).__name__}: {exc}"})
                print(f"[done {done:3d}/{len(sample)}] {commit.sha[:8]} ERROR {exc}", file=sys.stderr)
                # A failure is checkpointed too, so a resume can tell a commit
                # that was never attempted from one that was tried and blew up.
                write_partial(chk, rows, failures)
                continue
            if res is None:
                failures.append({"sha": commit.sha, "error": "unusable"})
                print(f"[done {done:3d}/{len(sample)}] {commit.sha[:8]} unusable", file=sys.stderr)
                write_partial(chk, rows, failures)
                continue
            rows.append(res)
            # Checkpoint every commit: the JSON is a few hundred kilobytes and
            # the cost is negligible next to the hours a lost run would waste.
            write_partial(chk, rows, failures)
            print(
                f"[done {done:3d}/{len(sample)}] {'HIT ' if res.covered else 'miss'} "
                f"{res.repo.split('/')[-1][:18]:18s} "
                f"v={res.vulnerable.count} f={res.fixed.count} {res.seconds:5.1f}s  "
                f"{res.message[:52]}",
                flush=True,
            )
    rows.sort(key=lambda r: r.index)

    if not rows:
        print("no results", file=sys.stderr)
        return 1

    n = len(rows)
    covered = sum(r.covered for r in rows)
    residual = sum(r.residual for r in rows)
    vuln_findings = sum(r.vulnerable.count for r in rows)
    fixed_findings = sum(r.fixed.count for r in rows)
    distinct_rules = sorted({x for r in rows for x in r.vulnerable.rules})

    # The decomposition that matters. "Covered" only says the tool flagged the
    # vulnerable file; the interesting split is whether the flag survives the
    # fix (incidental -- the pattern was there all along) or disappears with it
    # (the tool's verdict tracked the vulnerability).
    both = sum(1 for r in rows if r.flagged_both)
    vuln_only = sum(1 for r in rows if r.vuln_only)
    fixed_only = sum(1 for r in rows if not r.vulnerable.count and r.fixed.count)
    neither = n - both - vuln_only - fixed_only
    on_removed = sum(1 for r in rows if r.vulnerable.on_removed > 0)

    summary = {
        "corpus": "javavfc",
        "tool": meta["name"],
        "tool_version": meta["version"],
        "tool_meta": meta,
        "stratum": args.stratum,
        "limit": args.limit,
        "stride": args.stride,
        "positive_control": control,
        "commits_evaluated": n,
        "scan_failures": failures,
        # Non-empty means the tool under-reported for reasons of its own
        # resources rather than the code's content; the finding counts below are
        # then a floor for a second, unrelated reason.
        "queries_failed": sorted({q for r in rows for q in r.failed_queries}),
        "commits_with_failed_queries": sum(1 for r in rows if r.failed_queries),
        # How many files each commit was judged on. A commit-level verdict over
        # five files is a different measurement from one over a single file, so
        # the distribution travels with the result rather than being implicit in
        # the stratum name.
        "files_per_commit": {
            "min": min(r.n_files for r in rows),
            "max": max(r.n_files for r in rows),
            "mean": sum(r.n_files for r in rows) / n,
            "multi_file_commits": sum(1 for r in rows if r.n_files > 1),
        },
        "note_on_commit_scope": (
            "A commit counts as flagged when any file it changed is flagged, on "
            "that side. The unit of analysis is the commit, not the file: the "
            "four-way decomposition asks whether the tool's verdict on this fix "
            "moved, and a fix spread over several files is one fix."
        ),
        "coverage": covered / n,
        "coverage_n": covered,
        "residual": residual / n,
        "residual_n": residual,
        "vuln_findings": vuln_findings,
        "fixed_findings": fixed_findings,
        "findings_per_vuln": vuln_findings / n,
        "findings_per_covered": vuln_findings / covered if covered else 0.0,
        "distinct_rules_fired": len(distinct_rules),
        "rules_fired": distinct_rules,
        "decomposition": {
            "flagged_both_revisions": both,
            "flagged_vulnerable_only": vuln_only,
            "flagged_fixed_only": fixed_only,
            "flagged_neither": neither,
        },
        "flagged_on_removed_line": on_removed,
        "genuine_detection": on_removed / n,
        "verdict_flipped_with_fix": vuln_only / n,
        "note_on_genuine_detection": (
            "Lower bound, not the headline. A fix can neutralise a vulnerability "
            "without touching the line the tool flags, so no finding need ever land "
            "on a deleted line even when the tool is right. Read it alongside "
            "verdict_flipped_with_fix and the four-way decomposition."
        ),
        "note_on_input_shape": (
            "Each revision is presented as an isolated file with no project or "
            "dependency context. This is the only shape the reconstruction method "
            "can produce, and it is applied identically to every tool. It is a "
            "floor for tools that resolve types and a near-neutral condition for "
            "pattern matchers."
        ),
    }

    print("\n" + "=" * 66)
    print(f"tool                   {meta['name']} {meta['version']}")
    print(f"commits evaluated      {n}")
    multi = sum(1 for r in rows if r.n_files > 1)
    print(f"files per commit       mean {sum(r.n_files for r in rows) / n:.2f}, "
          f"max {max(r.n_files for r in rows)}; {multi} commits changed >1 file")
    print(f"coverage (file flagged){covered / n:6.1%}  ({covered}/{n})")
    print(f"residual (fixed flagged){residual / n:6.1%}  ({residual}/{n})")
    print(f"findings on vulnerable {vuln_findings}  ({vuln_findings / n:.2f}/commit)")
    print(f"findings on fixed      {fixed_findings}")
    print(f"distinct rules fired   {len(distinct_rules)}")
    print("-" * 66)
    print(f"  flagged on BOTH revisions (not the vuln) {both:4d}  {both / n:6.1%}")
    print(f"  flagged vulnerable ONLY (verdict flipped){vuln_only:4d}  {vuln_only / n:6.1%}")
    print(f"  flagged fixed ONLY                       {fixed_only:4d}  {fixed_only / n:6.1%}")
    print(f"  flagged neither                          {neither:4d}  {neither / n:6.1%}")
    print("-" * 66)
    print(f"verdict flipped with the fix        {vuln_only}/{n}  {vuln_only / n:.1%}")
    print(f"finding on a line the fix deleted   {on_removed}/{n}  {on_removed / n:.1%}  (lower bound)")
    if failures:
        print(f"scan failures                       {len(failures)}")
    with_qfail = sum(1 for r in rows if r.failed_queries)
    if with_qfail:
        names = sorted({q for r in rows for q in r.failed_queries})
        print(f"commits where a query failed        {with_qfail}/{n}  "
              f"({', '.join(Path(q).name for q in names)})")
        print("  The tool's own resources, not the code: those queries returned")
        print("  nothing because they did not finish. Counts above are a floor")
        print("  for this reason in addition to any other.")
    print("=" * 66)

    # A run that covered only part of its sample must not look complete. The
    # flag is set before serialising, so the file on disk carries it; the
    # checkpoint is kept in that case so a resume can finish the job.
    attempted = len(rows) + len(failures)
    if attempted < len(sample):
        summary["incomplete"] = True
        summary["commits_attempted"] = attempted
        summary["commits_sampled"] = len(sample)
        print(
            f"INCOMPLETE: {attempted}/{len(sample)} commits attempted; "
            f"resume with --resume",
            file=sys.stderr,
        )

    RESULTS.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps({"summary": summary, "rows": [r.as_row() for r in rows]}, indent=2)
    )
    print(f"wrote {out}")
    if attempted >= len(sample):
        chk.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
