# A benchmark score that nothing can be concluded from

### What the OWASP Benchmark measures, and why it is not detection capability

---

## Summary

The OWASP Benchmark is the standard instrument for comparing Java security
scanners. Its output is a single number, `score = TPR − FPR`, and that number is
used to rank tools, justify purchases, and stand in for "detection capability".
This study asks whether the number is well defined, and whether it predicts what
the tools do on code that was not written to be benchmarked.

It does not, on both counts. Three findings, each measured and each independent:

1. **The score is not a property of the tool.** It moves by 6.7 points when one
   build of an engine is swapped for another build of the *same* engine, holding
   the corpus and the rule bytes fixed — and that same swap produces *literally
   zero* difference on 120 real security fixes. The two builds differ only where
   the synthetic corpus is. A statistic that responds to a variable with no
   measurable effect on the quantity it claims to measure is not measuring that
   quantity. (Section 2.3)

2. **The score does not predict performance on real code.** On 120 real Java
   security fixes the tools' verdict flipped with the fix in 1 case out of 120.
   Tightening the denominator to the strictest standard available — commits an
   outside authority certified as fixing a named vulnerability, in code a
   scanner can read — raises this to 7.1% against a benchmark TPR of 78%, and
   the interval's upper bound stays far below it. The mechanism is structural,
   not a matter of tool quality: a scanner whose signal is "this dangerous
   construct exists here" cannot respond to a fix that removes nothing, and
   20.7% of real security fixes delete no line at all. (Section 3)

3. **The corpus used to establish that tools generalise does not contain what it
   claims.** JavaVFC, the corpus of "manually-verified Java vulnerability-fixing
   commits" used in recent work, is 18.0% genuine security fixes. Its own shipped
   filter admits commits that fix crashes and games. (Section 4)

The through-line: **a measurement can be reproducible, internally consistent,
widely cited, and still not be a measurement of the thing it is used to measure.**
Reproducibility is not validity. This study is an existence proof, with numbers,
that the two come apart — and a method (the four-way decomposition of Section
3.2) for noticing when they have.

---

## 1. What was measured

Three scanners behind one interface, two corpora, and a control set that every
run must pass.

| | |
|---|---|
| **Tools** | Semgrep 1.177.0 · opengrep 1.30.0 · CodeQL 2.27.0 |
| **Synthetic corpus** | OWASP Benchmark v1.2 — 2,740 Java servlet cases, 11 categories, ground truth from `expectedresults-1.2.csv` |
| **Real corpus** | JavaVFC (Zenodo 13731781) — 784 commits advertised as vulnerability fixes |
| **Controls** | 21 files: 18 canonical vulnerabilities across the benchmark's own categories, 3 negative controls (safe variants) |

Everything is pinned in `artifact/pins.json`: rule bytes, query packs, dataset
hashes, commits. Nothing in the evaluation loop is a moving target, because the
claim being tested is about the *measurement*, and a measurement that cannot be
re-run cannot be audited.

**Every result file without a passing positive control is void.** A zero from a
misconfigured scanner and a zero from a working scanner are the same number;
this is the single most common way a study like this goes wrong. Each of the
three tools detects 12/18, 12/18 and 16/18 canonical vulnerabilities on the
control set before its corpus numbers are reported.

**A note on what is and is not independent.** Semgrep and opengrep are one engine
family — opengrep is a fork of Semgrep — so agreement between them is weak
evidence about detection in general. They are reported separately rather than
pooled, for the reason Section 2.3 gives: they are not interchangeable. CodeQL is
the genuinely independent implementation, using taint tracking over a compiled
database rather than pattern matching.

---

## 2. Result 1: the score is not well defined

### 2.1 The scorer grants different tools different answers

`BenchmarkUtils`, the reference scorer, accepts CWE-327 (broken crypto) as a
correct answer to a CWE-328 (weak hash) case — but only for tools whose names
begin with `AppScan`, `Vera` or `CodeQL`. Every other tool must get the CWE
exactly right. CWE-564 is accepted for CWE-89 for everyone.

This is hardcoded in the scorer. It means two tools can produce byte-identical
findings and receive different scores, and the difference is not a mistake in
the tools' output but a property of their names.

An unreleased upstream branch, `generalizeScoring` (`a279082d`), deletes this
leniency and replaces it with a uniform `ChildOf`/`ParentOf` walk over the CWE
hierarchy applied identically to every tool. That is the right fix. It is worth
stating plainly: **the defect is already known to the maintainers and is not
addressed in any released version**, which changes the finding from "undiscovered
flaw" to "known but unreleased" — and does not change it from "defect".

### 2.2 The aggregation is inconsistent with itself

The published overall TPR and FPR are **macro-averaged** — an unweighted mean
over the 11 categories (`totalTPRate / numCategories`) — while precision is
pooled over cases. Two different averaging rules in one scorecard.

Macro-averaging gives a category with 22 cases the same weight as one with 504.
The consequence is that the headline number depends on how the cases happen to
be distributed across categories rather than on how many cases the tool got
right.

**This was measured and the naive version of the claim failed.** The hypothesis
that macro-averaging *inflates* scores is not supported: correcting it to a
case-weighted mean moves Semgrep's score from 35.88% to 38.67%, a +2.79 point
change, and across the tools tested the deltas run from −1.08 to +4.66 points
with mixed direction. A variance-amplification hypothesis also failed.

The finding that survives is narrower and still matters: the published aggregate
is not the case-weighted accuracy it is read as, and the two differ by several
points in a direction that is not predictable from the tool. **A negative result
is reported here rather than dropped**, because the failure is informative —
it establishes that the aggregation problem is real but bounded, which is what
stops it from being overclaimed.

### 2.3 The score moves with a variable that has no effect on real code

This is the sharpest single result in the study, and it requires both halves to
see.

Semgrep 1.177.0 and opengrep 1.30.0 were run against the same corpus with the
same ruleset bytes (sha256 `77df32e0`, 690 rules).

| | controls (21 files) | real fixes (120 commits) | OWASP v1.2 (2,740 cases) |
|---|---|---|---|
| **agreement** | identical | **identical** | differs |

On the real stratum, **no commit differs in any verdict-bearing respect** — same
rules fired, same finding counts, same line numbers, same decomposition, same
single flip. That is agreement across 240 scans (each commit is scanned as two
isolated revisions).

One difference does exist, and it is the only one found. All nine commits that
carry a finding disagree on the CWE *display string*: Semgrep records
`CWE-611: Improper Restriction of XML External Entity Reference` where opengrep
records `CWE-611`. No CWE *identifier* differs anywhere in the stratum — 120 of
120 agree once the strings are normalised, and 111 commits have no CWE to compare.
It is reported rather than smoothed over for two reasons: an equivalence claim is
only as strong as its statement of where it breaks, and this is precisely the
site a CWE-matching scorer would read. It does not touch the benchmark half of
this table — that path parses the bare `CWE-<n>` tag out of each SARIF rule
(`benchmark_owasp.py:83`) and dropped zero findings for an unparseable CWE — so
the divergence is a property of the two binaries' SARIF formatting on the real
corpus, not of what they detect.

On the benchmark, the same two builds differ by **+30 true positives and −56
false positives**, moving the published score 6.7 points:

| OWASP v1.2 | TPR | FPR | score | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|
| Semgrep 1.177.0 | 77.97% | 42.09% | 35.88% | 1094 | 512 | 321 | 813 |
| opengrep 1.30.0 | **79.79%** | **37.25%** | **42.54%** | 1124 | 456 | 291 | 869 |

The differences are concentrated in the taint-shaped categories (`sqli` +14/−39,
`xss` +18/−17, `cmdi` +8/−36, `pathtraver` +10/−11) and absent from every
category where both are already perfect or already at zero (`crypto`, `hash`,
`securecookie`, `weakrand`).

Across the entire real stratum only nine rules fire at all, and this bounds the
explanation in a way that had to be checked rather than assumed. Of the four
categories where the builds separate, three contribute none of those nine: there
is no SQL-injection, command-injection or path-traversal rule among them. The
fourth, `xss`, contributes one — `no-direct-response-writer`, twice — and it is a
genuine taint rule (`mode: taint`, sources at `HttpServletRequest` parameter
reads, sinks at response writers, with an interfile option set). The two builds
report those two findings identically.

So the disagreement is not "taint engines disagree". It is confined to the
taint-shaped cases the synthetic corpus is constructed to elicit, and does not
reach the only two real occurrences available to observe. With n=2 that second
half is a thin observation and is stated as one; the first half — three of the
four diverging categories firing nothing at all on real code — is the load-bearing
part.

So: swapping one build of an engine for another changes the benchmark score by
6.7 points and changes real-world detection by *zero*. Published scorecards name
a tool, not a build, so this variation is unattributable from the scorecard
alone — a reader cannot tell whether a 6.7-point gap between two published
numbers is a difference in tools or a difference in builds.

**A correction is recorded here deliberately.** An earlier working note in this
study generalised "the two are interchangeable" from the 21 control files. The
benchmark run disproved it. The claim was retracted rather than quietly dropped,
because the episode is itself an instance of the study's subject: a conclusion
drawn from a corpus too small and too uniform to support it, which survived until
a different corpus was tried. It is the same failure mode as the one being
audited, at one remove.

---

## 3. Result 2: the score does not predict real detection

### 3.1 The gap

| corpus | quantity | value |
|---|---|---|
| OWASP Benchmark v1.2 | TPR (published aggregation) | **77.97%** |
| JavaVFC security stratum (n=120) | verdict flipped with the fix | **0.83%** (1/120) |
| | tool silent on both revisions | 92.5% (111/120) |
| JavaVFC CVE stratum, in-code fixes only (n=14) | verdict flipped with the fix | **7.1%** [1.3–31.5%] |

**These two numbers are not the same kind of quantity and the ratio between them
should not be quoted as one.** The first is the fraction of *known vulnerabilities*
detected, on cases built to contain one. The second is the fraction of *commits*
whose verdict moved. JavaVFC commits are not all vulnerabilities — Section 4
measures that only 18% are — so the denominator includes material no scanner
could be expected to detect.

An earlier draft of this study led with a 93.6× contrast between them. That
framing is withdrawn, because it compares two different denominators and the
comparison flatters the conclusion. Sections 3.4 and 3.5 report what happens when
the denominator is tightened to the strictest standard the corpus allows — every
commit an outside authority certified as fixing a named vulnerability, in code a
source scanner can read — and the finding survives that, which is the only thing
that makes it worth stating.

### 3.2 The four-way decomposition

A naive "coverage" metric on the real stratum reports **7.5%** — the tool flagged
a file the commit changed. That number is nearly meaningless, and this is the
reusable contribution of the study.

Eight of those nine flagged commits are also flagged on the **fixed** revision.
The pattern survives the fix, so the tool never detected the vulnerability: it
matched a construct that was there before and after, and would have reported it
identically had the vulnerability never been fixed. Only the decomposition
exposes this:

| | flagged both revisions | flagged vulnerable only | flagged fixed only | flagged neither |
|---|---|---|---|---|
| Semgrep | 8 | **1** | 0 | 111 |
| opengrep | 8 | **1** | 0 | 111 |

The middle column is the only one where the tool's verdict tracked the
vulnerability. **Naive coverage over-reports the detection signal by roughly
9×** (7.5% against 0.83%).

A stricter reading — a finding landing on a line the patch actually deleted —
gives **0/120**. That is a *lower bound*, not the headline: a fix can neutralise
a vulnerability without touching the line the tool flags, so no finding need ever
land on a deleted line even when the tool is right. It is reported alongside the
decomposition rather than instead of it.

### 3.3 Why: the shape of a real fix

If the gap were merely "the tools are bad", it would be a restatement of the
number. It is not — it is structural, and the mechanism is measurable from the
patch text alone, with no scanner and no network involved.

**20.7% of real security fixes delete no line at all** (23 of 111 distinct
patches, 95% CI 14.2–29.2%).

A patch that deletes nothing leaves every construct that was present before the
fix present after it. For a tool whose signal is the presence of that construct,
the input it reads is **identical in both revisions**, so its verdict cannot
move. The tool is not so much missing the vulnerability as being structurally
unable to express it.

The cross-tabulation against Semgrep confirms the direction:

| patch shape | neither | both | vuln-only (flip) |
|---|---|---|---|
| deletes no line (23) | 21 | 2 | **0** |
| deletes ≥1 line (88) | 83 | 4 | **1** |

Of 23 purely additive fixes, **zero** produced a verdict change; the single flip
in the whole stratum sits in the group that deletes something.

**Honest limit, stated plainly:** only 2 of those 23 additive fixes were flagged
at all, so the *observations* are consistent with the mechanism without being
proof of it. The argument is the mechanism itself, which is a priori — an
identity, not a correlation. The observations do not contradict it.

Reading the additive fixes shows what they are:

- AOSP adding `callingUid != ROOT_UID` to `startInstrumentation`
- xxl-job adding `@PermissionLimit(adminuser=true)` (CVE-2022-36157)
- Trebuchet adding an extras-null consent check

**The vulnerability is a missing check — an absence, not a construct.** There is
no source, no sink and no propagation for a taint engine to follow.

And the OWASP Benchmark cannot pose that question at all — not as a matter of
degree, but of what it contains. Its 2,740 cases are 2,740 separate static files
(1,415 labelled vulnerable, 1,325 safe, counted from `expectedresults-1.2.csv`),
and **there is no revision anywhere in the corpus**. Scoring is a single scan of a
single tree compared against that CSV. The benchmark never presents the same code
before and after a change, because it contains no changes. So the quantity Section
3.2 measures — whether a tool's verdict *moves* when the vulnerability is removed —
is not merely unmeasured there; it is not expressible. A purely additive fix leaves
every dangerous construct exactly where it was, and the benchmark has no mechanism
that could notice the check that was added.

*On the safe cases, supporting evidence rather than proof.* The safe half is
generated as separate files, and one expects each safe file to be its vulnerable
twin with a sanitiser substituted. A similarity search that assigns each safe case
one-to-one to the closest vulnerable case in its category, at line granularity,
pairs **185 of the 1,325** safe cases at ≥0.90 — **all 185 by substitution and none
by addition**, which is the shape the claim requires.

The count is deliberately reported with its method attached, because it is a
direct function of the matching granularity: comparing whole lines under `difflib`
cascades an alignment when one line changes, so a stricter measure under-reports
pairing and a character-level one would report more. An earlier draft carried
**675 paired / 674 substitution / 1 pure deletion / 650 unpaired** as a bare
number, and that figure is **not reproducible from any code in this repository** —
the same defect Section 4 corrects at 44.3%, committed here first and in the same
document. The search is now a module (`eval/benchmark_structure.py`) whose output
is persisted with it, and the numbers above are what it prints.

The assignment is one-to-one, and that matters: scoring each safe case against its
own best match independently is *not* a pairing, because the generator gives every
case in a category the same scaffold, so similarity is inflated across the family
and several safe cases name the same twin. The first run of this module reported
218 pairs that collapsed to 171 distinct vulnerable cases, which is what exposed
it. What the two figures agree on is the part the argument uses: **substitution
dominates and a purely additive pair does not occur.** 1,140 cases went unpaired at
this threshold, so this corroborates the construction rather than verifying all
2,740, and is reported as the partial result it is.

So the benchmark cannot penalise a tool for the behaviour that dominates real code,
and cannot measure the capability that real fixes demand. **Its score is not merely
optimistic; it is answering a question the real corpus does not ask.**

### 3.4 Tightening the denominator

The objection to Section 3.1 is that JavaVFC commits are not all vulnerabilities.
The strictest available answer is to use ground truth from outside this study: a
**CVE identifier in the commit message**. An authority with no stake in this work
has asserted the commit fixes a named vulnerability.

This gives 32 commits, of which 20 are multi-file. Restricting to single-file
commits — as the other strata do — would leave 12, and the 20 it discards are
exactly the classes a taint engine models: XSS escaping, XXE doctype parsing,
Java deserialization, REST bulk-read authorization. The two that survive outside
the security stratum are both dependency bumps. **The `cve` stratum therefore
does not apply the single-file rule**, because applying it would exclude
precisely the fixes most likely to be detectable and manufacture the finding.
`evaluate()` is unaffected: it materialises every changed file on both sides and
partitions findings by side, so commit-level flagging is well defined either way.

Within the 120-commit security stratum, 10 commits name a CVE. Six change no code
a source scanner can read — dependency bumps, where the vulnerable code is in a
jar rather than in the diff — and are trivially absent for reasons that say
nothing about the tool. The four that change code split into the two failure
modes this study names:

| commit | class | Semgrep |
|---|---|---|
| `apache/ofbiz` OFBIZ-12857 | authentication bypass (Solr) | silent on both revisions |
| `xxl-job` CVE-2022-36157 | authorization | **flagged identically on both revisions** |
| `payara` CVE-2023-41080 | protocol-relative redirect | **flagged identically on both revisions** |
| `apache/kafka` CVE-2022-37434 | rocksdb (incidental file) | silent on both revisions |

**Zero verdict flips among in-code, externally-certified vulnerability fixes.**

*The limit is real and large:* n=4, so the Wilson interval for 0/4 runs to ~49%.
This does not establish a low rate with any precision. What it establishes is
that the criterion for a fair denominator can be tightened all the way to
externally-certified, in-code vulnerability fixes and the flip count is still
zero — so the gap is not manufactured by the choice of denominator. The 32-commit
`cve` stratum is evaluated separately in Section 3.5.

### 3.5 The CVE stratum: three nested restrictions

The same argument, run at scale instead of on the security stratum's ten.
Restricting the whole corpus to commits naming a CVE gives 32, and then two
further restrictions each remove something a source scanner provably cannot
report on:

| restriction | commits | why |
|---|---|---|
| names a CVE, changes Java | 32 | external ground truth; no judgement by this study |
| **the fix is in code, not in a jar** | **14** | 18 are dependency bumps — the vulnerable code is inside a library, not in the diff, so no source analysis could ever report it |
| a flip was structurally possible | 11 | 3 delete no line, so a flip is impossible by construction (§3.3) |

The dependency/code split is a judgement about 32 specific commits, recorded as
data and guarded against the sample (`eval/cve_denominator.py`) rather than
inferred. The signals that look mechanical do not work: `has_non_test_java`
fails to separate them, because a version bump routinely touches a Java file
incidentally — a version constant, an API rename, a test pinning the old
behaviour.

**Semgrep's verdict moved on 1 of 14 in-code CVE fixes — 7.1% [95% CI
1.3–31.5%]** — against a benchmark TPR of 78.0%. On the 11 where a flip was
possible at all, 9.1% [1.6–37.7%]. Both intervals are wide, because n is small;
that is a limit of the corpus, not of the argument, and the intervals are
reported rather than suppressed. **Even the upper bound, 31.5%, sits far below
78.0%.**

Two further things the table shows, which matter more than the point estimate:

- **3 of the 14 fired identically before and after the fix** (an authorization
  fix, a redirect fix, an XXE fix). That is the §3.2 failure mode, and no
  coverage metric can distinguish it from detection.
- **One XSS fix scored zero findings.** `Fix for #2269 and #2267 XSS
  vulnerability. Escaping the user supplied input when outputting` — a real,
  externally-certified XSS fix, in a ruleset of 690 rules that includes XSS
  rules, on a class the benchmark has 246 cases of.

**This is a floor on detection, not a detection rate.** A flip is the strongest
signal the method can observe, and a tool can detect a vulnerability without
producing one — by flagging the vulnerable revision and something narrower after
the fix, which this method reads as "both". The `both` count is the size of that
blind spot, and it is reported alongside for exactly this reason.

---

## 4. Result 3: the corpus used to test generalisation is itself broken

JavaVFC is described as "manually-verified Java vulnerability-fixing commits" and
is the corpus of choice for asking whether a scanner generalises. It is 784
records. Two disjoint interleaved samples were read and judged by hand (n=61):

| | genuine security fix | partial / adjacent | not security |
|---|---|---|---|
| **pooled (n=61)** | **18.0%** [95% CI 10.4–29.5%] | 19.7% | **62.3%** |
| half A (n=31) | 16.1% [7.1–32.6%] | | 61.3% |
| half B (n=30) | 20.0% [9.5–37.3%] | | 63.3% |

The two halves are reported separately rather than only pooled. A single labeller
cannot supply inter-rater agreement; what two independently-read disjoint halves
supply is a check that the rate is not an artefact of one reading. They agree, and
the agreement is **stability, not correctness** — both readings are the same
person's.

The rubric, applied identically to both halves: **Y** = a specific exploitable
flaw fixed in code, or a security defect (plaintext credentials, a fixed default
password) eliminated. **P** = security-motivated but not a code-level flaw fix —
a CVE dependency bump, a resource-exhaustion limit, test-only changes, hardening
with no specific flaw. **N** = crash, deadlock, infinite recursion, overflow,
OOM, performance, functional bug. DoS is classified N, matching this study's own
shipped-alternative taxonomy, which classes it as reliability; applying a
stricter rule to the corpus than to the critique of it would be incoherent.

### The rate is rubric-sensitive and the sensitivity is reported

The rubric's most consequential choice is whether resource exhaustion counts as
security. A DoS is a security issue under CWE-400, so a reader may reasonably
disagree, and the disagreement is not small.

| vocabulary | genuine security | not security |
|---|---|---|
| as applied (availability = N) | 18.0% [10.4–29.5%] | **62.3%** |
| availability counted as security — narrow vocabulary | 32.8% [22.3–45.3%] | 47.5% |
| availability counted as security — wide vocabulary | 37.7% [26.6–50.3%] | 42.6% |

**The generous bound is not a single number, and that is itself the result.** It
depends entirely on how wide a vocabulary "availability" is given, so both ends
are computed in `corpus_audit.py` and persisted: a **narrow** set reusing the
corpus's own reliability vocabulary, which flags 9 of the 38 N-labelled commits,
and a **wide** set adding the terms a reader would reach for next, which flags
12. The wide set is deliberately not extended further — widening a proxy until it
reproduces a preferred figure is the practice this study documents.

*One coincidence, flagged so it is not mistaken for a copy-paste error.* The wide
row's point estimate and interval are numerically identical to the separately
computed "partial / adjacent" rate: 37.7%, [26.6–50.3%], because the wide
vocabulary happens to flag 12 of the 38 N-labelled commits and there are also 12
P-labelled commits, so both quantities are 23/61. The two counts are independent —
one comes from a regex over N-labelled messages, the other from hand labels — and
the agreement is arithmetic, not evidence. `results/javavfc_composition.json`
carries both under distinct keys.

Inspection shows most flagged commits are **not** attacker-triggerable
availability failures at all: an infinite recursion in a buffer utility, an
Android `Spinner` UI loop, a `setScopedValueBindings` invariant, a deadlock in a
Kafka test source, a memory-efficiency refactor that merely mentions heap-attack
tests. Only one commit in the whole sample names an attack explicitly:
"Backported deep DOS parse attack into 17.x branch".

So the defensible reading sits near the applied rubric, and the honest statement
of the result carries the range rather than the point estimate. **What survives
across the whole range is the part that matters: between 42.6% and 62.3% of a
corpus advertised as "manually-verified Java vulnerability-fixing commits" is not
a security fix at all**, and the provenance paragraph below shows the inclusion
mechanism that produced this.

*Correction.* An earlier draft gave this bound as a single figure, 44.3%, and
carried "36%" as the low end of the range above. That number is computed nowhere
in this codebase and cannot be re-derived — an unpinned statistic of exactly the
kind this study criticises, sitting in this study's own write-up. It has been
replaced by the two measured ends. The sensitivity analysis is kept rather than
dropped because a bound computed with a vocabulary too crude to trust is still
better evidence than a point estimate defended as if it had no error bar.

The rubric question is also **bypassed entirely** in Section 3.4, which uses CVE
identifiers — external ground truth that needs no judgement from this study at
all.

Two entries that the commit message alone would have placed wrongly, found by
reading the diff:

- `[CST-12108] porting of security part for QAEvents` reads as a security fix.
  It is 1,275 lines adding a `UUID focus` field to a research-information system,
  where "security" means *securities/instruments*.
- Pulsar's `Allow proxy to pass same role for authRole and originalRole` touches
  authorization, and *loosens* the check to repair the authors' own regression.
  **A change that widens access is not a vulnerability fix.**

Both are instances of the failure this study documents, and neither is detectable
from a keyword.

**How they got in.** JavaVFC ships its own inclusion regex, and 333 of 784 records
are admitted by an alternative that selects for *reliability* rather than
security. The largest single contributor is one clause — `fix ... crash`,
`clashing`, `bypass` or `auth` within 50 characters — which alone accounts for 230
inclusions. "Fix crash when fighting divine dragon spirit" (a Minetest bug) is a
corpus entry. The shipped regex reproduces only 440 of the 784 inclusions, so the
provenance is not even self-consistent.

This is provenance, not opinion: it shows *how* non-security commits entered,
which is what makes the finding a defect in the artifact rather than a
disagreement about labels.

---

## 5. What would have to change

Stated as conditions a benchmark must meet to be evidence about detection
capability. Each follows from a measurement above rather than from principle.

1. **The scorer must not know the tool's name.** Leniency keyed on a name string
   makes the score a property of the tool's branding. (2.1)
2. **One aggregation rule, stated.** Macro and micro must not be mixed within a
   scorecard, and whichever is used must be named. (2.2)
3. **The build must be part of the score's identity.** A 6.7-point swing from an
   engine build makes a bare tool name insufficient to identify what was
   measured. (2.3)
4. **The corpus must contain fixes that delete nothing.** Of the benchmark's safe
   cases that pair to a vulnerable twin at all, every one differs by substitution
   — a construct replaced, never one added. 20.7% of real fixes delete no line and
   add only. The capability the benchmark measures is therefore not the capability
   real code demands. (3.3)
5. **Detection must be measured as a change in verdict, not as a flag on a file.**
   Naive coverage over-reported by ~9×. A tool that flags a construct before and
   after a fix has detected nothing. (3.2)
6. **A corpus of "known vulnerabilities" needs provenance.** If the inclusion
   rule admits crash fixes, the corpus measures crash fixes. (4)

Point 5 is the one this study would most want carried forward, because it is a
measurement technique rather than a criticism: it applies to any before/after
scanner evaluation, on any corpus, and it costs nothing to compute.

---

## 6. Limitations

Stated as limits on what the numbers support, not as a list of caveats.

- **Two of three tools share an engine.** Semgrep and opengrep are one family.
  Their agreement is weak evidence about detection; their *disagreement* is
  strong evidence about build sensitivity, which is what Section 2.3 uses it for.
- **Every revision is scanned as an isolated file.** A real fix sits inside a
  project; the reconstruction method cannot supply one. This is applied
  identically to every tool, and it is a floor for tools that resolve types and
  near-neutral for pattern matchers. Recorded per result as `note_on_input_shape`.
- **Single-file commits.** The `raw` and `security` strata admit only commits
  touching one file, so cross-file neutralisation is outside the sample by
  construction. The `cve` stratum deliberately lifts this (3.4).
- **The additive-patch mechanism is a priori, its confirmation is weak.** Only 2
  of 23 additive fixes were flagged at all.
- **The corpus-composition rate is one labeller's.** Stability across two halves
  is not inter-rater agreement.
- **`n=14` on the strictest denominator.** The CVE-stratum rate is a direction,
  not a precise value; its interval spans 1.3–31.5%. The claim it supports is
  that tightening the denominator does not close the gap, not that the rate is
  7.1%.
- **The dependency/code split is a judgement**, recorded as data and guarded
  against the sample, not derived. `has_non_test_java` was tried as a mechanical
  discriminator and fails: a version bump routinely touches a Java file
  incidentally.
- **CodeQL cell of the OWASP table is not yet measured.** It is deliberately not
  filled from a published scorecard: citing one would import exactly the
  unreliability this study demonstrates.
- **CodeQL loses whole commits when a query exhausts its heap, and the loss is
  loud.** Measured, not assumed: the evaluator dies, CodeQL exits non-zero, no
  SARIF is written, and the commit lands in `scan_failures` — 2 of the first 15
  commits attempted, both on a marginal query that merely ships inside the
  security-extended suite. An earlier draft of this section stated the opposite,
  that CodeQL "exits 0 and merely omits its results, which is indistinguishable
  from ran and matched nothing". That was written from expectation and is wrong
  for this failure mode. It is corrected here rather than deleted, because an
  unmeasured mechanism asserted as fact is this study's own subject. Whether some
  *other* query failure is non-fatal and does exit 0 with a partial SARIF remains
  unestablished: `real_corpus.failed_queries()` parses stderr for that case, and
  if the OOM is the only failure mode it never fires.
- **The CodeQL heap budget was raised from 1500 to 3072 MB mid-run, on resume.**
  Heap bounds whether a query *completes*, never what it *matches*, so the change
  fills in missing observations rather than adding favourable ones; every pinned
  condition — suite, pack versions, build mode, ruleset, corpus — is unchanged.
  The original 1500 was chosen to avoid memory pressure, and that reasoning was
  sound but rested on a false premise: the pressure came from the process-tree
  leak recorded in Section 7, not from the evaluator. Recorded in `pins.json`
  under `ram_revision`.

---

## 7. Reproduction

```
pins.json          every external artifact, hashed
results/           every number in this document, as JSON, with its inputs
tests/             99 tests, including regression tests for each defect found
```

The three latent bugs found during this work are recorded because of what they say
about the method, not as housekeeping.

The diff parser read added Java lines beginning `++x;` as file headers and
undercounted deletions — and an undercounted deletion is exactly what makes a fix
look purely additive, i.e. it would have corrupted the Section 3.3 headline
silently.

The file cache was not written atomically, so two concurrent tool runs could
interleave into a truncated entry that later runs read back and trusted,
surfacing only as a silently skipped commit.

The third is the sharpest, because it is this study's own subject happening to
this study. `subprocess.run(..., timeout=)` kills only the direct child. For CodeQL
that child is a shell launcher, so every timeout left an orphaned java extractor
resident — 2.2 GB each, against 3.6 GB free on this host. Several accumulated, and
every later commit ran at about a tenth of its speed. The run went silent for two
hours and read as hung; it was starved. The timeout itself reported success on
schedule, so nothing observable at the call site could reveal it: a silent stall
indistinguishable from working, which is precisely the failure mode Section 3
names as the one the benchmark cannot see. It was fixed by killing the entire
process group and verifying the group is empty, and the regression test was
confirmed to *fail* against the old implementation rather than merely to pass
against the new one.

That regression test then failed for a third reason, which is worth recording
because it is this study's own failure mode reappearing inside the test written to
guard against it. The test counted the scanner's processes *globally*, before and
after; whenever any other CodeQL run was in flight its children appeared between
the two snapshots and counted as survivors. It passed alone and failed under the
full suite — and it failed under the full suite precisely when a real stratum was
being scanned. Cross-talk from a concurrent run, which is the mechanism that
starved the run in the first place, showing up as a false positive in the guard.
It is now scoped to the temp directory that test alone creates, and the detection
was re-proved sensitive by leaking a real tree on purpose: four processes survive
a direct-child-only kill, and the scoped detector names all four.

Two hypotheses formed during that diagnosis were also wrong, and are recorded for
the same reason. That the timeout was being defeated by the process tree — it is
not; it fires on schedule. And that `--build-mode=none` was being ignored, because
stderr showed `autobuild.sh` running — it is not; in no-build mode that script only
enumerates and indexes files and never compiles. Both were plausible, both were
disproved by running the thing rather than reasoning about it, and neither would
have been caught by inspection.

All three were found by testing the harness rather than the tools, and all three
are now regression-tested.

That second promise in the block above — `results/` holds *every* number in this
document, as JSON — was then tested too, by re-deriving the document's quantities
from the result files field by field. It found a fourth defect, the only one on the
write-up side rather than in the harness. Section 3.1 asserted that the two builds'
real-stratum results agreed *without exception*: "not one of the 120 commits
differs in any respect". Re-deriving it showed all nine commits carrying a finding
disagree on the CWE display string — Semgrep records `CWE-611: Improper Restriction
of XML External Entity Reference`, opengrep records `CWE-611`. No identifier
differs, so no result of this study changes; the claim's *width* did. The
enumeration that follows it — same rules, same counts, same lines, same
decomposition, same flip — was true all along, which is exactly why the
overstatement survived review: the evidence for the true claim was in hand, and
the sentence asserted more than the evidence. A test now holds both halves of the
corrected claim, the strong one and the exception, so neither can drift.

**The general lesson, which is the one worth keeping:** every defect in this study
was found by disbelieving a number that looked fine. The positive control exists
because a zero from a broken scanner is silent. The four-way decomposition exists
because a 7.5% coverage figure was 9× too generous. The build-sensitivity result
exists because a 21-file agreement was generalised too far. The heap budget was
defended on a memory-pressure premise that the leak itself had manufactured. None
of these were visible in an aggregate. And the last one was not a number at all
but the word "any" in front of one.
