# Revision record: `FINDINGS.md`

`FINDINGS.md` is the only markdown file this study produces. Everything else
under `sastaudit/` is code, data or JSON results; the other `.md` files in the
repository are vendored CodeQL licence notices or belong to the earlier
VulnDetect phases and are not part of this artifact.

This file records every correction made to `FINDINGS.md`, what the claim was
before, and how it was found. It exists for the reason the study gives for
recording its own bugs (Section 7): a write-up that quietly edits itself is not
auditable, and this study's whole subject is claims that were never checked
against their source.

The corrections below are not all the same kind of thing, and the distinction
matters:

- **Unreproducible** — the number was never computed by any code here. The worst
  kind, because it looks identical to a measured one.
- **Overstated** — the measurement was real; the sentence asserted more than it.
- **Not propagated** — a correction made in one section was not carried to
  another section that repeated the claim.
- **Retracted** — the claim was wrong, not merely too wide.

---

## Round 1 — prose reviewed against its source

Found by reading each section against the code and results it cites.

### 1. §6 — the CodeQL failure mode was asserted, not measured *(retracted)*

**Was:** that when a query runs out of heap, CodeQL "exits 0 and merely omits its
results, which is indistinguishable from ran and matched nothing".

**Is:** the evaluator dies, CodeQL exits non-zero, no SARIF is written, and the
whole commit lands in `scan_failures` — 2 of the first 15 commits attempted. The
quiet case the old text described has never been observed.

**Why it matters:** the retracted version was written from expectation, and it is
the exact unmeasured-mechanism error the study exists to name — committed inside
the study's own limitations section. The same sentence had also been written into
two source files, `eval/real_corpus.py` and `tests/test_real_corpus.py`, and was
removed from both; the parser that covers the quiet case is kept and its docstring
now says plainly that it has never fired.

**Also in this section:** a new bullet recording that the CodeQL `--ram` budget
was raised 1500 → 3072 MB mid-run on resume, with why that does not compromise the
before/after comparison (heap determines whether a query *completes*, not what it
matches).

### 2. §2.3 — an over-generalised mechanism *(overstated)*

**Was:** that the four categories where the two builds separate are "exactly the
ones where neither build fires on real code at all".

**Is:** of the four, three contribute none of the nine rules that fire on the real
stratum — but `xss` contributes `no-direct-response-writer`, twice. It is a genuine
taint rule (`mode: taint`, sources at `HttpServletRequest` parameter reads, sinks
at response writers), and both builds report those two findings identically. n=2,
stated as thin.

**How found:** by reading the rule definition rather than assuming. A proposed
correction calling it "a pattern check, not a taint query" was itself wrong and was
not written; checking `rules/p-java-best.yaml` showed `mode: taint`.

### 3. §3.3 — a universal claim about the benchmark *(overstated)*

**Was:** "Every one of its 2,740 cases is a synthetic servlet whose vulnerable sink
is present when vulnerable and *replaced* when fixed."

**Is:** 2,740 separate static files (1,415 labelled vulnerable, 1,325 safe), with
**no revisions anywhere in the corpus**. So the quantity Section 3.2 measures is
not merely unmeasured there; it is not expressible. A supporting-evidence
paragraph was added reporting the pairing result.

### 4. §4 — an unreproducible number *(unreproducible)*

**Was:** a single generous bound of **44.3%**, with "36%" as the low end of the
range.

**Is:** two measured ends, both computed in `eval/corpus_audit.py` and persisted —
a **narrow** vocabulary reusing the corpus's own reliability terms (32.8% genuine,
47.5% not security) and a **wide** one adding the next terms a reader would reach
for (37.7% / 42.6%). The defensible headline range became **42.6%–62.3%**.

**Why it matters:** 44.3% is computed nowhere in this codebase and cannot be
re-derived — an unpinned statistic of exactly the kind the study criticises,
sitting in the study's own write-up. The sensitivity analysis was kept rather than
dropped, because a bound computed with a crude vocabulary is still better evidence
than a point estimate defended as having no error bar.

### 5. §7 — a stale count *(not propagated)*

"Two latent bugs" → "three latent bugs", after the process-tree leak was found;
test count 85 → 91.

---

## Round 2 — every quantitative claim re-derived from `results/`

Section 7 promises that `results/` holds "every number in this document, as JSON,
with its inputs". That promise was then tested by re-deriving the document's
quantities from the result files, field by field.

**Verified sound, reproducing exactly:** the §2.2 OWASP table for both tools
(Semgrep 77.97 / 42.09 / 35.88 with TP1094 FP512 FN321 TN813; opengrep 79.79 /
37.25 / 42.54 with TP1124 FP456 FN291 TN869, and `TP+FN = 1415`, `FP+TN = 1325` for
both); the §2.3 aggregation deltas (−1.08 to +4.66 points across five tools); §3.1's
gap figures (0.83%, 92.5%); §3.2's four-way decomposition (8 both / 1 vuln-only /
0 fixed-only / 111 neither, for both tools; 7.5% naive; 0.83% flip; 9.0×
over-report); §3.3's patch arithmetic (23 additive of 111, 20.7%, and the
cross-tabulation 21/2/0 and 83/4/1); §4's entire sensitivity table including every
confidence interval; the CVE stratum (32 commits, 14 in code, 7.14% with CI
1.3–31.5%); the control-set figures (12/18 and 1/3 for both tools).

**A false alarm, recorded so it is not repeated.** The first pass reported three
mismatches in Section 3. Those were the audit's error, not the document's:
Section 3.2's table is per *commit* (n=120) and Section 3.3's is per *patch*
(n=111), and the check compared one against the other. Both tables are correct.

### 6. §3.1 — an equivalence claimed more widely than measured *(overstated)*

**Was:** "not one of the 120 commits differs in any respect" between Semgrep and
opengrep on the real stratum.

**Is:** no commit differs in any *verdict-bearing* respect — same rules, same
counts, same lines, same decomposition, same single flip, all confirmed. But all
nine commits carrying a finding disagree on the CWE **display string**: Semgrep
records `CWE-611: Improper Restriction of XML External Entity Reference`, opengrep
records `CWE-611`. No CWE *identifier* differs anywhere in the stratum.

**Why it matters:** the enumeration beside the claim was true throughout, which is
why the overstatement survived review — the evidence for the true claim was in
hand and the sentence asserted more than it. The exception is now stated, and a
test (`tests/test_cross_tool_agreement.py`) holds both halves so neither can drift.
The same overstatement was found and corrected in `pins.json`.

**Checked for consequences:** none. The divergence does not reach the benchmark
half of the comparison, which parses the bare `CWE-<n>` tag out of each SARIF rule
(`eval/benchmark_owasp.py:83`) and dropped zero findings for an unparseable CWE.

### 7. §3.3 — a pairing count with no source *(unreproducible)*

**Was:** **675 paired / 674 substitution / 1 pure deletion / 650 unpaired**, as a
bare number.

**Is:** **185 paired, all 185 by substitution, none by addition; 1,140 unpaired** —
produced by a module, `eval/benchmark_structure.py`, whose output is persisted
beside it.

**Why it matters:** the 675 figure was not reproducible from any code in this
repository. This is the 44.3% defect again, in a different section, in the same
document — which is why the correction is written as "committed here first".

**A second correction inside the first.** The module's first run reported 218
pairs. A test asserting the pairing was one-to-one showed those 218 claimed only
171 distinct vulnerable cases: the generator gives every case in a category the
same scaffold, so similarity is inflated across the family and several safe cases
named the same twin. Those 47 were matches to the scaffold, not to a twin.
Enforcing a bijection gives 185. Both the wrong count and the reason are recorded
here, because only the qualitative claim — **substitution yes, addition no** —
survives all three versions, and it is the only part the argument uses.

### 8. §5 item 4 — a correction not propagated *(not propagated)*

**Was:** "Every case in the benchmark replaces its sink when fixed."

**Is:** the measured version — of the safe cases that pair to a vulnerable twin at
all, every one differs by substitution; 20.7% of real fixes delete no line and add
only.

**How found:** by re-reading §5 after §3.3 had been corrected. This is the third
instance of the same class of defect (a correction living in one section while a
second section still carried the old claim).

### 9. §4 — an arithmetic coincidence flagged *(pre-emptive)*

The wide-vocabulary row (37.7%, [26.6–50.3%]) is numerically identical to the
separately computed partial/adjacent rate, because the wide vocabulary flags 12 of
the 38 N-labelled commits and there are also 12 P-labelled commits — both 23/61.
The two counts are independent; the agreement is arithmetic, not evidence. Noted
in the text so a reader checking `results/` does not read it as a copy-paste error.

### 10. §7 — a fourth defect, and a guard that failed for the wrong reason *(not propagated, and self-inflicted)*

Test count 91 → 95 → 99 as the new tests landed.

The fourth defect is the §3.1 overstatement above, and it was found by testing the
`results/` promise rather than by reading prose — the only one of the four on the
write-up side rather than in the harness. The closing line of the section now
notes that the last defect was not a number at all but the word "any" in front of
one.

Separately, the regression test written to guard the process-tree leak **failed
under the full suite for a reason unrelated to the leak**: it counted the
scanner's processes globally, so any concurrent CodeQL run's children appeared
between the before and after snapshots and counted as survivors. It passed alone
and failed precisely while a real stratum was being scanned — cross-talk from a
concurrent run, the same mechanism that starved the run in the first place,
reappearing inside the test written to guard against it. It is now scoped to the
temp directory that test alone creates, and the detection was re-proved sensitive
by leaking a real tree deliberately: four processes survive a direct-child-only
kill, and the scoped detector names all four.

---

## Scope of the audit, stated so it is not overread

**Re-derived from `results/`:** the quantities listed at the top of Round 2.

**Read but not independently re-derived:** §2.1's scorer-leniency claims
(`BenchmarkUtils` granting CWE-327-for-328 only to `AppScan`, `Vera` and `CodeQL`),
and §6's remaining prose beyond the two items corrected above.

**Not yet present at all:** §3's tables have no CodeQL rows — the security stratum
was still running (27 of 120 at the time of writing), and the OWASP and CVE strata
for CodeQL have not started. The `--ram` revision and the process-tree fix were
made to let that run finish.

**Measured and deliberately left alone:** a character-level version of the pairing
search would pair more cases than the line-level one and would raise the 185. It
was not run, because the match is CPU-bound and the CodeQL stratum was in flight —
resource contention is what starved that run to a tenth of its speed, which
Section 7 records. It would change the paired count, not the qualitative claim.
