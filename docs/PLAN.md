# PLAN — North Star

**Status:** canonical. This supersedes the sprawl; other docs are background.
**Date:** 2026-09-24

---

## 1. The take in one paragraph

Build a **thin, honest security adjudicator** and use it to answer **one
measurable question**: *when does composing deterministic verifiers make an LLM's
security verdict trustworthy, and when does it merely relocate the trust problem
one layer down?* The pipeline is a **vehicle**; the **benchmark and measurement
are the product**. Small model, evidence-first, abstention by default, adversary
always. Everything else is explicitly out of scope.

## 2. Why this and not the alternatives

| Option | Verdict |
|---|---|
| Big agent with many tools | Already done (OpenAnt, FuzzingBrain, VulAgentRL, Antares) |
| Seven-tier "LLM last" cascade (LastLine) | Product architecture, not research; starves the hard case; silent-FN risk |
| From-scratch model | Economically impossible (ADR-0001) |
| **Measurement-first + thin vehicle** | **The only gap that is real, unowned, cheap, and hardware-feasible** |

## 3. The contribution

**Headline:** verifier composition and design determine whether an agentic
security verdict can be trusted under adaptive adversarial code.

**This extends prior work by the same author.** `~/Projects/Patch` already
produced (`sastaudit/artifact/FINDINGS.md`) a rigorous measurement that
*static-scanner* benchmark scores do not predict real detection, and introduced
the **four-way decomposition** (flagged-both / vulnerable-only / fixed-only /
neither) plus the finding that **20.7% of real security fixes delete no line**.
RewardAudit asks the **same question of LLM/agentic verifiers**, with the
**same instrument** — and adds an adversary.

**Sharpened E1 (the headline experiment):** apply the four-way decomposition to
LLM adjudicators. *Does an LLM's verdict move when the vulnerability is removed,
or does it flag the same construct before and after — exactly the failure mode
FINDINGS.md measured in Semgrep?* Then attack it with adversarial code comments
and measure the evasion delta.

**Open sub-question:** does adding deterministic verifiers improve trust, or move
it (DB freshness, reachability, router calibration) one layer down?

**Artifacts:** RewardAudit benchmark + harness (canary repos, adversarial
generator, verifier implementations, calibration toolkit, reporting protocol),
built by extending `sastaudit`.

## 4. Ideal architecture — evidence-first, not cost-first

The mistake in a "cheap-first cascade" is that it gives the *hardest* cases the
*least* evidence and the *weakest* model. Invert that: gather evidence cheaply and
in parallel, then spend reasoning where uncertainty **and** impact are highest.

```
EVIDENCE PLANE  (parallel, deterministic, cheap, NO LLM)
  ingest/CPG · scanners · OSV/CVE dependency match · reachability · tests/sanitizers
      └─▶ normalized Evidence[] with provenance; code/tool output is untrusted DATA
                          │
                          ▼
DECISION PLANE  (small, scoped, measured)
  calibrate ─▶ route by impact × uncertainty ─▶ SMALL LoRA adjudicator
      · evidence-grounded · schema-validated · every claim CPG-verified
      · may call bounded tools · may ABSTAIN (unknown_risk)
      └─▶ high-impact & low-confidence → human
                          │
                          ▼
  FROZEN BENCHMARK + CANARIES + ADVERSARIAL STRESS TEST   ← the actual contribution
```

**Principles**
1. **Evidence before reasoning.** Tools run in parallel; they are not a
   cost ladder that filters cases away from the model.
2. **Small model, narrow job.** It adjudicates evidence — it does not discover.
   A 1.5–3B LoRA is enough *because the job is scoped*.
3. **Route by impact × uncertainty**, not by cost alone. High impact → most
   evidence, best model, human.
4. **Deterministic for known, LLM for novel** — and *measure the boundary*
   rather than assuming it.
5. **Abstention is a feature.** `unknown_risk` beats a confident guess.
6. **Adversary always.** No result counts unless it survives the attack generator.

## 5. What we are explicitly NOT doing

LastLine's seven tiers · auto-rule synthesis · online RL/GRPO · pretraining ·
multi-language v1 (start C/C++ and Python) · dynamic fuzzing as core ·
big models · building ten threat-feed integrations (use OSV API) · patch
generation.

## 6. The vehicle, minimal

- **T0:** tree-sitter → CPG, dependency graph, SBOM.
- **T1:** one or two scanners (Semgrep; secrets) — enough to produce candidates.
- **Evidence:** OSV dependency match, reachability, test/sanitizer where cheap.
- **Verdict:** one small LoRA adjudicator (1.5–3B) + abstention + calibration.
- **Ledger:** every finding carries its evidence chain; claims verified against
  the graph.
- Stop there. No more tiers.

### What the LLM actually sees (the I/O contract)

**Not the codebase.** The model receives a bounded, structured **verdict request**:

```
VerdictRequest {
  candidate:   { rule_id, cwe_hint, file, line_range, sink, source, scanner_confidence }
  code_slice:  { enclosing_function, dataflow_path, sanitizers_present,
                 direct_callers, direct_callees, line_numbers }   # minimal, graph-selected
  repo_context:{ language, framework, threat_model }               # metadata only
  retrieval:   [ cwe_definition, similar_past_findings, fix_pattern_from_db ]
  budget:      { max_tokens }
}
→ Verdict { disposition, cwe, severity, confidence, evidence_refs[], rationale, abstain }
```

Rules:

- **Never the whole repo, never whole files by default.** A *code slice* is
  selected by the graph around the candidate (function + dataflow + immediate
  callers/callees). Small files may be sent verbatim; repos never are.
- **Every `evidence_ref` must resolve to a real CPG node / file:line**, or the
  verdict is rejected. The model cannot assert without citing.
- **All code and tool output is untrusted data, never instructions** (defends
  against adversarial comments).
- **The model adjudicates; it does not discover.** Discovery is T0/T1.
- **Backend-configurable:** a single `LLMBackend` interface with an
  `OpenAICompatibleBackend` (any cloud API) and a `LocalBackend`
  (ollama / llama.cpp / vLLM). Chosen by config; a `MockBackend` for tests.

**Why not dump the codebase:** context limits and cost explode, precision
collapses ("lost in the middle"), results stop being reproducible, it cannot
scale to real repos, and it hands an attacker unbounded surface. It is also
exactly the strawman our E1 measurement is designed to beat — so we must not
become it.

## 7. Experiments (in order)

| ID | Experiment | Needs training? | Purpose |
|---|---|---|---|
| **E1** | **Four-way decomposition applied to LLM verifiers** + adversarial comment evasion across V1 LLM-judge / V2 exact-CPG / V5 hybrid | **No** | the headline number |
| **E1b** | Attack the verifier *score* directly (RL-free reward-hack proxy) | No | RQ2 without RL |
| **E2** | Calibration + auditable FNR + cost-per-TP | No | the measurement instrument |
| **E3** | Small LoRA adjudicator on residual cases; does it match an API model? | Yes (cheap) | validates the small-model thesis |

**Metrics:** evasion ASR · precision · **FNR estimate** · cost per true positive ·
abstention rate · reward-hack rate (reward↑ while blinded audit↓).

**Frozen benchmark:** 10 known CVEs + ~5 canary/trap repos + synthetic
injections, with a hidden holdout and pre-registered thresholds.

## 8. Milestones and kill criteria

**Status (2026-09-24): M0–M2 complete, with real cross-family results**
(`docs/e1-results.md`). `rewardaudit/` reproduces the pinned Java control result
(12/18 vulnerable, 1/3 safe flagged); supports Java + Python; implements the
four-way decomposition, evidence ledger, canary check, ALIBI-style adversarial
comment generator, and an **adaptive LLM attacker**. 64 tests green.

### Done

| M | Deliverable |
|---|---|
| M0 | wrapped `sastaudit` tool runners + pins; reproduced the control result |
| M1 | four-way decomposition, evidence ledger, Python support + canaries |
| M2 | adversarial generator, `e1`/`evade`/`adaptive`; real runs across 5 model families (n=5) |
| P1 | **JavaVFC scale-up**: 207 pairs materialised offline; E1 on the 21-pair security subset → **flip rate 19–24%** vs Semgrep's 0.83% |
| P2 | evasion split into false-positive vs abstention → **almost all evasions are abstention** |
| P3 | adaptive attacker at scale → **50% evasion** (3/6), all via abstention |

See `docs/e1-results.md` (round 3). Remaining: P4 composition, P5 calibration/FNR,
P6 write-up.

### Remaining phases — bounded finish (P1–P6)

| P | Deliverable | Gate / value | Effort |
|---|---|---|---|
| **P1** | **Scale E1 to JavaVFC (784 real fixes)**: wire sastaudit's Java before/after loader; run `e1` across ≥3 verifiers with CIs | **decisive** — a robust surprise, or a documented null | 2–4 d |
| **P2** | Split evasion into `→false_positive` vs `→abstention` | metric reported both ways (abstention is a distinct path) | 0.5 d |
| **P3** | Adaptive attacker at scale, cross-model | evasion per tactic at n≥100 | 1 d |
| **P4** | **Composition test**: LLM alone vs +exact-CPG verifier vs hybrid | *does adding verifiers improve trust or relocate it?* — the sharpest question | 2–3 d |
| **P5** | Calibration + auditable FNR + cost-per-TP | selective-risk curve at a pre-registered target | 2–3 d |
| **P6** | Ship: open artifact + write-up + reporting protocol | reproducible from README | 2–4 d |
| (P7) | Small LoRA adjudicator | only if P1–P4 justify it; otherwise **cut** | conditional |

Scope is capped at P1–P6 (~2 weeks, $0–50, inference-only). **No new subsystems.**

### Kill criteria (pre-committed)

- **P1 shows nothing beyond the qualitative result** → ship the
  methodology/negative-result artifact and **stop**. Do not start a v5.
- **P1 cannot be wired in ≤2 days** → cut to a ~100-pair stratified subsample.
- **FNR needs more human audit than available** → report a bound, not a point
  estimate.
- If the thin vehicle is not cheaper per true positive than API-only → stop
  building pipeline.

## 9. Compute and money

- **Budget: $0–$1k, inference-only** (ADR-0002). M0–M3 need no GPU training.
- M4: one modest LoRA run (5–20 GPU-hr) — a cheap rented GPU or the local 3070 Ti.
- GPU rentals (G4 Flex $2.25/GPU-hr, H200 ~$4.30/GPU-hr) are contingency only,
  **after** E1 justifies them.

## 10. Reuse — the substrate already exists (do not rebuild)

Prior project `/home/amon/Projects/Patch` (VulnDetect → revguard, closed
2026-09-14) already built most of the measurement substrate. It is a 5 GB data +
1.7 GB harness asset, not a sketch.

| Asset | What it is |
|---|---|
| `sastaudit/` | **Pinned, tested SAST evaluation harness**: tool runners (Semgrep 1.177.0, opengrep 1.30.0, CodeQL 2.27.0, PMD), OWASP Benchmark v1.2 + JavaVFC corpora, original + corrected scoring, `pins.json`, 99 tests, `results/*.json`, controls with positive/negative checks |
| `sastaudit/artifact/FINDINGS.md` | A rigorous **negative result**: benchmark score ≠ real detection (78% OWASP TPR vs 0.83–7.1% real flip rate); the **four-way decomposition** (flagged-both / vuln-only / fixed-only / neither); 20.7% of real fixes delete no line |
| `data/` | **179,481 commit pairs**, 15 cloned C/C++/Python repos (tcpdump, openssl, curl, ImageMagick, redis, …), BigVul splits |
| `measure_revert_rate.py` | Base-rate measurement methodology |
| `guardrail/` | Signal interface + benchmark seam |
| `vulndetect/` | The closed detector — **do not extend** |

**The pivotal fact:** Patch's own postmortem independently recommends pivot #1 =
*"an evaluator of detectors."* **That is RewardAudit.** So M0 is not greenfield —
it is **extending `sastaudit`**.

**The pretrained C/C++ model is not useful here.** The postmortem records that the
InfoNCE pre-training did not transfer and the best detector reached Val F1 0.16 /
AUC 0.78. Our design needs no vulnerability classifier (scanners detect;
LLM/verifiers adjudicate), and bolting a weak, unvalidated detector onto a
trust-measurement system would confound the very thing we measure. Keep
`vulndetect/` frozen; at most use it as a *baseline to beat*.

**What to actually reuse:** the tool runners + `pins.json` discipline, the
corpora, the four-way decomposition, the controls, the test suite. That is weeks
of work already done and validated.

## 11. Background documents

- `docs/rl-vulnerability-analysis-plan.md` — original broad plan (background).
- `docs/compute-and-model-strategy.md`, `docs/gcp-rl-cost-estimate.md`,
  `docs/compute-reduction.md` — cost and efficiency (contingency).
- `docs/novelty-and-related-work.md` — prior art and positioning.
- `docs/architecture-lastline.md` — rejected alternative + its critique.
- `docs/issues.md`, `docs/adr/` — decisions and tracked work.

## 12. The only next action

**Build M0, then M2 — on top of `sastaudit`, not from scratch.** The smallest
thing that produces a real number is: wrap the existing pinned tool runners with
the verifier interface, reuse the OWASP/JavaVFC/repo corpora, add the adversarial
comment generator and canary repos, then run **E1**. Everything else —
architecture, cost models, tiers — is procrastination until that number exists.
