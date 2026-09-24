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

**Open sub-question (the interesting one):** does adding deterministic verifiers
improve trust, or move it (DB freshness, reachability, router calibration) one
layer down?

**Artifacts:** RewardAudit benchmark + harness (canary repos, adversarial
generator, verifier implementations, calibration toolkit, reporting protocol).

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

## 7. Experiments (in order)

| ID | Experiment | Needs training? | Purpose |
|---|---|---|---|
| **E1** | Adversarial verifier evasion across V1 LLM-judge / V2 exact-CPG / V5 hybrid | **No** | the headline number |
| **E1b** | Attack the verifier *score* directly (RL-free reward-hack proxy) | No | RQ2 without RL |
| **E2** | Calibration + auditable FNR + cost-per-TP | No | the measurement instrument |
| **E3** | Small LoRA adjudicator on residual cases; does it match an API model? | Yes (cheap) | validates the small-model thesis |

**Metrics:** evasion ASR · precision · **FNR estimate** · cost per true positive ·
abstention rate · reward-hack rate (reward↑ while blinded audit↓).

**Frozen benchmark:** 10 known CVEs + ~5 canary/trap repos + synthetic
injections, with a hidden holdout and pre-registered thresholds.

## 8. Milestones and kill criteria

| M | Deliverable | Gate |
|---|---|---|
| M0 | Finding/Evidence schema, T0+T1, OSV dep match, canary repos | `pytest` green; reproducible manifest |
| M1 | Evidence ledger + verifiers V1/V2 | reproduce known labels on clean code |
| M2 | **E1 result** (adversarial generator + evasion ASR per verifier) | **a real number exists** |
| M3 | E1b + E2 (calibration, FNR, cost-per-TP) | selective-risk curve reported |
| M4 | Small LoRA adjudicator + abstention | matches API baseline at lower cost |
| M5 | Paper draft + open artifact | reproducible from README |

**Kill criteria**
- If E1 shows **no** verifier-dependent evasion → headline dies; pivot to the
  calibration/FNR measurement (still publishable) rather than forcing it.
- If M0–M2 is not done in ~3 weeks → scope is wrong; cut further.
- If the thin vehicle is not cheaper per true positive than API-only → stop
  building pipeline.

## 9. Compute and money

- **Budget: $0–$1k, inference-only** (ADR-0002). M0–M3 need no GPU training.
- M4: one modest LoRA run (5–20 GPU-hr) — a cheap rented GPU or the local 3070 Ti.
- GPU rentals (G4 Flex $2.25/GPU-hr, H200 ~$4.30/GPU-hr) are contingency only,
  **after** E1 justifies them.

## 10. Background documents

- `docs/rl-vulnerability-analysis-plan.md` — original broad plan (background).
- `docs/compute-and-model-strategy.md`, `docs/gcp-rl-cost-estimate.md`,
  `docs/compute-reduction.md` — cost and efficiency (contingency).
- `docs/novelty-and-related-work.md` — prior art and positioning.
- `docs/architecture-lastline.md` — rejected alternative + its critique.
- `docs/issues.md`, `docs/adr/` — decisions and tracked work.

## 11. The only next action

**Build M0, then M2.** The smallest thing that produces a real number is:
finding schema + one scanner + two verifiers + ten CVEs + a canary repo, then
run E1. Everything else — architecture, cost models, tiers — is procrastination
until that number exists.
