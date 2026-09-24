# Architecture: LastLine — Tool-First, LLM-Last Cascade

**Status:** Proposed design (candidate ADR-0003)
**Date:** 2026-09-24
**Working name:** LastLine (check for collisions before publication)
**Related:** `docs/compute-reduction.md`, `docs/novelty-and-related-work.md`,
`docs/adr/0002-reposition-measurement-first.md`

---

## 0. The inversion

Conventional agentic security tools put the LLM in charge and let it call tools.
LastLine does the opposite:

> **Deterministic tools, an active threat database, and small discriminative
> models resolve the overwhelming majority of cases. A small generative model is
> invoked only for the residual long tail that nothing cheaper can resolve.**

Two consequences follow:

1. **The LLM's job shrinks → the LLM can shrink.** Adjudicating an
   already-formed, evidence-backed candidate is a narrow task; a 1.5–3B adapted
   model suffices. "Bigger model" is replaced by "narrower job."
2. **Cost collapses.** LLM tokens are the most expensive unit; they are spent on
   <15% of cases. Compute is dominated by cheap, parallel CPU tools.

This is the structural version of the compute-reduction guide: instead of making
training cheaper, we make **inference rarely necessary**.

---

## 1. Architecture

```
                    ┌───────────────────────────────────────────────────────────┐
                    │              CASCADE CONTROLLER (cost-aware)              │
                    │  routes each candidate only as far as needed              │
                    │  • conformal thresholds • precision target • budget caps  │
                    │  • abstention + "unknown_risk" • full evidence ledger     │
                    └──┬────────┬────────┬────────┬────────┬────────┬──────────┘
   cheap / deterministic        │        │        │        │        │   expensive / reasoning
                                ▼        ▼        ▼        ▼        ▼
   ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐
   │ T0       │─▶│ T1       │─▶│ T2 ACTIVE │─▶│ T3       │─▶│ T4       │─▶│ T5       │─▶│ T6     │
   │ Ingest   │  │ Scanners │  │ THREAT DB │  │ Verifiers│  │ Small ML │  │ SMALL LLM│  │ Human  │
   │          │  │          │  │           │  │          │  │          │  │ LAST LINE│  │        │
   │ parse    │  │ static   │  │ CVE/OSV   │  │ taint    │  │ triage   │  │ 1.5–3B   │  │ queue  │
   │ CPG      │  │ secret   │  │ GHSA/NVD  │  │ symbolic │  │ dedup    │  │ LoRA     │  │        │
   │ SBOM     │  │ dep/OSV  │  │ KEV/EPSS  │  │ fuzz     │  │ severity │  │ adjudicate│ │        │
   │ deps     │  │ IaC      │  │ advisories│  │ tests    │  │ novelty  │  │ explain  │  │        │
   │          │  │ license  │  │ + auto-   │  │ reach.   │  │ ROUTER   │  │ abstain  │  │        │
   │          │  │          │  │   rules   │  │          │  │          │  │ +tools   │  │        │
   └──────────┘  └──────────┘  └─────┬─────┘  └──────────┘  └──────────┘  └──────────┘  └────────┘
                                     ▲
                                     │  FEEDBACK LOOP (makes the DB "active")
                                     └── outcomes, fixes, FP/TP labels → recalibrate
                                         T4 thresholds, auto-generate new rules,
                                         refresh reachability & exploitability
```

---

## 2. Tiers

### T0 — Ingestion & normalization (no LLM, deterministic)
- Languages/build systems, tree-sitter parse, **Code Property Graph** (AST+CFG+
  call graph+dataflow), dependency graph, **SBOM**, lockfiles, CI/CD config,
  secrets in history.
- Emits normalized `Finding` candidates with precise locations and node IDs.

### T1 — Deterministic scanners (no LLM)
- Static (Semgrep/CodeQL/Joern/linters), secrets, dependency/CVE (OSV, Trivy,
  Grype), IaC/container, license.
- Cheap, parallel, reproducible. High recall, high noise — **noise is the input
  to the cascade, not the output.**

### T2 — Active Threat & Vulnerability Database (the load-bearing layer)
"Active" = continuously synced *and* it learns from outcomes.

**Sources (pull + push):** NVD/CVE, OSV, GitHub Security Advisories, CISA KEV,
EPSS, Exploit-DB/Metasploit, vendor advisory feeds, package registries, distro
trackers, plus an internal corpus of past findings/fixes.

**Per-record enrichment**
- Affected package/version ranges → matched against the local SBOM.
- **Reachability**: is the vulnerable function actually reachable from an entry
  point? (uses T0/T3 graph).
- **Exploitability**: EPSS, KEV membership, public PoC presence.
- **Patch availability + fix-diff mining** → the "active" magic.

**Auto-rule synthesis (threat intel → detector).** When an advisory ships a fix,
the DB mines the diff, extracts the vulnerable pattern, and **generates a
candidate detector rule** (e.g., a Semgrep/CodeQL rule), validated against the
fix commit and a benign corpus. New threat intel therefore becomes new
deterministic detection — *without an LLM in the loop* (the small LLM may help
draft/validate rules offline, but never per-scan).

**Auto-resolution.** Known vulnerable dependency with an available fix and
confirmed reachability → resolved deterministically. This is most of what real
scanners find, and it never touches T5.

### T3 — Verification engines (no LLM)
- Taint/dataflow confirmation, symbolic/concolic execution, targeted fuzzing,
  sanitizer runs, test runner, differential execution.
- Confirm/refute a candidate mechanically. Runs only on candidates that survive
  T2, gated by cost/benefit.

### T4 — Small discriminative models (no generative LLM)
- **Triage classifier**: P(true positive | features) — gradient-boosted trees or
  a small code encoder (≤300M).
- **Dedup/clustering** via embeddings; **severity/CVSS** predictor;
  **novelty/anomaly** detector.
- **The ROUTER**: decides whether a case is auto-resolved, escalated to T5, or
  escalated to T6. Trained cost-sensitively so that escalation happens only when
  the expected loss exceeds the next tier's cost.
- Calibrated with **conformal prediction / selective classification** to enforce
  a target precision or FNR bound: *the LLM sees only the provably ambiguous
  fraction*.

### T5 — Small generative LLM, the LAST LINE
- **1.5–3B code model** (Qwen2.5-Coder / Granite / SmolLM2 class), **LoRA-adapted**
  on adjudication trajectories, Q4-quantized.
- Invoked only for residuals: ambiguous logic, novel patterns, cross-file
  synthesis, explanation, and evidence-grounded adjudication.
- **Hard constraints:** bounded tool budget; structured output schema; every
  claim must cite a **CPG node ID / file:line** that is **exactly verified**
  against the graph (cheap, deterministic check); must output
  `abstain/unknown_risk` when unconvinced.
- Because its task is *narrow*, 1.5–3B is enough. No 70B needed.

### T6 — Human escalation
- High-impact, low-confidence findings go to an analyst with a complete evidence
  bundle (locations, dataflow path, DB record, exploitability, LLM rationale).
- Outcomes feed the feedback loop.

---

## 3. Cascade controller — where accuracy is actually controlled

For each candidate `f`, the controller compares the **expected loss of stopping**
against the **cost of escalating**:

```
Loss(f)   = P_error(f | evidence so far) × impact(f)
Escalate  ⟺  Loss(f) > cost(next tier)      (constrained by precision target P*)
```

- `P_error` comes from the calibrated T4 model; **conformal thresholds** give a
  distribution-free guarantee that the escalated set contains the cases where
  error is most likely.
- **Budget caps** per scan; when exhausted, remaining low-impact cases are
  reported as `unknown_risk`, not as findings (honest abstention).
- Every decision and its inputs are written to the **evidence ledger** for audit
  and for feedback.

This is the mechanism that lets a small model "maintain accuracy": the model is
never asked to solve the whole problem, only the residual slice the rest of the
system has *proven* it cannot solve.

---

## 4. Active database — schema and feedback

```
AdvisoryRecord
  id, source, cve/ghsa/osv_ids, published, updated
  affected: [{package, ecosystem, version_ranges}]
  cwe, cvss, epss, kev: bool, exploit_refs[]
  patch: {commit, diff_ref, fixed_versions}
  derived_rule_ids[]            # auto-generated detectors
  reachability_cache: {repo_hash, reachable, path_hash}

DerivedRule
  id, origin_advisory, language, pattern, rule_blob
  validation: {fix_commit_pass, benign_corpus_fp_rate}
  status: candidate|active|retired

OutcomeEvent
  finding_id, disposition(TP|FP|fixed|unknown), verifier, actor
  evidence_chain[], timestamp
```

**Loop:** sync → enrich (reachability/exploitability) → mine fix diffs → generate
& validate rules → scan → outcomes → recalibrate T4 + retire/boost rules. The
database gets *more* deterministic over time, so the LLM's share shrinks.

---

## 5. Small-model strategy

| Component | Size / type | Runs |
|---|---|---|
| Triage + router | 100–300M encoder **or** GBDT | CPU/GPU, always |
| Dedup/embeddings | small encoder | CPU/GPU, always |
| **Last-line adjudicator** | **1.5–3B, LoRA, Q4** | **only residual cases (<15%)** |
| Optional escalate-to-large | API/frontier, off by default | rare, opt-in |

Adaptation: SFT/DPO on adjudication trajectories (evidence + candidate → schema
output + abstention). No RL required to start; RFT/DPO if improvement is needed
(see `docs/compute-reduction.md`). Deployment: one small GPU or even CPU-quantized
for the last line, plus CPU workers for tiers 0–4.

**Why this beats "bigger base model":** the hard part was never language — it was
evidence. Deterministic tiers produce the evidence; the model only reasons over
it, which is a small-model task.

---

## 6. Metrics

- **Auto-resolution rate per tier** (goal: T1/T2 resolve the majority).
- **Escalation rate to T5** (goal: <15%) and to T6.
- **Cost per true positive**, LLM tokens per finding.
- Precision / recall / **FNR estimate** at the target `P*`.
- Calibration (risk–coverage curves); abstention rate.
- DB freshness (median advisory-to-rule latency), rule FP rate.
- Wall-clock time-to-first-finding.

---

## 7. Failure modes and defenses

| Failure | Defense |
|---|---|
| DB lag on 0-days | T3/T5 still function; mark `unknown_risk`; feed new intel back |
| Scanner blind spots | multi-tool ensemble + T3 dynamic verification |
| Cascade misrouting | conformal calibration + shadow-mode evaluation; audit sample |
| Small model ceiling on novel logic | T5 may call one frontier API model (opt-in) or abstain |
| ALIBI-style adversarial comments | **all code is untrusted data, never instructions**; evidence must be graph-verifiable; comment stripping before LLM |
| Feedback poisoning | signed/attributed outcomes; outlier detection before recalibration |
| Rule auto-generation FP | validate against fix commit + benign corpus before activation |
| Privacy | local-first; DB synced from public feeds; no code egress unless opted in |

---

## 8. Build order (MVP → full)

1. **M0** T0 + T1 + normalized `Finding` schema + SBOM → reproducible scan.
2. **M1** T2 passive: OSV/NVD/KEV/EPSS sync + dependency matching + auto-resolve
   of known vulnerable deps. *(Highest value per line of code.)*
3. **M2** T2 active: reachability cache + fix-diff → auto-rule synthesis with
   validation.
4. **M3** T4 triage + calibrated router + conformal thresholds (no LLM yet).
5. **M4** T5 last-line small model (1.5–3B LoRA) on residual cases + evidence
   verification + abstention.
6. **M5** T3 dynamic verifiers (fuzz/sanitizer/symbolic) on gated cases.
7. **M6** feedback loop + T6 human queue + dashboards.

This ordering means **each milestone improves accuracy before any model is
trained**, and the LLM arrives last — exactly matching the inversion.

---

## 9. How this satisfies the project constraints

- **Inference-only, $0–1k:** the expensive tier (T5) is rare and tiny; tiers 0–4
  are CPU and free/cheap.
- **No big base model:** the last-line task is narrow → 1.5–3B suffices.
- **Wide range of tools:** the tool registry feeds T1/T3; the active DB coordinates
  them and turns intel into detectors.
- **Research value:** the cascade itself is a measurable object — auto-resolution
  rate, escalation rate, and verifier trustworthiness are exactly the RewardAudit
  questions, now with a concrete system to measure.
- **Portfolio value:** a real, reproducible, local-first security pipeline that
  demonstrably gets stronger as its database learns.
