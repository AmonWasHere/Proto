# Research Proposal — RewardAudit: Can Security-Agent Rewards Be Trusted?

Draft v0.2 · 2026-09-24 · companion to ADR-0002 and
`docs/novelty-and-related-work.md`

**Scope decision (ADR-0002):** inference-only, budget $0–$1k. The deliverable is
the RewardAudit **harness + benchmark + measurement**, not a trained policy. RL
experiments (E2, C4) are future work.

## 1. Problem

Agentic vulnerability discovery has converged on a standard recipe: an LLM
policy queries tools and a Code Property Graph, and is trained with
reinforcement learning from **verifiable rewards** (VulAgentRL 2607.26656,
Antares 2608.02407, EAVA 2608.25905). The recipes differ in tooling, not in how
the reward is trusted. Meanwhile:

- **ALIBI** (2607.24964) shows a single adversarial source comment defeats >90%
  of LLM vulnerability detectors, and prompt-level defenses do not help.
- **DREA** (2607.13439) finds 26–55% of *correct* findings rest on flawed
  rationales.
- The 2608.21107 survey names proxy-only oracles, unmeasured false negatives, and
  unreported budgets/human intervention as pervasive validity threats.

**No work asks whether the reward/verifier itself survives optimization.** RL
makes this acute: a policy trained against a gameable verifier will find the
game before it finds vulnerabilities.

## 2. Research questions

- **RQ1 (verifier robustness):** under adaptive adversarial code, how do
  reward-oracle designs compare — LLM judge, exact CPG/evidence match,
  proof-kernel verifier, hybrid?
- **RQ2 (reward hacking under RL):** does an RL policy learn to exploit verifier
  weaknesses, and at what rate? Which designs resist?
- **RQ3 (calibration & FNR):** can a security agent be made to abstain when
  uncertain and report an auditable false-negative estimate?
- **RQ4 (cost):** what is the precision / cost-per-true-positive Pareto front,
  and does adversarial training move it?

## 3. Contributions

- **C1 — RewardAudit benchmark & harness.** Canary/trap repositories, a
  co-evolving adversarial comment/code generator, verifier-rotation plumbing,
  fixed budgets, human-intervention logging, and an FNR-estimation protocol.
- **C2 — Verifier stress study (RQ1).** Systematic comparison of oracle designs
  under attack; reports evasion success rate and reward-hack rate.
- **C3 — Calibration & FNR instrumentation (RQ3, RQ4).** Selective-prediction
  curves, calibrated abstention, auditable FNR, cost-per-TP.
- **C4 — Adversarial co-training (future work, needs RL).** Out of scope under
  the inference-only budget; recorded as the natural extension.

## 4. Method

**Verifier taxonomy (the independent variable).**

| ID | Verifier | Signal | Gaming surface |
|---|---|---|---|
| V1 | LLM judge | textual rationale | high (comments, fabricated evidence) |
| V2 | Exact CPG/evidence match | cited node IDs match graph | low, but only for graph-expressible claims |
| V3 | Proof-kernel / SMT (LeanGuard-style) | discharging an obligation | lowest, narrow coverage |
| V4 | Dynamic oracle (test/PoC/sanitizer) | reproduced effect | low, expensive |
| V5 | Hybrid (V2/V3 gate + V4 confirmation) | composed | — |

**Attacker.** Extends ALIBI: a coding agent that introduces a vulnerability and
inserts adversarial comments; iteratively refines using detector feedback.
For C4, co-evolve (CoER-style) against the policy population.

**Policy.** Pre-existing 3–8B code model + LoRA (ADR-0001). Warm start by
distilling teacher investigations, then GRPO against each verifier in turn.
Rationale for warm start is established (VulAgentRL: RL cannot sample tool use
it has never seen).

**Metrics.** Evasion success rate; reward-hack rate (reward ↑ while blinded
human audit ↓); calibrated abstention (risk–coverage); auditable FNR estimate vs.
injection-recovery ground truth; cost-per-true-positive; tool calls per finding.

## 5. Experiments

- **E1 — Verifier evasion (RQ1, cheap, PRIMARY).** Attack each verifier with the
  ALIBI-style generator on a fixed repo set. **Inference-only — no RL.** This is
  the headline experiment and the first thing to build.
- **E1b — Reward hacking without RL (RQ2, proxy).** Instead of training a policy,
  score candidate findings with each verifier and let the attacker optimize
  **directly against the verifier score** (a gradient-free / LLM-driven attack).
  This approximates what RL would exploit, at inference cost. (E2 with real RL is
  future work.)
- **E3 — Calibration & FNR (RQ3).** Selective-prediction curves; compare FNR
  estimates to injection-recovery ground truth.
- **E4 — Cost Pareto (RQ4).** Precision vs. cost-per-TP across verifiers and
  attacker strengths.
- **E2 — Reward hacking under RL (future work, out of scope).** Train one 3–8B
  policy per verifier with GRPO; requires RL compute.

## 6. Baselines & infrastructure reuse

- Baselines: static ensemble (Semgrep/CodeQL), prompted agent (no RL), Antares-style
  RLVR, VulAgentRL-style exact-match verifier, V1–V5 above.
- Existing plan components become instrumentation: tool registry, CPG, sandbox,
  finding ledger, reward red-teaming, canary repos, run manifests.

## 7. Feasibility & compute

- **E1/E1b/E3/E4:** inference + tooling + human audit. Fits the **$0–$1k**
  budget: a local 7B Q4 model and/or a modest API allowance, plus CPU tooling.
  No GPU rental required; one cheap GPU-week optional for throughput.
- **E2/C4:** out of scope (needs RL).
- **Binding constraint:** blinded human-audit budget, not GPU.
- Overall: **$0–$1k**, 2–4 months part-time.

## 8. Threats to validity

- Adversarial generator may not represent real attackers → include human-written
  attacks and report generator strength.
- Canary repos are synthetic → pair with real CVE-fix repos.
- RL reward-hack rate may not transfer to production → report per-verifier, not
  aggregate.
- Small models may under-represent frontier behavior → include one API model as a
  ceiling.
- Contamination → temporal/private splits (see D2), canaries.

## 9. Related work (positioning)

- **Closest:** VulAgentRL (exact-match CPG verifier — we stress-test it),
  ALIBI (attacks detectors — we attack *verifiers* and *RL rewards*),
  CoER (co-evolution for prompt injection — we apply it to code security),
  AWA-RL (abstention in QA — we build the security version), EAVA (two-stage
  SFT/RL — we audit its reward source).
- We do **not** claim novelty for the agent, the tools, the CPG, or RLVR itself.

## 10. Deliverables & venues

- Artifacts: RewardAudit harness + benchmark (open), verifier implementations,
  attack generator, calibration toolkit, reporting protocol.
- Target: IEEE S&P / USENIX Security / CCS / NDSS; SE framing ICSE/FSE/ISSTA;
  early feedback at a NeurIPS/ICML safety workshop.

## 11. Immediate next steps

1. **Scaffold the RewardAudit harness** (`rewardaudit/`): repo/ground-truth loader,
   verifier interface + V1/V2/V5, finding schema, run harness, report writer.
2. **Build the E1 dataset:** ~20 known-CVE snippets + ~10 canary/trap repos +
   synthetic injection set with exact labels.
3. **Implement the ALIBI-style adversarial comment generator** (template +
   LLM-optional) and the verifier-optimization attack for E1b.
4. **Run E1** (verifier evasion) and publish the first result plus the harness.
5. Only then: E3 (calibration/FNR) and E4 (cost Pareto).

## 12. Milestones

| M | Deliverable | Gate |
|---|---|---|
| M0 | Harness + finding/verifier schemas + canary repos | `pytest` green; deterministic run manifest |
| M1 | V1/V2/V5 verifiers + E1 dataset | verifiers reproduce known labels on clean code |
| M2 | Adversarial generator + E1 results | evasion ASR differs across verifiers (or null result recorded) |
| M3 | E1b verifier-score optimization | shows RL-free reward-hack proxy |
| M4 | E3 calibration/FNR + E4 cost Pareto | selective-risk + FNR report |
| M5 | Paper draft + open artifact release | reproducible from README |
