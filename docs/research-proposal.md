# Research Proposal — RewardAudit: Can Security-Agent Rewards Be Trusted?

Draft v0.1 · 2026-09-24 · companion to ADR-0002 and
`docs/novelty-and-related-work.md`

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
- **C4 — Adversarial co-training (stretch, RQ2).** VulAgentRL/Antares-style
  policy co-evolved against the attacker; measures robustness gained vs. policy
  collapse.

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

- **E1 — Verifier evasion (RQ1, cheap).** Attack each verifier with the ALIBI-style
  generator on a fixed repo set. Inference-only. Primary result.
- **E2 — Reward hacking under RL (RQ2).** Train one 3–8B policy per verifier with
  GRPO; measure reward-hack rate and canary-trap false positives.
- **E3 — Calibration & FNR (RQ3).** Selective-prediction curves; compare FNR
  estimates to injection-recovery ground truth.
- **E4 — Cost Pareto (RQ4).** Precision vs. cost-per-TP, with and without
  adversarial training.

## 6. Baselines & infrastructure reuse

- Baselines: static ensemble (Semgrep/CodeQL), prompted agent (no RL), Antares-style
  RLVR, VulAgentRL-style exact-match verifier, V1–V5 above.
- Existing plan components become instrumentation: tool registry, CPG, sandbox,
  finding ledger, reward red-teaming, canary repos, run manifests.

## 7. Feasibility & compute

- **E1/E3/E4:** inference + tooling + human audit. A few hundred GPU-hours or API
  budget; laptop-feasible with API, better with one rented GPU.
- **E2/C4:** one modest GRPO run (3–8B, short horizons), ~$1–5k on spot A100s.
- **Binding constraint:** blinded human audit budget, not GPU.
- Overall: **~$2–6k**, 3–6 months part-time. See
  `docs/compute-and-model-strategy.md` §6.

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

1. Confirm go/no-go and the goal (publication vs. portfolio) — see open question.
2. Freeze verifier taxonomy V1–V5 and the metric set (C2/C3).
3. Implement E1 (verifier evasion) — inference-only, no RL, fastest signal.
4. Only if E1 shows verifier-dependent evasion, build E2 (RL) and C4.
