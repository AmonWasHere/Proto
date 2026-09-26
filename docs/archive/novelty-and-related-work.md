# Novelty Assessment & Related Work

Answers the question: **"What is new here vs. existing work?"**
Assessed 2026-09-24 against arXiv (cs.CR / cs.SE / cs.LG, through Sep 2026).

> **Bottom line:** as currently written, the plan is **not novel**. It is an
> engineering synthesis of components that were independently published in 2026 —
> and two papers already implement its central idea (agentic RL from verifiable
> rewards on a Code Property Graph). Novelty must be re-earned by picking a
> sharp, under-served axis. The most defensible one is **adversarial robustness
> of the reward/verifier and calibrated abstention** — the literature's weakest
> spot, not the strongest.

---

## 1. Prior art map (our claim → who already did it)

| Plan claim | Closest prior art | Status |
|---|---|---|
| Tool-using LLM agent for repo-scale vuln discovery | **OpenAnt** (2606.19149): decomposition + adversarial verification + sandboxed dynamic validation; found real bugs in OpenSSL/WordPress. **FuzzingBrain V2** (2605.21779): multi-agent + OSS-Fuzz + MCP tools; 29 zero-days. **DREA** (2607.13439): reasoning/exploration agents, 16–48× cost cut. | **Done** |
| Multi-agent orchestration (planner/investigator/verifier) | **CLEAR** (2608.03134): 4 agents + causal knowledge graph. **ATLANTIS** (2509.14589, AIxCC winner): LLM + symbolic execution + directed fuzzing. | **Done** |
| **Agentic RL from verifiable rewards for vulnerability detection** | **VulAgentRL** (2607.26656): *"Graph Is the Verifier"* — CPG is queried at inference **and verifies cited evidence at training via exact node IDs**; distillation warm start because RL can't discover tool use it never samples; repo-level split. **Antares** (2608.02407): SFT + RLVR over vulnerable repos; 350M/1B/3B; beats 200× larger open models; <$0.002/task. | **Done (this is our core)** |
| SFT → RL training pipeline with evidence/explanations | **EAVA** (2608.25905, ISSTA'26): two-stage SFT then RL for reasoning; retrieval of historical vulns as evidence; expert user study. | **Done** |
| CPG / taint / dataflow as the analysis substrate | VulAgentRL, ATLANTIS, CodeQL query synthesis (2609.10412), SETYPE (2608.14533). | **Done** |
| Cheap small-model deployment | **Antares**: 3B on one H100, 500-task sweep in ~15 min, <$0.002/task. | **Done — our cost angle is weaker than assumed** |
| Synthetic vulnerability injection for training | Smart-contract injection (2609.02624); LLMVul dataset (2609.10945). | **Done** |
| Evidence-linked explanations, severity/classification | EAVA; "Answer is cheap, show me the evidence." | **Done** |
| Abstention / fabrication penalty in RL agents | **AWA-RL** (2607.10738): abstention-aware RL, RA-F1 metric — but open-domain QA, **not security**. | Adjacent, gap |
| Adversarial comments defeat LLM vuln detectors | **ALIBI** (2607.24964): >90% attack success on 5 systems; prompt defenses weak, architectural isolation helps. | Threat **demonstrated**, defense open |
| Separating interpretation from verdict | **LeanGuard** (2607.03963): LLM only filters facts; a Lean 4 kernel discharges safety obligations. | Principle established |
| Validity threats, budget/human-intervention reporting | Survey (2608.21107): weak oracles, temporal leakage, proxy checks, under-reported budgets. | **Named as open** |
| Reward hacking / gaming in security RL | *No security-specific treatment found.* VulAgentRL solves one instance via exact-match CPG verification. | **Open** |

---

## 2. Direct duplications that must be acknowledged

1. **VulAgentRL already is "our" thesis.** Agentic RL, CPG as both tool and
   verifier, evidence-grounded reward, distillation warm start, leak-free split.
   Any claim of novelty for §2.6/§2.7 must be dropped or sharply differentiated.
2. **Antares already is "our" compute story.** Small model + SFT + RLVR + cheap
   local inference, with better numbers than our estimates. The
   "affordable RL security agent" framing is taken.
3. **OpenAnt / FuzzingBrain already are "our" verification-first pipeline.**
   Dynamic verification in sandboxes is productized.
4. **EAVA already is "our" evidence + two-stage SFT/RL design.**
5. **AWA-RL already is "our" abstention idea** — but in QA, leaving the security
   transfer open.

**Implication:** the project needs a contribution that is *not* the pipeline, the
tools, the CPG, or generic RLVR. Those are 2026 table stakes.

---

## 3. Where the literature is genuinely weak (candidate novelties)

Ranked by defensibility and fit with existing effort.

### N1. Adversarial robustness of the reward/verifier (strongest)
- **Gap:** ALIBI shows >90% evasion via adversarial code comments; prompt
  defenses fail. CoER (2609.07529) co-evolves attacker/defender for *general*
  indirect prompt injection, but **nobody has co-evolved an adversarial
  comment-writer against a vulnerability-detection RL policy with verified
  rewards**, nor measured the resulting robustness.
- **Contribution:** an adversarially-trained, verifier-grounded security policy,
  plus a **reward-hacking/evasion benchmark** and a canary-trap methodology.
- **Why defensible:** it is a *method* and a *measurement*, not a pipeline
  recombination; it directly addresses the field's demonstrated blind spot.
- **Novel artifact:** "evasion-vs-reward" curves, canary repos, held-out verifier
  rotation, reward-hack regression suite.

### N2. Calibrated abstention + false-negative estimation for security agents
- **Gap:** AWA-RL does abstention in QA; DREA shows **26–55% of true positives
  have flawed rationales**; the survey flags proxy-only oracles and unmeasured
  false negatives. No security agent optimizes *selective risk* or reports an
  auditable FNR estimate.
- **Contribution:** risk-calibrated policy with a learned abstention threshold,
  a **FNR estimator** (injection recovery + blinded sampling), and the
  **cost-per-true-positive** objective formalized as first-class.
- **Why defensible:** measurement contribution the survey explicitly asks for.

### N3. Budget-constrained RL with cost in the reward
- **Gap:** DREA reports cost savings *post hoc*; no work trains the policy with
  tool/token cost **inside** the reward under a hard budget.
- **Contribution:** formal constrained-MDP (budget as constraint), cost-aware
  advantage, and a Pareto front of precision vs. cost-per-TP.
- **Why defensible:** clean RL formulation; measurable.

### N4. Neuro-symbolic verifier as the reward oracle, composed with RL
- **Gap:** LeanGuard establishes "the interpreter must not discharge the
  obligation"; nobody has wired a proof kernel as the RL **reward oracle** and
  measured whether it resists reward hacking better than LLM judges.
- **Contribution:** reward-oracle comparison study (LLM judge vs. exact-match CPG
  vs. SMT/proof kernel) under adversarial pressure.
- **Why defensible:** directly tests the reward-trust problem; strong result
  regardless of sign.

### N5. Cross-language continual adaptation with drift
- **Gap:** FA-LoRA (2608.19680) does continual adaptation for smart contracts;
  not extended to multi-language repos with distribution drift.
- **Contribution:** continual/streaming adaptation benchmark for security agents.

### N6. Reproducibility + honest reporting protocol
- **Gap:** survey (2608.21107) explicitly asks for a minimum reporting protocol
  and jointly secure-and-functional benchmarks.
- **Contribution:** reproducible harness, fixed budgets, human-intervention
  logging, FNR-reported results. Useful, but weaker as "new science."

---

## 4. Recommended repositioning

**From:** "an RL agent with many tools to find vulnerabilities" (done, 2026).

**To:** **"Adversarially robust, risk-calibrated security agents: can we trust
the reward?"**

Proposed thesis statement:
> Existing agentic vulnerability detectors and RL-trained policies are evaluated
> without an adversary and without calibrated abstention, even though a single
> adversarial comment defeats >90% of them. We introduce (a) a co-evolving
> adversarial code/comment generator, (b) reward verifiers grounded in exact
> program-graph evidence and proof kernels instead of LLM judges, and (c) a
> calibrated, budget-aware policy that abstains and reports an auditable
> false-negative estimate — and we show which verifier designs survive
> adversarial optimization.

This reuses the plan's infrastructure (tools, CPG, sandbox, RL loop) but aims at
the part that is actually unsolved. It also reframes Phases 0–2 as *instrumentation*
for a measurement study rather than the product.

**Fallback if N1 underdelivers:** N2 (calibration + FNR + cost-per-TP) is a
self-contained measurement contribution and is lower-risk.

---

## 5. Naming collision

Our plan's working name **"VulnGym"** collides with **VulnGym** (2607.24552), a
published RL vulnerability-management simulation. The plan header has been
changed to provisional **TriAgent**; a unique name must be chosen before any
publication.

---

## 6. Open decisions this raises

1. Is the goal a **research contribution** (needs N1–N4) or a **product/portfolio
   project** (synthesis is fine, but novelty claims must be dropped)?
2. Which single axis is the headline: adversarial robustness, calibration, or
   reward-oracle design?
3. Are we willing to change scope away from "find vulnerabilities" toward
   "measure whether security agents can be trusted"? This is a smaller, sharper,
   and more publishable claim.

---

## 7. References (arXiv, 2026 unless noted)

- **VulAgentRL** — *Graph Is the Verifier: Agentic RL for Interprocedural
  Vulnerability Detection*, 2607.26656
- **Antares** — *Foundation Models for Agentic Vulnerability Localization*,
  2608.02407
- **EAVA** — *Answer Is Cheap, Show Me the Evidence!*, 2608.25905 (ISSTA'26)
- **OpenAnt** — *LLM-Powered Vulnerability Discovery Through Code
  Decomposition, Adversarial Verification, and Dynamic Testing*, 2606.19149
- **FuzzingBrain V2** — *Multi-Agent LLM System for Automated Vulnerability
  Discovery and Reproduction*, 2605.21779
- **DREA** — *Decoupled Reasoning and Exploration Agents for Repository-Level
  Vulnerability Detection*, 2607.13439 (Internetware'26)
- **CLEAR** — *Causal Context-Based Agentic Reasoning for Vulnerability
  Detection*, 2608.03134
- **ATLANTIS** — *AI-driven Threat Localization, Analysis, and Triage
  Intelligence System*, 2509.14589 (AIxCC winner, 2025)
- **AWA-RL** — *To Answer or to Abstain: Mitigating Search-Agent Hallucinations
  via Abstention-Aware RL*, 2607.10738
- **ALIBI** — *Adaptive Agentic Attacks on LLM-Based Vulnerability Detectors via
  Adversarial Code Comments*, 2607.24964
- **LeanGuard** — *Neuro-Symbolic Reasoning for Vulnerability Detection*,
  2607.03963
- **CoER** — *Defending against Adaptive Indirect Prompt Injection via
  Adversarial Co-Evolution and Refinement*, 2609.07529
- **LLM CodeQL query generation** — 2609.10412
- **Survey** — *LLMs at the Intersection of Software Engineering and Software
  Security* (research agenda, minimum reporting protocol), 2608.21107
- **Smart-contract vuln injection** — 2609.02624
- **LLMVul dataset** — 2609.10945
- **FA-LoRA continual learning** — 2608.19680
- **VulnGym** (name collision) — 2607.24552
