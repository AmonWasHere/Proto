# ADR-0002 — Reposition as a measurement-first study of reward/verifier trustworthiness

- **Status:** Proposed (recommended; pending owner confirmation of goal and budget)
- **Date:** 2026-09-24
- **Deciders:** TBD
- **Related:** `docs/novelty-and-related-work.md`, issues E1–E3, B1, B7, D3

## Context

The novelty assessment found the original plan is a synthesis of 2026 work whose
core is already implemented by VulAgentRL (2607.26656) and Antares (2608.02407).
Competing on detection performance is a compute race the project cannot win on
8 GB VRAM. However, three axes are demonstrably under-served:

1. **Adversarial robustness of reward/verifier design** (ALIBI: >90% evasion;
   CoER co-evolution exists for general prompt injection, not code security).
2. **Calibrated abstention and auditable false-negative estimation** (DREA:
   26–55% of true positives have flawed rationales).
3. **Cost-aware, budget-constrained objectives** (cost-per-true-positive).

## Decision

**Reposition the project from "build a vulnerability-finding agent" to "study
whether security-agent rewards can be trusted," and deliver it as a
measurement-first empirical research project with a benchmark.**

- **Headline claim:** verifier design determines whether agentic security
  analysis can be trusted under adaptive adversarial code.
- **Primary axis (N4):** reward-oracle comparison — LLM judge vs. exact
  CPG/evidence match vs. proof-kernel verifier vs. hybrid, under adversarial
  pressure.
- **Measurement instrument (N2):** calibration, selective abstention, auditable
  false-negative estimation, and cost-per-true-positive.
- **Stress test / stretch (N1):** co-evolve an adversarial comment generator
  against the policy; measure robustness gains from adversarial training.
- **Rebrand:** provisional name `TriAgent`; "VulnGym" is taken (2607.24552).

## Rationale

- **It is the only gap that is real, unowned, and hardware-feasible.** It needs
  inference, tooling, and modest RL — not frontier-scale training.
- **It avoids head-on competition** with Antares/VulAgentRL on accuracy.
- **Outcome risk is low:** positive and negative results are both publishable, and
  the benchmark + protocol are sticky contributions.
- **No wasted work:** the existing plan (tools, CPG, sandbox, RL loop, rewards)
  becomes instrumentation for the study.
- **Venue-ready rationale:** the 2608.21107 survey explicitly requests a minimum
  reporting protocol, jointly secure-and-functional benchmarks, and calibrated
  human oversight.

## Consequences

- **Scope shrinks deliberately.** Drop: dynamic fuzzing/symbolic execution as
  core (optional oracle only), multi-language in v1 (start C/C++ and/or Python),
  full patch generation, any from-scratch model training.
- **One headline, three contributions** (C1 benchmark, C2 verifier stress test,
  C3 calibration/FNR). C4 (adversarial co-training) is stretch.
- **Success is measured by evidence quality**, not detection leaderboard rank.
- The human-audit budget, not GPU, becomes the binding constraint.

## Fallbacks

- **If goal is portfolio/employment rather than publication:** build the tool +
  rigorous evaluation as an open, reproducible harness; drop novelty claims.
- **If compute budget < ~$1k:** drop C4 (RL) and run the study with inference-only
  adversarial stress tests plus calibration analysis.

## Alternatives considered

| Alternative | Why not chosen |
|---|---|
| Keep original plan, claim novelty | Unsupported by prior art; would be rejected/rebutted. |
| Compete on detection SOTA | Compute race vs. well-funded labs; unwinnable on this hardware. |
| Pure tools/engineering project | Viable, but no defensible contribution; duplicates OpenAnt. |
| From-scratch model | See ADR-0001; economically infeasible. |
