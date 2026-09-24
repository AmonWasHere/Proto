# Issue Backlog — Research

Stable IDs for the issues identified in the project review of
`docs/rl-vulnerability-analysis-plan.md` and the local environment.
IDs are permanent; do not renumber. State changes should be made in place.

**Legend**

- **Severity:** `Blocker` (stops progress) · `High` · `Medium` · `Low`
- **State:** `open` · `in-progress` · `blocked` · `resolved` · `wontfix` · `deferred`
- **Owner:** `TBD` until assigned
- **Areas:** `repo` · `plan` · `env` · `method` · `product`

**Summary**

| ID | Sev | State | Area | Title |
|---|---|---|---|---|
| A1 | High | open | repo | No LICENSE |
| A2 | High | open | repo | No SECURITY.md |
| A3 | High | open | repo | No CI, tests, or lint/format config |
| A4 | Medium | open | repo | Monolithic design doc; no decision log |
| A5 | Medium | open | repo | Risk register not tracked as issues |
| A6 | Medium | open | repo | Unattributed claims / unverified benchmark availability |
| A7 | Low | open | repo | Thin README; no CONTRIBUTING / templates / CHANGELOG |
| A8 | Low | open | repo | No versioning of design decisions |
| B1 | Blocker | open | plan | Six stakeholder decisions unanswered |
| B2 | Blocker | open | plan | No formal MDP (state/action/transition/horizon) |
| B3 | Blocker | open | plan | Reward weights are placeholders |
| B4 | High | open | plan | PoC/harness synthesis assumed, not solved |
| B5 | High | open | plan | Acceptance gates use undefined `X%`; no baselines |
| B6 | High | open | method | Model-based verifiers are circular / gameable |
| B7 | High | resolved | plan | No compute budget estimate |
| B8 | High | open | plan | Privacy/redaction architecture not concrete |
| B9 | Medium | open | plan | Synthetic injection gym underspecified |
| B10 | Medium | open | plan | Benchmarks named but not validated |
| B11 | Medium | open | plan | Logic/business flaws deferred without verifier design |
| B12 | Medium | open | plan | No per-track success criteria |
| B13 | Medium | open | product | No consumer/persona, integration, SLA, or cost model |
| B14 | Low | open | plan | Non-stationarity / continual-learning strategy vague |
| C1 | Blocker | resolved | env | 8 GB VRAM / 15 GB RAM cannot support the stated plan |
| C2 | High | open | env | Python 3.14; no trl/vllm; dependency risk |
| C3 | High | open | env | No Docker (podman only); no sandbox/microVM |
| C4 | High | open | env | Semgrep / CodeQL / Opengrep not on PATH |
| C5 | Medium | open | env | No Go/Rust toolchains despite multi-language goals |
| C6 | Medium | open | env | Bleeding-edge/EA toolchains (Python 3.14, Java 27-ea, clang 22) |
| C7 | Medium | open | env | Untrusted-code execution on a personal workstation |
| C8 | Low | open | env | Dataset/model/bundle egress availability unknown |
| D1 | High | open | method | Precision and recall only partially measurable |
| D2 | High | open | method | Pretraining contamination cannot be fully eliminated |
| D3 | Medium | deferred | method | RL premise unvalidated and currently unaffordable |
| D4 | Medium | open | method | No threat model for the analyzer itself |
| D5 | Medium | open | method | Reproducibility promised but not implemented |
| D6 | Low | open | method | No external/adversarial review recorded |
| E1 | Blocker | resolved | novelty | Plan is not novel; core overlaps VulAgentRL / Antares |
| E2 | Blocker | resolved | novelty | No single declared research contribution |
| E3 | Medium | resolved | repo | Working name "VulnGym" collides with published work |

**Blocking order (post-ADR-0002):** `B1` → `A1`/`A3`/`A4` → **M0 harness**
→ **M1 verifiers/dataset** → **M2 E1 result**. RL items (B2/B3/D3/E2-RL) are
deferred; the project is inference-only.

---

## A. Repository / project hygiene

### A1 — No LICENSE
- **Severity:** High · **State:** open · **Owner:** TBD
- **Problem:** Repository has no license, so rights to use, modify, and
  redistribute are undefined.
- **Impact:** Blocks safe consumption of third-party code/datasets/benchmarks;
  inconsistent with the project's own license-contamination risk.
- **Resolution:** Add a `LICENSE` (candidate: Apache-2.0 or MIT for code, plus a
  separate data-use note for corpora).
- **Depends on:** B1 (commercial vs open intent).

### A2 — No SECURITY.md
- **Severity:** High · **State:** open · **Owner:** TBD
- **Problem:** No vulnerability-disclosure or handling policy for the analyzer
  itself.
- **Impact:** A security tool with no security policy; no reporting channel.
- **Resolution:** Add `SECURITY.md` with scope, reporting channel, and handling
  SLAs.

### A3 — No CI, tests, or lint/format config
- **Severity:** High · **State:** open · **Owner:** TBD
- **Problem:** Nothing enforces the reproducibility and pinning the plan demands.
- **Impact:** Regressions are undetectable; the plan's own gates can't be
  automated.
- **Resolution:** Add `.github/workflows/ci.yml` (lint, format check, tests,
  docs link check), formatter/linter config, and a `tests/` skeleton.

### A4 — Monolithic design doc; no decision log
- **Severity:** Medium · **State:** open · **Owner:** TBD
- **Problem:** One 31 KB document mixes architecture, rewards, roadmap, and
  risk; no ADRs.
- **Impact:** Hard to review, assign, or update independently.
- **Resolution:** Split into `docs/architecture.md`, `docs/reward-design.md`,
  `docs/roadmap.md`, `docs/evaluation.md`; add `docs/adr/` with numbered ADRs.

### A5 — Risk register not tracked as issues
- **Severity:** Medium · **State:** open · **Owner:** TBD
- **Problem:** Risks live in a markdown table with no IDs, owners, or state.
- **Impact:** Risks can't be assigned, closed, or regression-tested.
- **Resolution:** This backlog becomes the tracker; link each §7 risk row to an
  issue ID and add owner + state + review date.

### A6 — Unattributed claims / unverified benchmark availability
- **Severity:** Medium · **State:** open · **Owner:** TBD
- **Problem:** Tools and benchmarks are named without versions, citations,
  licenses, or verified availability.
- **Impact:** Plan may rely on resources that can't be obtained or legally used.
- **Resolution:** Maintain `docs/references.md` with tool + version + license +
  URL, and a benchmark inventory table with access status. (See B10.)

### A7 — Thin README; no CONTRIBUTING / templates / CHANGELOG
- **Severity:** Low · **State:** open · **Owner:** TBD
- **Problem:** Minimal project scaffolding.
- **Resolution:** Expand README; add `CONTRIBUTING.md`, issue/PR templates,
  `CHANGELOG.md`.

### A8 — No versioning of design decisions
- **Severity:** Low · **State:** open · **Owner:** TBD
- **Problem:** "Draft v2" exists only in prose; v1→v2 delta unrecorded.
- **Resolution:** Tag design milestones (`plan-v1`, `plan-v2`) and record changes
  in ADRs / CHANGELOG.

---

## B. Plan-level substantive gaps

### B1 — Six stakeholder decisions unanswered
- **Severity:** Blocker · **State:** open · **Owner:** TBD
- **Problem:** §9 questions remain open: deployment mode (local vs external LLM),
  primary metric (recall vs cost-per-TP), appetite for dynamic execution,
  mandatory languages, logic-flaw scope, human-review budget.
- **Impact:** Downstream architecture, legal posture, and compute are undefined.
- **Resolution:** Record decisions as ADRs; update plan accordingly.
- **Blocks:** A1, B7, B8, C1, C3, C7, D3.

### B2 — No formal MDP
- **Severity:** Blocker · **State:** open · **Owner:** TBD
- **Problem:** State, action space, transition, horizon, discount, and
  termination are not specified in RL terms.
- **Impact:** GRPO/PPO cannot be implemented from the current spec.
- **Resolution:** Add `docs/rl-formalism.md` with a written MDP definition, action
  schema (typed), observation schema, episode/budget definition, and termination
  conditions.

### B3 — Reward weights are placeholders
- **Severity:** Blocker · **State:** open · **Owner:** TBD
- **Problem:** `w_v, w_c, w_s, w_n, w_e, w_p, w_h` and `α, β, γ_w, δ` have no
  values, ranges, or normalization derivation.
- **Impact:** Reward is unimplementable and untunable.
- **Resolution:** Produce a reward-constants worksheet: value, range, rationale,
  sensitivity plan; specify per-group normalization and clipping.

### B4 — PoC/harness synthesis assumed, not solved
- **Severity:** High · **State:** open · **Owner:** TBD
- **Problem:** Independent verification is the load-bearing reward source, but
  automatic PoC/harness generation is an open research problem treated as given.
- **Impact:** If verification fails, the RL loop collapses to weak proxies.
- **Resolution:** Spike a harness/PoC generator on 5–10 known CVEs; document
  success rate and fallback verifiers. Add explicit manual-verification path.

### B5 — Acceptance gates use undefined X%; no baselines
- **Severity:** High · **State:** open · **Owner:** TBD
- **Problem:** Every gate has an unspecified threshold; no baseline numbers.
- **Impact:** No go/no-go is decidable.
- **Resolution:** After Phase 1/2, populate baselines and concrete thresholds;
  add statistical power/sample-size notes.

### B6 — Model-based verifiers are circular / gameable
- **Severity:** High · **State:** open · **Owner:** TBD
- **Problem:** Class, severity, and evidence-quality rewards are model-judged,
  so an LLM policy can exploit an LLM verifier.
- **Impact:** Reward hacking that survives deterministic-verifier checks.
- **Resolution:** Prefer deterministic verifiers for the dominant weight; use
  cross-family models for judges; add judge-swap and canary audits; cap
  model-judged reward contribution until calibrated.

### B7 — No compute budget estimate
- **Severity:** High · **State:** resolved · **Owner:** TBD
- **Problem:** No GPU-hours, token spend, or sandbox-minute estimate.
- **Impact:** The ablation gate (RL vs SFT) is undecidable; costs can explode.
- **Resolution:** Budget fixed at **$0–$1k, inference-only** (ADR-0002). Phase and
  scenario estimates in `docs/compute-and-model-strategy.md`.

### B8 — Privacy/redaction architecture not concrete
- **Severity:** High · **State:** open · **Owner:** TBD
- **Problem:** External-call boundary and redaction algorithm unspecified.
- **Impact:** Legal/privacy exposure for proprietary code.
- **Resolution:** Data-flow diagram, redaction spec, local-only default, audit
  trail; decide via B1.

### B9 — Synthetic injection gym underspecified
- **Severity:** Medium · **State:** open · **Owner:** TBD
- **Problem:** Label fidelity, subtlety control, and realism unproven.
- **Impact:** Core training asset may produce distribution-mismatched policies.
- **Resolution:** Design doc for injection categories, mutation operators,
  difficulty tiers, and a held-out realism audit.

### B10 — Benchmarks named but not validated
- **Severity:** Medium · **State:** open · **Owner:** TBD
- **Problem:** Availability, licensing, contamination status, label granularity
  unchecked.
- **Impact:** Eval may be unusable or invalid.
- **Resolution:** Benchmark inventory + acquisition test; record license and
  checksum. (Pairs with A6.)

### B11 — Logic/business flaws deferred without verifier design
- **Severity:** Medium · **State:** open · **Owner:** TBD
- **Problem:** In scope but no verifier; relies on human-in-the-loop.
- **Impact:** A whole declared track has no automation path.
- **Resolution:** Define spec-based/differential verifier design or formally
  scope out of v1 (B1).
- **Depends on:** B1.

### B12 — No per-track success criteria
- **Severity:** Medium · **State:** open · **Owner:** TBD
- **Problem:** "Categorize" and "analyze" both claimed; tracks lack metrics.
- **Resolution:** Metric + threshold per track (memory safety, injection,
  auth/crypto, supply chain, correctness, maintainability).

### B13 — No consumer/persona, integration, SLA, or cost model
- **Severity:** Medium · **State:** open · **Owner:** TBD
- **Problem:** Output format chosen without a validated consumer; no CI/IDE
  integration, latency target, or $ per scan.
- **Resolution:** Persona + workflow doc; integration spike (SARIF → CI/PR);
  define latency and cost targets.

### B14 — Non-stationarity / continual-learning strategy vague
- **Severity:** Low · **State:** open · **Owner:** TBD
- **Problem:** Drift monitors specified only in one line.
- **Resolution:** Specify drift metrics, retraining triggers, and rollback.

---

## C. Feasibility vs. this machine

Measured 2026-09-24: Fedora 44, RTX 3070 Ti Laptop (8192 MiB), 15 GiB RAM
(~11 GiB used), Python 3.14.7, Node 22.23.1, podman 5.8.7, clang 22.1.8,
OpenJDK 27-ea, torch/transformers/datasets/tree_sitter present, `trl`/`vllm`
absent, `docker`/`semgrep`/`codeql`/`opengrep`/`go`/`cargo` not on PATH.

### C1 — 8 GB VRAM / 15 GB RAM cannot support the stated plan
- **Severity:** Blocker · **State:** resolved · **Owner:** TBD
- **Problem:** No headroom to fine-tune or serve a competitive tool-using LLM
  locally; RL rollout workers infeasible at scale here.
- **Resolution:** Architecture is **inference-only**: local 7B Q4 + CPU tooling,
  optional modest API. No training. See ADR-0002 and
  `docs/compute-and-model-strategy.md` §4 (verdict table).

### C2 — Python 3.14; no trl/vllm; dependency risk
- **Severity:** High · **State:** open · **Owner:** TBD
- **Problem:** Bleeding-edge Python; RL training libraries absent/incompatible.
- **Resolution:** Use a pinned toolchain (e.g., Python 3.11 via `uv`/venv);
  lock dependencies; document setup.

### C3 — No Docker (podman only); no sandbox/microVM
- **Severity:** High · **State:** open · **Owner:** TBD
- **Problem:** Plan assumes Dockerized environments and gVisor/microVM isolation;
  neither exists.
- **Resolution:** Decide podman vs. dedicated isolated host; document sandbox
  build; add `Containerfile`. MicroVM on a laptop is a project — consider a
  separate bare-metal/VM worker.
- **Depends on:** B1, C7.

### C4 — Semgrep / CodeQL / Opengrep not on PATH
- **Severity:** High · **State:** open · **Owner:** TBD
- **Problem:** Only `~/.semgrep/settings.yml` and `~/.codeql/packages` residue
  exist; no CLIs.
- **Impact:** Phase 0/1 assume a tool ensemble that isn't installed.
- **Resolution:** Tool installer + version pinning + `tools.lock`; smoke-test each
  tool on a fixture repo.

### C5 — No Go/Rust toolchains despite multi-language goals
- **Severity:** Medium · **State:** open · **Owner:** TBD
- **Problem:** `gosec`, `cargo-audit` targets can't run.
- **Resolution:** Install or explicitly scope languages for v1 (B1).

### C6 — Bleeding-edge/EA toolchains
- **Severity:** Medium · **State:** open · **Owner:** TBD
- **Problem:** Python 3.14, Java 27-ea, clang 22 will break many analysis tools.
- **Resolution:** Per-tool pinned container; avoid host toolchains for analysis.

### C7 — Untrusted-code execution on a personal workstation
- **Severity:** Medium · **State:** open · **Owner:** TBD
- **Problem:** Plan executes vulnerable code; host has SSH/GPG keys, VPN,
  personal data; no isolation.
- **Impact:** Real risk of host compromise.
- **Resolution:** Mandate isolated VM/dedicated box, no-host-exec policy, and
  egress allowlist before any dynamic track.

### C8 — Dataset/model/bundle egress availability unknown
- **Severity:** Low · **State:** open · **Owner:** TBD
- **Problem:** Network access for datasets, model weights, and CodeQL bundles
  unverified.
- **Resolution:** Egress test + offline mirror plan.

---

## D. Methodological / scientific

### D1 — Precision and recall only partially measurable
- **Severity:** High · **State:** open · **Owner:** TBD
- **Problem:** Unknown unknowns; FNR mentioned but no instrument.
- **Impact:** Optimizing an unmeasurable objective invites gaming.
- **Resolution:** Design a false-negative estimation method (e.g., injection
  recovery tests, blinded audit sampling); add confidence intervals.

### D2 — Pretraining contamination cannot be fully eliminated
- **Severity:** High · **State:** open · **Owner:** TBD
- **Problem:** Temporal/private holdouts reduce but don't remove leakage.
- **Resolution:** Add sensitivity analysis and a contamination audit; treat
  contaminated-benchmark gains as suspect.

### D3 — RL premise unvalidated and currently unaffordable
- **Severity:** Medium · **State:** deferred · **Owner:** TBD
- **Problem:** The ablation gate is correct but undecidable on this hardware.
- **Resolution:** **Out of scope** under the inference-only budget (ADR-0002).
  E1b approximates RL reward hacking without training; real RL is future work.

### D4 — No threat model for the analyzer itself
- **Severity:** Medium · **State:** open · **Owner:** TBD
- **Problem:** Prompt injection and supply-chain attacks are risk rows, not a
  threat model.
- **Resolution:** Write `docs/threat-model.md` (assets, actors, trust boundaries,
  abuse cases) covering the analyzer and its tool fleet.

### D5 — Reproducibility promised but not implemented
- **Severity:** Medium · **State:** open · **Owner:** TBD
- **Problem:** Seeds, pinned digests, and run manifests absent.
- **Resolution:** Implement run-manifest format + seeded runners + pinned image
  digests; wire into CI (A3).

### D6 — No external/adversarial review recorded
- **Severity:** Low · **State:** open · **Owner:** TBD
- **Problem:** The "cross-validation" was self-authored.
- **Resolution:** Seek external review (security researcher / ML reviewer);
  record findings as new issues.

---

## E. Novelty & positioning

### E1 — Plan is not novel; core overlaps published work
- **Severity:** Blocker · **State:** resolved · **Owner:** TBD
- **Problem:** Agentic RL from verifiable rewards on a CPG is already implemented
  by **VulAgentRL** (arXiv:2607.26656); small-model SFT+RLVR is **Antares**
  (2608.02407); verification-first pipelines are **OpenAnt** (2606.19149) and
  **FuzzingBrain V2** (2605.21779); evidence + two-stage SFT/RL is **EAVA**
  (2608.25905).
- **Resolution:** Repositioned to a measurement study on reward/verifier
  trustworthiness (ADR-0002); pipeline novelty claims dropped. See
  `docs/novelty-and-related-work.md`.
- **Depends on:** B1.

### E2 — No single declared research contribution
- **Severity:** Blocker · **State:** resolved · **Owner:** TBD
- **Problem:** The plan targets seven layers at once with no headline claim.
- **Resolution:** Headline chosen in ADR-0002 — verifier design determines
  trustworthiness under adversarial code (N4), instrumented by calibration/FNR
  (N2). Deliverable: RewardAudit harness + benchmark. See
  `docs/research-proposal.md`.

### E3 — Working name "VulnGym" collides
- **Severity:** Medium · **State:** resolved · **Owner:** TBD
- **Problem:** "VulnGym" is a published RL vulnerability-management simulator
  (arXiv:2607.24552).
- **Resolution:** Renamed. Study/artifact name is **RewardAudit**; plan header
  uses provisional **TriAgent**. Rename complete.

---

## Change log

| Date | Change |
|---|---|
| 2026-09-24 | Initial backlog created from project review; IDs A1–D6 assigned. |
| 2026-09-24 | B7, C1, D3 moved to in-progress; compute/model strategy added. |
| 2026-09-24 | ADR-0001: pre-existing LLM + LoRA/QLoRA adaptation; no pretraining from scratch. |
| 2026-09-24 | Added novelty assessment; issues E1–E3 (novelty/positioning) opened. |
| 2026-09-24 | ADR-0002 (proposed) + research proposal: RewardAudit measurement study. |
| 2026-09-24 | ADR-0002 **accepted**: goal = research + portfolio, budget $0–$1k inference-only, no RL. B7/C1/E1/E2/E3 resolved; D3 deferred. |
| 2026-09-24 | GCP RL contingency cost estimate added (Tier A ~$0.4k spot, Tier B ~$3.3k spot). |
| 2026-09-24 | GCP estimate revised with fetched prices: Tier A ~$0.45k, Tier B ~$3.7k, Tier C ~$11k (spot). |
| 2026-09-24 | Compute-reduction guide added (free 2–4×, structural 10–100×). |
| 2026-09-24 | LastLine architecture proposed (tool-first, active DB, small LLM last). |
