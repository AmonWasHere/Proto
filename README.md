# Research

Research and design work for an **evidence-first security adjudicator** and the
**RewardAudit** benchmark: measuring when deterministic verifiers make an LLM's
security verdict trustworthy.

## Start here

- **[`docs/REPORT.md`](docs/REPORT.md)** — consolidated findings report (draft,
  P6). The results.
- **[`docs/COST.md`](docs/COST.md)** — measured cost and optimizations (thinking
  mode, verdict cache).
- **[`docs/PLAN.md`](docs/PLAN.md)** — the plan and remaining phases.
  - [`docs/tools.md`](docs/tools.md) — language coverage and analyzer inventory.
- **[`rewardaudit/`](rewardaudit/)** — the working harness **and a local web app**
  (`./scripts/rewardaudit-app`, or the `rewardaudit.desktop` entry) so users need
  no command line.

## Everything else (background)

- [`docs/rl-vulnerability-analysis-plan.md`](docs/rl-vulnerability-analysis-plan.md) —
  original broad plan (superseded as a spine; kept for context).
- [`docs/research-proposal.md`](docs/research-proposal.md) — RewardAudit proposal.
- [`docs/novelty-and-related-work.md`](docs/novelty-and-related-work.md) — prior art.
- [`docs/compute-and-model-strategy.md`](docs/compute-and-model-strategy.md),
  [`docs/gcp-rl-cost-estimate.md`](docs/gcp-rl-cost-estimate.md),
  [`docs/compute-reduction.md`](docs/compute-reduction.md) — cost/efficiency.
- [`docs/architecture-lastline.md`](docs/architecture-lastline.md) — rejected
  alternative, with critique.
- [`docs/issues.md`](docs/issues.md) — tracked backlog.
- [`docs/adr/`](docs/adr/) — decisions.
  - [ADR-0001](docs/adr/0001-model-strategy-preexisting-llm.md) — adapt a
    pre-existing LLM; never pretrain from scratch.
  - [ADR-0002](docs/adr/0002-reposition-measurement-first.md) — measurement-first,
    inference-only.
  - [ADR-0003](docs/adr/0003-hybrid-knowledge-store.md) — hybrid knowledge store:
    pinned public feed + active own findings.

## Status

**M0–M2 complete, including the first real E1 run** (see
[`docs/e1-results.md`](docs/e1-results.md)): across three verifiers on identical
input, flip rate 80–100% and canary false positives 0/3–1/3 — verifier-dependence
confirmed on a small sample. 59 tests green.

Reproduce the offline pipeline:

```bash
cd rewardaudit
PYTHONPATH=src python3 -m pytest
PYTHONPATH=src python3 -m rewardaudit.harness controls
PYTHONPATH=src python3 -m rewardaudit.harness pairs
PYTHONPATH=src python3 -m rewardaudit.harness e1    --backend scripted
PYTHONPATH=src python3 -m rewardaudit.harness evade --backend scripted
```

Real runs use `--backend local` (ollama/LM Studio) or `--backend cloud`
(`REWARDAUDIT_LLM_BASE_URL/MODEL/API_KEY`). Next: scale E1 to the JavaVFC
real-fix corpus (784 pinned commits).

## Status (design)

Design + planning. Next action: **M0** (finding schema, one scanner, two
verifiers, ten CVEs, a canary repo) → **M2 (E1)**.
