# RewardAudit

Measuring whether an LLM's security verdict can be trusted under adaptive
adversarial code — built by wrapping the pinned analyzers, corpora, and the
four-way decomposition from the prior `~/Projects/Patch/sastaudit` study.

## M0 scope

- `schema` — `Finding`, `Evidence`, `Verdict`, `Disposition`.
- `analyzers` — a uniform adapter over pinned analyzers (opengrep first).
- `sarif` — SARIF 2.1.0 → `Finding`.
- `cpg` — tree-sitter evidence verification (every LLM claim must resolve to a
  real node).
- `llm` — backend-agnostic `LLMBackend`: `mock` / `openai_compat` (cloud) /
  `local` (ollama, llama.cpp).
- `verifiers` — `tool_verdict` (V2, deterministic) and `llm_judge` (V1).
- `controls` — load the pinned Java control set and compute the detection matrix.

## M0 exit gate

Reproduce the pinned opengrep control result: **12/18 vulnerable detected, 1/3
safe flagged** (`python -m rewardaudit.harness --controls`).

## Run tests

```bash
PYTHONPATH=src python3 -m pytest
```

Integration tests that need the bundled opengrep binary are skipped
automatically when it is absent.
