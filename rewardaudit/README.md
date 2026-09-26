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

## Whole-codebase graph (MVP)

Analysis treats the **system** as the unit, not the file:

- `languages.py` — registry + **coverage report**. Every language is
  `covered` / `find_only` / `ground_only` / `unsupported`; files whose language has
  no ruleset are reported as **unchecked, never clean**.
- `graph.py` — a graph-lite of files, functions, calls, HTTP routes, package
  imports, and findings, with **reachability from entrypoints**. Findings become
  **path candidates** (`entry → … → sink`) carrying a per-path coverage label.
- **Interface edges** connect the seams: an HTTP client call in one function is
  bound to the route handler it reaches (by URL path), reads of
  environment/config keys become untrusted **sources** bound to where the value is
  defined (`.env`, Dockerfile, compose), and declared **dependencies** are joined
  to advisories (`file → package → dependency → advisory`). Outbound calls that
  cannot be resolved become explicit **opaque boundary nodes** rather than silent
  gaps.
- `Opengrep` accepts **multiple rulesets in one scan**, so a polyglot repo is
  scanned with every ruleset it has (instead of picking one).

The web app's Review tab shows the language mix, `languages checked` %, the
unchecked languages, and each finding's path from an entrypoint.

```bash
PYTHONPATH=src python3 -m pytest          # 97 tests
```

## Desktop / web app (no command line for users)

The operator launches it once:

```bash
./scripts/rewardaudit-app            # starts the server and opens the browser
```

or install the desktop entry:

```bash
cp rewardaudit.desktop ~/.local/share/applications/   # then launch "RewardAudit" from the menu
```

Users then use three tabs in the browser — no shell:

- **Review** — point at a folder; the analyzer finds candidates and the LLM
  verifier returns a grounded verdict per candidate (true/false/abstain) with
  rationale and tokens.
- **Measure** — reproduce the project's own results on pinned datasets (Java
  controls, Python pairs, JavaVFC four-way, calibration/FNR).
- **Settings** — pick `scripted` (offline), `local` (ollama/LM Studio), or
  `cloud`; the API key is stored in `~/.config/rewardaudit/env` (mode 600) and is
  never returned to the browser.

The server binds to `127.0.0.1` only. Code stays local unless a cloud backend is
selected.

Integration tests that need the bundled opengrep binary are skipped
automatically when it is absent.
