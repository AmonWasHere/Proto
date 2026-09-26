# Research

An **evidence-first security adjudicator**: deterministic analyzers find
candidates, a bounded LLM verifier adjudicates them, and a measurement (the
**four-way decomposition**) asks whether the verdict actually tracks the fix.
Umbrella name for the code: **RewardAudit**.

It is a *measurement harness with a usable front end*, not a vulnerability
detector — detection is done by pinned off-the-shelf analyzers.

## Quick start

```bash
make app        # launch the local web app and open the browser (no CLI for users)
make test       # run the test suite
```

The app binds to `127.0.0.1` only. It runs **offline** out of the box (the
`scripted` backend needs no model); connect a Local or Cloud model in the Setup
drawer when you want real LLM verdicts. API keys live in
`~/.config/rewardaudit/env` (mode 600) and are never sent to the browser.

## Layout

| Path | What |
|---|---|
| `rewardaudit/` | the harness, verifiers, graph, store, and local web app |
| `rewardaudit/scripts/` | `rewardaudit-app` launcher, `with_env.sh`, `env.example` |
| `rewardaudit/packaging/` | `rewardaudit.desktop` + install instructions |
| `pinned/` | pinned analyzers, rules, controls, corpora (see `pinned/README.md`) |
| `docs/` | plan, findings, cost, tools, ADRs, design, archive (see `docs/README.md`) |
| `paper/` | IEEE-format manuscript (draft) |
| `Makefile` | `make app` · `make test` · `make clean` |

## Documentation

Start with **[`docs/README.md`](docs/README.md)**. The essentials:

- [`docs/PLAN.md`](docs/PLAN.md) — plan and phases
- [`docs/REPORT.md`](docs/REPORT.md) — findings report
- [`docs/e1-results.md`](docs/e1-results.md) — measured results by round
- [`docs/COST.md`](docs/COST.md) — measured cost and optimizations
- [`docs/tools.md`](docs/tools.md) — languages and analyzers
- [`docs/design/whole-codebase-graph.md`](docs/design/whole-codebase-graph.md) — system-level design
- [`docs/issues.md`](docs/issues.md) — tracked backlog
- [`paper/main.tex`](paper/main.tex) — IEEE-format manuscript (draft)

## Status

Working and tested: **112 tests**. The app, the harness commands
(`controls`, `pairs`, `javavfc`, `e1`, `evade`, `adaptive`, `calibrate`,
`threat`), the four verifier arms (LLM gated/ungated, tool, hybrid), the
Whole-Codebase graph (interface edges, reachability, coverage), the cost
optimizations (thinking-off, verdict cache), and the frontend are all in place.
Language coverage is **Java (full)** and **Python (minimal rules)**; other
languages are reported as *unchecked*, never silently clean.

## Reproduce offline

```bash
cd rewardaudit
PYTHONPATH=src python3 -m pytest
PYTHONPATH=src python3 -m rewardaudit.harness controls          # 12/18, 1/3
PYTHONPATH=src python3 -m rewardaudit.harness pairs             # four-way
PYTHONPATH=src python3 -m rewardaudit.harness javavfc --offline # build the corpus
```

## License

MIT — see [`LICENSE`](LICENSE). Security policy: [`SECURITY.md`](SECURITY.md).
