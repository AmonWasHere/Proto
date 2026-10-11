# Demonstration guide

**VERITAS — an evidence-first security adjudicator.** Deterministic analyzers find
candidates; a bounded LLM verifier adjudicates them; a measurement (the four-way
decomposition) asks whether the verdict actually tracks the fix.

It is a **measurement harness with a usable front end**, not another vulnerability
detector — detection is done by pinned off-the-shelf analyzers.

## Run it (offline, no model, no key)

```bash
./demo.sh        # or: make demo
```

Runs in well under a minute. Every step below is reproducible with no network.

## The script (what to say)

**1. Analyzer regression** — *"First, the analyzer half is pinned and reproducible:
opengrep 1.30.0 with a fixed rule set detects 12/18 known-vulnerable controls and
flags 1/3 safe controls. That's the off-the-shelf detector we build on."*

**2. Four-way decomposition** — *"Now the core idea. For a vulnerable/fixed pair we
ask: did the verdict move with the fix? All five pairs land in `vuln_only` — a
100% flip rate — and nothing lands in `both`, so the tool is not just matching a
construct present in both revisions."*

**3. Canary check** — *"Safe look-alikes must not be flagged. Three canaries —
`subprocess` argv form, `safe_load`, and `literal_eval` — are all clean. This is
the false-positive guard."*

**4. End-to-end review of the example app** — the headline demo. *"Point the tool
at a small app and it reports one finding at the `os.system` sink, with the
entry-to-sink path `/run → handler → run_command`, and a verdict with evidence.
Crucially, it also says `javascript` is **unchecked** — no rule set — so the tool
refuses to call the repo clean. Silence is not safety."*

**5. Dependency advisories** — *"The app's declared dependencies are matched against
a pinned advisory snapshot: `flask==2.2.0` and `pyyaml==5.3` both map to
advisories, offline, by hash-pinned data."*

**6. Test suite** — *"125 tests cover the analyzer adapter, graph, verifier arms,
decomposition, statistics, store, and web app."*

## What to highlight

- **Evidence, not vibes:** the verdict is accompanied by a resolvable path, not just
  a label.
- **Unchecked is not clean:** unsupported languages are reported, never omitted.
- **Reproducible offline:** pinned analyzer, pinned rules, pinned advisories; no API.
- **The measurement:** the four-way decomposition is the instrument the paper is about.

## Optional: run against a real model

```bash
set -a; . ~/.config/rewardaudit/env; set +a
export PYTHONPATH=src
python3 -m rewardaudit.harness review --path ../examples/vulnerable-app --backend cloud
```

With `deepseek-flash` the same finding is judged `true_positive` at confidence 0.60
(≈282 input + 1,019 output tokens).

## The app (GUI)

```bash
make app        # local server on 127.0.0.1:8765, opens the browser
```

Review tab: choose `examples/vulnerable-app` — same coverage warning, finding, and
path, with the verdict and rationale. Measure tab: run the study experiments.

## Local models (LM Studio) — auto-recognized

The verifier can run a **local** model with no API key; the endpoint and model are
auto-recognized.

- **GUI:** Setup → **Local** → **Detect local models**. It lists the served models
  and selects the loaded one; leaving the model field as `auto` uses it.
- **CLI:** point at the endpoint; the model is optional (auto-recognized):

```bash
lms server start
lms unload --all && lms load qwen2.5-coder-7b-instruct-gtap-v3 -y
cd rewardaudit
REWARDAUDIT_LOCAL_BASE_URL=http://localhost:1234/v1 \
REWARDAUDIT_LLM_CACHE=off PYTHONPATH=src \
python3 -m rewardaudit.harness review --path <repo> --backend local
```

Discovery prefers a **loaded, non-embedding** LLM (via LM Studio's native API),
falling back to the generic `/v1/models` list.

- **Use an instruct model, not a reasoning model.** `qwen2.5-coder-7b-instruct`
  works. A reasoning model (`prism-ml/bonsai-27b`) returns an empty `content` and
  puts everything in `reasoning_content`, burning the budget without emitting a
  parseable verdict — the paper's "reasoning verifier degrades to abstain" pitfall.
- **JSON mode is handled.** Local servers that reject
  `response_format: json_object` (LM Studio) are fine: JSON mode is off for local by
  default. Set `REWARDAUDIT_LOCAL_JSON_MODE=1` for servers that support it.

## Likely questions

- **Is this a detector?** No — detection is delegated to pinned analyzers; the
  project measures whether a model's *verdict* can be trusted.
- **Does it need an API?** No. The demo is fully offline with a scripted verifier;
  a local or cloud model is optional.
- **What's the novelty?** Measuring verdict *trust* against the fix (four-way
  decomposition), evidence gating, and adversarially probing the verifier — the
  paper in `paper/main.pdf`.

## Artifacts

| Path | What |
|---|---|
| `paper/main.pdf` | the 7-page IEEE-format paper (7 figures/tables, 31 refs) |
| `docs/e1-results.md` | every measured result, by round |
| `docs/REPORT.md` | findings report |
| `demo.sh` / `make demo` | this demonstration |
