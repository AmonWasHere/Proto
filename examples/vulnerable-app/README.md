# Example: a small vulnerable app

An intentionally vulnerable app used to demo RewardAudit end to end. **Nothing
here is production code** — it exists to exercise the analyzer, the codebase
graph, the coverage report, and the verifier.

## What each file demonstrates

| File | Shows |
|---|---|
| `app.py` | a Flask route `/run` whose handler reads an untrusted value from the environment and calls into `core` |
| `core.py` | the **sink** (`os.system`) one call away from the handler |
| `safe.py` | a safe look-alike (`subprocess.run([...])`) that must **not** be flagged |
| `requirements.txt` | a declared dependency (`pyyaml==5.3`) that maps to an advisory |
| `.env` | where the config value (`CMD`) is defined |
| `static/app.js` | a language the tool has **no ruleset** for — it must be reported *unchecked*, never as "clean" |

## Run it (offline, no model needed)

```bash
cd rewardaudit
PYTHONPATH=src python3 -m rewardaudit.harness review \
    --path ../examples/vulnerable-app --backend scripted
```

Expected output:

```
path:      .../examples/vulnerable-app
analyzer:  opengrep 1.30.0  rulesets=['python-minimal.yaml']
coverage:  {'covered': 3, 'unsupported': 1}  checked=75%
UNCHECKED: javascript  (no ruleset; not clean)
candidates 1  |  true positive 1  false positive 0  abstained 0  |  reachable paths 1

  core.py:8  [python]  true_positive  conf=0.85 ra-python-os-system
      path: /run -> handler -> run_command   coverage=covered

tokens: in=0 out=0
```

## Run it with a real model

Configure a model (see the root README), then:

```bash
cd rewardaudit
set -a; . ~/.config/rewardaudit/env; set +a
export PYTHONPATH=src
python3 -m rewardaudit.harness review --path ../examples/vulnerable-app --backend cloud
```

Observed with `deepseek-flash`: the same finding, judged `true_positive` at
confidence 0.60, using 282 input + 1,019 output tokens.

## Or use the app

```bash
make app          # from the repo root; opens the browser
```

In the **Review** tab, choose this folder (`examples/vulnerable-app`) — you'll see
the same coverage warning, the finding, and its `/run → handler → run_command`
path, with the verdict and rationale.

## What to look for

- **One finding**, at the `os.system` sink, reachable from the `/run` route.
- **`safe.py` is not flagged** — the tool is not just matching the word `subprocess`.
- **`javascript` is listed as unchecked** — the polyglot gap is visible instead of
  silently omitted.
- **`pyyaml==5.3`** appears as a dependency; against the pinned advisory fixture it
  is *vulnerable* (see the codebase graph in the app).
