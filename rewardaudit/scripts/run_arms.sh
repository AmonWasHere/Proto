#!/usr/bin/env bash
# Consistency arms for the verifier study.
#
# E0 (runs/e0_flash.json) established the *gated* LLM arm with k=5. The paper's
# arms table used a separate single run, so its point estimates disagree with E0.
# This script re-runs every arm on the same JavaVFC-21 subset with the same k, and
# adds a second model family (deepseek-v4-pro) at scale, so the arms table and the
# cross-family claim rest on one coherent measurement.
#
# Usage:  ./scripts/run_arms.sh
# Cost:   a few US$ on the DeepSeek key (balance must cover it).
set -euo pipefail
cd "$(dirname "$0")/.."
set -a
# shellcheck disable=SC1090
. "${REWARDAUDIT_ENV:-$HOME/.config/rewardaudit/env}"
set +a
export PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}src"
export REWARDAUDIT_LLM_CACHE=off

run() {
  echo "=== $1 ==="
  shift
  python3 -m rewardaudit.harness repeats --dir datasets/javavfc_pairs "$@"
  echo
}

# V1 — LLM, evidence gating disabled (isolates the gating effect).
run "ungated (V1) k=5" --experiments e1 --models deepseek-flash --verifier ungated --k 5 \
    --json runs/arms_ungated.json

# V5 — hybrid: gated LLM AND the deterministic tool.
run "hybrid (V5) k=5" --experiments e1 --models deepseek-flash --verifier hybrid --k 5 \
    --json runs/arms_hybrid.json

# V2 — deterministic tool (no sampling; one run is the measurement).
run "tool (V2) k=1" --experiments e1 --models deepseek-flash --verifier tool --k 1 \
    --json runs/arms_tool.json

# Second family at scale: does the gated arm's behaviour replicate?
run "gated (V1g) deepseek-v4-pro e1 k=3" --experiments e1 --models deepseek-v4-pro \
    --verifier llm --k 3 --json runs/e0_v4pro.json

echo "=== done ==="
