#!/usr/bin/env bash
# VERITAS — offline end-to-end demonstration.
#
# Runs the whole pipeline with no model, no API key, and no network:
# analyzer regression, four-way decomposition, canary check, an end-to-end
# review of the example app, dependency advisories, and the test suite.
#
#   ./demo.sh
set -euo pipefail
cd "$(dirname "$0")/rewardaudit"
export PYTHONPATH="src"

banner() { printf '\n\033[1;36m== %s\033[0m\n' "$1"; }

banner "VERITAS — evidence-first security adjudicator"

banner "1/6  Analyzer regression (pinned opengrep + rules)"
python3 -m rewardaudit.harness controls | tail -n 4

banner "2/6  Four-way decomposition over vulnerable/fixed pairs"
python3 -m rewardaudit.harness pairs | tail -n 11

banner "3/6  Canary check (safe look-alikes must not be flagged)"
python3 -m rewardaudit.harness canaries | tail -n 6

banner "4/6  End-to-end review of the example app (offline verifier)"
python3 -m rewardaudit.harness review --path ../examples/vulnerable-app --backend scripted

banner "5/6  Pinned dependency advisories"
python3 -m rewardaudit.harness threat --requirements ../examples/vulnerable-app/requirements.txt

banner "6/6  Test suite"
python3 -m pytest 2>&1 | grep -E "[0-9]+ (passed|failed)" | tail -n 1 || true

printf '\n\033[1;32mDemo complete.\033[0m  Paper: paper/main.pdf\n'
