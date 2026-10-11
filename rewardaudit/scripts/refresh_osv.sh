#!/usr/bin/env bash
# Produce a NEW dated OSV snapshot for declared dependencies (never edits an
# existing snapshot — ADR-0003).
#
#   ./scripts/refresh_osv.sh [requirements.txt] [ecosystem]
#
# Defaults to the example app's requirements and the PyPI ecosystem. Requires
# network access to https://api.osv.dev.
set -euo pipefail
cd "$(dirname "$0")/.."

req="${1:-${REWARDAUDIT_REQUIREMENTS:-../examples/vulnerable-app/requirements.txt}}"
eco="${2:-PyPI}"

PYTHONPATH=src python3 -m rewardaudit.harness threat-refresh \
    --requirements "$req" --ecosystem "$eco"
