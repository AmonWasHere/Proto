#!/usr/bin/env bash
# Produce a NEW dated OSV snapshot (never edit an existing one — ADR-0003).
#
#   ./scripts/refresh_osv.sh [output_dir]
#
# Requires network. Real OSV bulk data: https://osv.dev/docs/#tag/api
# Easiest offline-friendly route is the OSV database export or `osv-scanner`'s
# cached DB; this script uses the public GCS export of per-ecosystem zips.
set -euo pipefail
out_dir="${1:-datasets/threat}"
date_str="$(date +%F)"
out="${out_dir}/osv-${date_str}.jsonl"
echo "Refreshing OSV snapshot -> ${out}"
echo "This is a documented placeholder: wire the OSV bulk export here,"
echo "then write ${out}.meta.json with {\"date\": \"${date_str}\", \"source\": \"osv.dev\"}."
exit 1
