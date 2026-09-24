#!/usr/bin/env bash
# Run a RewardAudit command with secrets loaded from an out-of-repo env file,
# so keys never appear in a tracked file or a command line.
#
#   ./scripts/with_env.sh python3 -m rewardaudit.harness e1 --backend cloud
#
# Override the file with REWARDAUDIT_ENV=/path/to/env
set -euo pipefail

env_file="${REWARDAUDIT_ENV:-$HOME/.config/rewardaudit/env}"
if [[ -f "$env_file" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$env_file"
  set +a
else
  echo "rewardaudit: no env file at $env_file (copy scripts/env.example)" >&2
fi

export PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}src"
exec "$@"
