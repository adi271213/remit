#!/usr/bin/env bash
set -euo pipefail
# The stdlib-only controller records setup failures as explicit error outcomes.
# -I prevents importing modules from the analyzed checkout or PYTHONPATH.
exec python3 -I "$GITHUB_ACTION_PATH/scripts/action_runner.py"
