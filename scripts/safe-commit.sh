#!/usr/bin/env bash
set -euo pipefail
[[ $# -ge 1 ]] || { echo 'Usage: scripts/safe-commit.sh "commit message"'; exit 1; }
bash scripts/check-secrets.sh all
git add --all
bash scripts/check-secrets.sh staged
git commit -m "$1"
