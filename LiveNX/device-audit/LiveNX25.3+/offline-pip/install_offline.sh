#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

python3 -m pip install \
  --no-index \
  --find-links "${SCRIPT_DIR}/wheels" \
  -r "${SCRIPT_DIR}/requirements.txt"
