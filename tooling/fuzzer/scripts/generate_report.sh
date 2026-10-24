#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
VENV="$REPO_ROOT/.venv-fuzzer-report"
if [ ! -d "$VENV" ]; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q -r "$REPO_ROOT/tooling/fuzzer/scripts/requirements-report.txt"
fi
"$VENV/bin/python3" "$REPO_ROOT/tooling/fuzzer/scripts/generate_report.py" "$@"
