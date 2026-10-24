#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cmake --build "$REPO_ROOT/cmake-build-debug-local" --target opcua-fuzzer
FUZZER="$REPO_ROOT/cmake-build-debug-local/tooling/fuzzer/opcua-fuzzer"
"$FUZZER" --fuzz --layers service --max-cases 10000 "$@"
