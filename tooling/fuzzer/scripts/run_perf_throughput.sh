#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
# Defaults to the gcc-release preset's tree; override for another toolchain.
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/cmake-build-release-gcc}"
cmake --build "$BUILD_DIR" --target opcua-fuzzer
FUZZER="$BUILD_DIR/tooling/fuzzer/opcua-fuzzer"
"$FUZZER" --perf --perf-mode throughput "$@"
