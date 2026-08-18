#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BUILD=${FAISAL_BUILD_DIR:-"$ROOT/../build/m228-sandbox-execution"}
mkdir -p "$BUILD"
CC=${CC:-cc}
CFLAGS="-O2 -Wall -Wextra -Werror -Wno-deprecated-declarations"
INCLUDES="-I$ROOT/tools/faisal-sandbox"
SOURCE="$ROOT/tools/faisal-sandbox/faisal_sandbox_execution.c"
SELFTEST="$BUILD/faisal_sandbox_execution_test"
BENCH="$BUILD/faisal_sandbox_execution_benchmark"
LOG="$BUILD/m228-sandbox-execution-validation.log"
{
  printf 'M228_ROOT=%s\n' "$ROOT"
  printf 'M228_BUILD=%s\n' "$BUILD"
  printf 'M228_COMPILE_SELFTEST\n'
  "$CC" $CFLAGS $INCLUDES "$SOURCE" \
    "$ROOT/tools/testing/selftests/faisal_sandbox_execution_test.c" \
    -o "$SELFTEST" -lcrypto
  printf 'M228_RUN_SELFTEST\n'
  "$SELFTEST"
  printf 'M228_COMPILE_BENCHMARK\n'
  "$CC" $CFLAGS $INCLUDES "$SOURCE" \
    "$ROOT/tools/testing/selftests/faisal_sandbox_execution_benchmark.c" \
    -o "$BENCH" -lcrypto
  printf 'M228_RUN_BENCHMARK\n'
  "$BENCH"
  printf 'M228_SCOPE=local_userspace_policy_fixture_not_wasm_or_microvm_or_provider_latency\n'
  printf 'M228_BACKEND_QUALIFICATION=wasmtime_firecracker_physical_kvm_and_real_tool_execution_pending\n'
  printf 'M228_RUNNER_EXIT=0\n'
} 2>&1 | tee "$LOG"
