#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BUILD=${FAISAL_BUILD_DIR:-"$ROOT/../build/m225-fleet"}
mkdir -p "$BUILD"
CC=${CC:-cc}
CFLAGS="-O2 -Wall -Wextra -Werror -Wno-deprecated-declarations"
INCLUDES="-I$ROOT/tools/faisal-fleet"
SOURCE="$ROOT/tools/faisal-fleet/faisal_fleet_intent.c"
SELFTEST="$BUILD/faisal_fleet_intent_test"
BENCH="$BUILD/faisal_fleet_intent_benchmark"
LOG="$BUILD/m225-fleet-intent-validation.log"

{
  printf 'M225_ROOT=%s\n' "$ROOT"
  printf 'M225_BUILD=%s\n' "$BUILD"
  printf 'M225_COMPILE_SELFTEST\n'
  "$CC" $CFLAGS $INCLUDES "$SOURCE" \
    "$ROOT/tools/testing/selftests/faisal_fleet_intent_test.c" \
    -o "$SELFTEST" -lcrypto
  printf 'M225_RUN_SELFTEST\n'
  "$SELFTEST"
  printf 'M225_COMPILE_BENCHMARK\n'
  "$CC" $CFLAGS $INCLUDES "$SOURCE" \
    "$ROOT/tools/testing/selftests/faisal_fleet_intent_benchmark.c" \
    -o "$BENCH" -lcrypto
  printf 'M225_RUN_BENCHMARK\n'
  "$BENCH"
  printf 'M225_SCOPE=local_userspace_policy_fixture_not_kubernetes_or_physical_gpu_qualification\n'
  printf 'M225_RUNNER_EXIT=0\n'
} 2>&1 | tee "$LOG"
