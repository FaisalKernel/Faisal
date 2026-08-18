#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BUILD=${FAISAL_BUILD_DIR:-"$ROOT/../build/m227-model-action"}
mkdir -p "$BUILD"
CC=${CC:-cc}
CFLAGS="-O2 -Wall -Wextra -Werror -Wno-deprecated-declarations"
INCLUDES="-I$ROOT/tools/faisal-model-action"
SOURCE="$ROOT/tools/faisal-model-action/faisal_model_action.c"
SELFTEST="$BUILD/faisal_model_action_test"
BENCH="$BUILD/faisal_model_action_benchmark"
LOG="$BUILD/m227-model-action-validation.log"

{
  printf 'M227_ROOT=%s\n' "$ROOT"
  printf 'M227_BUILD=%s\n' "$BUILD"
  printf 'M227_COMPILE_SELFTEST\n'
  "$CC" $CFLAGS $INCLUDES "$SOURCE" \
    "$ROOT/tools/testing/selftests/faisal_model_action_test.c" \
    -o "$SELFTEST" -lcrypto
  printf 'M227_RUN_SELFTEST\n'
  "$SELFTEST"
  printf 'M227_COMPILE_BENCHMARK\n'
  "$CC" $CFLAGS $INCLUDES "$SOURCE" \
    "$ROOT/tools/testing/selftests/faisal_model_action_benchmark.c" \
    -o "$BENCH" -lcrypto
  printf 'M227_RUN_BENCHMARK\n'
  "$BENCH"
  printf 'M227_SCOPE=local_userspace_policy_fixture_not_model_inference_or_paid_provider_latency\n'
  printf 'M227_RUNNER_EXIT=0\n'
} 2>&1 | tee "$LOG"
