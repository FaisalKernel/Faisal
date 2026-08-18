#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BUILD=${FAISAL_BUILD_DIR:-"$ROOT/../build/m223-inference"}
mkdir -p "$BUILD"
CC=${CC:-cc}
CFLAGS="-O2 -Wall -Wextra -Werror -Wno-deprecated-declarations"
INCLUDES="-I$ROOT/tools/faisal-inference -I$ROOT/tools/faisal-model-router"
COMMON="$ROOT/tools/faisal-model-router/faisal_model_router.c $ROOT/tools/faisal-inference/faisal_inference_contract.c"
SELFTEST="$BUILD/faisal_inference_contract_test"
BENCH="$BUILD/faisal_inference_contract_benchmark"
LOG="$BUILD/m223-inference-contract-validation.log"

{
  printf 'M223_ROOT=%s\n' "$ROOT"
  printf 'M223_BUILD=%s\n' "$BUILD"
  printf 'M223_COMPILE_SELFTEST\n'
  "$CC" $CFLAGS $INCLUDES $COMMON \
    "$ROOT/tools/testing/selftests/faisal_inference_contract_test.c" \
    -o "$SELFTEST" -lcrypto
  printf 'M223_RUN_SELFTEST\n'
  "$SELFTEST"
  printf 'M223_COMPILE_BENCHMARK\n'
  "$CC" $CFLAGS $INCLUDES $COMMON \
    "$ROOT/tools/testing/selftests/faisal_inference_contract_benchmark.c" \
    -o "$BENCH" -lcrypto
  printf 'M223_RUN_BENCHMARK\n'
  "$BENCH"
  printf 'M223_RUNNER_EXIT=0\n'
} 2>&1 | tee "$LOG"
