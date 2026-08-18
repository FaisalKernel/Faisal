#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BUILD=${FAISAL_BUILD_DIR:-"$ROOT/../build/m226-accelerator"}
mkdir -p "$BUILD"
CC=${CC:-cc}
CFLAGS="-O2 -Wall -Wextra -Werror -Wno-deprecated-declarations"
INCLUDES="-I$ROOT/tools/faisal-accelerator"
SOURCE="$ROOT/tools/faisal-accelerator/faisal_accelerator_fabric.c"
SELFTEST="$BUILD/faisal_accelerator_fabric_test"
BENCH="$BUILD/faisal_accelerator_fabric_benchmark"
LOG="$BUILD/m226-accelerator-fabric-validation.log"

{
  printf 'M226_ROOT=%s\n' "$ROOT"
  printf 'M226_BUILD=%s\n' "$BUILD"
  printf 'M226_COMPILE_SELFTEST\n'
  "$CC" $CFLAGS $INCLUDES "$SOURCE" \
    "$ROOT/tools/testing/selftests/faisal_accelerator_fabric_test.c" \
    -o "$SELFTEST" -lcrypto
  printf 'M226_RUN_SELFTEST\n'
  "$SELFTEST"
  printf 'M226_COMPILE_BENCHMARK\n'
  "$CC" $CFLAGS $INCLUDES "$SOURCE" \
    "$ROOT/tools/testing/selftests/faisal_accelerator_fabric_benchmark.c" \
    -o "$BENCH" -lcrypto
  printf 'M226_RUN_BENCHMARK\n'
  "$BENCH"
  printf 'M226_SCOPE=local_userspace_policy_fixture_not_vendor_collective_or_physical_dma_qualification\n'
  printf 'M226_RUNNER_EXIT=0\n'
} 2>&1 | tee "$LOG"
