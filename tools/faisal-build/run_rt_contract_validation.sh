#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BUILD=${FAISAL_BUILD_DIR:-"$ROOT/../build/m224-rt"}
mkdir -p "$BUILD"
CC=${CC:-cc}
CFLAGS="-O2 -Wall -Wextra -Werror"
INCLUDES="-I$ROOT/tools/faisal-rt"
SOURCE="$ROOT/tools/faisal-rt/faisal_rt_contract.c"
SELFTEST="$BUILD/faisal_rt_contract_test"
BENCH="$BUILD/faisal_rt_contract_benchmark"
LOG="$BUILD/m224-rt-contract-validation.log"
CONFIG=${FAISAL_RT_CONFIG:-"$ROOT/../build/industry-production-m153/.config"}

{
  printf 'M224_ROOT=%s\n' "$ROOT"
  printf 'M224_BUILD=%s\n' "$BUILD"
  printf 'M224_RT_PROFILE\n'
  python3 "$ROOT/tools/faisal-build/verify_faisal_rt_profile.py" --config "$CONFIG"
  printf 'M224_COMPILE_SELFTEST\n'
  "$CC" $CFLAGS $INCLUDES "$SOURCE" \
    "$ROOT/tools/testing/selftests/faisal_rt_contract_test.c" \
    -o "$SELFTEST"
  printf 'M224_RUN_SELFTEST\n'
  "$SELFTEST"
  printf 'M224_COMPILE_BENCHMARK\n'
  "$CC" $CFLAGS $INCLUDES "$SOURCE" \
    "$ROOT/tools/testing/selftests/faisal_rt_contract_benchmark.c" \
    -o "$BENCH"
  printf 'M224_RUN_BENCHMARK\n'
  "$BENCH"
  printf 'M224_SCOPE=policy_fixture_not_PREEMPT_RT_or_hard_latency_qualification\n'
  printf 'M224_RUNNER_EXIT=0\n'
} 2>&1 | tee "$LOG"
