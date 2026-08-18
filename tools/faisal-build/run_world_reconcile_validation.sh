#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT=${FAISAL_M233_OUT:-"$ROOT/../build/m233-world-reconcile"}
CC=${CC:-cc}
CFLAGS='-O2 -Wall -Wextra -Werror -std=c11'
INCLUDES='-Itools/faisal-world-reconcile'
SRC='tools/faisal-world-reconcile/faisal_world_reconcile.c'
TEST='tools/testing/selftests/faisal_world_reconcile_test.c'
BENCH='tools/testing/selftests/faisal_world_reconcile_benchmark.c'
rm -rf "$OUT"
mkdir -p "$OUT"
$CC $CFLAGS $INCLUDES "$SRC" "$TEST" -lcrypto -o "$OUT/faisal_world_reconcile_test"
$CC $CFLAGS $INCLUDES "$SRC" "$BENCH" -lcrypto -o "$OUT/faisal_world_reconcile_benchmark"
"$OUT/faisal_world_reconcile_test" | tee "$OUT/selftest.log"
grep -q 'M233_SELFTEST_EXIT=0' "$OUT/selftest.log"
"$OUT/faisal_world_reconcile_benchmark" | tee "$OUT/benchmark.log"
grep -q 'M233_BENCHMARK_EXIT=0' "$OUT/benchmark.log"
$CC -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Werror -std=c11 $INCLUDES "$SRC" "$TEST" -lcrypto -o "$OUT/faisal_world_reconcile_test_san"
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 "$OUT/faisal_world_reconcile_test_san" | tee "$OUT/sanitizer.log"
grep -q 'M233_SELFTEST_EXIT=0' "$OUT/sanitizer.log"
printf '%s\n' 'M233_WORLD_RECONCILE_VALIDATION_OK'
