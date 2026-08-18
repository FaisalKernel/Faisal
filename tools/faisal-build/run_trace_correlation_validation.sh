#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT=${FAISAL_M234_OUT:-"$ROOT/../build/m234-trace-correlation"}
CC=${CC:-cc}
CFLAGS='-O2 -Wall -Wextra -Werror -std=c11'
INCLUDES='-Itools/faisal-trace-correlation'
SRC='tools/faisal-trace-correlation/faisal_trace_correlation.c'
TEST='tools/testing/selftests/faisal_trace_correlation_test.c'
BENCH='tools/testing/selftests/faisal_trace_correlation_benchmark.c'
rm -rf "$OUT"
mkdir -p "$OUT"
$CC $CFLAGS $INCLUDES "$SRC" "$TEST" -lcrypto -o "$OUT/faisal_trace_correlation_test"
$CC $CFLAGS $INCLUDES "$SRC" "$BENCH" -lcrypto -o "$OUT/faisal_trace_correlation_benchmark"
"$OUT/faisal_trace_correlation_test" | tee "$OUT/selftest.log"
grep -q 'M234_SELFTEST_EXIT=0' "$OUT/selftest.log"
"$OUT/faisal_trace_correlation_benchmark" | tee "$OUT/benchmark.log"
grep -q 'M234_BENCHMARK_EXIT=0' "$OUT/benchmark.log"
$CC -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Werror -std=c11 $INCLUDES "$SRC" "$TEST" -lcrypto -o "$OUT/faisal_trace_correlation_test_san"
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 "$OUT/faisal_trace_correlation_test_san" | tee "$OUT/sanitizer.log"
grep -q 'M234_SELFTEST_EXIT=0' "$OUT/sanitizer.log"
printf '%s\n' 'M234_TRACE_CORRELATION_VALIDATION_OK'
