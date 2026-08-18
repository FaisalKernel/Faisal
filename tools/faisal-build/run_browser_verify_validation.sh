#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT=${FAISAL_M235_OUT:-"$ROOT/../build/m235-browser-verify"}
CC=${CC:-cc}
CFLAGS='-O2 -Wall -Wextra -Werror -std=c11'
INCLUDES='-Itools/faisal-browser-verify'
SRC='tools/faisal-browser-verify/faisal_browser_verify.c'
TEST='tools/testing/selftests/faisal_browser_verify_test.c'
BENCH='tools/testing/selftests/faisal_browser_verify_benchmark.c'
rm -rf "$OUT"
mkdir -p "$OUT"
$CC $CFLAGS $INCLUDES "$SRC" "$TEST" -lcrypto -o "$OUT/faisal_browser_verify_test"
$CC $CFLAGS $INCLUDES "$SRC" "$BENCH" -lcrypto -o "$OUT/faisal_browser_verify_benchmark"
"$OUT/faisal_browser_verify_test" | tee "$OUT/selftest.log"
grep -q 'M235_SELFTEST_EXIT=0' "$OUT/selftest.log"
"$OUT/faisal_browser_verify_benchmark" | tee "$OUT/benchmark.log"
grep -q 'M235_BENCHMARK_EXIT=0' "$OUT/benchmark.log"
$CC -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Werror -std=c11 $INCLUDES "$SRC" "$TEST" -lcrypto -o "$OUT/faisal_browser_verify_test_san"
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 "$OUT/faisal_browser_verify_test_san" | tee "$OUT/sanitizer.log"
grep -q 'M235_SELFTEST_EXIT=0' "$OUT/sanitizer.log"
printf '%s\n' 'M235_BROWSER_VERIFY_VALIDATION_OK'
