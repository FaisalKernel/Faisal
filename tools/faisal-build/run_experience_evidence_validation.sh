#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT=${FAISAL_M229_OUT:-"$ROOT/../build/m229-experience-evidence"}
CC=${CC:-cc}
CFLAGS='-O2 -Wall -Wextra -Werror -std=c11'
INCLUDES='-Itools/faisal-experience'
SRC='tools/faisal-experience/faisal_experience_evidence.c'
TEST='tools/testing/selftests/faisal_experience_evidence_test.c'
BENCH='tools/testing/selftests/faisal_experience_evidence_benchmark.c'
rm -rf "$OUT"
mkdir -p "$OUT"
$CC $CFLAGS $INCLUDES "$SRC" "$TEST" -lcrypto -o "$OUT/faisal_experience_evidence_test"
$CC $CFLAGS $INCLUDES "$SRC" "$BENCH" -lcrypto -o "$OUT/faisal_experience_evidence_benchmark"
"$OUT/faisal_experience_evidence_test" | tee "$OUT/selftest.log"
grep -q 'M229_SELFTEST_EXIT=0' "$OUT/selftest.log"
"$OUT/faisal_experience_evidence_benchmark" | tee "$OUT/benchmark.log"
grep -q 'M229_BENCHMARK_EXIT=0' "$OUT/benchmark.log"
$CC -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Werror -std=c11 $INCLUDES "$SRC" "$TEST" -lcrypto -o "$OUT/faisal_experience_evidence_test_san"
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 "$OUT/faisal_experience_evidence_test_san" | tee "$OUT/sanitizer.log"
grep -q 'M229_SELFTEST_EXIT=0' "$OUT/sanitizer.log"
printf '%s\n' 'M229_EXPERIENCE_EVIDENCE_VALIDATION_OK'
