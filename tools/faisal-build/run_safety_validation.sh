#!/usr/bin/env bash
set -eu
set -o pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
OUT=${FAISAL_SAFETY_OUT:-"$ROOT/../build/security-hardening-m246"}
mkdir -p "$OUT"
cd "$ROOT"
COMMON='-pthread -Itools/faisal-safety'
STRICT='-O2 -Wall -Wextra -Werror -std=c11'
SAN='-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -Wall -Wextra -Werror -std=c11'
SOURCES='tools/faisal-safety/faisal_safety.c'

cc $STRICT $COMMON tools/testing/selftests/faisal_safety_test.c $SOURCES -lcrypto -o "$OUT/faisal_safety_test"
"$OUT/faisal_safety_test" | tee "$OUT/safety-selftest-runner.log"

cc $STRICT $COMMON tools/testing/selftests/faisal_safety_benchmark.c $SOURCES -lcrypto -o "$OUT/faisal_safety_benchmark"
"$OUT/faisal_safety_benchmark" | tee "$OUT/safety-benchmark-runner.log"

cc $STRICT $COMMON tools/testing/selftests/faisal_safety_concurrency_test.c $SOURCES -lcrypto -o "$OUT/faisal_safety_concurrency_test"
"$OUT/faisal_safety_concurrency_test" | tee "$OUT/safety-concurrency-runner.log"

cc $STRICT $COMMON tools/testing/selftests/faisal_safety_fuzz_test.c $SOURCES -lcrypto -o "$OUT/faisal_safety_fuzz_test"
"$OUT/faisal_safety_fuzz_test" | tee "$OUT/safety-fuzz-runner.log"

cc $SAN $COMMON tools/testing/selftests/faisal_safety_test.c $SOURCES -lcrypto -o "$OUT/faisal_safety_test_asan"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$OUT/faisal_safety_test_asan" | tee "$OUT/safety-asan-selftest-runner.log"

cc $SAN $COMMON tools/testing/selftests/faisal_safety_concurrency_test.c $SOURCES -lcrypto -o "$OUT/faisal_safety_concurrency_test_asan"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$OUT/faisal_safety_concurrency_test_asan" | tee "$OUT/safety-asan-concurrency-runner.log"

cc $SAN $COMMON tools/testing/selftests/faisal_safety_fuzz_test.c $SOURCES -lcrypto -o "$OUT/faisal_safety_fuzz_test_asan"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$OUT/faisal_safety_fuzz_test_asan" | tee "$OUT/safety-asan-fuzz-runner.log"

if command -v gcc >/dev/null 2>&1; then
  gcc -O1 -g -fno-omit-frame-pointer -fsanitize=thread -Wall -Wextra -Werror -std=c11 \
    $COMMON tools/testing/selftests/faisal_safety_concurrency_test.c $SOURCES -lcrypto \
    -o "$OUT/faisal_safety_concurrency_tsan_gcc"
  TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1 \
    "$OUT/faisal_safety_concurrency_tsan_gcc" | tee "$OUT/safety-tsan-runner.log"
else
  printf 'M246_SAFETY_TSAN_UNAVAILABLE=gcc_missing\n' | tee "$OUT/safety-tsan-runner.log"
fi

printf 'M246_SAFETY_VALIDATION_OK\n' | tee "$OUT/safety-validation.marker"
