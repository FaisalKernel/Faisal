#!/usr/bin/env bash
set -eu
set -o pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
OUT=${FAISAL_ADAPTIVE_OUT:-"$ROOT/../build/frontier-m243"}
mkdir -p "$OUT"
cd "$ROOT"
COMMON='-pthread -Itools/faisal-adaptive'
STRICT='-O2 -Wall -Wextra -Werror -std=c11'
SAN='-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -Wall -Wextra -Werror -std=c11'

cc $STRICT $COMMON tools/testing/selftests/faisal_adaptive_test.c \
  tools/faisal-adaptive/faisal_adaptive.c -lcrypto -o "$OUT/faisal_adaptive_test"
"$OUT/faisal_adaptive_test" | tee "$OUT/selftest-runner.log"

cc $STRICT $COMMON tools/testing/selftests/faisal_adaptive_benchmark.c \
  tools/faisal-adaptive/faisal_adaptive.c -lcrypto -o "$OUT/faisal_adaptive_benchmark"
"$OUT/faisal_adaptive_benchmark" | tee "$OUT/benchmark-runner.log"

cc $STRICT $COMMON tools/testing/selftests/faisal_adaptive_concurrency_test.c \
  tools/faisal-adaptive/faisal_adaptive.c -lcrypto -o "$OUT/faisal_adaptive_concurrency_test"
"$OUT/faisal_adaptive_concurrency_test" | tee "$OUT/concurrency-runner.log"

cc $STRICT $COMMON tools/testing/selftests/faisal_adaptive_fuzz_test.c \
  tools/faisal-adaptive/faisal_adaptive.c -lcrypto -o "$OUT/faisal_adaptive_fuzz_test"
"$OUT/faisal_adaptive_fuzz_test" | tee "$OUT/fuzz-runner.log"

cc $SAN $COMMON tools/testing/selftests/faisal_adaptive_test.c \
  tools/faisal-adaptive/faisal_adaptive.c -lcrypto -o "$OUT/faisal_adaptive_test_asan"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$OUT/faisal_adaptive_test_asan" | tee "$OUT/asan-selftest-runner.log"

cc $SAN $COMMON tools/testing/selftests/faisal_adaptive_concurrency_test.c \
  tools/faisal-adaptive/faisal_adaptive.c -lcrypto -o "$OUT/faisal_adaptive_concurrency_test_asan"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$OUT/faisal_adaptive_concurrency_test_asan" | tee "$OUT/asan-concurrency-runner.log"

cc $SAN $COMMON tools/testing/selftests/faisal_adaptive_fuzz_test.c \
  tools/faisal-adaptive/faisal_adaptive.c -lcrypto -o "$OUT/faisal_adaptive_fuzz_test_asan"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$OUT/faisal_adaptive_fuzz_test_asan" | tee "$OUT/asan-fuzz-runner.log"

printf 'M243_ADAPTIVE_VALIDATION_OK\n' | tee "$OUT/validation.marker"
