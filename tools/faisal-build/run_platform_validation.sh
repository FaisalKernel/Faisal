#!/usr/bin/env bash
set -eu
set -o pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
OUT=${FAISAL_PLATFORM_OUT:-"$ROOT/../build/platform-ecosystem-m245"}
mkdir -p "$OUT"
cd "$ROOT"
COMMON='-pthread -Itools/faisal-platform -Itools/faisal-fleet'
STRICT='-O2 -Wall -Wextra -Werror -std=c11'
SAN='-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -Wall -Wextra -Werror -std=c11'
SOURCES='tools/faisal-platform/faisal_platform.c tools/faisal-platform/faisal_platform_adapter.c tools/faisal-fleet/faisal_fleet_intent.c'

cc $STRICT $COMMON tools/testing/selftests/faisal_platform_test.c $SOURCES -lcrypto -o "$OUT/faisal_platform_test"
"$OUT/faisal_platform_test" | tee "$OUT/platform-selftest-runner.log"

cc $STRICT $COMMON tools/testing/selftests/faisal_platform_benchmark.c $SOURCES -lcrypto -o "$OUT/faisal_platform_benchmark"
"$OUT/faisal_platform_benchmark" | tee "$OUT/platform-benchmark-runner.log"

cc $STRICT $COMMON tools/testing/selftests/faisal_platform_concurrency_test.c $SOURCES -lcrypto -o "$OUT/faisal_platform_concurrency_test"
"$OUT/faisal_platform_concurrency_test" | tee "$OUT/platform-concurrency-runner.log"

cc $STRICT $COMMON tools/testing/selftests/faisal_platform_fuzz_test.c $SOURCES -lcrypto -o "$OUT/faisal_platform_fuzz_test"
"$OUT/faisal_platform_fuzz_test" | tee "$OUT/platform-fuzz-runner.log"

cc $SAN $COMMON tools/testing/selftests/faisal_platform_test.c $SOURCES -lcrypto -o "$OUT/faisal_platform_test_asan"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$OUT/faisal_platform_test_asan" | tee "$OUT/platform-asan-selftest-runner.log"

cc $SAN $COMMON tools/testing/selftests/faisal_platform_concurrency_test.c $SOURCES -lcrypto -o "$OUT/faisal_platform_concurrency_test_asan"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$OUT/faisal_platform_concurrency_test_asan" | tee "$OUT/platform-asan-concurrency-runner.log"

cc $SAN $COMMON tools/testing/selftests/faisal_platform_fuzz_test.c $SOURCES -lcrypto -o "$OUT/faisal_platform_fuzz_test_asan"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$OUT/faisal_platform_fuzz_test_asan" | tee "$OUT/platform-asan-fuzz-runner.log"

printf 'M245_PLATFORM_VALIDATION_OK\n' | tee "$OUT/platform-validation.marker"
