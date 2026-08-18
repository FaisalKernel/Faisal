#!/usr/bin/env bash
set -eu
set -o pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
OUT=${FAISAL_FABRIC_OUT:-"$ROOT/../build/final-evolution-m242"}
mkdir -p "$OUT"
cd "$ROOT"

COMMON='-pthread -Itools/faisal-fabric'
STRICT='-O2 -Wall -Wextra -Werror -std=c11'
SAN='-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -Wall -Wextra -Werror -std=c11'

cc $STRICT $COMMON tools/testing/selftests/faisal_fabric_test.c \
  tools/faisal-fabric/faisal_fabric.c -lcrypto -o "$OUT/faisal_fabric_test"
"$OUT/faisal_fabric_test" | tee "$OUT/selftest-final.log"

cc $STRICT $COMMON tools/testing/selftests/faisal_fabric_benchmark.c \
  tools/faisal-fabric/faisal_fabric.c -lcrypto -o "$OUT/faisal_fabric_benchmark"
"$OUT/faisal_fabric_benchmark" | tee "$OUT/benchmark-final.log"

cc $STRICT $COMMON tools/testing/selftests/faisal_fabric_concurrency_test.c \
  tools/faisal-fabric/faisal_fabric.c -lcrypto -o "$OUT/faisal_fabric_concurrency_test"
"$OUT/faisal_fabric_concurrency_test" | tee "$OUT/concurrency-final.log"

cc $STRICT $COMMON tools/testing/selftests/faisal_fabric_fuzz_test.c \
  tools/faisal-fabric/faisal_fabric.c -lcrypto -o "$OUT/faisal_fabric_fuzz_test"
"$OUT/faisal_fabric_fuzz_test" | tee "$OUT/fuzz-final.log"

cc $SAN $COMMON tools/testing/selftests/faisal_fabric_test.c \
  tools/faisal-fabric/faisal_fabric.c -lcrypto -o "$OUT/faisal_fabric_test_asan"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$OUT/faisal_fabric_test_asan" | tee "$OUT/asan-selftest-final.log"

cc $SAN $COMMON tools/testing/selftests/faisal_fabric_concurrency_test.c \
  tools/faisal-fabric/faisal_fabric.c -lcrypto -o "$OUT/faisal_fabric_concurrency_test_asan"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$OUT/faisal_fabric_concurrency_test_asan" | tee "$OUT/asan-concurrency-final.log"

printf 'M242_FABRIC_VALIDATION_OK\n' | tee "$OUT/validation.marker"
