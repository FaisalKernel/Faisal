#!/usr/bin/env bash
set -eu
set -o pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
OUT=${FAISAL_AGENT_RUNTIME_OUT:-"$ROOT/../build/agent-runtime-m241"}
mkdir -p "$OUT"
cd "$ROOT"

COMMON='-pthread -Itools/faisal-budget -Itools/faisal-agent-runtime'
STRICT='-O2 -Wall -Wextra -Werror -std=c11'
SAN='-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -Wall -Wextra -Werror -std=c11'

cc $STRICT $COMMON \
  tools/testing/selftests/faisal_agent_runtime_test.c \
  tools/faisal-agent-runtime/faisal_agent_runtime.c \
  tools/faisal-budget/faisal_budget.c \
  -lcrypto -o "$OUT/faisal_agent_runtime_test"
"$OUT/faisal_agent_runtime_test" | tee "$OUT/selftest.log"

cc $STRICT $COMMON \
  tools/testing/selftests/faisal_agent_runtime_benchmark.c \
  tools/faisal-agent-runtime/faisal_agent_runtime.c \
  tools/faisal-budget/faisal_budget.c \
  -lcrypto -o "$OUT/faisal_agent_runtime_benchmark"
"$OUT/faisal_agent_runtime_benchmark" | tee "$OUT/benchmark.log"

cc $STRICT $COMMON \
  tools/testing/selftests/faisal_agent_runtime_concurrency_test.c \
  tools/faisal-agent-runtime/faisal_agent_runtime.c \
  tools/faisal-budget/faisal_budget.c \
  -lcrypto -o "$OUT/faisal_agent_runtime_concurrency_test"
"$OUT/faisal_agent_runtime_concurrency_test" | tee "$OUT/concurrency.log"

cc $SAN $COMMON \
  tools/testing/selftests/faisal_agent_runtime_test.c \
  tools/faisal-agent-runtime/faisal_agent_runtime.c \
  tools/faisal-budget/faisal_budget.c \
  -lcrypto -o "$OUT/faisal_agent_runtime_test_asan"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$OUT/faisal_agent_runtime_test_asan" | tee "$OUT/asan-selftest.log"

cc $SAN $COMMON \
  tools/testing/selftests/faisal_agent_runtime_concurrency_test.c \
  tools/faisal-agent-runtime/faisal_agent_runtime.c \
  tools/faisal-budget/faisal_budget.c \
  -lcrypto -o "$OUT/faisal_agent_runtime_concurrency_test_asan"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$OUT/faisal_agent_runtime_concurrency_test_asan" | tee "$OUT/asan-concurrency.log"

printf 'M241_AGENT_RUNTIME_VALIDATION_OK\n' | tee "$OUT/validation.marker"
