#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
OUT=${FAISAL_M240_OUT:-"$ROOT/../../build/m240-budget"}
CC=${CC:-cc}
CFLAGS=${CFLAGS:--O2 -Wall -Wextra -Werror -std=c11}
mkdir -p "$OUT"

$CC $CFLAGS -I"$ROOT/tools/faisal-budget" \
  "$ROOT/tools/faisal-budget/faisal_budget.c" \
  "$ROOT/tools/testing/selftests/faisal_budget_test.c" \
  -lcrypto -o "$OUT/faisal_budget_test"
$CC $CFLAGS -I"$ROOT/tools/faisal-budget" \
  "$ROOT/tools/faisal-budget/faisal_budget.c" \
  "$ROOT/tools/testing/selftests/faisal_budget_benchmark.c" \
  -lcrypto -o "$OUT/faisal_budget_benchmark"

"$OUT/faisal_budget_test" | tee "$OUT/selftest.log"
"$OUT/faisal_budget_benchmark" | tee "$OUT/benchmark.log"

$CC -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
  -Wall -Wextra -Werror -std=c11 -I"$ROOT/tools/faisal-budget" \
  "$ROOT/tools/faisal-budget/faisal_budget.c" \
  "$ROOT/tools/testing/selftests/faisal_budget_test.c" \
  -lcrypto -o "$OUT/faisal_budget_test-asan-ubsan"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1 \
  "$OUT/faisal_budget_test-asan-ubsan" | tee "$OUT/asan-ubsan.log"

echo "M240_BUDGET_VALIDATION_OK"
