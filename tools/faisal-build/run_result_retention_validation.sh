#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
OUT=${FAISAL_M238_OUT:-/home/ubuntu/agi-kernel/build/m238-retention}
CC=${CC:-cc}
CFLAGS="-O2 -Wall -Wextra -Werror -std=c11 -I$ROOT/tools/faisal-result-retention"
SRC="$ROOT/tools/faisal-result-retention/faisal_result_retention.c"
TEST="$ROOT/tools/testing/selftests/faisal_result_retention_test.c"
BENCH="$ROOT/tools/testing/selftests/faisal_result_retention_benchmark.c"
BRIDGE="$ROOT/tools/testing/selftests/faisal_result_retention_bridge_test.c"
RET_BRIDGE="$ROOT/tools/faisal-result-retention/faisal_result_retention_bridge.c"
FSV="$ROOT/tools/faisal-result-verify/faisal_result_verify.c"
mkdir -p "$OUT"

$CC $CFLAGS "$SRC" "$TEST" -lcrypto -o "$OUT/faisal_result_retention_test"
$CC $CFLAGS "$SRC" "$BENCH" -lcrypto -o "$OUT/faisal_result_retention_benchmark"
$CC $CFLAGS -I"$ROOT/tools/faisal-result-verify" "$SRC" "$RET_BRIDGE" "$FSV" "$BRIDGE" -lcrypto -o "$OUT/faisal_result_retention_bridge_test"
"$OUT/faisal_result_retention_test" | tee "$OUT/selftest.log"
"$OUT/faisal_result_retention_bridge_test" | tee "$OUT/bridge.log"
"$OUT/faisal_result_retention_benchmark" | tee "$OUT/benchmark.log"

$CC -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined \
	-Wall -Wextra -Werror -std=c11 \
	-I"$ROOT/tools/faisal-result-retention" "$SRC" "$TEST" -lcrypto \
	-o "$OUT/faisal_result_retention_sanitized"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1 \
"$OUT/faisal_result_retention_sanitized" | tee "$OUT/sanitizer.log"

echo "M238_RESULT_RETENTION_VALIDATION_OK"
