#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
OUT=${FAISAL_M239_OUT:-/home/ubuntu/agi-kernel/build/m239-kv-tier}
CC=${CC:-cc}
CFLAGS="-O2 -Wall -Wextra -Werror -std=c11 -I$ROOT/tools/faisal-kv-tier"
SRC="$ROOT/tools/faisal-kv-tier/faisal_kv_tier.c"
TEST="$ROOT/tools/testing/selftests/faisal_kv_tier_test.c"
BENCH="$ROOT/tools/testing/selftests/faisal_kv_tier_benchmark.c"
mkdir -p "$OUT"

$CC $CFLAGS "$SRC" "$TEST" -lcrypto -o "$OUT/faisal_kv_tier_test"
$CC $CFLAGS "$SRC" "$BENCH" -lcrypto -o "$OUT/faisal_kv_tier_benchmark"
"$OUT/faisal_kv_tier_test" | tee "$OUT/selftest.log"
"$OUT/faisal_kv_tier_benchmark" | tee "$OUT/benchmark.log"

$CC -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined \
	-Wall -Wextra -Werror -std=c11 -I"$ROOT/tools/faisal-kv-tier" \
	"$SRC" "$TEST" -lcrypto -o "$OUT/faisal_kv_tier_sanitized"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1 \
"$OUT/faisal_kv_tier_sanitized" | tee "$OUT/sanitizer.log"

echo "M239_KV_TIER_VALIDATION_OK"
