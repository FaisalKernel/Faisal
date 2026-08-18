#!/bin/bash
set -euo pipefail

ROOT=${FAISAL_ROOT:-/home/ubuntu/agi-kernel}
LINUX=${FAISAL_LINUX:-$ROOT/linux}
OUT=${FAISAL_TOOL_CONTEXT_OUT:-$ROOT/build/frontier/tool-context-validation}
SRC="$LINUX/tools/faisal-tool-context/faisal_tool_context.c"
INC="$LINUX/tools/faisal-tool-context"
SELF="$LINUX/tools/testing/selftests/faisal_tool_context_test.c"
BENCH="$LINUX/tools/testing/selftests/faisal_tool_context_benchmark.c"
FUZZ="$LINUX/tools/testing/selftests/faisal_tool_context_fuzz_test.c"
mkdir -p "$OUT"
cd "$LINUX"

CFLAGS=(-O2 -Wall -Wextra -Werror -std=c11 -pthread)
cc "${CFLAGS[@]}" -I"$INC" "$SRC" "$SELF" -lcrypto -o "$OUT/selftest"
cc "${CFLAGS[@]}" -I"$INC" "$SRC" "$BENCH" -lcrypto -o "$OUT/benchmark"
cc "${CFLAGS[@]}" -I"$INC" "$SRC" "$FUZZ" -lcrypto -o "$OUT/fuzz"

"$OUT/selftest" | tee "$OUT/selftest.log"
"$OUT/benchmark" | tee "$OUT/benchmark.log"
"$OUT/fuzz" | tee "$OUT/fuzz.log"

SANITIZER_FLAGS=(-O1 -g -Wall -Wextra -Werror -std=c11 -pthread -fsanitize=address,undefined -fno-omit-frame-pointer)
cc "${SANITIZER_FLAGS[@]}" -I"$INC" "$SRC" "$SELF" -lcrypto -o "$OUT/selftest-asan-ubsan"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  "$OUT/selftest-asan-ubsan" | tee "$OUT/asan-ubsan.log"
printf 'FTC_TOOL_CONTEXT_ASAN_UBSAN_OK\n' | tee "$OUT/asan-ubsan.marker"

TSAN_FLAGS=(-O1 -g -Wall -Wextra -Werror -std=c11 -pthread -fsanitize=thread)
cc "${TSAN_FLAGS[@]}" -I"$INC" "$SRC" "$SELF" -lcrypto -o "$OUT/selftest-tsan"
TSAN_OPTIONS=halt_on_error=1:exitcode=66 "$OUT/selftest-tsan" | tee "$OUT/tsan.log"
printf 'FTC_TOOL_CONTEXT_TSAN_OK\n' | tee "$OUT/tsan.marker"

printf 'FTC_TOOL_CONTEXT_VALIDATION_OK\n' | tee "$OUT/validation.marker"
