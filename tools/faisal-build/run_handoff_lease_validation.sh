#!/bin/bash
set -euo pipefail

ROOT=${FAISAL_ROOT:-/home/ubuntu/agi-kernel}
LINUX=${FAISAL_LINUX:-$ROOT/linux}
OUT=${FAISAL_HANDOFF_LEASE_OUT:-$ROOT/build/frontier/handoff-lease-validation}
SRC="$LINUX/tools/faisal-handoff-lease/faisal_handoff_lease.c"
INC="$LINUX/tools/faisal-handoff-lease"
TEST="$LINUX/tools/testing/selftests/faisal_handoff_lease_test.c"
BENCH="$LINUX/tools/testing/selftests/faisal_handoff_lease_benchmark.c"
FUZZ="$LINUX/tools/testing/selftests/faisal_handoff_lease_fuzz_test.c"
mkdir -p "$OUT"
cd "$LINUX"

CFLAGS=(-O2 -Wall -Wextra -Werror -std=c11 -pthread)
cc "${CFLAGS[@]}" -I"$INC" "$SRC" "$TEST" -lcrypto -o "$OUT/selftest"
cc "${CFLAGS[@]}" -I"$INC" "$SRC" "$BENCH" -lcrypto -o "$OUT/benchmark"
cc "${CFLAGS[@]}" -I"$INC" "$SRC" "$FUZZ" -lcrypto -o "$OUT/fuzz"
"$OUT/selftest" | tee "$OUT/selftest.log"
"$OUT/benchmark" | tee "$OUT/benchmark.log"
"$OUT/fuzz" | tee "$OUT/fuzz.log"

SANITIZER_FLAGS=(-O1 -g -Wall -Wextra -Werror -std=c11 -pthread -fsanitize=address,undefined -fno-omit-frame-pointer)
cc "${SANITIZER_FLAGS[@]}" -I"$INC" "$SRC" "$TEST" -lcrypto -o "$OUT/selftest-asan-ubsan"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  "$OUT/selftest-asan-ubsan" | tee "$OUT/asan-ubsan.log"
printf 'FHL_HANDOFF_LEASE_ASAN_UBSAN_OK\n' | tee "$OUT/asan-ubsan.marker"

TSAN_FLAGS=(-O1 -g -Wall -Wextra -Werror -std=c11 -pthread -fsanitize=thread)
cc "${TSAN_FLAGS[@]}" -I"$INC" "$SRC" "$TEST" -lcrypto -o "$OUT/selftest-tsan"
TSAN_OPTIONS=halt_on_error=1:exitcode=66 "$OUT/selftest-tsan" | tee "$OUT/tsan.log"
printf 'FHL_HANDOFF_LEASE_TSAN_OK\n' | tee "$OUT/tsan.marker"

FAISAL_BUILD_DIR="$OUT/m223-inference" "$LINUX/tools/faisal-build/run_inference_contract_validation.sh" | tee "$OUT/m223-inference-regression.log"
"$LINUX/tools/faisal-build/run_coordination_validation.sh" | tee "$OUT/coordination-regression.log"
"$LINUX/tools/faisal-build/run_agent_runtime_validation.sh" | tee "$OUT/agent-runtime-regression.log"
FAISAL_ADAPTIVE_OUT="$OUT/adaptive-router" "$LINUX/tools/faisal-build/run_model_router_adaptive_validation.sh" | tee "$OUT/adaptive-router-regression.log"
printf 'FHL_HANDOFF_LEASE_VALIDATION_OK\n' | tee "$OUT/validation.marker"
