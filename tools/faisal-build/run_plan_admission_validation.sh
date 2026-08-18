#!/bin/bash
set -euo pipefail

ROOT=${FAISAL_ROOT:-/home/ubuntu/agi-kernel}
LINUX=${FAISAL_LINUX:-$ROOT/linux}
OUT=${FAISAL_PLAN_ADMISSION_OUT:-$ROOT/build/frontier/plan-admission-validation}
SRC="$LINUX/tools/faisal-plan-admission/faisal_plan_admission.c"
INC="$LINUX/tools/faisal-plan-admission"
TEST="$LINUX/tools/testing/selftests/faisal_plan_admission_test.c"
BENCH="$LINUX/tools/testing/selftests/faisal_plan_admission_benchmark.c"
FUZZ="$LINUX/tools/testing/selftests/faisal_plan_admission_fuzz_test.c"
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
printf 'FPA_PLAN_ADMISSION_ASAN_UBSAN_OK\n' | tee "$OUT/asan-ubsan.marker"

TSAN_FLAGS=(-O1 -g -Wall -Wextra -Werror -std=c11 -pthread -fsanitize=thread)
cc "${TSAN_FLAGS[@]}" -I"$INC" "$SRC" "$TEST" -lcrypto -o "$OUT/selftest-tsan"
TSAN_OPTIONS=halt_on_error=1:exitcode=66 "$OUT/selftest-tsan" | tee "$OUT/tsan.log"
printf 'FPA_PLAN_ADMISSION_TSAN_OK\n' | tee "$OUT/tsan.marker"

"$LINUX/tools/faisal-build/run_durable_task_qemu.sh" | tee "$OUT/durable-task-regression.log"
"$LINUX/tools/faisal-build/run_autonomy_control_qemu.sh" | tee "$OUT/autonomy-control-regression.log"
"$LINUX/tools/faisal-build/run_mission_autonomy_qemu.sh" | tee "$OUT/mission-autonomy-regression.log"
printf 'FPA_PLAN_ADMISSION_VALIDATION_OK\n' | tee "$OUT/validation.marker"
