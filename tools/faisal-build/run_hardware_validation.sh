#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUT=${FAISAL_HARDWARE_OUT:-/home/ubuntu/agi-kernel/build/hardware-evolution-m247}
mkdir -p "$OUT"
cd "$ROOT"

COMMON=(-pthread -Itools/faisal-hardware)
STRICT=(-O2 -Wall -Wextra -Werror -std=c11)
SAN=(-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -Wall -Wextra -Werror -std=c11)

cc "${STRICT[@]}" "${COMMON[@]}" tools/testing/selftests/faisal_hardware_discovery_test.c tools/faisal-hardware/faisal_hardware.c -lcrypto -o "$OUT/faisal_hardware_discovery_test"
cc "${STRICT[@]}" "${COMMON[@]}" tools/testing/selftests/faisal_hardware_test.c tools/faisal-hardware/faisal_hardware.c -lcrypto -o "$OUT/faisal_hardware_test"
cc "${STRICT[@]}" "${COMMON[@]}" tools/testing/selftests/faisal_hardware_benchmark.c tools/faisal-hardware/faisal_hardware.c -lcrypto -o "$OUT/faisal_hardware_benchmark"
cc "${STRICT[@]}" "${COMMON[@]}" tools/testing/selftests/faisal_hardware_concurrency_test.c tools/faisal-hardware/faisal_hardware.c -lcrypto -o "$OUT/faisal_hardware_concurrency_test"
cc "${STRICT[@]}" "${COMMON[@]}" tools/testing/selftests/faisal_hardware_fuzz_test.c tools/faisal-hardware/faisal_hardware.c -lcrypto -o "$OUT/faisal_hardware_fuzz_test"

"$OUT/faisal_hardware_discovery_test" | tee "$OUT/hardware-discovery.log"
"$OUT/faisal_hardware_test" | tee "$OUT/hardware-selftest.log"
"$OUT/faisal_hardware_benchmark" | tee "$OUT/hardware-benchmark.log"
"$OUT/faisal_hardware_concurrency_test" | tee "$OUT/hardware-concurrency.log"
"$OUT/faisal_hardware_fuzz_test" | tee "$OUT/hardware-fuzz.log"

cc "${SAN[@]}" "${COMMON[@]}" tools/testing/selftests/faisal_hardware_test.c tools/faisal-hardware/faisal_hardware.c -lcrypto -o "$OUT/faisal_hardware_test_asan"
cc "${SAN[@]}" "${COMMON[@]}" tools/testing/selftests/faisal_hardware_discovery_test.c tools/faisal-hardware/faisal_hardware.c -lcrypto -o "$OUT/faisal_hardware_discovery_test_asan"
cc "${SAN[@]}" "${COMMON[@]}" tools/testing/selftests/faisal_hardware_concurrency_test.c tools/faisal-hardware/faisal_hardware.c -lcrypto -o "$OUT/faisal_hardware_concurrency_test_asan"
cc "${SAN[@]}" "${COMMON[@]}" tools/testing/selftests/faisal_hardware_fuzz_test.c tools/faisal-hardware/faisal_hardware.c -lcrypto -o "$OUT/faisal_hardware_fuzz_test_asan"

ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 "$OUT/faisal_hardware_test_asan" | tee "$OUT/hardware-asan-selftest.log"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 "$OUT/faisal_hardware_discovery_test_asan" | tee "$OUT/hardware-asan-discovery.log"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 "$OUT/faisal_hardware_concurrency_test_asan" | tee "$OUT/hardware-asan-concurrency.log"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 "$OUT/faisal_hardware_fuzz_test_asan" | tee "$OUT/hardware-asan-fuzz.log"

cc -O1 -g -fno-omit-frame-pointer -fsanitize=thread -Wall -Wextra -Werror -std=c11 "${COMMON[@]}" \
  tools/testing/selftests/faisal_hardware_concurrency_test.c tools/faisal-hardware/faisal_hardware.c -lcrypto \
  -o "$OUT/faisal_hardware_concurrency_tsan"
TSAN_OPTIONS=halt_on_error=1:exitcode=1 "$OUT/faisal_hardware_concurrency_tsan" | tee "$OUT/hardware-tsan-concurrency.log"

echo 'M247_HARDWARE_VALIDATION_OK'
