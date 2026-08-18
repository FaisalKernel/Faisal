#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
LINUX=$ROOT/linux
BUILD=${FAISAL_M222_BUILD:-$ROOT/build/m222-aios-parity-runner}
CC=${CC:-gcc}
CFLAGS="-O2 -Wall -Wextra -Werror -Wno-error=cpp"
LDFLAGS="-lcrypto -lpthread"

if [ "${FAISAL_M222_SANITIZERS:-0}" = 1 ]; then
	CFLAGS="-O1 -g -Wall -Wextra -Werror -Wno-error=cpp -fsanitize=address,undefined -fno-omit-frame-pointer"
fi

rm -rf "$BUILD"
mkdir -p "$BUILD"
$CC $CFLAGS \
	-I"$LINUX/include/uapi" \
	-I"$LINUX/include" \
	-I"$LINUX/tools" \
	-I"$LINUX/tools/faisal-execution" \
	-I"$LINUX/tools/faisal-task" \
	"$LINUX/tools/testing/selftests/agi_aios_parity_benchmark.c" \
	"$LINUX/tools/faisal-execution/faisal_execution_engine.c" \
	"$LINUX/tools/faisal-task/faisal_task_service.c" \
	$LDFLAGS -o "$BUILD/agi_aios_parity_benchmark"

if [ "${FAISAL_M222_SANITIZERS:-0}" = 1 ]; then
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
	"$BUILD/agi_aios_parity_benchmark" | tee "$BUILD/run.log"
else
	"$BUILD/agi_aios_parity_benchmark" | tee "$BUILD/run.log"
fi

printf 'M222_RUNNER_BINARY_SHA256=%s\n' "$(sha256sum "$BUILD/agi_aios_parity_benchmark" | awk '{print $1}')"
printf 'M222_RUNNER_EXIT=0\n'
