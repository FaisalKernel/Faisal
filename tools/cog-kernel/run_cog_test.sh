#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BUILD=${FAISAL_BUILD:-"$ROOT/../../build/recovered"}
MODULE="$ROOT/tools/cog-kernel/cog_kernel.ko"
TESTER="$ROOT/tools/cog-kernel/cog_tester"

cc -O2 -Wall -Wextra -Werror -static "$ROOT/tools/cog-kernel/cog_tester.c" -o "$TESTER"
make -C "$ROOT/tools/cog-kernel" KDIR="$ROOT" KBUILD_OUTPUT="$BUILD"
if [ "$(id -u)" -ne 0 ]; then
  echo 'COG_HOST_TEST_SKIPPED:root required for insmod/rmmod'
  exit 77
fi
insmod "$MODULE" attention_drift=0
trap 'rmmod cog_kernel 2>/dev/null || true' EXIT
"$TESTER"
rmmod cog_kernel
trap - EXIT
echo COG_MODULE_LIFECYCLE_OK
