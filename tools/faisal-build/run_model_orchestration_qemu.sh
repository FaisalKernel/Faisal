#!/bin/sh
set -eu

ROOT=/home/ubuntu/agi-kernel
exec "$ROOT/linux/tools/faisal-build/run_unqualified_legacy_qemu_guard.sh" "$(basename "$0")"
