#!/bin/sh
set -eu

ROOT=/home/ubuntu/agi-kernel
exec "$ROOT/linux/tools/faisal-build/run_self_healing_hardened_qemu.sh" "$@"
