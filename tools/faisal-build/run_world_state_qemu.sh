#!/bin/sh
set -eu

ROOT=/home/ubuntu/agi-kernel
exec "$ROOT/linux/tools/faisal-build/run_world_state_hardened_qemu.sh" "$@"
