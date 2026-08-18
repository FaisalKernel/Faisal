#!/bin/sh
set -eu

runner=${1:-unknown-runner}
printf 'FAISAL_LEGACY_QEMU_BLOCKED runner=%s reason=unqualified_legacy_entry_point\n' "$runner" >&2
printf '%s\n' 'FAISAL_LEGACY_QEMU_BLOCKED production_gate_requires_current_lts_hardened_runner' >&2
exit 78
