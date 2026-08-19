#!/bin/bash
set -euo pipefail

ROOT=${FAISAL_ROOT:-/home/ubuntu/agi-kernel}
LINUX=${FAISAL_LINUX:-$ROOT/linux}
OUT=${FAISAL_HARDWARE_OUT:-$ROOT/build/frontier/hardware-qualification-2026-08-24}
TOOL="$LINUX/tools/faisal-hardware-qualify/faisal_hardware_qualify.py"
TEST="$LINUX/tools/faisal-hardware-qualify/test_faisal_hardware_qualify.py"
rm -rf "$OUT"
mkdir -p "$OUT"
cd "$LINUX"
python3 -m py_compile "$TOOL" "$TEST"
python3 "$TEST" | tee "$OUT/selftest.log"
python3 "$TOOL" --output "$OUT/live-host-observation.json" | tee "$OUT/live-observation.log"
python3 "$TOOL" --verify "$OUT/live-host-observation.json" | tee "$OUT/live-verify.log"
if python3 "$TOOL" --output "$OUT/required-gpu-observation.json" --require gpu > "$OUT/required-gpu.log" 2>&1; then
  echo 'required GPU qualification unexpectedly passed' >&2
  exit 1
fi
if python3 "$TOOL" --output "$OUT/required-iommu-observation.json" --require iommu > "$OUT/required-iommu.log" 2>&1; then
  echo 'required IOMMU qualification unexpectedly passed in an unqualified host' >&2
  exit 1
fi
printf 'FAISAL_HARDWARE_QUALIFICATION_RUN_OK synthetic_selftest=passed live_observation=passed live_digest_verify=passed absent_capability_fail_closed=passed fake_hardware=not_claimed\n' | tee "$OUT/validation.marker"
