#!/usr/bin/env bash
set -euo pipefail

ROOT=${FAISAL_ROOT:-/home/ubuntu/agi-kernel}
LINUX=${FAISAL_LINUX:-$ROOT/linux}
OUT=${FAISAL_FINAL_OUT:-$ROOT/build/final-integration-m248}
EVIDENCE=${FAISAL_EVIDENCE:-$LINUX/tools/faisal-build/evidence/m247-portable-hardware-performance-validation.json}
STATE=${FAISAL_STATE:-$LINUX/FAISAL-PROGRAM-STATE.json}
TAG=${FAISAL_EXPECTED_TAG:-FAISAL-M247-PORTABLE-HARDWARE-PERFORMANCE-EVOLUTION}
mkdir -p "$OUT/logs" "$OUT/artifacts" "$OUT/artifacts/provenance"
CANDIDATE=${FAISAL_CANDIDATE:-$OUT/artifacts/FAISAL-production-candidate-manifest.json}
PROVENANCE=${FAISAL_PROVENANCE:-$OUT/artifacts/provenance/FAISAL-build-manifest.json}
cd "$LINUX"

python3 tools/faisal-build/generate_candidate_provenance.py \
  --repo "$LINUX" \
  --build "$ROOT/build/faisal-lts-6.18.44" \
  --output "$OUT/artifacts/provenance" | tee "$OUT/logs/provenance.log"
python3 tools/faisal-build/prepare_production_candidate_manifest.py \
  --repo "$LINUX" \
  --lts-build "$ROOT/build/faisal-lts-6.18.44" \
  --output "$CANDIDATE" | tee "$OUT/logs/candidate-manifest.log"
python3 tools/faisal-build/generate_faisal_sbom.py \
  --repo "$LINUX" \
  --output "$OUT/artifacts/FAISAL-SBOM.spdx.json" | tee "$OUT/logs/sbom.log"

FAISAL_HARDWARE_OUT="$OUT/hardware" tools/faisal-build/run_hardware_validation.sh | tee "$OUT/logs/m247-hardware.log"
FAISAL_SAFETY_OUT="$OUT/safety" tools/faisal-build/run_safety_validation.sh | tee "$OUT/logs/m246-safety.log"
FAISAL_PLATFORM_OUT="$OUT/platform" tools/faisal-build/run_platform_validation.sh | tee "$OUT/logs/m245-platform.log"
FAISAL_OPTIMIZER_OUT="$OUT/optimizer" tools/faisal-build/run_optimizer_validation.sh | tee "$OUT/logs/m244-optimizer.log"
FAISAL_FABRIC_OUT="$OUT/fabric" tools/faisal-build/run_fabric_validation.sh | tee "$OUT/logs/m242-fabric.log"
FAISAL_AGENT_RUNTIME_OUT="$OUT/agent-runtime" tools/faisal-build/run_agent_runtime_validation.sh | tee "$OUT/logs/m241-agent-runtime.log"
./tools/faisal-build/run_budget_validation.sh | tee "$OUT/logs/m240-budget.log"
./tools/faisal-build/run_kv_tier_validation.sh | tee "$OUT/logs/m239-kv-tier.log"

FAISAL_BUILD=${FAISAL_BUILD:-$ROOT/build/recovered} \
FAISAL_QEMU_ACPI=on FAISAL_QEMU_SMP=1 FAISAL_QEMU_MEMORY=4G \
FAISAL_QEMU_TIMEOUT_SECONDS=240 \
  ./tools/faisal-build/run_end_to_end_hardened_qemu.sh | tee "$OUT/logs/linux72-hardened-qemu.log"
FAISAL_BUILD=${FAISAL_BUILD:-$ROOT/build/recovered} \
FAISAL_SOAK_ROUNDS=2 FAISAL_SOAK_ITERATIONS=256 \
  ./tools/faisal-build/run_industry_soak_qemu.sh | tee "$OUT/logs/linux72-industry-soak.log"
FAISAL_BUILD=$ROOT/build/faisal-lts-6.18.44 \
FAISAL_QEMU_ACPI=on FAISAL_QEMU_SMP=1 FAISAL_QEMU_MEMORY=4G \
FAISAL_QEMU_TIMEOUT_SECONDS=240 \
  ./tools/faisal-build/run_end_to_end_hardened_qemu.sh | tee "$OUT/logs/lts-compatibility-qemu.log"

set +e
FAISAL_BUILD="${FAISAL_BUILD:-$ROOT/build/recovered}" \
FAISAL_CURRENT_AUDIT_OUT="$OUT/current-audit" \
  ./tools/faisal-build/run_full_faisal_current_audit.sh > "$OUT/logs/full-system-audit.log" 2>&1
full_audit_rc=$?
set -e
printf 'FULL_SYSTEM_CURRENT_AUDIT_RC=%s\n' "$full_audit_rc" | tee "$OUT/logs/full-system-audit-result.log"
if [ "$full_audit_rc" -ne 0 ]; then
  tail -160 "$OUT/logs/full-system-audit.log" >&2
  exit "$full_audit_rc"
fi

python3 tools/faisal-build/faisal_readiness_gate.py \
  --repo "$LINUX" \
  --candidate "$CANDIDATE" \
  --state "$STATE" \
  --evidence "$EVIDENCE" \
  --provenance "$PROVENANCE" \
  --expected-tag "$TAG" \
  --mode local \
  --output "$OUT/FAISAL-readiness-gate-local.json" \
  --log "$OUT/logs/m247-hardware.log" \
  --log "$OUT/logs/m246-safety.log" \
  --log "$OUT/logs/m245-platform.log" \
  --log "$OUT/logs/m244-optimizer.log" \
  --log "$OUT/logs/m242-fabric.log" \
  --log "$OUT/logs/m241-agent-runtime.log" \
  --log "$OUT/logs/m240-budget.log" \
  --log "$OUT/logs/m239-kv-tier.log" \
  --log "$OUT/logs/full-system-audit.log" | tee "$OUT/logs/readiness-local.log"

python3 -m json.tool "$OUT/artifacts/FAISAL-SBOM.spdx.json" >/dev/null
python3 -m json.tool "$OUT/FAISAL-readiness-gate-local.json" >/dev/null
printf 'FAISAL_FINAL_INTEGRATION_VALIDATION_OK\n' | tee "$OUT/final-marker.log"
