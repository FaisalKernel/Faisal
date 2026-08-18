#!/usr/bin/env bash
set -euo pipefail

ROOT=${FAISAL_ROOT:-/home/ubuntu/agi-kernel}
LINUX=${FAISAL_LINUX:-$ROOT/linux}
BUILD=${FAISAL_BUILD:-$ROOT/build/recovered}
OUT=${FAISAL_CURRENT_AUDIT_OUT:-$BUILD/faisal-current-audit}
mkdir -p "$OUT"
cd "$LINUX"

harnesses=(
  tools/faisal-build/run_agent_security_m64_qemu.sh
  tools/faisal-build/run_transport_qemu.sh
  tools/faisal-build/run_execution_domain_qemu.sh
  tools/faisal-build/run_heterogeneous_context_qemu.sh
  tools/faisal-build/run_graph_telemetry_qemu.sh
  tools/faisal-build/run_power_policy_qemu.sh
  tools/faisal-build/run_runtime_attestation_qemu.sh
  tools/faisal-build/run_concurrent_lifecycle_ipc_qemu.sh
  tools/faisal-build/run_memory_transaction_qemu.sh
  tools/faisal-build/run_runtime_verification_qemu.sh
  tools/faisal-build/run_durable_execution_qemu.sh
  tools/faisal-build/run_knowledge_precision_qemu.sh
  tools/faisal-build/run_collaboration_memory_qemu.sh
  tools/faisal-build/run_world_model_router_qemu.sh
  tools/faisal-build/run_sandbox_fabric_qemu.sh
  tools/faisal-build/run_software_engineering_qemu.sh
  tools/faisal-build/run_repository_adapter_qemu.sh
  tools/faisal-build/run_scanner_adapter_qemu.sh
  tools/faisal-build/run_sandbox_launcher_qemu.sh
  tools/faisal-build/run_self_healing_hardened_qemu.sh
  tools/faisal-build/run_end_to_end_hardened_qemu.sh
)

: > "$OUT/summary.tsv"
count=0
for harness in "${harnesses[@]}"; do
  test -x "$harness"
  count=$((count + 1))
  log="$OUT/harness-${count}.log"
  retry="$OUT/harness-${count}-retry.log"
  start=$(date +%s%N)
  set +e
  FAISAL_BUILD="$BUILD" "$harness" > "$log" 2>&1
  rc=$?
  retry_rc=0
  if [ "$rc" -ne 0 ]; then
    FAISAL_BUILD="$BUILD" "$harness" > "$retry" 2>&1
    retry_rc=$?
  fi
  set -e
  if grep -Eq 'BUG:|Oops:|kernel panic|KASAN:|KCSAN:|WARNING:.*kernel|general protection fault|unable to handle kernel|Tainted: \[W\]=WARN' "$log" ||
     { [ -r "$retry" ] && grep -Eq 'BUG:|Oops:|kernel panic|KASAN:|KCSAN:|WARNING:.*kernel|general protection fault|unable to handle kernel|Tainted: \[W\]=WARN' "$retry"; }; then
    printf '%02d\tharness=%s\tkernel_diagnostic=1\n' "$count" "$harness" | tee -a "$OUT/summary.tsv"
    tail -160 "$log"
    [ -r "$retry" ] && tail -160 "$retry" || true
    exit 1
  fi
  end=$(date +%s%N)
  elapsed=$(( (end - start) / 1000000 ))
  if [ "$rc" -eq 0 ]; then
    printf '%02d\tharness=%s\trc=0\telapsed_ms=%s\n' "$count" "$harness" "$elapsed" | tee -a "$OUT/summary.tsv"
  elif [ "$retry_rc" -eq 0 ]; then
    printf '%02d\tharness=%s\trc=0\tretry_after_initial_rc=%s\telapsed_ms=%s\n' "$count" "$harness" "$rc" "$elapsed" | tee -a "$OUT/summary.tsv"
  else
    printf '%02d\tharness=%s\trc=%s\tretry_rc=%s\telapsed_ms=%s\n' "$count" "$harness" "$rc" "$retry_rc" "$elapsed" | tee -a "$OUT/summary.tsv"
    tail -120 "$log"
    [ -r "$retry" ] && tail -120 "$retry" || true
    exit "$retry_rc"
  fi
done
printf 'FAISAL_FULL_CURRENT_AUDIT_COUNT=%s\n' "$count" | tee -a "$OUT/summary.tsv"
printf 'FAISAL_FULL_CURRENT_AUDIT_OK count=%s\n' "$count"
