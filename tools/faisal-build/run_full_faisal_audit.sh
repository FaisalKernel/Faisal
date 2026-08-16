#!/bin/sh
set -eu
ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD="$ROOT/build/recovered"
OUT="$BUILD/full-audit-summary.txt"
cd "$LINUX"
: > "$OUT"
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static \
  -Iinclude/uapi -Itools/faisal-memory -Itools/faisal-world \
  tools/faisal-memory/faisal_memory_service.c tools/faisal-world/faisal_world_state_service.c \
  tools/testing/selftests/agi_world_state_test.c \
  -o "$BUILD/agi_world_state_test" -lcrypto -ldl -lpthread
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static \
  -Iinclude/uapi -Itools/faisal-attestation \
  tools/faisal-attestation/faisal_runtime_attestation.c \
  tools/testing/selftests/agi_runtime_attestation_test.c \
  -o "$BUILD/agi_runtime_attestation_test" -lcrypto -ldl -lpthread
set -- \
 tools/faisal-build/run_agent_security_m64_qemu.sh \
 tools/faisal-build/run_transport_qemu.sh \
 tools/faisal-build/run_execution_domain_qemu.sh \
 tools/faisal-build/run_heterogeneous_context_qemu.sh \
 tools/faisal-build/run_graph_telemetry_qemu.sh \
 tools/faisal-build/run_power_policy_qemu.sh \
 tools/faisal-build/run_persistent_memory_qemu.sh \
 tools/faisal-build/run_experience_learning_qemu.sh \
 tools/faisal-build/run_world_state_qemu.sh \
 tools/faisal-build/run_model_orchestration_qemu.sh \
 tools/faisal-build/run_browser_tool_qemu.sh \
 tools/faisal-build/run_end_to_end_qemu.sh \
 tools/faisal-build/run_verified_research_qemu.sh \
 tools/faisal-build/run_deployment_supervisor_qemu.sh \
 tools/faisal-build/run_accelerator_validation_qemu.sh \
 tools/faisal-build/run_cross_subsystem_stress_qemu.sh \
 tools/faisal-build/run_memory_orchestrator_qemu.sh \
 tools/faisal-build/run_cog_kernel_qemu.sh \
 tools/faisal-build/run_self_healing_qemu.sh \
 tools/faisal-build/run_runtime_attestation_qemu.sh
count=0
for harness do
	count=$((count + 1))
	start=$(date +%s%N)
	set +e
	"$harness" > "$BUILD/full-audit-${count}.log" 2>&1
	rc=$?
	set -e
	end=$(date +%s%N)
	elapsed=$(( (end - start) / 1000000 ))
	printf '%02d harness=%s rc=%s elapsed_ms=%s\n' "$count" "$harness" "$rc" "$elapsed" | tee -a "$OUT"
	if [ "$rc" -ne 0 ]; then
		tail -80 "$BUILD/full-audit-${count}.log"
		exit "$rc"
	fi
done
printf 'FAISAL_FULL_AUDIT_COUNT=%s\n' "$count" | tee -a "$OUT"
