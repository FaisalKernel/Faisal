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
  tools/faisal-memory/faisal_memory_service.c \
  tools/faisal-world/faisal_world_state_service.c \
  tools/testing/selftests/agi_world_state_test.c \
  -o "$BUILD/agi_world_state_test" -lcrypto -ldl -lpthread
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static \
  -Iinclude/uapi -Itools/faisal-attestation \
  tools/faisal-attestation/faisal_runtime_attestation.c \
  tools/testing/selftests/agi_runtime_attestation_test.c \
  -o "$BUILD/agi_runtime_attestation_test" -lcrypto -ldl -lpthread
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static \
  -Iinclude/uapi -Itools/faisal-concurrency \
  tools/faisal-concurrency/faisal_concurrency_service.c \
  tools/testing/selftests/agi_concurrent_lifecycle_ipc_test.c \
  -o "$BUILD/agi_concurrent_lifecycle_ipc_test" -lpthread
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static \
  -Iinclude/uapi -Itools/faisal-memory -Itools/faisal-world \
  -Itools/faisal-browser -Itools/faisal-research \
  tools/faisal-memory/faisal_memory_service.c \
  tools/faisal-world/faisal_world_state_service.c \
  tools/faisal-browser/faisal_browser_tool_service.c \
  tools/faisal-research/faisal_research_service.c \
  tools/testing/selftests/agi_verified_research_test.c \
  -o "$BUILD/agi_verified_research_test" -lcrypto -ldl -lpthread
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static \
  -Iinclude/uapi -Itools/faisal-memory \
  tools/faisal-memory/faisal_memory_service.c \
  tools/faisal-memory/faisal_memory_transaction.c \
  tools/testing/selftests/agi_memory_transaction_test.c \
  -o "$BUILD/agi_memory_transaction_test" -lcrypto -lpthread
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static \
  -Iinclude/uapi -Itools/faisal-memory -Itools/faisal-deploy \
  -Itools/faisal-self-healing -Itools/faisal-attestation \
  -Itools/faisal-runtime-verification \
  tools/faisal-memory/faisal_memory_service.c \
  tools/faisal-deploy/faisal_deploy_supervisor.c \
  tools/faisal-self-healing/faisal_self_healing.c \
  tools/faisal-attestation/faisal_runtime_attestation.c \
  tools/faisal-runtime-verification/faisal_runtime_verification.c \
  tools/testing/selftests/agi_runtime_verification_test.c \
    -o "$BUILD/agi_runtime_verification_test" -lcrypto -ldl -lpthread

cc -O2 -Wall -Wextra -Werror -Wno-cpp -static \
  -Iinclude/uapi \
  tools/testing/selftests/agi_autonomy_control_test.c \
  -o "$BUILD/agi_autonomy_control_test"
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static \
  -Iinclude/uapi -Itools/faisal-memory -Itools/faisal-world \
  -Itools/faisal-browser -Itools/faisal-research -Itools/faisal-experience \
  -Itools/faisal-self-healing -Itools/faisal-deploy -Itools/faisal-autonomy \
  tools/faisal-memory/faisal_memory_service.c \
  tools/faisal-memory/faisal_memory_transaction.c \
  tools/faisal-world/faisal_world_state_service.c \
  tools/faisal-browser/faisal_browser_tool_service.c \
  tools/faisal-research/faisal_research_service.c \
  tools/faisal-experience/faisal_experience_service.c \
  tools/faisal-deploy/faisal_deploy_supervisor.c \
  tools/faisal-self-healing/faisal_self_healing.c \
  tools/faisal-autonomy/faisal_autonomy_orchestrator.c \
  tools/testing/selftests/agi_autonomy_orchestrator_test.c \
  -o "$BUILD/agi_autonomy_orchestrator_test" -lcrypto -ldl -lpthread
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static -pthread \
  -Iinclude/uapi -Itools/faisal-task -Itools/faisal-execution \
  tools/faisal-task/faisal_task_service.c \
  tools/faisal-execution/faisal_execution_engine.c \
  tools/testing/selftests/agi_durable_execution_test.c \
  -o "$BUILD/agi_durable_execution_test" -lcrypto -ldl -lpthread
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static -pthread \
  -Iinclude/uapi -Itools/faisal-collab -Itools/faisal-memory-unified \
  -Itools/faisal-task -Itools/faisal-memory \
  tools/faisal-collab/faisal_collaboration_service.c \
  tools/faisal-memory-unified/faisal_unified_memory.c \
  tools/testing/selftests/agi_collaboration_memory_test.c \
  -o "$BUILD/agi_collaboration_memory_test" -lcrypto -ldl -lpthread
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static -pthread \
  -Iinclude/uapi -Itools/faisal-world-model -Itools/faisal-model-router \
  tools/faisal-world-model/faisal_world_model_service.c \
  tools/faisal-model-router/faisal_model_router.c \
  tools/testing/selftests/agi_world_model_router_test.c \
  -o "$BUILD/agi_world_model_router_test" -lcrypto -ldl -lpthread
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static -pthread \
  -Itools/faisal-sandbox tools/faisal-sandbox/faisal_sandbox_service.c \
  tools/testing/selftests/agi_sandbox_fabric_test.c \
  -o "$BUILD/agi_sandbox_fabric_test" -ldl -lpthread
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static -pthread \
  -Itools/faisal-engineering tools/faisal-engineering/faisal_engineering_service.c \
  tools/testing/selftests/agi_software_engineering_test.c \
  -o "$BUILD/agi_software_engineering_test" -ldl -lpthread
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static -pthread \
  -Itools/faisal-repo-adapter tools/faisal-repo-adapter/faisal_repo_adapter.c \
  tools/testing/selftests/agi_repository_adapter_test.c \
  -o "$BUILD/agi_repository_adapter_test" -lcrypto -ldl -lpthread
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static -pthread \
  -Itools/faisal-scanners -Itools/faisal-engineering \
  tools/faisal-scanners/faisal_scanner_service.c \
  tools/faisal-engineering/faisal_engineering_service.c \
  tools/testing/selftests/agi_scanner_adapter_test.c \
  -o "$BUILD/agi_scanner_adapter_test" -lcrypto
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
 tools/faisal-build/run_scheduler_urgency_qemu.sh \
 tools/faisal-build/run_nondeterministic_adapter_qemu.sh \
 tools/faisal-build/run_lifecycle_uapi_fuzz_qemu.sh \
 tools/faisal-build/run_self_healing_qemu.sh \
 tools/faisal-build/run_runtime_attestation_qemu.sh \
 tools/faisal-build/run_concurrent_lifecycle_ipc_qemu.sh \
 tools/faisal-build/run_memory_transaction_qemu.sh \
 tools/faisal-build/run_runtime_verification_qemu.sh \
 tools/faisal-build/run_autonomy_control_qemu.sh \
 tools/faisal-build/run_autonomy_orchestrator_qemu.sh \
 tools/faisal-build/run_durable_execution_qemu.sh \
 tools/faisal-build/run_collaboration_memory_qemu.sh \
 tools/faisal-build/run_world_model_router_qemu.sh \
 tools/faisal-build/run_sandbox_fabric_qemu.sh \
 tools/faisal-build/run_software_engineering_qemu.sh \
 tools/faisal-build/run_repository_adapter_qemu.sh \
 tools/faisal-build/run_scanner_adapter_qemu.sh
count=0
for harness do
	count=$((count + 1))
	start=$(date +%s%N)
	rm -f "$BUILD/full-audit-${count}.log" "$BUILD/full-audit-${count}-retry.log"
	set +e
	"$harness" > "$BUILD/full-audit-${count}.log" 2>&1
	rc=$?
	retry_rc=0
	if [ "$rc" -ne 0 ]; then
		"$harness" > "$BUILD/full-audit-${count}-retry.log" 2>&1
		retry_rc=$?
	fi
	set -e
	if grep -Eq 'BUG:|Oops:|kernel panic|KASAN:|KCSAN:|WARNING:.*kernel|general protection fault|unable to handle kernel|Tainted: \[W\]=WARN' "$BUILD/full-audit-${count}.log" ||
	   { [ "$rc" -ne 0 ] && [ -r "$BUILD/full-audit-${count}-retry.log" ] && grep -Eq 'BUG:|Oops:|kernel panic|KASAN:|KCSAN:|WARNING:.*kernel|general protection fault|unable to handle kernel|Tainted: \[W\]=WARN' "$BUILD/full-audit-${count}-retry.log"; }; then
		printf '%02d harness=%s kernel_diagnostic=1\n' "$count" "$harness" | tee -a "$OUT"
		tail -120 "$BUILD/full-audit-${count}.log"
		[ -r "$BUILD/full-audit-${count}-retry.log" ] && tail -120 "$BUILD/full-audit-${count}-retry.log" || true
		exit 1
	fi
	end=$(date +%s%N)
	elapsed=$(( (end - start) / 1000000 ))
	if [ "$rc" -ne 0 ] && [ "$retry_rc" -eq 0 ]; then
		printf '%02d harness=%s rc=0 retry_after_initial_rc=%s elapsed_ms=%s\n' \
			"$count" "$harness" "$rc" "$elapsed" | tee -a "$OUT"
	elif [ "$rc" -eq 0 ]; then
		printf '%02d harness=%s rc=0 elapsed_ms=%s\n' \
			"$count" "$harness" "$elapsed" | tee -a "$OUT"
	else
		printf '%02d harness=%s rc=%s retry_rc=%s elapsed_ms=%s\n' \
			"$count" "$harness" "$rc" "$retry_rc" "$elapsed" | tee -a "$OUT"
		tail -80 "$BUILD/full-audit-${count}.log"
		tail -80 "$BUILD/full-audit-${count}-retry.log"
		exit "$retry_rc"
	fi
done
printf 'FAISAL_FULL_AUDIT_COUNT=%s\n' "$count" | tee -a "$OUT"
