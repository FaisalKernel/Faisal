#ifndef FAISAL_COORDINATOR_SERVICE_H
#define FAISAL_COORDINATOR_SERVICE_H

#include <stdint.h>
#include "../faisal-memory/faisal_memory_service.h"
#include "../faisal-experience/faisal_experience_service.h"
#include "../faisal-world/faisal_world_state_service.h"
#include "../faisal-orchestrator/faisal_orchestrator_service.h"
#include "../faisal-browser/faisal_browser_tool_service.h"

#define M76_MAX_GOAL 128
#define M76_MAX_SKILL 128
#define M76_FAILURE_NONE 0U
#define M76_FAILURE_EXPERIENCE 1U
#define M76_FAILURE_MODEL 2U
#define M76_FAILURE_WORLD 3U
#define M76_FAILURE_BROWSER 4U
#define M76_FAILURE_IPC 5U

enum m76_state {
	M76_DENIED = 0,
	M76_COMPLETED = 1,
	M76_RECOVERED = 2,
	M76_ROLLED_BACK = 3,
	M76_FAILED = 4
};

struct m76_request {
	char goal[M76_MAX_GOAL];
	char skill[M76_MAX_SKILL];
	uint8_t model_digest[FMS_DIGEST_SIZE];
	uint32_t supervisor_approved;
	uint32_t operator_approved;
	uint32_t failure_stage;
	uint32_t reserved;
	uint64_t supervisor_nonce;
	uint64_t operator_nonce;
};

struct m76_report {
	uint32_t state;
	uint32_t recovery_state;
	uint32_t deployment_gate_open;
	uint32_t canary_passed;
	uint32_t security_passed;
	uint32_t regression_passed;
	uint32_t supervisor_approved;
	uint32_t operator_approved;
	uint64_t experience_sequence;
	uint64_t model_run_id;
	uint64_t model_checkpoint_id;
	uint64_t world_event_sequence;
	uint64_t world_generation;
	uint64_t browser_session_id;
	uint64_t browser_action_id;
	uint64_t coordinator_agent_id;
	uint64_t planner_agent_id;
	uint64_t verifier_agent_id;
	uint64_t ipc_channel_id;
	uint64_t ipc_message_id;
	uint64_t ipc_cancelled_message_id;
	uint64_t reflection_action_id;
	uint64_t reflection_authority_capability;
	uint64_t reflection_event_sequence;
	uint64_t observability_emitted;
	uint64_t observability_last_sequence;
	uint64_t recovery_sequence;
	uint32_t completed_stages;
	uint32_t failure_stage;
};

int m76_run(const struct m76_request *request, struct m76_report *report,
	    const char *journal_prefix);
int m76_deployment_gate(const struct m76_request *request,
			const struct m76_report *report);
int m76_test_malformed_inputs(const struct m76_request *valid_request);

#endif
