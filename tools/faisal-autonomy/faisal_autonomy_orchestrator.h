#ifndef FAISAL_AUTONOMY_ORCHESTRATOR_H
#define FAISAL_AUTONOMY_ORCHESTRATOR_H

#include <stdint.h>
#include "../faisal-research/faisal_research_service.h"
#include "../faisal-experience/faisal_experience_service.h"
#include "../faisal-self-healing/faisal_self_healing.h"
#include <linux/agi_lifecycle.h>

#define M105_MAX_CYCLES 16U
#define M105_MAX_CLAIM M77_MAX_CLAIM
#define M105_MAX_DETAIL FAS_MAX_DETAIL

#define M105_OK 0
#define M105_ERR_ARGUMENT (-1)
#define M105_ERR_LIMIT (-2)
#define M105_ERR_UNVERIFIED (-3)
#define M105_ERR_KERNEL (-4)
#define M105_ERR_POLICY (-5)
#define M105_ERR_STATE (-6)

/* Model output, observations, and diagnoses are evidence only. */
struct m105_cycle {
	uint64_t sequence;
	uint64_t started_ns;
	uint64_t completed_ns;
	uint64_t source_id;
	uint64_t related_source_id;
	uint64_t memory_record_id;
	uint64_t experience_sequence;
	uint32_t evidence_mask;
	uint32_t verified;
	uint32_t promoted;
	uint32_t repair_state;
	int32_t status;
	uint8_t evidence_digest[FMS_DIGEST_SIZE];
	char claim[M105_MAX_CLAIM];
	char detail[M105_MAX_DETAIL];
};

struct m105_service {
	struct m77_service research;
	struct fes_service experience;
	struct fas_service healing;
	struct agi_lc_autonomy_control kernel_control;
	int kernel_fd;
	uint32_t cycle_count;
	uint32_t kernel_bound;
	uint64_t next_sequence;
	struct m105_cycle cycles[M105_MAX_CYCLES];
};

int m105_open(struct m105_service *service, const char *journal_prefix,
		      const char *kernel_device);
void m105_close(struct m105_service *service);
int m105_observe_verify_learn(struct m105_service *service,
			      const char *claim,
			      const char *primary_uri,
			      const char *primary_content,
			      const char *secondary_uri,
			      const char *secondary_content,
			      struct m105_cycle *out);
int m105_record_kernel_evidence(struct m105_service *service,
				uint32_t evidence_mask,
				const uint8_t evidence_digest[FMS_DIGEST_SIZE]);
int m105_query_kernel_gate(struct m105_service *service,
				   struct agi_lc_autonomy_control *out);
int m105_test_model_output_not_authority(struct m105_service *service);

#endif
