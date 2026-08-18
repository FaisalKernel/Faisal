#ifndef FAISAL_RT_CONTRACT_H
#define FAISAL_RT_CONTRACT_H

#include <stddef.h>
#include <stdint.h>

#define FRT_ABI_VERSION 1U
#define FRT_MAX_JOBS 64U
#define FRT_MAX_DEPENDENCIES 8U
#define FRT_MAX_REASON 192U
#define FRT_STATE_READY 1U
#define FRT_STATE_RUNNING 2U
#define FRT_STATE_BLOCKED 3U
#define FRT_STATE_COMPLETED 4U
#define FRT_STATE_OVERRUN 5U
#define FRT_STATE_MISSED 6U
#define FRT_STATE_REJECTED 7U
#define FRT_CRITICALITY_BEST_EFFORT 1U
#define FRT_CRITICALITY_SOFT 2U
#define FRT_CRITICALITY_HARD 3U
#define FRT_VIOLATION_BUDGET 1U
#define FRT_VIOLATION_DEADLINE 2U
#define FRT_VIOLATION_AUTHORITY 4U
#define FRT_VIOLATION_DEPENDENCY 8U
#define FRT_VIOLATION_CPU_AFFINITY 16U
#define FRT_POLICY_FAIL_CLOSED 1U
#define FRT_POLICY_REQUIRE_DEADLINE 2U
#define FRT_POLICY_REQUIRE_BUDGET 4U

enum frt_status {
	FRT_OK = 0,
	FRT_ERR_ARGUMENT = -1,
	FRT_ERR_FULL = -2,
	FRT_ERR_DUPLICATE = -3,
	FRT_ERR_CYCLE = -4,
	FRT_ERR_POLICY = -5,
	FRT_ERR_NOT_FOUND = -6,
	FRT_ERR_BLOCKED = -7,
	FRT_ERR_VIOLATION = -8,
	FRT_ERR_STATE = -9
};

struct frt_job {
	uint64_t job_id;
	uint64_t release_ns;
	uint64_t deadline_ns;
	uint64_t budget_ns;
	uint64_t consumed_ns;
	uint64_t last_dispatch_ns;
	uint64_t dispatch_sequence;
	uint64_t cpu_affinity_mask;
	uint32_t priority;
	uint32_t effective_priority;
	uint32_t criticality;
	uint32_t state;
	uint32_t violation_mask;
	uint32_t dependency_count;
	uint32_t dependencies[FRT_MAX_DEPENDENCIES];
};

struct frt_dispatch {
	uint64_t job_id;
	uint64_t dispatch_sequence;
	uint64_t slack_ns;
	uint64_t remaining_budget_ns;
	uint32_t effective_priority;
	uint32_t criticality;
	uint32_t dependency_fanout;
	uint32_t state;
	char reason[FRT_MAX_REASON];
};

struct frt_service {
	uint32_t abi_version;
	uint32_t policy_flags;
	uint64_t next_sequence;
	uint64_t now_ns;
	uint64_t cpu_mask;
	struct frt_job jobs[FRT_MAX_JOBS];
	size_t count;
};

int frt_init(struct frt_service *service, uint32_t policy_flags,
	uint64_t cpu_mask, uint64_t now_ns);
int frt_validate_job(const struct frt_service *service,
	const struct frt_job *job);
int frt_admit(struct frt_service *service, const struct frt_job *job);
int frt_select(const struct frt_service *service, struct frt_dispatch *out);
int frt_charge(struct frt_service *service, uint64_t job_id,
	uint64_t now_ns, uint64_t runtime_ns, uint32_t authorized);
int frt_complete(struct frt_service *service, uint64_t job_id,
	uint64_t now_ns, uint32_t authorized);
int frt_query(const struct frt_service *service, uint64_t job_id,
	struct frt_job *out);
int frt_test_policy_boundaries(struct frt_service *service);

#endif
