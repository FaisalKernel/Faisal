#include "faisal_rt_contract.h"
#include <stdio.h>
#include <string.h>

static int index_of(const struct frt_service *s, uint64_t job_id)
{
	size_t i;
	if (!s)
		return -1;
	for (i = 0; i < s->count; i++)
		if (s->jobs[i].job_id == job_id)
			return (int)i;
	return -1;
}

static int dfs_cycle(const struct frt_service *s, int idx,
	uint8_t visiting[FRT_MAX_JOBS], uint8_t finished[FRT_MAX_JOBS])
{
	uint32_t i;
	const struct frt_job *job;

	if (idx < 0 || (size_t)idx >= s->count)
		return FRT_ERR_CYCLE;
	if (finished[idx])
		return FRT_OK;
	if (visiting[idx])
		return FRT_ERR_CYCLE;
	visiting[idx] = 1;
	job = &s->jobs[idx];
	for (i = 0; i < job->dependency_count; i++) {
		int dep = index_of(s, job->dependencies[i]);
		if (dep < 0 || dfs_cycle(s, dep, visiting, finished) != FRT_OK)
			return FRT_ERR_CYCLE;
	}
	visiting[idx] = 0;
	finished[idx] = 1;
	return FRT_OK;
}

static uint32_t base_effective_priority(const struct frt_job *job)
{
	uint64_t value;
	if (!job)
		return 0;
	value = (uint64_t)job->priority + (uint64_t)job->criticality * 1000ULL;
	return value > 0xffffffffULL ? 0xffffffffU : (uint32_t)value;
}

static uint32_t inherited_priority(const struct frt_service *s, int idx,
	uint8_t visiting[FRT_MAX_JOBS])
{
	uint32_t best;
	size_t i;

	if (idx < 0 || (size_t)idx >= s->count || visiting[idx])
		return 0;
	visiting[idx] = 1;
	best = base_effective_priority(&s->jobs[idx]);
	for (i = 0; i < s->count; i++) {
		uint32_t d;
		uint32_t inherited;
		if (i == (size_t)idx)
			continue;
		for (d = 0; d < s->jobs[i].dependency_count; d++) {
			if (s->jobs[i].dependencies[d] != s->jobs[idx].job_id)
				continue;
			inherited = inherited_priority(s, (int)i, visiting);
			if (inherited > best)
				best = inherited;
			break;
		}
	}
	visiting[idx] = 0;
	return best;
}

static int dependency_ready(const struct frt_service *s,
	const struct frt_job *job, uint32_t *fanout)
{
	uint32_t i;
	if (fanout)
		*fanout = 0;
	for (i = 0; i < job->dependency_count; i++) {
		int dep = index_of(s, job->dependencies[i]);
		if (dep < 0)
			return 0;
		if (s->jobs[dep].state != FRT_STATE_COMPLETED)
			return 0;
		if (fanout)
			(*fanout)++;
	}
	return 1;
}

int frt_init(struct frt_service *service, uint32_t policy_flags,
	uint64_t cpu_mask, uint64_t now_ns)
{
	if (!service || !cpu_mask || (policy_flags & ~(
		FRT_POLICY_FAIL_CLOSED | FRT_POLICY_REQUIRE_DEADLINE |
		FRT_POLICY_REQUIRE_BUDGET)))
		return FRT_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->abi_version = FRT_ABI_VERSION;
	service->policy_flags = policy_flags;
	service->cpu_mask = cpu_mask;
	service->now_ns = now_ns;
	service->next_sequence = 1;
	return FRT_OK;
}

int frt_validate_job(const struct frt_service *service,
	const struct frt_job *job)
{
	uint32_t i, j;
	if (!service || !job || !job->job_id || !job->deadline_ns ||
		!job->release_ns || job->release_ns > job->deadline_ns ||
		(job->criticality < FRT_CRITICALITY_BEST_EFFORT ||
		 job->criticality > FRT_CRITICALITY_HARD) ||
		!job->cpu_affinity_mask || !(job->cpu_affinity_mask & service->cpu_mask) ||
		(job->dependency_count > FRT_MAX_DEPENDENCIES) ||
		((service->policy_flags & FRT_POLICY_REQUIRE_DEADLINE) &&
		 !job->deadline_ns) || ((service->policy_flags & FRT_POLICY_REQUIRE_BUDGET) &&
		 !job->budget_ns))
		return FRT_ERR_ARGUMENT;
	for (i = 0; i < job->dependency_count; i++) {
		if (!job->dependencies[i] || job->dependencies[i] == job->job_id)
			return FRT_ERR_CYCLE;
		for (j = i + 1; j < job->dependency_count; j++)
			if (job->dependencies[i] == job->dependencies[j])
				return FRT_ERR_DUPLICATE;
	}
	return FRT_OK;
}

int frt_admit(struct frt_service *service, const struct frt_job *job)
{
	struct frt_job copy;
	uint8_t visiting[FRT_MAX_JOBS];
	uint8_t finished[FRT_MAX_JOBS];
	uint32_t i;
	int rc;

	if (!service || !job || service->count >= FRT_MAX_JOBS)
		return FRT_ERR_ARGUMENT;
	if (index_of(service, job->job_id) >= 0)
		return FRT_ERR_DUPLICATE;
	rc = frt_validate_job(service, job);
	if (rc != FRT_OK)
		return rc;
	for (i = 0; i < job->dependency_count; i++)
		if (index_of(service, job->dependencies[i]) < 0)
			return FRT_ERR_NOT_FOUND;
	copy = *job;
	copy.state = FRT_STATE_READY;
	copy.effective_priority = base_effective_priority(&copy);
	copy.violation_mask = 0;
	service->jobs[service->count++] = copy;
	memset(visiting, 0, sizeof(visiting));
	memset(finished, 0, sizeof(finished));
	for (i = 0; i < service->count; i++) {
		rc = dfs_cycle(service, (int)i, visiting, finished);
		if (rc != FRT_OK) {
			service->count--;
			return rc;
		}
	}
	return FRT_OK;
}

int frt_select(const struct frt_service *service, struct frt_dispatch *out)
{
	struct frt_service *mutable_service = (struct frt_service *)service;
	int best = -1;
	uint64_t best_slack = UINT64_MAX;
	uint32_t best_priority = 0;
	uint32_t best_criticality = 0;
	size_t i;

	if (!service || !out)
		return FRT_ERR_ARGUMENT;
	for (i = 0; i < service->count; i++) {
		struct frt_job *job = &mutable_service->jobs[i];
		uint8_t visiting[FRT_MAX_JOBS] = {0};
		uint32_t fanout;
		uint32_t effective;
		uint64_t slack;
		if (job->state != FRT_STATE_READY ||
			!dependency_ready(service, job, &fanout))
			continue;
		if (service->now_ns >= job->deadline_ns) {
			job->state = FRT_STATE_MISSED;
			job->violation_mask |= FRT_VIOLATION_DEADLINE;
			continue;
		}
		if (job->budget_ns && job->consumed_ns >= job->budget_ns) {
			job->state = FRT_STATE_OVERRUN;
			job->violation_mask |= FRT_VIOLATION_BUDGET;
			continue;
		}
		effective = inherited_priority(service, (int)i, visiting);
		job->effective_priority = effective;
		slack = job->deadline_ns - service->now_ns;
		if (best < 0 || slack < best_slack ||
			(slack == best_slack && effective > best_priority) ||
			(slack == best_slack && effective == best_priority &&
			 job->criticality > best_criticality) ||
			(slack == best_slack && effective == best_priority &&
			 job->criticality == best_criticality &&
			 job->job_id < mutable_service->jobs[best].job_id)) {
			best = (int)i;
			best_slack = slack;
			best_priority = effective;
			best_criticality = job->criticality;
		}
	}
	if (best < 0)
		return FRT_ERR_BLOCKED;
	mutable_service->jobs[best].state = FRT_STATE_RUNNING;
	mutable_service->jobs[best].last_dispatch_ns = service->now_ns;
	mutable_service->jobs[best].dispatch_sequence = mutable_service->next_sequence++;
	memset(out, 0, sizeof(*out));
	out->job_id = mutable_service->jobs[best].job_id;
	out->dispatch_sequence = mutable_service->jobs[best].dispatch_sequence;
	out->slack_ns = best_slack;
	out->remaining_budget_ns = mutable_service->jobs[best].budget_ns >
		mutable_service->jobs[best].consumed_ns ?
		mutable_service->jobs[best].budget_ns - mutable_service->jobs[best].consumed_ns : 0;
	out->effective_priority = mutable_service->jobs[best].effective_priority;
	out->criticality = mutable_service->jobs[best].criticality;
	(void)dependency_ready(service, &mutable_service->jobs[best],
		&out->dependency_fanout);
	out->state = FRT_STATE_RUNNING;
	snprintf(out->reason, sizeof(out->reason),
		"deadline=%llu slack=%llu effective_priority=%u criticality=%u fail_closed=%u",
		(unsigned long long)mutable_service->jobs[best].deadline_ns,
		(unsigned long long)out->slack_ns, out->effective_priority,
		out->criticality,
		!!(service->policy_flags & FRT_POLICY_FAIL_CLOSED));
	return FRT_OK;
}

int frt_charge(struct frt_service *service, uint64_t job_id,
	uint64_t now_ns, uint64_t runtime_ns, uint32_t authorized)
{
	int idx;
	struct frt_job *job;
	if (!service || !job_id)
		return FRT_ERR_ARGUMENT;
	idx = index_of(service, job_id);
	if (idx < 0)
		return FRT_ERR_NOT_FOUND;
	job = &service->jobs[idx];
	if (job->state != FRT_STATE_RUNNING)
		return FRT_ERR_STATE;
	service->now_ns = now_ns;
	job->consumed_ns += runtime_ns;
	if (!authorized)
		job->violation_mask |= FRT_VIOLATION_AUTHORITY;
	if (job->budget_ns && job->consumed_ns > job->budget_ns) {
		job->state = FRT_STATE_OVERRUN;
		job->violation_mask |= FRT_VIOLATION_BUDGET;
	}
	if (now_ns > job->deadline_ns) {
		job->state = FRT_STATE_MISSED;
		job->violation_mask |= FRT_VIOLATION_DEADLINE;
	}
	if (job->violation_mask)
		return FRT_ERR_VIOLATION;
	return FRT_OK;
}

int frt_complete(struct frt_service *service, uint64_t job_id,
	uint64_t now_ns, uint32_t authorized)
{
	int idx;
	struct frt_job *job;
	if (!service || !job_id)
		return FRT_ERR_ARGUMENT;
	idx = index_of(service, job_id);
	if (idx < 0)
		return FRT_ERR_NOT_FOUND;
	job = &service->jobs[idx];
	if (job->state != FRT_STATE_RUNNING)
		return FRT_ERR_STATE;
	service->now_ns = now_ns;
	if (!authorized)
		job->violation_mask |= FRT_VIOLATION_AUTHORITY;
	if (now_ns > job->deadline_ns)
		job->violation_mask |= FRT_VIOLATION_DEADLINE;
	if (job->budget_ns && job->consumed_ns > job->budget_ns)
		job->violation_mask |= FRT_VIOLATION_BUDGET;
	if (job->violation_mask) {
		job->state = (job->violation_mask & FRT_VIOLATION_DEADLINE) ?
			FRT_STATE_MISSED : FRT_STATE_OVERRUN;
		return FRT_ERR_VIOLATION;
	}
	job->state = FRT_STATE_COMPLETED;
	return FRT_OK;
}

int frt_query(const struct frt_service *service, uint64_t job_id,
	struct frt_job *out)
{
	int idx;
	if (!service || !out)
		return FRT_ERR_ARGUMENT;
	idx = index_of(service, job_id);
	if (idx < 0)
		return FRT_ERR_NOT_FOUND;
	*out = service->jobs[idx];
	return FRT_OK;
}

int frt_test_policy_boundaries(struct frt_service *service)
{
	struct frt_job malformed;
	if (!service)
		return FRT_ERR_ARGUMENT;
	memset(&malformed, 0, sizeof(malformed));
	malformed.job_id = 9000;
	malformed.release_ns = service->now_ns;
	malformed.deadline_ns = service->now_ns + 1000;
	malformed.cpu_affinity_mask = service->cpu_mask;
	malformed.criticality = FRT_CRITICALITY_HARD;
	if (frt_admit(service, &malformed) == FRT_OK)
		return FRT_ERR_POLICY;
	return FRT_OK;
}
